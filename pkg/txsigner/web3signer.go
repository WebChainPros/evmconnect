// Copyright © 2026 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package txsigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/hyperledger-firefly/signer/pkg/ethsigner"
	"github.com/hyperledger-firefly/signer/pkg/ethtypes"
	"github.com/hyperledger-firefly/signer/pkg/secp256k1"
	"github.com/hyperledger-firefly/transaction-manager/pkg/ffcapi"
)

type web3SignerRequest struct {
	Data string `json:"data"`
}

type Web3SignerClient struct {
	web3signerURL string
	connector     ffcapi.API
	chainID       int64
	client        *http.Client
	pubKeyMap     map[string]string
	mux           sync.Mutex
}

func NewWeb3SignerClient(web3signerURL string, connector ffcapi.API) (*Web3SignerClient, error) {
	if web3signerURL == "" {
		return nil, fmt.Errorf("web3signer URL is required")
	}
	web3signerURL = strings.TrimSuffix(web3signerURL, "/")
	return &Web3SignerClient{
		web3signerURL: web3signerURL,
		connector:     connector,
		client:        &http.Client{Timeout: 30 * time.Second},
		pubKeyMap:     make(map[string]string),
	}, nil
}

func (s *Web3SignerClient) refreshPubKeyMap(ctx context.Context) error {
	apiURL := fmt.Sprintf("%s/api/v1/eth1/publicKeys", s.web3signerURL)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create publicKeys request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute GET publicKeys request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to fetch public keys from web3signer, status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var pubKeys []string
	if err := json.NewDecoder(resp.Body).Decode(&pubKeys); err != nil {
		return fmt.Errorf("failed to decode publicKeys response: %w", err)
	}

	newMap := make(map[string]string)
	for _, pk := range pubKeys {
		pkClean := strings.TrimPrefix(pk, "0x")
		pkBytes, err := hex.DecodeString(pkClean)
		if err != nil {
			continue
		}
		if len(pkBytes) == 64 {
			pkBytes = append([]byte{0x04}, pkBytes...)
		}
		pubKey, err := btcec.ParsePubKey(pkBytes)
		if err != nil {
			continue
		}
		addr := secp256k1.PublicKeyToAddress(pubKey)
		addrStr := strings.ToLower(addr.String())
		newMap[addrStr] = pk
	}

	s.mux.Lock()
	s.pubKeyMap = newMap
	s.mux.Unlock()
	return nil
}

func (s *Web3SignerClient) getPublicKey(ctx context.Context, keyID string) (string, error) {
	keyIDLower := strings.ToLower(keyID)
	s.mux.Lock()
	var pubKey string
	if s.pubKeyMap != nil {
		pubKey = s.pubKeyMap[keyIDLower]
	}
	s.mux.Unlock()

	if pubKey == "" {
		if err := s.refreshPubKeyMap(ctx); err != nil {
			return "", fmt.Errorf("failed to refresh public key map from web3signer: %w", err)
		}
		s.mux.Lock()
		if s.pubKeyMap != nil {
			pubKey = s.pubKeyMap[keyIDLower]
		}
		s.mux.Unlock()
	}

	if pubKey == "" {
		return "", fmt.Errorf("address %s not found in Web3Signer loaded keys", keyID)
	}
	return pubKey, nil
}

func (s *Web3SignerClient) getChainID(ctx context.Context) (int64, error) {
	s.mux.Lock()
	chainID := s.chainID
	s.mux.Unlock()

	if chainID != 0 {
		return chainID, nil
	}

	readyRes, _, err := s.connector.IsReady(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to check connector readiness for chain ID: %w", err)
	}
	if readyRes == nil || readyRes.DownstreamDetails == nil {
		return 0, fmt.Errorf("connector ready response returned no downstream details")
	}
	var details map[string]interface{}
	if err := json.Unmarshal(readyRes.DownstreamDetails.Bytes(), &details); err != nil {
		return 0, fmt.Errorf("failed to unmarshal downstream details: %w", err)
	}
	chainIDVal, ok := details["chainID"]
	if !ok {
		return 0, fmt.Errorf("chainID not found in downstream details")
	}

	switch v := chainIDVal.(type) {
	case string:
		if strings.HasPrefix(v, "0x") {
			val, err := strconv.ParseInt(strings.TrimPrefix(v, "0x"), 16, 64)
			if err != nil {
				return 0, err
			}
			chainID = val
		} else {
			val, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, err
			}
			chainID = val
		}
	case float64:
		chainID = int64(v)
	default:
		return 0, fmt.Errorf("unexpected chainID type: %T", chainIDVal)
	}

	s.mux.Lock()
	s.chainID = chainID
	s.mux.Unlock()
	return chainID, nil
}

func parseGasPrices(params *signerTxParams) (gasPrice, maxPriorityFeePerGas, maxFeePerGas *ethtypes.HexInteger) {
	if params.GasPrice == nil {
		return nil, nil, nil
	}
	gasPriceObject := params.GasPrice.JSONObjectNowarn()
	maxPriorityFee := gasPriceObject.GetInteger("maxPriorityFeePerGas")
	maxFee := gasPriceObject.GetInteger("maxFeePerGas")
	if (maxPriorityFee != nil && maxPriorityFee.Sign() > 0) || (maxFee != nil && maxFee.Sign() > 0) {
		if maxPriorityFee != nil {
			maxPriorityFeePerGas = (*ethtypes.HexInteger)(maxPriorityFee)
		}
		if maxFee != nil {
			maxFeePerGas = (*ethtypes.HexInteger)(maxFee)
		}
		return nil, maxPriorityFeePerGas, maxFeePerGas
	}

	gp := gasPriceObject.GetInteger("gasPrice")
	if gp != nil && gp.Sign() > 0 {
		gasPrice = (*ethtypes.HexInteger)(gp)
	} else {
		var bi big.Int
		if err := json.Unmarshal(params.GasPrice.Bytes(), &bi); err == nil {
			gasPrice = (*ethtypes.HexInteger)(&bi)
		}
	}
	return gasPrice, nil, nil
}

func (s *Web3SignerClient) requestSignature(ctx context.Context, pubKey string, signaturePayload []byte) (*secp256k1.SignatureData, error) {
	apiURL := fmt.Sprintf("%s/api/v1/eth1/sign/%s", s.web3signerURL, pubKey)
	reqPayload := &web3SignerRequest{
		Data: "0x" + hex.EncodeToString(signaturePayload),
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal web3signer request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request to Web3Signer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("web3signer sign request failed with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read web3signer response: %w", err)
	}

	sigHex := strings.TrimPrefix(strings.TrimSpace(string(respBytes)), "0x")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature hex from web3signer response: %w", err)
	}
	if len(sigBytes) != 65 {
		return nil, fmt.Errorf("invalid signature length received from web3signer (expected 65 bytes, got %d bytes)", len(sigBytes))
	}

	return &secp256k1.SignatureData{
		V: new(big.Int).SetBytes([]byte{sigBytes[64]}),
		R: new(big.Int).SetBytes(sigBytes[0:32]),
		S: new(big.Int).SetBytes(sigBytes[32:64]),
	}, nil
}

func (s *Web3SignerClient) SignTransaction(ctx context.Context, keyID string, txParamsJSON []byte) ([]byte, error) {
	pubKey, err := s.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	var params signerTxParams
	if err := json.Unmarshal(txParamsJSON, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tx params: %w", err)
	}

	var toAddress *ethtypes.Address0xHex
	if params.To != "" {
		toAddress = ethtypes.MustNewAddress(params.To)
	}

	var nonceVal, gasLimitVal, valueVal big.Int
	nonceVal.SetString(params.Nonce, 10)
	gasLimitVal.SetString(params.Gas, 10)
	if params.Value != "" {
		valueVal.SetString(params.Value, 10)
	}

	dataBytes, err := hex.DecodeString(strings.TrimPrefix(params.Data, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode data hex: %w", err)
	}

	gasPrice, maxPriorityFeePerGas, maxFeePerGas := parseGasPrices(&params)

	chainID, err := s.getChainID(ctx)
	if err != nil {
		return nil, err
	}

	tx := &ethsigner.Transaction{
		Nonce:                (*ethtypes.HexInteger)(&nonceVal),
		GasLimit:             (*ethtypes.HexInteger)(&gasLimitVal),
		To:                   toAddress,
		Value:                (*ethtypes.HexInteger)(&valueVal),
		Data:                 ethtypes.HexBytes0xPrefix(dataBytes),
		GasPrice:             gasPrice,
		MaxPriorityFeePerGas: maxPriorityFeePerGas,
		MaxFeePerGas:         maxFeePerGas,
	}

	signaturePayload := tx.SignaturePayload(chainID)

	sigData, err := s.requestSignature(ctx, pubKey, signaturePayload.Bytes())
	if err != nil {
		return nil, err
	}

	var signedTx []byte
	if tx.MaxPriorityFeePerGas.BigInt().Sign() > 0 || tx.MaxFeePerGas.BigInt().Sign() > 0 {
		signedTx, err = tx.FinalizeEIP1559WithSignature(signaturePayload, sigData)
	} else {
		signedTx, err = tx.FinalizeLegacyEIP155WithSignature(signaturePayload, sigData, chainID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to finalize transaction with signature: %w", err)
	}

	return signedTx, nil
}
