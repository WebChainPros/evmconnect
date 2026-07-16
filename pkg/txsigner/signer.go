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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type signerTxParams struct {
	Signer   string           `json:"signer"`
	Nonce    string           `json:"nonce"`
	Gas      string           `json:"gas"`
	To       string           `json:"to,omitempty"`
	Value    string           `json:"value,omitempty"`
	Data     string           `json:"data"`
	GasPrice *fftypes.JSONAny `json:"gasPrice,omitempty"`
}

type EthMemorySigner struct {
	keyPairs  map[string]*secp256k1.KeyPair
	connector ffcapi.API
	chainID   int64
	mux       sync.Mutex
}

func NewEthMemorySigner(privateKeys []string, connector ffcapi.API) (*EthMemorySigner, error) {
	keyPairs := make(map[string]*secp256k1.KeyPair)
	for _, pkHex := range privateKeys {
		pkHex = strings.TrimPrefix(pkHex, "0x")
		pkBytes, err := hex.DecodeString(pkHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key hex: %w", err)
		}
		kp := secp256k1.KeyPairFromBytes(pkBytes)
		addr := strings.ToLower(kp.Address.String())
		keyPairs[addr] = kp
	}
	return &EthMemorySigner{
		keyPairs:  keyPairs,
		connector: connector,
	}, nil
}

func (s *EthMemorySigner) SignTransaction(ctx context.Context, keyID string, txParamsJSON []byte) ([]byte, error) {
	addr := strings.ToLower(keyID)
	kp, ok := s.keyPairs[addr]
	if !ok {
		return nil, fmt.Errorf("private key for keyID %s not loaded in memory signer", keyID)
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

	// EVM specific gas price parsing (EIP-1559 and legacy gas formats)
	var gasPrice, maxPriorityFeePerGas, maxFeePerGas *ethtypes.HexInteger
	if params.GasPrice != nil {
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
		} else {
			gp := gasPriceObject.GetInteger("gasPrice")
			if gp != nil && gp.Sign() > 0 {
				gasPrice = (*ethtypes.HexInteger)(gp)
			} else {
				var bi big.Int
				if err := json.Unmarshal(params.GasPrice.Bytes(), &bi); err == nil {
					gasPrice = (*ethtypes.HexInteger)(&bi)
				}
			}
		}
	}

	s.mux.Lock()
	chainID := s.chainID
	s.mux.Unlock()

	if chainID == 0 {
		readyRes, _, err := s.connector.IsReady(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to check connector readiness for chain ID: %w", err)
		}
		if readyRes == nil || readyRes.DownstreamDetails == nil {
			return nil, fmt.Errorf("connector ready response returned no downstream details")
		}
		var details map[string]interface{}
		if err := json.Unmarshal(readyRes.DownstreamDetails.Bytes(), &details); err != nil {
			return nil, fmt.Errorf("failed to unmarshal downstream details: %w", err)
		}
		chainIDVal, ok := details["chainID"]
		if !ok {
			return nil, fmt.Errorf("chainID not found in downstream details")
		}

		switch v := chainIDVal.(type) {
		case string:
			if strings.HasPrefix(v, "0x") {
				val, err := strconv.ParseInt(strings.TrimPrefix(v, "0x"), 16, 64)
				if err != nil {
					return nil, err
				}
				chainID = val
			} else {
				val, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, err
				}
				chainID = val
			}
		case float64:
			chainID = int64(v)
		default:
			return nil, fmt.Errorf("unexpected chainID type: %T", chainIDVal)
		}

		s.mux.Lock()
		s.chainID = chainID
		s.mux.Unlock()
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

	signedTx, err := tx.Sign(kp, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return signedTx, nil
}
