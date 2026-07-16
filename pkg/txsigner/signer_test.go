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
	"strings"
	"testing"

	"github.com/hyperledger-firefly/common/pkg/fftypes"
	"github.com/hyperledger-firefly/transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
)

type mockConnector struct {
	ffcapi.API
}

func (m *mockConnector) IsReady(ctx context.Context) (*ffcapi.ReadyResponse, ffcapi.ErrorReason, error) {
	return &ffcapi.ReadyResponse{
		DownstreamDetails: fftypes.JSONAnyPtr(`{"chainID": 1337}`),
	}, "", nil
}

func TestEthMemorySigner(t *testing.T) {
	// Anvil/Hardhat standard test key
	privateKeyHex := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	expectedAddress := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

	signer, err := NewEthMemorySigner([]string{privateKeyHex}, &mockConnector{})
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Validate mapping is case-insensitive
	kp, ok := signer.keyPairs[expectedAddress]
	assert.True(t, ok)
	assert.Equal(t, expectedAddress, strings.ToLower(kp.Address.String()))

	// Test signing a legacy transaction
	txParamsJSON := `{
		"nonce": "1",
		"gas": "21000",
		"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"value": "1000000000000000000",
		"data": "0x",
		"gasPrice": 20000000000
	}`

	signedTx, err := signer.SignTransaction(context.Background(), expectedAddress, []byte(txParamsJSON))
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)

	// Signed transaction should be a valid RLP payload
	signedHex := hex.EncodeToString(signedTx)
	// A valid signed legacy transaction RLP starts with 'f8' for list
	assert.True(t, strings.HasPrefix(signedHex, "f8"))

	// Test signing with an unregistered address
	_, err = signer.SignTransaction(context.Background(), "0x0000000000000000000000000000000000000000", []byte(txParamsJSON))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not loaded in memory signer")

	// Test signing with EIP-1559 parameters
	eip1559ParamsJSON := `{
		"nonce": "1",
		"gas": "21000",
		"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"value": "1000000000000000000",
		"data": "0x",
		"gasPrice": {
			"maxPriorityFeePerGas": "1000000000",
			"maxFeePerGas": "30000000000"
		}
	}`

	signedEip1559Tx, err := signer.SignTransaction(context.Background(), expectedAddress, []byte(eip1559ParamsJSON))
	assert.NoError(t, err)
	assert.NotEmpty(t, signedEip1559Tx)

	// EIP-1559 transaction RLP starts with the transaction type byte '02'
	assert.Equal(t, byte(0x02), signedEip1559Tx[0])
}
