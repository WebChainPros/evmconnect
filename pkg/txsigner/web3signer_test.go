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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWeb3SignerClient(t *testing.T) {
	// Mock Web3Signer REST server
	mockSigHex := "0x" +
		"7a46f2c69d80d19e90098df2410a562efad8f90647895bc6e969966efad8f906" + // R
		"1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d" + // S
		"1b" // V = 27 (0x1b)

	expectedAddress := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/v1/eth1/publicKeys" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`["0x8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"]`))
			return
		}

		assert.Equal(t, "POST", r.Method)
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/eth1/sign/"))

		var signReq web3SignerRequest
		err := json.NewDecoder(r.Body).Decode(&signReq)
		assert.NoError(t, err)
		assert.NotEmpty(t, signReq.Data)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockSigHex))
	}))
	defer server.Close()

	client, err := NewWeb3SignerClient(server.URL, &mockConnector{})
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test signing a legacy transaction
	txParamsJSON := `{
		"nonce": "1",
		"gas": "21000",
		"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"value": "1000000000000000000",
		"data": "0x",
		"gasPrice": 20000000000
	}`

	signedTx, err := client.SignTransaction(context.Background(), expectedAddress, []byte(txParamsJSON))
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)

	// Legacy transaction RLP format check (starts with 'f8' for list)
	signedHex := hex.EncodeToString(signedTx)
	assert.True(t, strings.HasPrefix(signedHex, "f8"))

	// Test signing an EIP-1559 transaction
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

	signedEip1559Tx, err := client.SignTransaction(context.Background(), expectedAddress, []byte(eip1559ParamsJSON))
	assert.NoError(t, err)
	assert.NotEmpty(t, signedEip1559Tx)

	// EIP-1559 starts with type byte 0x02
	assert.Equal(t, byte(0x02), signedEip1559Tx[0])
}
