// Copyright 2024 LiveKit, Inc.
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

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/livekit/livekit-server/pkg/config"
)

func TestParsePublicKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	t.Run("valid PEM parses", func(t *testing.T) {
		keys, err := parsePublicKeys(map[string]string{"apikey": pemStr})
		require.NoError(t, err)
		require.NotNil(t, keys["apikey"])
	})

	t.Run("PKCS#1 RSA public key parses", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		p1 := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
		}))
		keys, err := parsePublicKeys(map[string]string{"apikey": p1})
		require.NoError(t, err)
		require.NotNil(t, keys["apikey"])
	})

	t.Run("garbage is rejected", func(t *testing.T) {
		_, err := parsePublicKeys(map[string]string{"apikey": "not a pem"})
		require.Error(t, err)
	})

	t.Run("provider returns configured key and delegates secret", func(t *testing.T) {
		keys, err := parsePublicKeys(map[string]string{"apikey": pemStr})
		require.NoError(t, err)
		p := &asymmetricKeyProvider{
			KeyProvider: fakeHMACProvider{secret: "s"},
			publicKeys:  keys,
		}
		require.NotNil(t, p.GetPublicKey("apikey"))
		require.Nil(t, p.GetPublicKey("unknown"))
		require.Equal(t, "s", p.GetSecret("apikey"))
	})
}

// TestCreateKeyProviderRejectsOverlap proves the deterministic startup guard: an
// API key present in both keys and public_keys is refused rather than silently
// resolving to a split-brain (asymmetric verify + a mintable HMAC secret).
func TestCreateKeyProviderRejectsOverlap(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	conf := &config.Config{
		Keys:       map[string]string{"dup": "a-shared-hmac-secret-at-least-32-chars"},
		PublicKeys: map[string]string{"dup": pemStr},
	}
	_, err = createKeyProvider(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "both keys and public_keys")
}

type fakeHMACProvider struct{ secret string }

func (f fakeHMACProvider) GetSecret(string) string { return f.secret }
func (f fakeHMACProvider) NumKeys() int            { return 1 }
