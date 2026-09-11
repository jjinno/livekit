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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/livekit/protocol/auth"
)

// asymmetricKeyProvider augments the standard HMAC KeyProvider with a set of
// per-API-key public keys for asymmetric token verification. HMAC secret lookups
// delegate to the embedded provider unchanged; GetPublicKey returns the parsed
// public key for an API key configured under `public_keys`, or nil otherwise.
//
// This lets the server verify a participant token that was minted with an
// asymmetric private key while holding only the public key — so it cannot itself
// mint tokens for that API key.
type asymmetricKeyProvider struct {
	auth.KeyProvider
	publicKeys map[string]crypto.PublicKey
}

// asymmetricKeyProvider is what activates asymmetric verification: the auth
// middleware type-asserts its KeyProvider to publicKeyProvider (see auth.go).
var _ publicKeyProvider = (*asymmetricKeyProvider)(nil)

// GetPublicKey returns the configured verification public key for apiKey, or nil
// if the API key is not configured for asymmetric verification.
func (p *asymmetricKeyProvider) GetPublicKey(apiKey string) crypto.PublicKey {
	return p.publicKeys[apiKey]
}

// parsePublicKeys parses a map of API key -> PEM-encoded public key into parsed
// crypto.PublicKey values. Both PKIX/SubjectPublicKeyInfo (`-----BEGIN PUBLIC
// KEY-----`) and PKCS#1 (`-----BEGIN RSA PUBLIC KEY-----`) encodings are accepted.
func parsePublicKeys(pems map[string]string) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey, len(pems))
	for apiKey, pemStr := range pems {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return nil, fmt.Errorf("public_keys: API key %q: no PEM block found", apiKey)
		}
		pub, err := parseDERPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("public_keys: API key %q: %w", apiKey, err)
		}
		out[apiKey] = pub
	}
	return out, nil
}

// parseDERPublicKey parses a DER-encoded public key in either PKIX
// (SubjectPublicKeyInfo) or PKCS#1 (RSA) form.
func parseDERPublicKey(der []byte) (crypto.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}
	return nil, errors.New("unsupported public key: expected PKIX (BEGIN PUBLIC KEY) or PKCS#1 (BEGIN RSA PUBLIC KEY)")
}
