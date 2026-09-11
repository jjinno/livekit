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

package service_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/livekit/protocol/auth"

	"github.com/livekit/livekit-server/pkg/service"
)

// asymProvider satisfies auth.KeyProvider AND the (unexported) publicKeyProvider
// interface the middleware type-asserts, standing in for a server configured
// with a `public_keys` entry.
type asymProvider struct {
	secret string
	pub    crypto.PublicKey
}

func (p *asymProvider) GetSecret(string) string              { return p.secret }
func (p *asymProvider) NumKeys() int                         { return 1 }
func (p *asymProvider) GetPublicKey(string) crypto.PublicKey { return p.pub }

func TestAuthMiddlewareAsymmetric(t *testing.T) {
	const api = "APIasym12345"
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Provider holds only the PUBLIC key — it cannot mint tokens for this API key.
	provider := &asymProvider{pub: &signing.PublicKey}
	m := service.NewAPIKeyAuthMiddleware(provider)

	var grants *auth.ClaimGrants
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants = service.GetGrants(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	orig := &auth.VideoGrant{Room: "room-1", RoomJoin: true}

	// A token minted with the matching ES256 private key verifies.
	token, err := auth.NewAccessToken(api, "").
		SetPrivateKey(signing).
		AddGrant(orig).
		ToJWT()
	require.NoError(t, err)

	r := &http.Request{Header: http.Header{}}
	w := httptest.NewRecorder()
	service.SetAuthorizationToken(r, token)
	m.ServeHTTP(w, r, handler)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, grants)
	require.EqualValues(t, orig, grants.Video)

	// A token minted with a DIFFERENT private key is rejected — the server holds
	// only the one public key and cannot be tricked into accepting a foreign one.
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	forged, err := auth.NewAccessToken(api, "").
		SetPrivateKey(attacker).
		AddGrant(orig).
		ToJWT()
	require.NoError(t, err)

	grants = nil
	r = &http.Request{Header: http.Header{}}
	w = httptest.NewRecorder()
	service.SetAuthorizationToken(r, forged)
	m.ServeHTTP(w, r, handler)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Nil(t, grants)
}
