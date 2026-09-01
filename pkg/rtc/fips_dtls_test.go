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

package rtc

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	dtls "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/stretchr/testify/require"

	"github.com/livekit/livekit-server/pkg/config"
)

// TestFIPSDTLSRequiresFIPSModule proves the deterministic gate: enabling
// fips_dtls without an active Go FIPS module (a plain `go test` binary is not a
// GOFIPS140 build, so fips140.Enabled() is false) is a hard startup error, not a
// silent "algorithms restricted but not FIPS-validated" state.
func TestFIPSDTLSRequiresFIPSModule(t *testing.T) {
	conf := &config.Config{}
	conf.RTC.FIPSDTLS = true
	_, err := NewWebRTCConfig(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fips_dtls")
}

// TestFIPSDTLSAllowlistExcludesNonFIPS asserts the allowlists contain ONLY
// FIPS-approved algorithms — a regression guard so a future edit can't silently
// reintroduce a non-FIPS suite/curve/profile into the pinned set. (The handshake
// tests below assert negotiated membership in these lists, which would be
// vacuously satisfied if the list itself were polluted — hence this check.)
func TestFIPSDTLSAllowlistExcludesNonFIPS(t *testing.T) {
	// Positive allowlist: every pinned value must be a member of the known
	// FIPS-approved set below. This inherently excludes ChaCha20, AES-CCM and
	// X25519 (the non-stdlib primitives) without naming them, and it fails if a
	// future edit adds anything outside the approved set.
	approvedCiphers := map[dtls.CipherSuiteID]bool{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	}
	require.NotEmpty(t, fipsDTLSCipherSuites)
	for _, cs := range fipsDTLSCipherSuites {
		require.True(t, approvedCiphers[cs],
			"non-approved cipher 0x%04x in fipsDTLSCipherSuites", uint16(cs))
	}

	approvedCurves := map[elliptic.Curve]bool{elliptic.P256: true, elliptic.P384: true}
	require.NotEmpty(t, fipsDTLSEllipticCurves)
	for _, c := range fipsDTLSEllipticCurves {
		require.True(t, approvedCurves[c], "non-approved curve %v in fipsDTLSEllipticCurves", c)
	}

	// SRTP: AEAD-AES-GCM only — no AES-CM/HMAC-SHA1 (SHA-1) or NULL profiles.
	approvedSRTP := map[dtls.SRTPProtectionProfile]bool{
		dtls.SRTP_AEAD_AES_128_GCM: true,
		dtls.SRTP_AEAD_AES_256_GCM: true,
	}
	require.NotEmpty(t, fipsDTLSSRTPProtectionProfiles)
	for _, p := range fipsDTLSSRTPProtectionProfiles {
		require.True(t, approvedSRTP[p], "non-approved SRTP profile %v in fipsDTLSSRTPProtectionProfiles", p)
	}
}

// newFIPSPinnedListener starts a DTLS listener pinned to the FIPS-only cipher
// suites, curves, and SRTP profiles (fips_dtls.go), standing in for a
// FIPS-DTLS-enabled SFU.
func newFIPSPinnedListener(t *testing.T) net.Listener {
	t.Helper()
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	listener, err := dtls.Listen("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		CipherSuites:           fipsDTLSCipherSuites,
		EllipticCurves:         fipsDTLSEllipticCurves,
		SRTPProtectionProfiles: fipsDTLSSRTPProtectionProfiles,
	})
	require.NoError(t, err)

	return listener
}

// acceptAndHandshake drives the server side of the handshake in the background.
func acceptAndHandshake(listener net.Listener) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = conn.(*dtls.Conn).HandshakeContext(ctx)
	}()

	return &wg
}

// TestFIPSDTLS_DefaultClientNegotiatesFIPS proves a client offering the full
// default suite set (incl. non-FIPS ChaCha20/CBC) connects to a FIPS-pinned
// endpoint and negotiates a FIPS AES-GCM suite — pinning does not break ordinary
// clients and forces them onto FIPS crypto.
func TestFIPSDTLS_DefaultClientNegotiatesFIPS(t *testing.T) {
	listener := newFIPSPinnedListener(t)
	defer func() { _ = listener.Close() }()

	serverDone := acceptAndHandshake(listener)

	client, err := dtls.Dial("udp", listener.Addr().(*net.UDPAddr), &dtls.Config{
		InsecureSkipVerify: true,
		// Offer a non-FIPS SRTP profile ahead of GCM; the server pins GCM-only,
		// so negotiation must still land on an AES-GCM profile.
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AES128_CM_HMAC_SHA1_80,
			dtls.SRTP_AEAD_AES_256_GCM,
		},
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, client.HandshakeContext(ctx),
		"a default client should complete a handshake with a FIPS-pinned server")

	state, ok := client.ConnectionState()
	require.True(t, ok)
	require.True(t, slices.Contains(fipsDTLSCipherSuites, state.CipherSuiteID),
		"negotiated cipher 0x%04x is not FIPS-approved", uint16(state.CipherSuiteID))

	// The negotiated SRTP profile must be AES-GCM — proving the server's SRTP pin
	// takes effect end-to-end, not just that the apply function was called.
	profile, ok := client.SelectedSRTPProtectionProfile()
	require.True(t, ok, "an SRTP profile should be negotiated")
	require.True(t, slices.Contains(fipsDTLSSRTPProtectionProfiles, profile),
		"negotiated SRTP profile %v is not FIPS-approved (AES-GCM)", profile)

	serverDone.Wait()
}

// TestFIPSDTLS_NonFIPSOnlyClientFails proves the fail-closed property: a client
// offering only a non-FIPS suite (ChaCha20-Poly1305) cannot handshake with a
// FIPS-pinned endpoint — no shared cipher, no fallback.
func TestFIPSDTLS_NonFIPSOnlyClientFails(t *testing.T) {
	listener := newFIPSPinnedListener(t)
	defer func() { _ = listener.Close() }()

	serverDone := acceptAndHandshake(listener)

	client, err := dtls.Dial("udp", listener.Addr().(*net.UDPAddr), &dtls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		EllipticCurves:     []elliptic.Curve{elliptic.P256},
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.Error(t, client.HandshakeContext(ctx),
		"a ChaCha20-only client must not complete a handshake with a FIPS-pinned server")

	serverDone.Wait()
}
