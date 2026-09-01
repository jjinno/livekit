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
	dtls "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/webrtc/v4"
)

// FIPS-approved DTLS-SRTP algorithms, pinned on the SettingEngine when
// RTCConfig.FIPSDTLS is enabled. Because the SFU is one DTLS endpoint of every
// media session and the negotiated suite/curve/profile must be in both peers'
// lists, pinning these forces FIPS-validated crypto for every session,
// regardless of what a remote offers. Off by default — negotiation is unchanged
// unless the operator opts in.
var (
	// AES-GCM only. ChaCha20-Poly1305 and AES-CCM are excluded: their ciphers
	// are not provided by the Go FIPS module.
	fipsDTLSCipherSuites = []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}

	// NIST curves only; X25519 is excluded (not FIPS-approved).
	fipsDTLSEllipticCurves = []elliptic.Curve{elliptic.P256, elliptic.P384}

	// AEAD AES-GCM SRTP only. The legacy AES-CM + HMAC-SHA1 profiles are excluded
	// to avoid SHA-1 on the media path, per FIPS media-plane guidance.
	fipsDTLSSRTPProtectionProfiles = []dtls.SRTPProtectionProfile{
		dtls.SRTP_AEAD_AES_256_GCM,
		dtls.SRTP_AEAD_AES_128_GCM,
	}
)

// applyFIPSDTLS pins the FIPS-approved cipher suites, curves, and SRTP profiles
// onto the SettingEngine. Single apply-site for the fips_dtls restriction; the
// handshake tests in fips_dtls_test.go prove the negotiated result.
func applyFIPSDTLS(se *webrtc.SettingEngine) {
	se.SetDTLSCipherSuites(fipsDTLSCipherSuites...)
	se.SetDTLSEllipticCurves(fipsDTLSEllipticCurves...)
	se.SetSRTPProtectionProfiles(fipsDTLSSRTPProtectionProfiles...)
}
