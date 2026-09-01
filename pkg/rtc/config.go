// Copyright 2023 LiveKit, Inc.
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
	"crypto/fips140"
	"fmt"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"

	"github.com/livekit/livekit-server/pkg/config"
	"github.com/livekit/livekit-server/pkg/sfu/buffer"
	act "github.com/livekit/livekit-server/pkg/sfu/rtpextension/abscapturetime"
	dd "github.com/livekit/livekit-server/pkg/sfu/rtpextension/dependencydescriptor"
	"github.com/livekit/mediatransportutil/pkg/rtcconfig"
)

const (
	frameMarkingURI        = "urn:ietf:params:rtp-hdrext:framemarking"
	repairedRTPStreamIDURI = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
)

type WebRTCConfig struct {
	rtcconfig.WebRTCConfig

	BufferFactory *buffer.Factory
	Receiver      ReceiverConfig
	Publisher     DirectionConfig
	Subscriber    DirectionConfig
	FIPSDTLS      bool
}

type ReceiverConfig struct {
	PacketBufferSizeVideo int
	PacketBufferSizeAudio int
}

type RTPHeaderExtensionConfig struct {
	Audio []string
	Video []string
}

type RTCPFeedbackConfig struct {
	Audio []webrtc.RTCPFeedback
	Video []webrtc.RTCPFeedback
}

type DirectionConfig struct {
	RTPHeaderExtension RTPHeaderExtensionConfig
	RTCPFeedback       RTCPFeedbackConfig
}

func NewWebRTCConfig(conf *config.Config) (*WebRTCConfig, error) {
	rtcConf := conf.RTC

	// fips_dtls means the media path must be FIPS-validated, which requires the
	// Go FIPS module (a GOFIPS140 build) so the primitives resolve to the
	// certified module. Restricting the negotiated algorithms without the module
	// active would leave the server in an ambiguous "claims FIPS, isn't validated"
	// state, so refuse to start rather than mislead the operator. Build with
	// GOFIPS140, or disable fips_dtls.
	if rtcConf.FIPSDTLS && !fips140.Enabled() {
		return nil, fmt.Errorf("fips_dtls is enabled but the Go FIPS module is not active: " +
			"build with GOFIPS140 so DTLS-SRTP crypto is FIPS-validated, or disable fips_dtls")
	}

	webRTCConfig, err := rtcconfig.NewWebRTCConfig(&rtcConf.RTCConfig, conf.Development)
	if err != nil {
		return nil, err
	}

	// we don't want to use active TCP on a server, clients should be dialing
	webRTCConfig.SettingEngine.DisableActiveTCP(true)

	if rtcConf.PacketBufferSize == 0 {
		rtcConf.PacketBufferSize = 500
	}
	if rtcConf.PacketBufferSizeVideo == 0 {
		rtcConf.PacketBufferSizeVideo = rtcConf.PacketBufferSize
	}
	if rtcConf.PacketBufferSizeAudio == 0 {
		rtcConf.PacketBufferSizeAudio = rtcConf.PacketBufferSize
	}

	return &WebRTCConfig{
		WebRTCConfig: *webRTCConfig,
		Receiver: ReceiverConfig{
			PacketBufferSizeVideo: rtcConf.PacketBufferSizeVideo,
			PacketBufferSizeAudio: rtcConf.PacketBufferSizeAudio,
		},
		Publisher:  getPublisherConfig(false),
		Subscriber: getSubscriberConfig(rtcConf.CongestionControl.UseSendSideBWEInterceptor || rtcConf.CongestionControl.UseSendSideBWE),
		FIPSDTLS:   rtcConf.FIPSDTLS,
	}, nil
}

func (c *WebRTCConfig) UpdatePublisherConfig(consolidated bool) {
	c.Publisher = getPublisherConfig(consolidated)
}

func (c *WebRTCConfig) UpdateSubscriberConfig(ccConf config.CongestionControlConfig) {
	c.Subscriber = getSubscriberConfig(ccConf.UseSendSideBWEInterceptor || ccConf.UseSendSideBWE)
}

func (c *WebRTCConfig) SetBufferFactory(factory *buffer.Factory) {
	c.BufferFactory = factory
	c.SettingEngine.BufferFactory = factory.GetOrNew
}

func getPublisherConfig(consolidated bool) DirectionConfig {
	if consolidated {
		return DirectionConfig{
			RTPHeaderExtension: RTPHeaderExtensionConfig{
				Audio: []string{
					sdp.SDESMidURI,
					sdp.SDESRTPStreamIDURI,
					sdp.AudioLevelURI,
					act.AbsCaptureTimeURI,
				},
				Video: []string{
					sdp.SDESMidURI,
					sdp.SDESRTPStreamIDURI,
					sdp.TransportCCURI,
					sdp.ABSSendTimeURI,
					frameMarkingURI,
					dd.ExtensionURI,
					repairedRTPStreamIDURI,
					act.AbsCaptureTimeURI,
				},
			},
			RTCPFeedback: RTCPFeedbackConfig{
				Audio: []webrtc.RTCPFeedback{
					{Type: webrtc.TypeRTCPFBNACK},
				},
				Video: []webrtc.RTCPFeedback{
					{Type: webrtc.TypeRTCPFBTransportCC},
					{Type: webrtc.TypeRTCPFBGoogREMB},
					{Type: webrtc.TypeRTCPFBCCM, Parameter: "fir"},
					{Type: webrtc.TypeRTCPFBNACK},
					{Type: webrtc.TypeRTCPFBNACK, Parameter: "pli"},
				},
			},
		}
	}

	return DirectionConfig{
		RTPHeaderExtension: RTPHeaderExtensionConfig{
			Audio: []string{
				sdp.SDESMidURI,
				sdp.SDESRTPStreamIDURI,
				sdp.AudioLevelURI,
				act.AbsCaptureTimeURI,
			},
			Video: []string{
				sdp.SDESMidURI,
				sdp.SDESRTPStreamIDURI,
				sdp.TransportCCURI,
				frameMarkingURI,
				dd.ExtensionURI,
				repairedRTPStreamIDURI,
				act.AbsCaptureTimeURI,
			},
		},
		RTCPFeedback: RTCPFeedbackConfig{
			Audio: []webrtc.RTCPFeedback{
				{Type: webrtc.TypeRTCPFBNACK},
			},
			Video: []webrtc.RTCPFeedback{
				{Type: webrtc.TypeRTCPFBTransportCC},
				{Type: webrtc.TypeRTCPFBCCM, Parameter: "fir"},
				{Type: webrtc.TypeRTCPFBNACK},
				{Type: webrtc.TypeRTCPFBNACK, Parameter: "pli"},
			},
		},
	}
}

func getSubscriberConfig(enableTWCC bool) DirectionConfig {
	subscriberConfig := DirectionConfig{
		RTPHeaderExtension: RTPHeaderExtensionConfig{
			Video: []string{
				dd.ExtensionURI,
				act.AbsCaptureTimeURI,
			},
			Audio: []string{
				act.AbsCaptureTimeURI,
			},
		},
		RTCPFeedback: RTCPFeedbackConfig{
			Audio: []webrtc.RTCPFeedback{
				// always enable NACK for audio but disable it later for red enabled transceiver. https://github.com/pion/webrtc/pull/2972
				{Type: webrtc.TypeRTCPFBNACK},
			},
			Video: []webrtc.RTCPFeedback{
				{Type: webrtc.TypeRTCPFBCCM, Parameter: "fir"},
				{Type: webrtc.TypeRTCPFBNACK},
				{Type: webrtc.TypeRTCPFBNACK, Parameter: "pli"},
			},
		},
	}
	if enableTWCC {
		subscriberConfig.RTPHeaderExtension.Video = append(subscriberConfig.RTPHeaderExtension.Video, sdp.TransportCCURI)
		subscriberConfig.RTCPFeedback.Video = append(subscriberConfig.RTCPFeedback.Video, webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBTransportCC})
	} else {
		subscriberConfig.RTPHeaderExtension.Video = append(subscriberConfig.RTPHeaderExtension.Video, sdp.ABSSendTimeURI)
		subscriberConfig.RTCPFeedback.Video = append(subscriberConfig.RTCPFeedback.Video, webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBGoogREMB})
	}

	return subscriberConfig
}
