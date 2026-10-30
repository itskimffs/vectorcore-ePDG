// Added by itskimffs (2026-10), see NOTICE: default bearer QCI from the Create Session Response.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package s2b

import (
	"log/slog"
	"net"
	"testing"
)

func createSessionResponseWithBearer(bearerIEs ...ie) message {
	children := append([]ie{
		{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
		uint8IE(ieEBI, 5),
		fteidIE(2, ifaceS2BPGWGTPU, 0x22222222, net.ParseIP("10.90.250.92")),
	}, bearerIEs...)
	return message{
		Type: msgCreateSessionResp, TEID: 0x01020304, HasTEID: true, Sequence: 1,
		Payload: encodeIEs(
			ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
			ie{Type: iePAA, Payload: []byte{pdnTypeIPv4, 172, 20, 0, 9}},
			fteidIE(1, ifaceS2BPGWGTPC, 0x11111111, net.ParseIP("10.90.250.92")),
			ie{Type: ieBearerContext, Payload: encodeIEs(children...)},
		),
	}
}

func TestParseCreateSessionResponseDefaultBearerQCI(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())

	// PGW changed the QoS (e.g. QCI 5 for ims): Bearer Level QoS present.
	r, err := c.parseCreateSessionResponse(createSessionResponseWithBearer(bearerQoSIE(5)), 0x01020304, 0x05060708)
	if err != nil {
		t.Fatalf("parseCreateSessionResponse() error = %v", err)
	}
	if r.QCI != 5 {
		t.Fatalf("QCI = %d, want 5 from Bearer Level QoS", r.QCI)
	}

	// No Bearer Level QoS: the requested QCI applies (TS 29.274 Table 7.2.2-2).
	r, err = c.parseCreateSessionResponse(createSessionResponseWithBearer(), 0x01020304, 0x05060708)
	if err != nil {
		t.Fatalf("parseCreateSessionResponse() error = %v", err)
	}
	if r.QCI != defaultBearerQCI {
		t.Fatalf("QCI = %d, want requested %d", r.QCI, defaultBearerQCI)
	}
}
