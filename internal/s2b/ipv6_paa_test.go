// Added by itskimffs (2026-10), see NOTICE: IPv6 PDN connections on S2b.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package s2b

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
)

func TestCreateSessionPayloadRequestsIPv6PAA(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	payload := c.createSessionPayload(CreateSessionRequest{IMSI: "001010000182739", APN: "ims", IPv6: true},
		0, 0, 0x01020304, 0x05060708)
	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatal(err)
	}
	paa, ok := findIE(ies, iePAA, 0)
	want := append([]byte{pdnTypeIPv6, 0}, make([]byte, 16)...)
	if !ok || !bytes.Equal(paa.Payload, want) {
		t.Fatalf("PAA request = % x ok=%t, want % x", paa.Payload, ok, want)
	}
}

func ipv6CreateSessionResponse(paaPayload []byte) message {
	return message{
		Type: msgCreateSessionResp, TEID: 0x01020304, HasTEID: true, Sequence: 1,
		Payload: encodeIEs(
			ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
			ie{Type: iePAA, Payload: paaPayload},
			fteidIE(1, ifaceS2BPGWGTPC, 0x11111111, net.ParseIP("10.10.41.40")),
			ie{Type: ieBearerContext, Payload: encodeIEs(
				ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
				uint8IE(ieEBI, 5),
				fteidIE(2, ifaceS2BPGWGTPU, 0x22222222, net.ParseIP("10.10.41.41")),
			)},
		),
	}
}

func TestParseCreateSessionResponseIPv6PAA(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	addr := net.ParseIP("fd2e:8dd5:6c93:2000::1")
	resp := ipv6CreateSessionResponse(append([]byte{pdnTypeIPv6, 64}, addr...))
	result, err := c.parseCreateSessionResponseFor(resp, 1, 2, pdnTypeIPv6)
	if err != nil {
		t.Fatalf("parseCreateSessionResponseFor() error = %v", err)
	}
	if !result.PAA.Equal(addr) || result.PAA.To4() != nil || result.PAAPrefixLen != 64 {
		t.Fatalf("PAA = %v /%d, want %v /64", result.PAA, result.PAAPrefixLen, addr)
	}

	// IPv4 PAA in the response to an IPv6 request is an error, not an IPv4 session.
	if _, err := c.parseCreateSessionResponseFor(ipv6CreateSessionResponse([]byte{pdnTypeIPv4, 10, 41, 201, 9}), 1, 2, pdnTypeIPv6); err == nil {
		t.Fatal("IPv4 PAA accepted for an IPv6 request")
	}
}

func TestParsePAAIPv6FromIPv4v6(t *testing.T) {
	addr := net.ParseIP("fd2e:8dd5:6c93:2001::5")
	payload := append(append([]byte{pdnTypeIPv4v6, 64}, addr...), 10, 41, 201, 9)
	ip, plen := parsePAAIPv6([]ie{{Type: iePAA, Payload: payload}})
	if !ip.Equal(addr) || plen != 64 {
		t.Fatalf("parsePAAIPv6() = %v /%d", ip, plen)
	}
	if ip, _ := parsePAAIPv6([]ie{{Type: iePAA, Payload: []byte{pdnTypeIPv4, 10, 41, 201, 9}}}); ip != nil {
		t.Fatalf("parsePAAIPv6(IPv4 PAA) = %v, want nil", ip)
	}
}
