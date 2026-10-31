// Added by itskimffs (2026-10), see NOTICE: IPv4v6 PDN connections on S2b.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package s2b

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
)

func TestCreateSessionPayloadRequestsIPv4v6PAA(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	payload := c.createSessionPayload(CreateSessionRequest{IMSI: "001010000182730", APN: "ims", IPv4v6: true},
		0, 0, 0x01020304, 0x05060708)
	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatal(err)
	}
	paa, ok := findIE(ies, iePAA, 0)
	want := append([]byte{pdnTypeIPv4v6, 0}, make([]byte, 20)...)
	if !ok || !bytes.Equal(paa.Payload, want) {
		t.Fatalf("PAA request = % x ok=%t, want % x", paa.Payload, ok, want)
	}
}

func cause(resp message, value uint8) message {
	ies, _ := decodeIEs(resp.Payload)
	for i := range ies {
		if ies[i].Type == ieCause {
			ies[i].Payload = []byte{value, 0}
		}
	}
	resp.Payload = encodeIEs(ies...)
	return resp
}

func TestParseCreateSessionResponseIPv4v6PAA(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	addr6 := net.ParseIP("fd2e:8dd5:6c93:2000::7")
	payload := append(append([]byte{pdnTypeIPv4v6, 64}, addr6...), 10, 41, 201, 7)
	result, err := c.parseCreateSessionResponseFor(ipv6CreateSessionResponse(payload), 1, 2, pdnTypeIPv4v6)
	if err != nil {
		t.Fatalf("parseCreateSessionResponseFor() error = %v", err)
	}
	if !result.PAA.Equal(net.ParseIP("10.41.201.7")) || !result.PAA6.Equal(addr6) ||
		result.PAAPrefixLen != 64 || result.PDNType != pdnTypeIPv4v6 {
		t.Fatalf("PAA = %v, PAA6 = %v /%d, type %d", result.PAA, result.PAA6, result.PAAPrefixLen, result.PDNType)
	}
}

func TestParseCreateSessionResponseIPv4v6Downgraded(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())

	// Cause 18 with an IPv4 PAA: an IPv4 PDN connection.
	resp := cause(ipv6CreateSessionResponse([]byte{pdnTypeIPv4, 10, 41, 201, 9}), causeNewPDNTypeNetworkPreference)
	result, err := c.parseCreateSessionResponseFor(resp, 1, 2, pdnTypeIPv4v6)
	if err != nil {
		t.Fatalf("IPv4 downgrade: %v", err)
	}
	if result.PDNType != pdnTypeIPv4 || !result.PAA.Equal(net.ParseIP("10.41.201.9")) || result.PAA6 != nil {
		t.Fatalf("IPv4 downgrade: PAA = %v, PAA6 = %v, type %d", result.PAA, result.PAA6, result.PDNType)
	}

	// Cause 19 with an IPv6 PAA: an IPv6 PDN connection.
	addr6 := net.ParseIP("fd2e:8dd5:6c93:2000::9")
	resp = cause(ipv6CreateSessionResponse(append([]byte{pdnTypeIPv6, 64}, addr6...)), causeNewPDNTypeSingleAddrBearer)
	result, err = c.parseCreateSessionResponseFor(resp, 1, 2, pdnTypeIPv4v6)
	if err != nil {
		t.Fatalf("IPv6 downgrade: %v", err)
	}
	if result.PDNType != pdnTypeIPv6 || !result.PAA.Equal(addr6) || result.PAA6 != nil {
		t.Fatalf("IPv6 downgrade: PAA = %v, PAA6 = %v, type %d", result.PAA, result.PAA6, result.PDNType)
	}

	// Cause 18 is only accepted for an IPv4v6 request.
	resp = cause(ipv6CreateSessionResponse([]byte{pdnTypeIPv4, 10, 41, 201, 9}), causeNewPDNTypeNetworkPreference)
	if _, err := c.parseCreateSessionResponseFor(resp, 1, 2, pdnTypeIPv4); err == nil {
		t.Fatal("cause 18 accepted for an IPv4 request")
	}
}
