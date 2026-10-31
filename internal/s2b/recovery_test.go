// Added by itskimffs (2026-10), see NOTICE: PGW restart detection with GTPv2-C Echo (Restart Counter).
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package s2b

import (
	"net"
	"testing"
)

func TestParseRecoveryPresent(t *testing.T) {
	ies, err := decodeIEs(recoveryIE(42).encode())
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := parseRecoveryPresent(ies); !ok || r != 42 {
		t.Fatalf("got %d %t", r, ok)
	}
	if r, ok := parseRecoveryPresent(nil); ok || r != 0 {
		t.Fatalf("absent: got %d %t", r, ok)
	}
}

func TestPGWPeer(t *testing.T) {
	static := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 2123}
	c := &Client{peer: static}
	if p := c.pgwPeer(nil); p != static {
		t.Fatalf("nil: %v", p)
	}
	if p := c.pgwPeer(net.ParseIP("10.0.0.1")); p.String() != "10.0.0.1:2123" {
		t.Fatalf("ip: %v", p)
	}
}
