// Added by itskimffs (2026-10), see NOTICE: IPv6 PDN connections over SWu.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"bytes"
	"net"
	"testing"

	"vectorcore-epdg/internal/pco"

	"github.com/free5gc/ike/message"
)

func TestWantsIPv6PDN(t *testing.T) {
	cases := []struct{ ip4, ip6, want bool }{
		{false, true, true},
		{true, true, false}, // both: IPv4 + PDN_TYPE_IPv4_ONLY_ALLOWED
		{true, false, false},
		{false, false, false},
	}
	for _, c := range cases {
		sa := &ikeSA{cpWantsIP: c.ip4, cpWantsIP6: c.ip6}
		if got := sa.wantsIPv6PDN(); got != c.want {
			t.Errorf("wantsIPv6PDN(ip4=%t, ip6=%t) = %t, want %t", c.ip4, c.ip6, got, c.want)
		}
	}
}

func TestPAATrafficSelectors(t *testing.T) {
	l, r := paaTrafficSelectors(net.ParseIP("10.41.201.9"))
	if l.String() != "0.0.0.0/0" || r.String() != "10.41.201.9/32" {
		t.Fatalf("IPv4: %v %v", l, r)
	}
	l, r = paaTrafficSelectors(net.ParseIP("fd2e:8dd5:6c93:2000::1"))
	if l.String() != "::/0" || r.String() != "fd2e:8dd5:6c93:2000::/64" {
		t.Fatalf("IPv6: %v %v", l, r)
	}
	l, r = paaTrafficSelectors(nil)
	if l.String() != "0.0.0.0/0" || r.String() != "0.0.0.0/0" {
		t.Fatalf("none: %v %v", l, r)
	}
}

func TestInternalIP6AddressValue(t *testing.T) {
	addr := net.ParseIP("fd2e:8dd5:6c93:2000::1")
	v := internalIP6AddressValue(addr)
	if len(v) != 17 || !bytes.Equal(v[:16], addr) || v[16] != 64 {
		t.Fatalf("INTERNAL_IP6_ADDRESS value = % x", v)
	}
}

func TestBuildTSResponseIPv6(t *testing.T) {
	var c message.IKEPayloadContainer
	buildTSResponse(&c, net.ParseIP("fd2e:8dd5:6c93:2000::1"))
	if len(c) != 2 {
		t.Fatalf("payloads = %d, want TSi and TSr", len(c))
	}
	tsi := c[0].(*message.TrafficSelectorInitiator).TrafficSelectors[0]
	if tsi.TSType != message.TS_IPV6_ADDR_RANGE ||
		!net.IP(tsi.StartAddress).Equal(net.ParseIP("fd2e:8dd5:6c93:2000::")) ||
		!net.IP(tsi.EndAddress).Equal(net.ParseIP("fd2e:8dd5:6c93:2000:ffff:ffff:ffff:ffff")) {
		t.Fatalf("TSi = %+v", tsi)
	}
	tsr := c[1].(*message.TrafficSelectorResponder).TrafficSelectors[0]
	if tsr.TSType != message.TS_IPV6_ADDR_RANGE || !net.IP(tsr.StartAddress).Equal(net.IPv6zero) {
		t.Fatalf("TSr = %+v", tsr)
	}
	// Marshals (lengths checked by free5gc).
	if _, err := c.Encode(); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var c4 message.IKEPayloadContainer
	buildTSResponse(&c4, net.ParseIP("10.41.201.9"))
	if ts := c4[0].(*message.TrafficSelectorInitiator).TrafficSelectors[0]; ts.TSType != message.TS_IPV4_ADDR_RANGE {
		t.Fatalf("IPv4 TSi type = %d", ts.TSType)
	}
}

func TestAppendIPv6FromPCOOnlyRequested(t *testing.T) {
	decoded := &pco.Decoded{
		DNSv4:   []net.IP{net.ParseIP("10.10.41.20")},
		DNSv6:   []net.IP{net.ParseIP("fd2e:8dd5:6c93:1041::20")},
		PCSCFv4: []net.IP{net.ParseIP("10.10.41.60")},
		PCSCFv6: []net.IP{net.ParseIP("fd2e:8dd5:6c93:1041::60")},
	}
	types := func(sa *ikeSA) []uint16 {
		cp := &message.Configuration{ConfigurationType: message.CFG_REPLY}
		appendIPv6FromPCO(cp, decoded, sa)
		var out []uint16
		for _, a := range cp.ConfigurationAttribute {
			out = append(out, a.Type)
		}
		return out
	}
	// As the Samsung A33 asks: 8, 10, 16390.
	got := types(&ikeSA{cpWantsIP6: true, cpWantsDNS6: true, cpWantsPCSCF6Private: true})
	want := []uint16{message.INTERNAL_IP6_DNS, attrPCSCF6Private}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("attributes = %v, want %v", got, want)
	}
	if got := types(&ikeSA{cpWantsIP6: true, cpWantsPCSCF6: true}); len(got) != 1 || got[0] != internalIP6PCSCF {
		t.Fatalf("attributes = %v, want [P_CSCF_IP6_ADDRESS]", got)
	}
	if got := types(&ikeSA{cpWantsIP6: true}); len(got) != 0 {
		t.Fatalf("attributes = %v, want none", got)
	}
}
