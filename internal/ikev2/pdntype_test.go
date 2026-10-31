// Added by itskimffs (2026-10), see NOTICE: subscribed PDN type from SWm limits the PDN type on S2b.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"testing"

	"vectorcore-epdg/internal/config"
)

func TestPDNFamiliesSubscription(t *testing.T) {
	cases := []struct {
		name          string
		ue4, ue6      bool
		present       bool
		sub           uint8
		v4, v6, ok    bool
		wantIPv6PDN   bool
		wantIPv4v6PDN bool
	}{
		{"no subscription, UE both", true, true, false, 0, true, true, true, false, true},
		{"no subscription, UE v6", false, true, false, 0, false, true, true, true, false},
		{"no subscription, UE none", false, false, false, 0, true, false, true, false, false},
		{"IPv4, UE both", true, true, true, subPDNIPv4, true, false, true, false, false},
		{"IPv4, UE v6 only", false, true, true, subPDNIPv4, false, false, false, false, false},
		{"IPv6, UE both", true, true, true, subPDNIPv6, false, true, true, true, false},
		{"IPv6, UE v4 only", true, false, true, subPDNIPv6, false, false, false, false, false},
		{"IPv6, UE none", false, false, true, subPDNIPv6, false, false, false, false, false},
		{"IPv4v6, UE both", true, true, true, subPDNIPv4v6, true, true, true, false, true},
		{"IPv4v6, UE v6", false, true, true, subPDNIPv4v6, false, true, true, true, false},
		{"IPv4_OR_IPv6, UE both", true, true, true, subPDNIPv4OrIPv6, true, false, true, false, false},
		{"IPv4_OR_IPv6, UE v6", false, true, true, subPDNIPv4OrIPv6, false, true, true, true, false},
		{"unknown value not enforced", true, true, true, 9, true, true, true, false, true},
	}
	s := &Server{fullCfg: &config.Config{}}
	s.fullCfg.IKEv2.IPv4v6 = true
	for _, c := range cases {
		sa := &ikeSA{cpWantsIP: c.ue4, cpWantsIP6: c.ue6, subPDNType: c.sub, subPDNTypePresent: c.present}
		v4, v6, ok := sa.pdnFamilies()
		if v4 != c.v4 || v6 != c.v6 || ok != c.ok {
			t.Errorf("%s: pdnFamilies = %v %v %v, want %v %v %v", c.name, v4, v6, ok, c.v4, c.v6, c.ok)
		}
		if got := sa.wantsIPv6PDN(); got != c.wantIPv6PDN {
			t.Errorf("%s: wantsIPv6PDN = %v, want %v", c.name, got, c.wantIPv6PDN)
		}
		if got := s.wantsIPv4v6PDN(sa); got != c.wantIPv4v6PDN {
			t.Errorf("%s: wantsIPv4v6PDN = %v, want %v", c.name, got, c.wantIPv4v6PDN)
		}
	}
}
