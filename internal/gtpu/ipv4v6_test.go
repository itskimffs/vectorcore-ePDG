// Added by itskimffs (2026-10), see NOTICE: IPv4v6 PDN connections.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package gtpu

import (
	"net"
	"testing"
)

func ipv4v6Session() *Session {
	return &Session{
		ID:         "s1",
		APN:        "ims",
		PAA:        net.ParseIP("10.41.201.7").To4(),
		PAA6:       net.ParseIP("fd2e:8dd5:6c93:2000::7"),
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5, RemoteTXTEID: 100, QoS: BearerQoS{QCI: 5}},
			6: {
				EBI:          6,
				RemoteTXTEID: 200,
				QoS:          BearerQoS{QCI: 1},
				TFT: &TFT{Filters: []PacketFilter{
					{
						Direction: dirUplink, Precedence: 10,
						RemoteIPv6: net.ParseIP("fd2e:8dd5:6c93:1041::70"), RemoteIPv6Mask: net.CIDRMask(128, 128),
					},
					{
						Direction: dirUplink, Precedence: 11,
						RemoteIPv4: net.ParseIP("10.10.41.70").To4(), RemoteIPv4Mask: net.CIDRMask(32, 32),
					},
					{ // no address: matches both families
						Direction: dirUplink, Precedence: 12,
						HasProtocol: true, Protocol: 17,
					},
				}},
			},
		},
	}
}

func TestBuildTCBPFTFTRulesIPv4v6SplitsByFamily(t *testing.T) {
	ds := ipv4v6Session()
	v4 := buildTCBPFTFTRulesFor(ds, ds.PAA)
	v6 := buildTCBPFTFTRulesFor(ds, ds.PAA6)
	prec := func(rules []TCBPFTFTRule) []uint8 {
		var out []uint8
		for _, r := range rules {
			out = append(out, r.Precedence)
		}
		return out
	}
	if p := prec(v4); len(p) != 2 || p[0] != 11 && p[1] != 11 {
		t.Fatalf("IPv4 rules precedences %v, want 11 and 12", p)
	}
	if p := prec(v6); len(p) != 2 || p[0] != 10 && p[1] != 10 {
		t.Fatalf("IPv6 rules precedences %v, want 10 and 12", p)
	}
	for _, r := range v4 {
		if r.Precedence == 11 && !net.IP(r.RemoteIP[:]).Equal(net.ParseIP("10.10.41.70")) {
			t.Fatalf("IPv4 rule remote %v", net.IP(r.RemoteIP[:]))
		}
	}
	for _, r := range v6 {
		if r.Precedence == 10 && !net.IP(r.RemoteIP6[:]).Equal(net.ParseIP("fd2e:8dd5:6c93:1041::70")) {
			t.Fatalf("IPv6 rule remote %v", net.IP(r.RemoteIP6[:]))
		}
	}
	if got := len(ds.paas()); got != 2 {
		t.Fatalf("paas() = %d, want 2", got)
	}
}

func TestTEIDEntryFamilies(t *testing.T) {
	e, err := teidEntry(net.ParseIP("10.41.201.7"), net.ParseIP("fd2e:8dd5:6c93:2000::7"))
	if err != nil || e.IsV6 != teidFamilyIPv4v6 || net.IP(e.Paa[:]).String() != "10.41.201.7" ||
		net.IP(append(e.Paa6[:], make([]byte, 8)...)).String() != "fd2e:8dd5:6c93:2000::" {
		t.Fatalf("IPv4v6 entry %+v err %v", e, err)
	}
	if e, err = teidEntry(net.ParseIP("10.41.201.7"), nil); err != nil || e.IsV6 != teidFamilyIPv4 {
		t.Fatalf("IPv4 entry %+v err %v", e, err)
	}
	if e, err = teidEntry(net.ParseIP("fd2e:8dd5:6c93:2000::7"), nil); err != nil || e.IsV6 != teidFamilyIPv6 {
		t.Fatalf("IPv6 entry %+v err %v", e, err)
	}
	if _, err = teidEntry(net.ParseIP("fd2e::1"), net.ParseIP("fd2e::2")); err == nil {
		t.Fatal("two IPv6 PAAs accepted")
	}
}

func TestMetricsPDNTypeIPv4v6(t *testing.T) {
	m := &Manager{sessionsByID: map[string]*Session{"s1": ipv4v6Session()}}
	for _, b := range m.Bearers() {
		if b.PDNType != PDNTypeIPv4v6 {
			t.Fatalf("bearer EBI %d PDN type %q, want ipv4v6", b.EBI, b.PDNType)
		}
	}
	ds := m.sessionsByID["s1"]
	m.accountLocked(ds, ds.Bearers[6], DirectionUplink, 3, 300)
	if tot := m.TrafficTotals()[TrafficKey{APN: "ims", PDNType: PDNTypeIPv4v6, QCI: 1, Direction: DirectionUplink}]; tot.Bytes != 300 {
		t.Fatalf("traffic totals %+v", m.TrafficTotals())
	}
}
