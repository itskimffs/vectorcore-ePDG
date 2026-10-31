// Added by itskimffs (2026-10), see NOTICE: IPv4v6 PDN connections over SWu.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/pco"
	"vectorcore-epdg/internal/s2b"
	"vectorcore-epdg/internal/xfrm"

	"github.com/free5gc/ike/message"
)

func newIPv4v6TestServer(ipv4v6 bool) *Server {
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cfg := config.Default()
	cfg.IKEv2.IPv4v6 = ipv4v6
	cfg.PCO.RequestDNSv4, cfg.PCO.RequestPCSCFv4 = true, true
	cfg.PCO.RequestDNSv6, cfg.PCO.RequestPCSCFv6 = true, true
	srv.fullCfg = cfg
	return srv
}

// xiaomiSA is the CFG_REQUEST of the Xiaomi on core2: attributes 1, 3, 20, 8, 10, 21.
func xiaomiSA() *ikeSA {
	return &ikeSA{cpWantsIP: true, cpWantsIP6: true, cpWantsDNS6: true, cpWantsPCSCF6: true, imsi: "001010000182730", apn: "ims"}
}

func TestWantsIPv4v6PDN(t *testing.T) {
	if !newIPv4v6TestServer(true).wantsIPv4v6PDN(xiaomiSA()) {
		t.Fatal("IPv4 and IPv6 requested, ipv4v6 on: want IPv4v6")
	}
	if newIPv4v6TestServer(false).wantsIPv4v6PDN(xiaomiSA()) {
		t.Fatal("ipv4v6 off: want no IPv4v6")
	}
	if newIPv4v6TestServer(true).wantsIPv4v6PDN(&ikeSA{cpWantsIP6: true}) {
		t.Fatal("only IPv6 requested: want no IPv4v6")
	}
	if (&Server{}).wantsIPv4v6PDN(xiaomiSA()) {
		t.Fatal("no configuration: want no IPv4v6")
	}
}

func TestSetChildTrafficSelectorsIPv4v6(t *testing.T) {
	var p xfrm.ChildSAParams
	setChildTrafficSelectors(&p, net.ParseIP("10.41.201.7").To4(), net.ParseIP("fd2e:8dd5:6c93:2000::7"))
	if p.LocalTS.String() != "0.0.0.0/0" || p.RemoteTS.String() != "10.41.201.7/32" ||
		p.LocalTS6.String() != "::/0" || p.RemoteTS6.String() != "fd2e:8dd5:6c93:2000::/64" {
		t.Fatalf("selectors %v %v %v %v", p.LocalTS, p.RemoteTS, p.LocalTS6, p.RemoteTS6)
	}
	setChildTrafficSelectors(&p, net.ParseIP("10.41.201.7").To4(), nil)
	if p.LocalTS6 != nil || p.RemoteTS6 != nil {
		t.Fatalf("IPv4 only: IPv6 selectors %v %v", p.LocalTS6, p.RemoteTS6)
	}
}

func pdnResponse(t *testing.T, srv *Server, sa *ikeSA, paa, paa6 net.IP) (message.IKEPayloadContainer, map[uint16]int, []uint16) {
	t.Helper()
	res := &s2b.CreateSessionResult{ResponseAPCO: &pco.Decoded{
		DNSv4:   []net.IP{net.ParseIP("10.10.41.20")},
		DNSv6:   []net.IP{net.ParseIP("fd2e:8dd5:6c93:1041::20")},
		PCSCFv4: []net.IP{net.ParseIP("10.10.41.60")},
		PCSCFv6: []net.IP{net.ParseIP("fd2e:8dd5:6c93:1041::60")},
	}}
	var c message.IKEPayloadContainer
	srv.buildPDNConfiguration(&c, sa, paa, paa6, res)
	if _, err := c.Encode(); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	attrs := map[uint16]int{}
	var notifies []uint16
	for _, p := range c {
		switch v := p.(type) {
		case *message.Configuration:
			for _, a := range v.ConfigurationAttribute {
				attrs[a.Type]++
			}
		case *message.Notification:
			notifies = append(notifies, v.NotifyMessageType)
		}
	}
	return c, attrs, notifies
}

func TestBuildPDNConfigurationIPv4v6(t *testing.T) {
	srv := newIPv4v6TestServer(true)
	paa, paa6 := net.ParseIP("10.41.201.7").To4(), net.ParseIP("fd2e:8dd5:6c93:2000::7")
	c, attrs, notifies := pdnResponse(t, srv, xiaomiSA(), paa, paa6)

	want := map[uint16]int{
		message.INTERNAL_IP4_ADDRESS: 1, message.INTERNAL_IP6_ADDRESS: 1,
		message.INTERNAL_IP4_DNS: 1, message.INTERNAL_IP6_DNS: 1,
		internalIP4PCSCF: 1, internalIP6PCSCF: 1,
	}
	for k, n := range want {
		if attrs[k] != n {
			t.Fatalf("CFG_REPLY attributes %v, want %v", attrs, want)
		}
	}
	if len(attrs) != len(want) {
		t.Fatalf("CFG_REPLY attributes %v, want %v", attrs, want)
	}
	if len(notifies) != 0 {
		t.Fatalf("notifies %v, want none for IPv4v6", notifies)
	}

	tsi := c[0].(*message.TrafficSelectorInitiator).TrafficSelectors
	tsr := c[1].(*message.TrafficSelectorResponder).TrafficSelectors
	if len(tsi) != 2 || len(tsr) != 2 {
		t.Fatalf("TSi %d, TSr %d selectors, want 2 and 2", len(tsi), len(tsr))
	}
	if tsi[0].TSType != message.TS_IPV4_ADDR_RANGE || !net.IP(tsi[0].StartAddress).Equal(paa) || !net.IP(tsi[0].EndAddress).Equal(paa) ||
		tsi[1].TSType != message.TS_IPV6_ADDR_RANGE || !net.IP(tsi[1].StartAddress).Equal(net.ParseIP("fd2e:8dd5:6c93:2000::")) {
		t.Fatalf("TSi = %+v", tsi)
	}
	if tsr[0].TSType != message.TS_IPV4_ADDR_RANGE || tsr[1].TSType != message.TS_IPV6_ADDR_RANGE {
		t.Fatalf("TSr = %+v", tsr)
	}
}

func TestBuildPDNConfigurationSingleFamilyNotify(t *testing.T) {
	srv := newIPv4v6TestServer(true)

	// ipv4v6 off, or the PGW assigned only IPv4.
	_, attrs, notifies := pdnResponse(t, srv, xiaomiSA(), net.ParseIP("10.41.201.7").To4(), nil)
	if len(notifies) != 1 || notifies[0] != notifyPDNTypeIPv4OnlyAllowed || attrs[message.INTERNAL_IP6_ADDRESS] != 0 {
		t.Fatalf("IPv4 only: notifies %v attributes %v", notifies, attrs)
	}

	// The PGW assigned only IPv6.
	_, attrs, notifies = pdnResponse(t, srv, xiaomiSA(), net.ParseIP("fd2e:8dd5:6c93:2000::7"), nil)
	if len(notifies) != 1 || notifies[0] != notifyPDNTypeIPv6OnlyAllowed ||
		attrs[message.INTERNAL_IP6_ADDRESS] != 1 || attrs[message.INTERNAL_IP4_ADDRESS] != 0 {
		t.Fatalf("IPv6 only: notifies %v attributes %v", notifies, attrs)
	}

	// The A33 asks only for IPv6: no notify.
	a33 := &ikeSA{cpWantsIP6: true, cpWantsDNS6: true, cpWantsPCSCF6Private: true}
	if _, _, notifies = pdnResponse(t, srv, a33, net.ParseIP("fd2e:8dd5:6c93:2000::9"), nil); len(notifies) != 0 {
		t.Fatalf("IPv6 request: notifies %v, want none", notifies)
	}
}
