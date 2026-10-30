// Added by itskimffs (2026-10), see NOTICE: uplink TFT rules for IPv6 PDN connections.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package gtpu

import (
	"encoding/binary"
	"net"
	"testing"
)

// IPv6 packet filter components, TS 24.008 Table 10.5.162.

func compIPv6Remote(ip net.IP, mask net.IPMask) []byte {
	c := []byte{0x20}
	c = append(c, ip.To16()...)
	return append(c, []byte(mask)...)
}

func compIPv6RemotePrefix(ip net.IP, prefixLen uint8) []byte {
	c := []byte{0x21}
	c = append(c, ip.To16()...)
	return append(c, prefixLen)
}

func compIPv6LocalPrefix(ip net.IP, prefixLen uint8) []byte {
	c := []byte{0x23}
	c = append(c, ip.To16()...)
	return append(c, prefixLen)
}

func TestParseTFT_IPv6RemoteAddressMask(t *testing.T) {
	remote := net.ParseIP("fd2e:8dd5:6c93:1041::70")
	mask := net.CIDRMask(128, 128)
	raw := append([]byte{tftByte1(tftOpCreate, 1)},
		buildFilter(dirBidirectional, 1, 10, append(compIPv6Remote(remote, mask), compProtocol(17)...))...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]
	if !f.RemoteIPv6.Equal(remote) || f.RemoteIPv6Mask.String() != mask.String() {
		t.Fatalf("RemoteIPv6 = %s/%s, want %s/%s", f.RemoteIPv6, f.RemoteIPv6Mask, remote, mask)
	}
	if f.RemoteIPv4 != nil {
		t.Fatalf("RemoteIPv4 = %s, want nil", f.RemoteIPv4)
	}
	if !f.HasProtocol || f.Protocol != 17 {
		t.Fatalf("protocol after IPv6 component not parsed")
	}
}

func TestParseTFT_IPv6RemotePrefixAndLocalPrefix(t *testing.T) {
	remote := net.ParseIP("fd2e:8dd5:6c93:1041::70")
	local := net.ParseIP("fd2e:8dd5:6c93:2003::4")
	var content []byte
	content = append(content, compIPv6RemotePrefix(remote, 128)...)
	content = append(content, compIPv6LocalPrefix(local, 64)...)
	content = append(content, compRemotePortSingle(30000)...)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 2, 20, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]
	if !f.RemoteIPv6.Equal(remote) || f.RemoteIPv6Mask.String() != net.CIDRMask(128, 128).String() {
		t.Fatalf("RemoteIPv6 = %s/%s", f.RemoteIPv6, f.RemoteIPv6Mask)
	}
	if !f.LocalIPv6.Equal(local) || f.LocalIPv6Mask.String() != net.CIDRMask(64, 128).String() {
		t.Fatalf("LocalIPv6 = %s/%s", f.LocalIPv6, f.LocalIPv6Mask)
	}
	if !f.HasRemotePort || f.RemotePortLo != 30000 {
		t.Fatalf("remote port after IPv6 components not parsed")
	}
}

func TestParseTFT_IPv6ComponentErrors(t *testing.T) {
	for name, content := range map[string][]byte{
		"remote truncated":        compIPv6Remote(net.ParseIP("fd00::1"), net.CIDRMask(128, 128))[:20],
		"remote prefix truncated": compIPv6RemotePrefix(net.ParseIP("fd00::1"), 64)[:10],
		"remote prefix > 128":     compIPv6RemotePrefix(net.ParseIP("fd00::1"), 129),
		"local prefix > 128":      compIPv6LocalPrefix(net.ParseIP("fd00::1"), 200),
		"0x18 is not defined":     {0x18, 10, 0, 0, 1, 255, 255, 255, 255},
	} {
		raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 1, 10, content)...)
		if _, err := ParseTFT(raw); err == nil {
			t.Errorf("%s: ParseTFT() error = nil, want error", name)
		}
	}
}

func TestBuildTCBPFTFTRules_IPv6PDN(t *testing.T) {
	remote := net.ParseIP("fd2e:8dd5:6c93:1041::70")
	ds := &Session{
		PAA:        net.ParseIP("fd2e:8dd5:6c93:2003::4"),
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5, RemoteTXTEID: 100},
			6: {
				EBI:          6,
				RemoteTXTEID: 200,
				TFT: &TFT{Filters: []PacketFilter{
					{ // uplink RTP to rtpengine
						Direction: dirUplink, Precedence: 10,
						RemoteIPv6: remote, RemoteIPv6Mask: net.CIDRMask(128, 128),
						HasProtocol: true, Protocol: 17,
						HasRemotePort: true, RemotePortLo: 30000, RemotePortHi: 30001,
					},
					{ // downlink only: not an uplink rule
						Direction: dirDownlink, Precedence: 11,
						RemoteIPv6: remote, RemoteIPv6Mask: net.CIDRMask(128, 128),
					},
					{ // IPv4 filter on an IPv6 PDN connection: never matches
						Direction: dirUplink, Precedence: 12,
						RemoteIPv4: net.ParseIP("10.10.41.70").To4(), RemoteIPv4Mask: net.CIDRMask(32, 32),
					},
				}},
			},
		},
	}

	rules := buildTCBPFTFTRules(ds)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.TEID != 200 || r.Precedence != 10 {
		t.Fatalf("TEID/precedence = %d/%d, want 200/10", r.TEID, r.Precedence)
	}
	if r.Flags&tcTFTFlagRemoteIP == 0 || !net.IP(r.RemoteIP6[:]).Equal(remote) ||
		net.IPMask(r.RemoteMask6[:]).String() != net.CIDRMask(128, 128).String() {
		t.Fatalf("IPv6 remote not set: flags=0x%02x ip=%x mask=%x", r.Flags, r.RemoteIP6, r.RemoteMask6)
	}
	if r.RemoteIP != [4]uint8{} {
		t.Fatalf("IPv4 remote set on IPv6 rule: %v", r.RemoteIP)
	}
	if r.Flags&tcTFTFlagProtocol == 0 || r.Flags&tcTFTFlagRemotePort == 0 {
		t.Fatalf("protocol/remote port flags missing: 0x%02x", r.Flags)
	}

	// An IPv6 filter on an IPv4 PDN connection never matches and is skipped.
	ds.PAA = net.ParseIP("10.41.201.6").To4()
	ds.Bearers[6].TFT.Filters = ds.Bearers[6].TFT.Filters[:1]
	if rules := buildTCBPFTFTRules(ds); len(rules) != 0 {
		t.Fatalf("IPv4 PDN rules = %+v, want none", rules)
	}
}

// ipv6UDPPacket builds an inner IPv6/UDP packet with the given ports.
func ipv6UDPPacket(src, dst net.IP, sport, dport uint16) []byte {
	pkt := ipv6Packet(src, dst)
	binary.BigEndian.PutUint16(pkt[40:42], sport)
	binary.BigEndian.PutUint16(pkt[42:44], dport)
	return pkt
}

func TestTCSelectsDedicatedBearerForIPv6TFT(t *testing.T) {
	var objs GtpuEncapObjects
	if err := LoadGtpuEncapObjects(&objs, nil); err != nil {
		t.Fatalf("LoadGtpuEncapObjects() error = %v (requires root/CAP_BPF)", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	paa := net.ParseIP("fd2e:8dd5:6c93:2003::4")
	ue := net.ParseIP("fd2e:8dd5:6c93:2003:1111:2222:3333:4444")
	rtpengine := net.ParseIP("fd2e:8dd5:6c93:1041::70")
	pcscf := net.ParseIP("fd2e:8dd5:6c93:1041::60")
	const defaultTEID, rtpTEID, wideTEID = uint32(100), uint32(200), uint32(300)

	d := &TCDataplane{objs: objs}
	if err := d.AddUESession(paa, defaultTEID, net.IPv4(10, 10, 41, 41), net.IPv4(10, 10, 41, 50), 1); err != nil {
		t.Fatalf("AddUESession() error = %v", err)
	}
	rule := TCBPFTFTRule{
		TEID: rtpTEID, Precedence: 10,
		Flags:    tcTFTFlagRemoteIP | tcTFTFlagProtocol | tcTFTFlagRemotePort,
		Protocol: 17, RemotePortLo: 30000, RemotePortHi: 30001,
	}
	copy(rule.RemoteIP6[:], rtpengine.To16())
	copy(rule.RemoteMask6[:], net.CIDRMask(128, 128))
	// Lower priority (higher precedence value) rule matching all of 1041::/64.
	wide := TCBPFTFTRule{TEID: wideTEID, Precedence: 50, Flags: tcTFTFlagRemoteIP}
	copy(wide.RemoteIP6[:], rtpengine.To16())
	copy(wide.RemoteMask6[:], net.CIDRMask(64, 128))
	if err := d.SetTFTRules(paa, []TCBPFTFTRule{wide, rule}); err != nil {
		t.Fatalf("SetTFTRules() error = %v", err)
	}

	teidOf := func(inner []byte) uint32 {
		t.Helper()
		frame := append(make([]byte, 12), 0x86, 0xdd)
		frame = append(frame, inner...)
		ret, out, err := objs.TcGtpuEncapFunc.Test(frame)
		if err != nil || ret != tcActRedirect {
			t.Fatalf("verdict = %d (err %v), want TC_ACT_REDIRECT", ret, err)
		}
		return binary.BigEndian.Uint32(out[46:50])
	}

	if got := teidOf(ipv6UDPPacket(ue, rtpengine, 40000, 30000)); got != rtpTEID {
		t.Errorf("RTP to rtpengine: TEID = %d, want %d (dedicated, precedence 10)", got, rtpTEID)
	}
	if got := teidOf(ipv6UDPPacket(ue, rtpengine, 40000, 31000)); got != wideTEID {
		t.Errorf("other port to rtpengine: TEID = %d, want %d (wide rule)", got, wideTEID)
	}
	if got := teidOf(ipv6UDPPacket(ue, net.ParseIP("fd2e:8dd5:6c93:2000::1"), 40000, 30000)); got != defaultTEID {
		t.Errorf("outside 1041::/64: TEID = %d, want %d (default)", got, defaultTEID)
	}
	if got := teidOf(ipv6UDPPacket(ue, pcscf, 6100, 5060)); got != wideTEID {
		t.Errorf("SIP to P-CSCF: TEID = %d, want %d (wide rule)", got, wideTEID)
	}

	// Clearing the rules sends everything on the default bearer again.
	if err := d.SetTFTRules(paa, nil); err != nil {
		t.Fatalf("SetTFTRules(nil) error = %v", err)
	}
	if got := teidOf(ipv6UDPPacket(ue, rtpengine, 40000, 30000)); got != defaultTEID {
		t.Errorf("after clear: TEID = %d, want %d", got, defaultTEID)
	}

	// RemoveUESession also removes the IPv6 TFT rules.
	if err := d.SetTFTRules(paa, []TCBPFTFTRule{rule}); err != nil {
		t.Fatalf("SetTFTRules() error = %v", err)
	}
	if err := d.RemoveUESession(paa); err != nil {
		t.Fatalf("RemoveUESession() error = %v", err)
	}
	var key GtpuEncapTft6RuleKey
	copy(key.Prefix[:], paa.To16()[:8])
	var e GtpuEncapTft6RuleEntry
	if err := objs.Tft6RuleMap.Lookup(key, &e); err == nil {
		t.Fatalf("tft6_rule_map entry left after RemoveUESession")
	}
}
