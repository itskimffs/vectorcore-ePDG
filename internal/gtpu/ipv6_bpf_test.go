// Added by itskimffs (2026-10), see NOTICE: IPv6 PDN connections in the XDP/TC programs.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package gtpu

// Packet-level tests for inner IPv6 (IPv6 PDN connections), run against the
// compiled programs via BPF_PROG_TEST_RUN like xdp_peer_validation_test.go.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

const tcActRedirect = 7

// ipv6Packet builds a minimal inner IPv6/UDP packet.
func ipv6Packet(src, dst net.IP) []byte {
	pkt := make([]byte, 40+8+4)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40))
	pkt[6] = 17 // UDP
	pkt[7] = 64
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	binary.BigEndian.PutUint16(pkt[40:42], 5060)
	binary.BigEndian.PutUint16(pkt[42:44], 5060)
	binary.BigEndian.PutUint16(pkt[44:46], 12)
	copy(pkt[48:], []byte("test"))
	return pkt
}

// buildGPDU6 wraps an inner packet in Ethernet+IPv4+UDP+GTP-U.
func buildGPDU6(outerSrc, outerDst net.IP, teid uint32, inner []byte) []byte {
	pkt := make([]byte, 14+20+8+8+len(inner))
	pkt[12], pkt[13] = 0x08, 0x00
	ip := pkt[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(pkt)-14))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], outerSrc.To4())
	copy(ip[16:20], outerDst.To4())
	udp := pkt[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 2152)
	binary.BigEndian.PutUint16(udp[2:4], 2152)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(pkt)-34))
	gtp := pkt[42:50]
	gtp[0] = 0x30
	gtp[1] = 255
	binary.BigEndian.PutUint16(gtp[2:4], uint16(len(inner)))
	binary.BigEndian.PutUint32(gtp[4:8], teid)
	copy(pkt[50:], inner)
	return pkt
}

func TestXDPDecapsInnerIPv6InUEPrefix(t *testing.T) {
	objs := loadTestGtpuDecap(t)

	localIP := net.IPv4(10, 10, 41, 50)
	pgwIP := net.IPv4(10, 10, 41, 41)
	paa := net.ParseIP("fd2e:8dd5:6c93:2000::1")
	const teid = uint32(0x3000)

	if err := objs.ConfigMap.Put(configKeyLocalIP, binary.LittleEndian.Uint32(localIP.To4())); err != nil {
		t.Fatal(err)
	}
	if err := objs.ConfigMap.Put(configKeyValidatePeer, uint32(1)); err != nil {
		t.Fatal(err)
	}
	d := &BPFDataplane{objs: *objs}
	if err := d.AddTEID(teid, paa, nil, pgwIP); err != nil {
		t.Fatalf("AddTEID() error = %v", err)
	}

	pcscf := net.ParseIP("fd2e:8dd5:6c93:1041::60")
	// The UE may use any interface identifier in its /64 (TS 24.302 §7.2.2 NOTE 3).
	inner := ipv6Packet(pcscf, net.ParseIP("fd2e:8dd5:6c93:2000:1234:5678:9abc:def0"))
	ret, out, err := objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, inner))
	if err != nil {
		t.Fatalf("Program.Test() error = %v", err)
	}
	if ret != xdpActionPass {
		t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpActionPass)
	}
	if len(out) != 14+len(inner) || out[12] != 0x86 || out[13] != 0xdd || !bytes.Equal(out[14:], inner) {
		t.Fatalf("decapsulated frame = %x, want Ethernet (IPv6) + inner packet", out)
	}

	outside := ipv6Packet(pcscf, net.ParseIP("fd2e:8dd5:6c93:2001::1"))
	if ret, _, err = objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, outside)); err != nil || ret != xdpActionDrop {
		t.Fatalf("verdict for dst outside the UE prefix = %d (err %v), want XDP_DROP", ret, err)
	}

	ipv4Inner := make([]byte, 20)
	ipv4Inner[0] = 0x45
	binary.BigEndian.PutUint16(ipv4Inner[2:4], 20)
	copy(ipv4Inner[16:20], net.IPv4(10, 41, 201, 9).To4())
	if ret, _, err = objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, ipv4Inner)); err != nil || ret != xdpActionDrop {
		t.Fatalf("verdict for inner IPv4 on an IPv6 TEID = %d (err %v), want XDP_DROP", ret, err)
	}
}

func TestXDPIPv4TEIDDropsInnerIPv6(t *testing.T) {
	objs := loadTestGtpuDecap(t)

	localIP := net.IPv4(10, 10, 41, 50)
	pgwIP := net.IPv4(10, 10, 41, 41)
	const teid = uint32(0x3001)
	if err := objs.ConfigMap.Put(configKeyLocalIP, binary.LittleEndian.Uint32(localIP.To4())); err != nil {
		t.Fatal(err)
	}
	d := &BPFDataplane{objs: *objs}
	if err := d.AddTEID(teid, net.IPv4(10, 41, 201, 9), nil, pgwIP); err != nil {
		t.Fatal(err)
	}
	inner := ipv6Packet(net.ParseIP("fd2e::1"), net.ParseIP("fd2e:8dd5:6c93:2000::1"))
	if ret, _, err := objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, inner)); err != nil || ret != xdpActionDrop {
		t.Fatalf("verdict = %d (err %v), want XDP_DROP", ret, err)
	}
}

func TestTCEncapsulatesInnerIPv6(t *testing.T) {
	var objs GtpuEncapObjects
	if err := LoadGtpuEncapObjects(&objs, nil); err != nil {
		t.Fatalf("LoadGtpuEncapObjects() error = %v (requires root/CAP_BPF)", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	localIP := net.IPv4(10, 10, 41, 50)
	pgwIP := net.IPv4(10, 10, 41, 41)
	paa := net.ParseIP("fd2e:8dd5:6c93:2000::1")
	const ulTEID = uint32(0xabcd)

	d := &TCDataplane{objs: objs}
	if err := d.AddUESession(paa, ulTEID, pgwIP, localIP, 1); err != nil {
		t.Fatalf("AddUESession() error = %v", err)
	}

	inner := ipv6Packet(net.ParseIP("fd2e:8dd5:6c93:2000:aaaa:bbbb:cccc:dddd"), net.ParseIP("fd2e:8dd5:6c93:1041::60"))
	frame := make([]byte, 14+len(inner))
	frame[12], frame[13] = 0x86, 0xdd
	copy(frame[14:], inner)

	ret, out, err := objs.TcGtpuEncapFunc.Test(frame)
	if err != nil {
		t.Fatalf("Program.Test() error = %v", err)
	}
	if ret != tcActRedirect {
		t.Fatalf("verdict = %d, want TC_ACT_REDIRECT (%d); out=%x", ret, tcActRedirect, out)
	}
	if len(out) != 14+36+len(inner) {
		t.Fatalf("output length = %d, want %d: %x", len(out), 14+36+len(inner), out)
	}
	ip := out[14:34]
	if ip[0] != 0x45 || ip[9] != 17 || !bytes.Equal(ip[12:16], localIP.To4()) || !bytes.Equal(ip[16:20], pgwIP.To4()) ||
		binary.BigEndian.Uint16(ip[2:4]) != uint16(36+len(inner)) {
		t.Fatalf("outer IPv4 header = %x", ip)
	}
	if binary.BigEndian.Uint16(out[34:36]) != 2152 || binary.BigEndian.Uint16(out[36:38]) != 2152 {
		t.Fatalf("outer UDP header = %x", out[34:42])
	}
	gtp := out[42:50]
	if gtp[0] != 0x30 || gtp[1] != 255 || binary.BigEndian.Uint16(gtp[2:4]) != uint16(len(inner)) ||
		binary.BigEndian.Uint32(gtp[4:8]) != ulTEID {
		t.Fatalf("GTP-U header = %x", gtp)
	}
	if !bytes.Equal(out[50:], inner) {
		t.Fatalf("inner packet = %x, want %x", out[50:], inner)
	}

	other := ipv6Packet(net.ParseIP("fd2e:8dd5:6c93:2001::1"), net.ParseIP("fd2e:8dd5:6c93:1041::60"))
	frame2 := append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}, other...)
	if ret, _, err = objs.TcGtpuEncapFunc.Test(frame2); err != nil || ret != 0 {
		t.Fatalf("verdict for unknown prefix = %d (err %v), want TC_ACT_OK (0)", ret, err)
	}

	if err := d.RemoveUESession(paa); err != nil {
		t.Fatalf("RemoveUESession() error = %v", err)
	}
	var e GtpuEncapUeSessionEntry
	var key GtpuEncapIpv6PrefixKey
	copy(key.Prefix[:], paa.To16()[:8])
	if err := objs.Ue6SessionMap.Lookup(key, &e); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("ue6_session_map entry after RemoveUESession: err = %v, want ErrKeyNotExist", err)
	}
}

func TestPAARouteDst(t *testing.T) {
	cases := map[string]string{
		"10.41.201.9":                 "10.41.201.9/32",
		"fd2e:8dd5:6c93:2000::1":      "fd2e:8dd5:6c93:2000::/64",
		"fd2e:8dd5:6c93:2abc:1:2:3:4": "fd2e:8dd5:6c93:2abc::/64",
	}
	for in, want := range cases {
		got, err := paaRouteDst(net.ParseIP(in))
		if err != nil || got.String() != want {
			t.Errorf("paaRouteDst(%s) = %v, %v; want %s", in, got, err, want)
		}
	}
	if _, err := paaRouteDst(nil); err == nil {
		t.Error("paaRouteDst(nil) error = nil, want error")
	}
}

// The IPv4 uplink path is unchanged by the IPv6 dispatch.
func TestTCEncapsulatesInnerIPv4Unchanged(t *testing.T) {
	var objs GtpuEncapObjects
	if err := LoadGtpuEncapObjects(&objs, nil); err != nil {
		t.Fatalf("LoadGtpuEncapObjects() error = %v (requires root/CAP_BPF)", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	localIP := net.IPv4(10, 10, 41, 50)
	pgwIP := net.IPv4(10, 10, 41, 41)
	paa := net.IPv4(10, 41, 201, 9)
	const ulTEID = uint32(0x1234)
	d := &TCDataplane{objs: objs}
	if err := d.AddUESession(paa, ulTEID, pgwIP, localIP, 1); err != nil {
		t.Fatal(err)
	}

	inner := make([]byte, 28)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], 28)
	inner[8] = 64
	inner[9] = 17
	copy(inner[12:16], paa.To4())
	copy(inner[16:20], net.IPv4(10, 10, 41, 60).To4())
	frame := append(make([]byte, 14), inner...)
	frame[12] = 0x08

	ret, out, err := objs.TcGtpuEncapFunc.Test(frame)
	if err != nil || ret != tcActRedirect {
		t.Fatalf("verdict = %d (err %v), want TC_ACT_REDIRECT", ret, err)
	}
	if len(out) != 14+36+len(inner) || !bytes.Equal(out[50:], inner) ||
		binary.BigEndian.Uint32(out[46:50]) != ulTEID {
		t.Fatalf("encapsulated frame = %x", out)
	}
}

// TestXDPIPv4v6TEIDAcceptsBothFamilies: an IPv4v6 PDN connection's TEID
// decapsulates inner IPv4 to its IPv4 address and inner IPv6 to its /64.
func TestXDPIPv4v6TEIDAcceptsBothFamilies(t *testing.T) {
	objs := loadTestGtpuDecap(t)

	localIP := net.IPv4(10, 10, 41, 50)
	pgwIP := net.IPv4(10, 10, 41, 41)
	const teid = uint32(0x3002)
	if err := objs.ConfigMap.Put(configKeyLocalIP, binary.LittleEndian.Uint32(localIP.To4())); err != nil {
		t.Fatal(err)
	}
	d := &BPFDataplane{objs: *objs}
	paa4, paa6 := net.IPv4(10, 41, 201, 7), net.ParseIP("fd2e:8dd5:6c93:2000::7")
	if err := d.AddTEID(teid, paa4, paa6, pgwIP); err != nil {
		t.Fatalf("AddTEID() error = %v", err)
	}

	inner6 := ipv6Packet(net.ParseIP("fd2e:8dd5:6c93:1041::60"), net.ParseIP("fd2e:8dd5:6c93:2000::abcd"))
	if ret, _, err := objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, inner6)); err != nil || ret != xdpActionPass {
		t.Fatalf("inner IPv6 in the /64: verdict = %d (err %v), want XDP_PASS", ret, err)
	}
	ipv4Inner := func(dst net.IP) []byte {
		p := make([]byte, 20)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], 20)
		copy(p[16:20], dst.To4())
		return p
	}
	if ret, _, err := objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, ipv4Inner(paa4))); err != nil || ret != xdpActionPass {
		t.Fatalf("inner IPv4 to the PAA: verdict = %d (err %v), want XDP_PASS", ret, err)
	}
	if ret, _, err := objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, ipv4Inner(net.IPv4(10, 41, 201, 8)))); err != nil || ret != xdpActionDrop {
		t.Fatalf("inner IPv4 to another address: verdict = %d (err %v), want XDP_DROP", ret, err)
	}
	other6 := ipv6Packet(net.ParseIP("fd2e::1"), net.ParseIP("fd2e:8dd5:6c93:2001::1"))
	if ret, _, err := objs.GtpuDecapFunc.Test(buildGPDU6(pgwIP, localIP, teid, other6)); err != nil || ret != xdpActionDrop {
		t.Fatalf("inner IPv6 outside the /64: verdict = %d (err %v), want XDP_DROP", ret, err)
	}
}
