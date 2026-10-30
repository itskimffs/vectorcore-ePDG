// Added by itskimffs (2026-10), see NOTICE: IPv6 inner traffic over an IPv4 tunnel.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package xfrm

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func ipv6ChildSA() ChildSAParams {
	key16 := make([]byte, 16)
	key20 := make([]byte, 20)
	_, remoteTS, _ := net.ParseCIDR("fd2e:8dd5:6c93:2000::/64")
	_, localTS, _ := net.ParseCIDR("::/0")
	return ChildSAParams{
		LocalIP: net.IPv4(10, 10, 41, 50), RemoteIP: net.IPv4(10, 10, 41, 254),
		InboundSPI: 0x11111111, OutboundSPI: 0x22222222,
		EncKeyIn: key16, IntKeyIn: key20, EncKeyOut: key16, IntKeyOut: key20,
		EncAlgName: "cbc(aes)", IntAlgName: "hmac(sha1)", IntTruncBits: 96,
		LocalTS: localTS, RemoteTS: remoteTS, IfID: IfID,
	}
}

func TestReqidForIPv6(t *testing.T) {
	p := ipv6ChildSA()
	r1 := reqidFor(p)
	if r1 == 0 || r1&0x80000000 == 0 {
		t.Fatalf("reqidFor(IPv6) = %#x, want non-zero with the top bit set", r1)
	}
	_, other, _ := net.ParseCIDR("fd2e:8dd5:6c93:2001::/64")
	p.RemoteTS = other
	if r2 := reqidFor(p); r2 == r1 {
		t.Fatalf("reqidFor gives the same reqid %#x for two prefixes", r1)
	}
	_, v4, _ := net.ParseCIDR("10.41.201.9/32")
	p.RemoteTS = v4
	if r := reqidFor(p); r != 0x0a29c909 {
		t.Fatalf("reqidFor(IPv4) = %#x, want 0x0a29c909 (unchanged)", r)
	}
}

func TestInnerSelector(t *testing.T) {
	if sel := innerSelector(ipv6ChildSA()); sel == nil || sel.Dst.IP.To4() != nil {
		t.Fatalf("innerSelector(IPv6) = %v, want an IPv6 selector", sel)
	}
	p := ipv6ChildSA()
	_, p.RemoteTS, _ = net.ParseCIDR("10.41.201.9/32")
	if sel := innerSelector(p); sel != nil {
		t.Fatalf("innerSelector(IPv4) = %v, want nil", sel)
	}
}

// TestInstallChildSAIPv6InnerOverIPv4 installs and removes an IPv4-tunnel SA
// carrying IPv6 inner traffic in a fresh network namespace. Needs root.
func TestInstallChildSAIPv6InnerOverIPv4(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Skip(err)
	}
	defer orig.Close()
	ns, err := netns.New()
	if err != nil {
		t.Skipf("netns.New: %v", err)
	}
	defer func() { _ = netns.Set(orig); ns.Close() }()

	p := ipv6ChildSA()
	if err := InstallChildSA(p); err != nil {
		if errors.Is(err, unix.EPROTONOSUPPORT) {
			t.Skipf("kernel without ESP/XFRM support: %v", err)
		}
		t.Fatalf("InstallChildSA() error = %v", err)
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 2 {
		t.Fatalf("XfrmStateList = %d states (err %v), want 2", len(states), err)
	}
	for _, st := range states {
		if st.Selector == nil || st.Selector.Dst == nil || st.Selector.Dst.IP.To4() != nil {
			t.Fatalf("state %v has selector %v, want IPv6", st.Spi, st.Selector)
		}
	}
	pols, err := netlink.XfrmPolicyList(netlink.FAMILY_V6)
	if err != nil || len(pols) != 3 {
		t.Fatalf("XfrmPolicyList(V6) = %d policies (err %v), want 3", len(pols), err)
	}
	if err := RemoveChildSA(p); err != nil {
		t.Fatalf("RemoveChildSA() error = %v", err)
	}
}
