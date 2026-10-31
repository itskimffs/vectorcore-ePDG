// Added by itskimffs (2026-10), see NOTICE: IPv4v6 CHILD SAs (XFRM_STATE_AF_UNSPEC).
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package xfrm

import (
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestNewSARequestAFUnspec(t *testing.T) {
	p := ipv4v6ChildSA()
	p.NATT, p.NATTSrcPort, p.NATTDstPort = true, 4500, 51518
	in, _ := buildSAs(p, p.LocalIP, p.RemoteIP)
	req, err := newSARequestAFUnspec(in)
	if err != nil {
		t.Fatal(err)
	}
	b := req.Serialize()
	if len(b) < unix.SizeofNlMsghdr+nl.SizeofXfrmUsersaInfo {
		t.Fatalf("request too short: %d", len(b))
	}
	msg := nl.DeserializeXfrmUsersaInfo(b[unix.SizeofNlMsghdr:])
	if msg.Flags&nl.XFRM_STATE_AF_UNSPEC == 0 || msg.Sel.Family != 0 {
		t.Fatalf("flags %#x sel family %d, want AF_UNSPEC and 0", msg.Flags, msg.Sel.Family)
	}
	if msg.Family != unix.AF_INET || nl.Swap32(msg.Id.Spi) != p.InboundSPI || msg.Reqid != uint32(reqidFor(p)) ||
		msg.Mode != uint8(1) || msg.Lft.HardByteLimit != nl.XFRM_INF {
		t.Fatalf("usersa_info = %+v", msg)
	}
	attrs, err := nl.ParseRouteAttr(b[unix.SizeofNlMsghdr+nl.SizeofXfrmUsersaInfo:])
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint16]bool{}
	for _, a := range attrs {
		seen[a.Attr.Type] = true
	}
	for _, want := range []uint16{nl.XFRMA_ALG_AUTH_TRUNC, nl.XFRMA_ALG_CRYPT, nl.XFRMA_ENCAP, nl.XFRMA_IF_ID} {
		if !seen[want] {
			t.Fatalf("attribute %d missing (have %v)", want, seen)
		}
	}
}
