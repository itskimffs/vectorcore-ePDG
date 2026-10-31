// Added by itskimffs (2026-10), see NOTICE: release all sessions on shutdown.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/free5gc/ike/message"
)

func TestReleaseAllSessionsSendsIKEDelete(t *testing.T) {
	r := newDPDTestRig(t)
	r.sa.ourMsgID = 7
	// A half-open SA is torn down without a Delete to the UE.
	r.srv.storeSA(&ikeSA{spiI: 0x3333, state: ikeStateAuth, createdAt: time.Now()})

	if n := r.srv.ReleaseAllSessions(2 * time.Second); n != 2 {
		t.Fatalf("ReleaseAllSessions() = %d, want 2", n)
	}

	pkt := r.ueRecv(t)
	if got := binary.BigEndian.Uint32(pkt[20:24]); got != 7 {
		t.Fatalf("Message ID = %d, want 7 (ourMsgID)", got)
	}
	if pkt[18] != byte(message.INFORMATIONAL) || pkt[19]&0x20 != 0 || pkt[19]&0x08 != 0 {
		t.Fatalf("exchange %d flags %#x, want an INFORMATIONAL request from the responder", pkt[18], pkt[19])
	}
	// The UE decrypts with the ePDG's responder keys (decryptSK reads SK_ei/SK_ai).
	k := r.sa.saKey
	next, plain, err := decryptSK(&ikeSAKey{encr: k.encr, integ: k.integ, SK_ei: k.SK_er, SK_ai: k.SK_ar}, pkt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if next != uint8(message.TypeD) {
		t.Fatalf("first inner payload %d, want Delete (%d)", next, message.TypeD)
	}
	var payloads message.IKEPayloadContainer
	if err := payloads.Decode(next, plain); err != nil {
		t.Fatalf("decode: %v", err)
	}
	d, ok := payloads[0].(*message.Delete)
	if !ok || d.ProtocolID != protocolIDIKE || d.SPISize != 0 || d.NumberOfSPI != 0 {
		t.Fatalf("Delete payload = %+v, want IKE SA (protocol 1, no SPIs)", payloads[0])
	}

	if r.srv.lookupSA(0x1111) != nil || r.srv.lookupSA(0x3333) != nil {
		t.Fatal("SAs left after ReleaseAllSessions")
	}
	if r.sa.state != ikeStateDeleting {
		t.Fatalf("SA state %v, want deleting", r.sa.state)
	}

	// Nothing more to the UE (no Delete for the half-open SA).
	_ = r.ue.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := r.ue.Read(make([]byte, 64)); n != 0 {
		t.Fatalf("unexpected second packet (%d bytes)", n)
	}
}

func TestReleaseAllSessionsSkipsSADeletedConcurrently(t *testing.T) {
	r := newDPDTestRig(t)
	r.sa.state = ikeStateDeleting
	if n := r.srv.ReleaseAllSessions(time.Second); n != 0 {
		t.Fatalf("ReleaseAllSessions() = %d, want 0", n)
	}
	if n := (&Server{sas: map[uint64]*ikeSA{}}).ReleaseAllSessions(time.Second); n != 0 {
		t.Fatalf("no SAs: %d", n)
	}
}

func TestReleaseSessionByNetworkSendsIKEDelete(t *testing.T) {
	r := newDPDTestRig(t)
	r.sa.sessionID = "sess-1"
	r.sa.ourMsgID = 3

	if r.srv.ReleaseSessionByNetwork("other", true, "test") {
		t.Fatal("released an SA for an unknown session")
	}
	if !r.srv.ReleaseSessionByNetwork("sess-1", true, "test") {
		t.Fatal("ReleaseSessionByNetwork() = false, want true")
	}
	pkt := r.ueRecv(t)
	k := r.sa.saKey
	next, plain, err := decryptSK(&ikeSAKey{encr: k.encr, integ: k.integ, SK_ei: k.SK_er, SK_ai: k.SK_ar}, pkt)
	if err != nil || next != uint8(message.TypeD) || binary.BigEndian.Uint32(pkt[20:24]) != 3 {
		t.Fatalf("Delete to UE: next %d msg id %d err %v", next, binary.BigEndian.Uint32(pkt[20:24]), err)
	}
	var payloads message.IKEPayloadContainer
	if err := payloads.Decode(next, plain); err != nil {
		t.Fatal(err)
	}
	if d, ok := payloads[0].(*message.Delete); !ok || d.ProtocolID != protocolIDIKE {
		t.Fatalf("payload %+v, want IKE SA Delete", payloads[0])
	}
	if r.srv.lookupSA(r.sa.spiI) != nil {
		t.Fatal("SA left after release")
	}
	if r.srv.ReleaseSessionByNetwork("sess-1", true, "test") {
		t.Fatal("second release reported true")
	}
}
