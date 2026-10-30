// Added by itskimffs (2026-10), see NOTICE: DPD retransmission tests (RFC 7296 §2.1, §2.3, §2.4).
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/free5gc/ike/message"
)

// dpdTestRig is an ePDG server with one established SA and a UDP socket that
// plays the UE.
type dpdTestRig struct {
	srv   *Server
	sa    *ikeSA
	ue    *net.UDPConn
	ueKey *ikeSAKey // UE-side keys: encryptSK with SK_er/SK_ar = the ePDG's SK_ei/SK_ai
}

func newDPDTestRig(t *testing.T) *dpdTestRig {
	t.Helper()
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srvConn.Close() })
	srv.conn500 = srvConn

	ue, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ue.Close() })

	ei := randomKey(t, encrAesCbc256.KeyLen())
	er := randomKey(t, encrAesCbc256.KeyLen())
	ai := randomKey(t, integSha256_128.KeyLen())
	ar := randomKey(t, integSha256_128.KeyLen())
	sa := &ikeSA{
		saKey:      &ikeSAKey{encr: encrAesCbc256, integ: integSha256_128, SK_ei: ei, SK_er: er, SK_ai: ai, SK_ar: ar},
		spiI:       0x1111,
		spiR:       0x2222,
		state:      ikeStateEstablished,
		remoteAddr: ue.LocalAddr().(*net.UDPAddr),
		lastSeen:   time.Now(),
		imsi:       "001010000000001",
	}
	srv.storeSA(sa)

	return &dpdTestRig{
		srv:   srv,
		sa:    sa,
		ue:    ue,
		ueKey: &ikeSAKey{encr: encrAesCbc256, integ: integSha256_128, SK_er: ei, SK_ar: ai},
	}
}

// ueRecv reads one packet sent to the UE.
func (r *dpdTestRig) ueRecv(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	_ = r.ue.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := r.ue.Read(buf)
	if err != nil {
		t.Fatalf("UE did not receive a packet: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

// ueMessage builds an encrypted, empty INFORMATIONAL sent by the UE (IKE initiator).
func (r *dpdTestRig) ueMessage(t *testing.T, msgID uint32, response bool) ([]byte, *message.IKEHeader) {
	t.Helper()
	flags := uint8(message.InitiatorBitCheck)
	if response {
		flags |= message.ResponseBitCheck
	}
	totalLen, err := encryptedSKMessageLen(r.ueKey, 0)
	if err != nil {
		t.Fatalf("encryptedSKMessageLen: %v", err)
	}
	hdrBytes := buildIKERequestHeaderBytes(r.sa.spiI, r.sa.spiR, message.INFORMATIONAL, msgID, totalLen)
	hdrBytes[19] = flags
	pkt, err := encryptSK(r.ueKey, 0, nil, hdrBytes)
	if err != nil {
		t.Fatalf("encryptSK: %v", err)
	}
	return pkt, &message.IKEHeader{
		InitiatorSPI: r.sa.spiI, ResponderSPI: r.sa.spiR,
		ExchangeType: message.INFORMATIONAL, Flags: flags, MessageID: msgID,
	}
}

func probeMsgID(pkt []byte) uint32 { return binary.BigEndian.Uint32(pkt[20:24]) }

// A request from the UE proves liveness but must not cancel our outstanding probe:
// the probe is retransmitted bitwise identical with the same Message ID, and the
// next probe only gets a new Message ID after the UE answered.
func TestDPDProbeKeptAcrossUERequestAndRetransmittedIdentical(t *testing.T) {
	r := newDPDTestRig(t)
	r.sa.ourMsgID = 480

	r.sa.mu.Lock()
	r.srv.sendDPDProbe(r.sa)
	r.sa.mu.Unlock()
	probe := r.ueRecv(t)
	if got := probeMsgID(probe); got != 480 {
		t.Fatalf("probe Message ID = %d, want 480", got)
	}

	// UE liveness request (UE's own Message ID space) while our probe is outstanding.
	req, hdr := r.ueMessage(t, 17, false)
	r.srv.handleInformational(r.srv.conn500, r.ue.LocalAddr().(*net.UDPAddr), req, hdr)
	_ = r.ueRecv(t) // our response to the UE's request

	r.sa.mu.Lock()
	pending := !r.sa.dpdSentAt.IsZero()
	r.srv.retransmitDPDProbe(r.sa)
	r.sa.mu.Unlock()
	if !pending {
		t.Fatal("outstanding probe was cleared by the UE's request")
	}
	if retx := r.ueRecv(t); !bytes.Equal(retx, probe) {
		t.Fatal("retransmitted probe is not bitwise identical to the original")
	}

	// UE answers Message ID 480: the probe is done and the next one is 481.
	resp, rhdr := r.ueMessage(t, 480, true)
	r.srv.handleInformational(r.srv.conn500, r.ue.LocalAddr().(*net.UDPAddr), resp, rhdr)

	r.sa.mu.Lock()
	defer r.sa.mu.Unlock()
	if !r.sa.dpdSentAt.IsZero() || r.sa.dpdPkt != nil {
		t.Fatal("probe still pending after the UE's response")
	}
	if r.sa.ourMsgID != 481 {
		t.Fatalf("ourMsgID = %d, want 481", r.sa.ourMsgID)
	}
}

// Without a response the next probe must reuse the same Message ID.
func TestDPDMessageIDNotAdvancedWithoutResponse(t *testing.T) {
	r := newDPDTestRig(t)
	r.sa.ourMsgID = 5

	r.sa.mu.Lock()
	r.srv.sendDPDProbe(r.sa)
	r.sa.mu.Unlock()
	_ = r.ueRecv(t)

	r.sa.mu.Lock()
	defer r.sa.mu.Unlock()
	if r.sa.ourMsgID != 5 || r.sa.dpdMsgID != 5 {
		t.Fatalf("ourMsgID = %d, dpdMsgID = %d, want 5 and 5", r.sa.ourMsgID, r.sa.dpdMsgID)
	}
}

// A response that fails the integrity check, or answers another Message ID, does
// not complete the probe.
func TestDPDResponseMustMatchAndBeProtected(t *testing.T) {
	r := newDPDTestRig(t)
	r.sa.ourMsgID = 9

	r.sa.mu.Lock()
	r.srv.sendDPDProbe(r.sa)
	r.sa.mu.Unlock()
	_ = r.ueRecv(t)

	wrongID, whdr := r.ueMessage(t, 8, true)
	r.srv.handleInformational(r.srv.conn500, r.ue.LocalAddr().(*net.UDPAddr), wrongID, whdr)

	tampered, thdr := r.ueMessage(t, 9, true)
	tampered[len(tampered)-1] ^= 0xff
	r.srv.handleInformational(r.srv.conn500, r.ue.LocalAddr().(*net.UDPAddr), tampered, thdr)

	r.sa.mu.Lock()
	defer r.sa.mu.Unlock()
	if r.sa.dpdSentAt.IsZero() {
		t.Fatal("probe completed by a wrong-ID or tampered response")
	}
	if r.sa.ourMsgID != 9 {
		t.Fatalf("ourMsgID = %d, want 9", r.sa.ourMsgID)
	}
}
