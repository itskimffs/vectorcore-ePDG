// Added by itskimffs (2026-10), see NOTICE: INVALID_IKE_SPI for requests with an unknown IKE SA.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/free5gc/ike/message"
)

func invalidSPITestSetup(t *testing.T) (*Server, *net.UDPConn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srvConn.Close() })
	ueConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ueConn.Close() })
	return srv, srvConn, ueConn, ueConn.LocalAddr().(*net.UDPAddr)
}

// ueRequest builds an IKE header-only packet as the UE (original initiator) sends it.
func ueRequest(t *testing.T, exch uint8, spiI, spiR uint64, msgID uint32, response bool) []byte {
	t.Helper()
	b, err := message.NewMessage(spiI, spiR, exch, response, true, msgID, nil).Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func readIKE(t *testing.T, conn *net.UDPConn, wait time.Duration) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func TestUnknownSPIRequestGetsInvalidIKESPI(t *testing.T) {
	srv, srvConn, ueConn, ueAddr := invalidSPITestSetup(t)

	// DPD/liveness from a UE whose IKE SA this node tore down.
	srv.handlePacket(srvConn, ueAddr, ueRequest(t, message.INFORMATIONAL, 0x1111, 0x2222, 7, false), false)

	b := readIKE(t, ueConn, 2*time.Second)
	if b == nil {
		t.Fatal("no response to a request for an unknown IKE SA")
	}
	msg := new(message.IKEMessage)
	if err := msg.Decode(b); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.InitiatorSPI != 0x1111 || msg.ResponderSPI != 0x2222 || msg.MessageID != 7 || msg.ExchangeType != message.INFORMATIONAL {
		t.Fatalf("header not copied: spi_i=%x spi_r=%x msg_id=%d exch=%d", msg.InitiatorSPI, msg.ResponderSPI, msg.MessageID, msg.ExchangeType)
	}
	if msg.Flags&message.ResponseBitCheck == 0 || msg.Flags&message.InitiatorBitCheck != 0 {
		t.Fatalf("flags = 0x%02x, want Response set and Initiator clear", msg.Flags)
	}
	if len(msg.Payloads) != 1 || msg.Payloads[0].Type() != message.TypeN {
		t.Fatalf("payloads = %+v, want one unprotected Notify", msg.Payloads)
	}
	if n := msg.Payloads[0].(*message.Notification); n.NotifyMessageType != message.INVALID_IKE_SPI {
		t.Fatalf("notify type = %d, want INVALID_IKE_SPI (%d)", n.NotifyMessageType, message.INVALID_IKE_SPI)
	}
}

func TestUnknownSPIRequestOnNATTHasNonESPMarker(t *testing.T) {
	srv, srvConn, ueConn, ueAddr := invalidSPITestSetup(t)
	pkt := append([]byte{0, 0, 0, 0}, ueRequest(t, message.CREATE_CHILD_SA, 0x3333, 0x4444, 2, false)...)
	srv.handlePacket(srvConn, ueAddr, pkt, true)

	b := readIKE(t, ueConn, 2*time.Second)
	if len(b) < 4+message.IKE_HEADER_LEN || binary.BigEndian.Uint32(b[:4]) != nonESPMarker {
		t.Fatalf("NAT-T response without non-ESP marker: %x", b)
	}
	hdr, err := message.ParseHeader(b[4:])
	if err != nil || hdr.ExchangeType != message.CREATE_CHILD_SA || hdr.MessageID != 2 {
		t.Fatalf("header = %+v (err %v)", hdr, err)
	}
}

func TestUnknownSPIResponseIsNotAnswered(t *testing.T) {
	srv, srvConn, ueConn, ueAddr := invalidSPITestSetup(t)
	// e.g. a late answer to a DPD probe of an SA that is gone (RFC 7296 §1.5: MUST NOT respond).
	srv.handlePacket(srvConn, ueAddr, ueRequest(t, message.INFORMATIONAL, 0x5555, 0x6666, 3, true), false)
	if b := readIKE(t, ueConn, 300*time.Millisecond); b != nil {
		t.Fatalf("answered a response: %x", b)
	}
}

func TestKnownSPIIsNotAnsweredWithInvalidIKESPI(t *testing.T) {
	srv, srvConn, ueConn, ueAddr := invalidSPITestSetup(t)
	srv.storeSA(&ikeSA{spiI: 0x7777, spiR: 0x8888})
	hdr, err := message.ParseHeader(ueRequest(t, message.INFORMATIONAL, 0x7777, 0x8888, 1, false))
	if err != nil {
		t.Fatal(err)
	}
	if srv.answerUnknownSPI(srvConn, ueAddr, hdr, false) {
		t.Fatal("answerUnknownSPI() handled a message for a known IKE SA")
	}
	init, err := message.ParseHeader(ueRequest(t, message.IKE_SA_INIT, 0x9999, 0, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	if srv.answerUnknownSPI(srvConn, ueAddr, init, false) {
		t.Fatal("answerUnknownSPI() handled IKE_SA_INIT")
	}
	if b := readIKE(t, ueConn, 300*time.Millisecond); b != nil {
		t.Fatalf("unexpected packet: %x", b)
	}
}

func TestInvalidIKESPIRateLimit(t *testing.T) {
	var l invalidSPILimiter
	now := time.Now()
	for i := 0; i < invalidSPIMaxPerSecond; i++ {
		if !l.allow(now) {
			t.Fatalf("call %d refused within the limit", i+1)
		}
	}
	if l.allow(now.Add(500 * time.Millisecond)) {
		t.Fatal("allowed above the limit in the same second")
	}
	if !l.allow(now.Add(time.Second)) {
		t.Fatal("refused in the next window")
	}
}
