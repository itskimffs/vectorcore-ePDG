// Added by itskimffs (2026-10), see NOTICE: INVALID_IKE_SPI for requests with an unknown IKE SA.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"net"
	"sync"
	"time"

	"github.com/free5gc/ike/message"
)

// invalidSPIMaxPerSecond bounds the unprotected INVALID_IKE_SPI responses
// this node sends per second, so forged requests cannot use it to send
// traffic at will.
const invalidSPIMaxPerSecond = 20

// invalidSPILimiter is a fixed one-second window limiter. Zero value is ready.
type invalidSPILimiter struct {
	mu          sync.Mutex
	windowStart time.Time
	count       int
}

func (l *invalidSPILimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windowStart.IsZero() || now.Sub(l.windowStart) >= time.Second {
		l.windowStart = now
		l.count = 0
	}
	if l.count >= invalidSPIMaxPerSecond {
		return false
	}
	l.count++
	return true
}

// answerUnknownSPI handles an IKE message for an IKE SA this node does not
// know (e.g. torn down after a DPD timeout while the UE was asleep, or lost
// in a restart) and reports whether it did. RFC 7296 §1.5 and §2.21.4: a
// request MAY be answered with an unprotected response containing
// INVALID_IKE_SPI, sent to the source address and port with the IKE SPIs,
// Message ID and exchange type copied from the request; a response MUST NOT
// be answered. Without it the UE keeps its SA and only notices after its own
// timeouts. IKE_SA_INIT is not handled here (it creates the SA).
func (s *Server) answerUnknownSPI(conn *net.UDPConn, remote *net.UDPAddr, hdr *message.IKEHeader, natt bool) bool {
	if hdr.ExchangeType == message.IKE_SA_INIT || s.lookupSA(hdr.InitiatorSPI) != nil {
		return false
	}
	if hdr.Flags&message.ResponseBitCheck != 0 {
		s.log.Debug("IKEv2 response for unknown IKE SA ignored",
			"exchange", hdr.ExchangeType, "spi_i", hdr.InitiatorSPI, "remote", remote)
		return true
	}
	if !s.invalidSPILimit.allow(time.Now()) {
		s.log.Debug("INVALID_IKE_SPI rate limited", "spi_i", hdr.InitiatorSPI, "remote", remote)
		return true
	}

	var payloads message.IKEPayloadContainer
	payloads.BuildNotification(message.TypeNone, message.INVALID_IKE_SPI, nil, nil)
	// Response flag set; this node is not the original initiator.
	resp := message.NewMessage(hdr.InitiatorSPI, hdr.ResponderSPI, hdr.ExchangeType, true, false, hdr.MessageID, payloads)
	b, err := resp.Encode()
	if err != nil {
		s.log.Error("INVALID_IKE_SPI encode failed", "err", err)
		return true
	}
	s.send(conn, remote, b, natt)
	s.log.Info("INVALID_IKE_SPI sent for unknown IKE SA",
		"exchange", hdr.ExchangeType, "spi_i", hdr.InitiatorSPI, "spi_r", hdr.ResponderSPI,
		"msg_id", hdr.MessageID, "remote", remote)
	return true
}
