// Added by itskimffs (2026-10), see NOTICE: release all sessions on shutdown.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"sync"
	"time"

	"github.com/free5gc/ike/message"
)

// protocolIDIKE is the Delete payload Protocol ID for the IKE SA itself
// (RFC 7296 §3.11: 1 = IKE, SPI Size 0, no SPIs).
const protocolIDIKE uint8 = 1

// ReleaseAllSessions tears down every IKE SA before the ePDG stops. For an
// established SA the UE first gets an INFORMATIONAL request with a Delete
// payload for the IKE SA (RFC 7296 §1.4.1), so it can set up a new tunnel at
// once instead of finding out at its next liveness check. fullTeardown then
// removes the CHILD SA from XFRM, the GTP-U session, the S2b session (Delete
// Session Request, so the PGW/SMF releases the PDN connection and its UPF
// session) and the SWm session (STR). The SAs are released in parallel; the
// call returns when all are done or after timeout, whichever comes first, and
// reports how many were released in time.
//
// Must be called while the IKE sockets and the S2b/SWm clients still run.
func (s *Server) ReleaseAllSessions(timeout time.Duration) int {
	s.mu.RLock()
	sas := make([]*ikeSA, 0, len(s.sas))
	for _, sa := range s.sas {
		sas = append(sas, sa)
	}
	s.mu.RUnlock()
	if len(sas) == 0 {
		return 0
	}

	s.log.Info("IKEv2: releasing all sessions before shutdown", "ike_sas", len(sas), "timeout", timeout)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		released int
	)
	for _, sa := range sas {
		wg.Add(1)
		go func(sa *ikeSA) {
			defer wg.Done()
			if s.releaseSA(sa) {
				mu.Lock()
				released++
				mu.Unlock()
			}
		}(sa)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		s.log.Warn("IKEv2: session release timed out", "ike_sas", len(sas), "timeout", timeout)
	}
	mu.Lock()
	n := released
	mu.Unlock()
	s.log.Info("IKEv2: sessions released before shutdown", "released", n, "ike_sas", len(sas))
	return n
}

// releaseSA sends the IKE SA Delete to the UE (established SAs only) and tears
// the SA down. It reports false when the SA was already being deleted.
func (s *Server) releaseSA(sa *ikeSA) bool {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.state == ikeStateDeleting {
		return false
	}
	if sa.state == ikeStateEstablished {
		s.sendIKEDelete(sa)
	}
	sa.state = ikeStateDeleting
	s.fullTeardown(sa, "epdg_shutdown")
	return true
}

// sendIKEDelete sends an INFORMATIONAL request with a Delete payload for the
// IKE SA (RFC 7296 §1.4.1, §3.11); deleting the IKE SA also deletes its CHILD
// SAs. The response is not waited for. With a DPD probe outstanding the same
// Message ID is used (window size 1, RFC 7296 §2.3): a UE that missed the
// probe processes the Delete, one that answered it repeats its answer.
// Must be called with sa.mu held.
func (s *Server) sendIKEDelete(sa *ikeSA) {
	conn := s.dpdConn(sa)
	if conn == nil || sa.saKey == nil || sa.remoteAddr == nil {
		return
	}
	var payloads message.IKEPayloadContainer
	payloads.BuildDeletePayload(protocolIDIKE, 0, 0, nil)
	plain, err := payloads.Encode()
	if err != nil {
		s.log.Warn("IKE Delete encode failed", "imsi", sa.imsi, "err", err)
		return
	}
	out, err := s.encryptRequest(sa, message.INFORMATIONAL, sa.ourMsgID, uint8(message.TypeD), plain)
	if err != nil {
		s.log.Warn("IKE Delete encrypt failed", "imsi", sa.imsi, "err", err)
		return
	}
	s.send(conn, sa.remoteAddr, out, sa.natT)
	s.log.Info("IKE Delete sent to UE", "imsi", sa.imsi, "msg_id", sa.ourMsgID, "remote", sa.remoteAddr)
}
