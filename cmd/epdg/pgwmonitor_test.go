// Added by itskimffs (2026-10), see NOTICE: PGW restart detection with GTPv2-C Echo (Restart Counter).
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"vectorcore-epdg/internal/session"
)

func testSession(id string, pgw string, recovery uint8, present bool) *session.Session {
	s := session.New(id)
	s.State = session.StateS2BAccepted
	s.S2B = &session.S2BContext{
		PGWControlTEID:     1,
		PGWControlIP:       net.ParseIP(pgw),
		PGWRecovery:        recovery,
		PGWRecoveryPresent: present,
	}
	return s
}

type echoReply struct {
	recovery uint8
	present  bool
	err      error
}

type monitorHarness struct {
	m        *pgwMonitor
	now      time.Time
	replies  map[string]echoReply
	echoed   []string
	mu       sync.Mutex
	released []string
	sessions []*session.Session
}

func newHarness(sessions ...*session.Session) *monitorHarness {
	h := &monitorHarness{now: time.Unix(1000, 0), replies: map[string]echoReply{}, sessions: sessions}
	h.m = newPGWMonitor(0,
		func(_ context.Context, ip net.IP) (uint8, bool, error) {
			h.echoed = append(h.echoed, ip.String())
			r := h.replies[ip.String()]
			return r.recovery, r.present, r.err
		},
		func() []*session.Session { return h.sessions },
		func(_ context.Context, s *session.Session) {
			h.mu.Lock()
			h.released = append(h.released, s.ID)
			h.mu.Unlock()
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.m.now = func() time.Time { return h.now }
	return h
}

func (h *monitorHarness) tick(advance time.Duration) []string {
	h.now = h.now.Add(advance)
	h.released, h.echoed = nil, nil
	h.m.check(context.Background())
	sort.Strings(h.released)
	return h.released
}

func TestPGWMonitorIntervalAtLeast60s(t *testing.T) {
	if m := newPGWMonitor(10*time.Second, nil, nil, nil, nil); m.interval != minEchoInterval {
		t.Fatalf("interval = %v", m.interval)
	}
}

func TestPGWMonitorRestartCounterChange(t *testing.T) {
	h := newHarness(testSession("a", "10.0.0.1", 0, false), testSession("b", "10.0.0.1", 0, false))
	h.replies["10.0.0.1"] = echoReply{recovery: 7, present: true}
	if r := h.tick(0); len(r) != 0 || len(h.echoed) != 1 {
		t.Fatalf("first echo: released %v echoed %v", r, h.echoed)
	}
	// Not due yet: no echo within the interval.
	if h.tick(30 * time.Second); len(h.echoed) != 0 {
		t.Fatalf("echo before interval: %v", h.echoed)
	}
	h.replies["10.0.0.1"] = echoReply{recovery: 8, present: true}
	if r := h.tick(30 * time.Second); len(r) != 2 || r[0] != "a" || r[1] != "b" {
		t.Fatalf("restart: released %v", r)
	}
}

func TestPGWMonitorSessionCounterFromCreateSession(t *testing.T) {
	// Sessions with the counter from their Create Session Response are compared
	// with it, also at the first echo (the PGW restarted before it).
	h := newHarness(testSession("old", "10.0.0.1", 3, true), testSession("new", "10.0.0.1", 4, true))
	h.replies["10.0.0.1"] = echoReply{recovery: 4, present: true}
	if r := h.tick(0); len(r) != 1 || r[0] != "old" {
		t.Fatalf("released %v", r)
	}
}

func TestPGWMonitorPathFailureReleasesNothing(t *testing.T) {
	h := newHarness(testSession("a", "10.0.0.1", 0, false))
	h.replies["10.0.0.1"] = echoReply{recovery: 1, present: true}
	h.tick(0)
	h.replies["10.0.0.1"] = echoReply{err: errors.New("no response")}
	if r := h.tick(time.Minute); len(r) != 0 {
		t.Fatalf("path failure released %v", r)
	}
	// Back with another counter: restarted while unreachable.
	h.replies["10.0.0.1"] = echoReply{recovery: 2, present: true}
	if r := h.tick(time.Minute); len(r) != 1 {
		t.Fatalf("after path failure: released %v", r)
	}
}

func TestPGWMonitorPerPeerAndNoRecoveryIE(t *testing.T) {
	h := newHarness(testSession("a", "10.0.0.1", 0, false), testSession("b", "10.0.0.2", 0, false))
	h.replies["10.0.0.1"] = echoReply{recovery: 1, present: true}
	h.replies["10.0.0.2"] = echoReply{present: false}
	h.tick(0)
	h.replies["10.0.0.1"] = echoReply{recovery: 1, present: true}
	h.replies["10.0.0.2"] = echoReply{recovery: 9, present: true}
	// 10.0.0.2 had no counter before: this is its first value, nothing to compare.
	if r := h.tick(time.Minute); len(r) != 0 || len(h.echoed) != 2 {
		t.Fatalf("released %v echoed %v", r, h.echoed)
	}
}

func TestPGWMonitorSkipsSessionsWithoutS2B(t *testing.T) {
	s := session.New("x")
	gone := testSession("gone", "10.0.0.1", 0, false)
	gone.State = session.StateCleaningUp
	h := newHarness(s, gone)
	if h.tick(0); len(h.echoed) != 0 {
		t.Fatalf("echoed %v", h.echoed)
	}
}
