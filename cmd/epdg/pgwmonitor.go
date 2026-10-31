// Added by itskimffs (2026-10), see NOTICE: PGW restart detection with GTPv2-C Echo (Restart Counter).
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package main

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"vectorcore-epdg/internal/session"
)

// minEchoInterval: an Echo Request shall not be sent more often than every
// 60 s on each path (TS 23.007 §20.1).
const minEchoInterval = 60 * time.Second

// pgwMonitorTick is how often the monitor looks for PGW peers that are due an
// Echo Request; a new peer is echoed at the first tick after its first session.
const pgwMonitorTick = 5 * time.Second

// pgwMonitor sends a GTPv2-C Echo Request to each PGW that has PDN connections
// and compares the Restart Counter in the Echo Response with what the sessions
// on that PGW were set up with (TS 23.007 §18). A changed value means the PGW
// restarted and lost them: the ePDG removes the PDN connections and releases
// the SWu tunnels (IKE Delete to the UE), TS 23.007 §17B.1A.1, so the UEs set
// up new ones at once instead of at their next DPD.
//
// A session whose Create Session Response had a Recovery IE is compared with
// that value; a session without one with the value from the PGW's previous
// Echo Response. A path failure (no Echo Response) alone releases nothing: the
// counter is compared when the PGW answers again.
type pgwMonitor struct {
	interval time.Duration
	echo     func(ctx context.Context, pgwControlIP net.IP) (uint8, bool, error)
	sessions func() []*session.Session
	release  func(ctx context.Context, sess *session.Session)
	log      *slog.Logger
	now      func() time.Time

	peers map[string]*pgwPeer
}

type pgwPeer struct {
	ip       net.IP
	recovery uint8
	known    bool // recovery is the value from an earlier Echo Response
	lastEcho time.Time
	failing  bool
}

// pgwSession is the part of a session the monitor decides on.
type pgwSession struct {
	sess        *session.Session
	peerKey     string
	peerIP      net.IP
	recovery    uint8
	hasRecovery bool
}

func newPGWMonitor(interval time.Duration, echo func(context.Context, net.IP) (uint8, bool, error),
	sessions func() []*session.Session, release func(context.Context, *session.Session), log *slog.Logger) *pgwMonitor {
	if interval < minEchoInterval {
		interval = minEchoInterval
	}
	return &pgwMonitor{
		interval: interval,
		echo:     echo,
		sessions: sessions,
		release:  release,
		log:      log,
		now:      time.Now,
		peers:    map[string]*pgwPeer{},
	}
}

func (m *pgwMonitor) run(ctx context.Context) {
	m.log.Info("PGW restart detection: GTPv2-C Echo per PGW", "interval", m.interval)
	t := time.NewTicker(pgwMonitorTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.check(ctx)
		}
	}
}

// check echoes each PGW with sessions that is due one.
func (m *pgwMonitor) check(ctx context.Context) {
	byPeer := map[string][]pgwSession{}
	for _, ps := range activePGWSessions(m.sessions()) {
		byPeer[ps.peerKey] = append(byPeer[ps.peerKey], ps)
	}
	// A PGW without sessions is not echoed and its counter is forgotten.
	for key := range m.peers {
		if _, ok := byPeer[key]; !ok {
			delete(m.peers, key)
		}
	}
	for key, list := range byPeer {
		p := m.peers[key]
		if p == nil {
			p = &pgwPeer{ip: list[0].peerIP}
			m.peers[key] = p
		}
		if !p.lastEcho.IsZero() && m.now().Sub(p.lastEcho) < m.interval {
			continue
		}
		p.lastEcho = m.now()
		recovery, present, err := m.echo(ctx, p.ip)
		if ctx.Err() != nil {
			return
		}
		m.handleEcho(ctx, key, p, list, recovery, present, err)
	}
}

func (m *pgwMonitor) handleEcho(ctx context.Context, key string, p *pgwPeer, list []pgwSession, recovery uint8, present bool, err error) {
	if err != nil {
		if !p.failing {
			m.log.Warn("S2b path failure: no Echo Response from the PGW", "pgw", key, "sessions", len(list), "error", err)
		}
		p.failing = true
		return
	}
	if p.failing {
		m.log.Info("S2b path restored: Echo Response from the PGW", "pgw", key)
		p.failing = false
	}
	if !present {
		m.log.Debug("PGW Echo Response without Recovery IE", "pgw", key)
		return
	}
	stale := staleSessions(list, p.known, p.recovery, recovery)
	if p.known && p.recovery != recovery {
		m.log.Warn("PGW restart detected: Restart Counter changed", "pgw", key, "old", p.recovery, "new", recovery, "sessions", len(stale))
	} else if len(stale) > 0 {
		m.log.Warn("PGW restart detected: sessions set up with another Restart Counter", "pgw", key, "restart_counter", recovery, "sessions", len(stale))
	}
	p.recovery, p.known = recovery, true
	if len(stale) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, ps := range stale {
		wg.Add(1)
		go func(sess *session.Session) {
			defer wg.Done()
			m.release(ctx, sess)
		}(ps.sess)
	}
	wg.Wait()
}

// staleSessions returns the sessions the PGW has lost, given its Restart
// Counter now: a session with a counter from its Create Session Response is
// stale when that differs; one without, when the counter from the previous
// Echo Response (known) differs.
func staleSessions(list []pgwSession, known bool, prev, now uint8) []pgwSession {
	var stale []pgwSession
	for _, ps := range list {
		if ps.hasRecovery {
			if ps.recovery != now {
				stale = append(stale, ps)
			}
		} else if known && prev != now {
			stale = append(stale, ps)
		}
	}
	return stale
}

// activePGWSessions returns the sessions with an S2b PDN connection, keyed by
// the PGW control-plane address ("" for the static pgw_gtpc peer).
func activePGWSessions(all []*session.Session) []pgwSession {
	var out []pgwSession
	for _, sess := range all {
		sess.RLock()
		s2b := sess.S2B
		state := sess.State
		var ps pgwSession
		ok := s2b != nil && s2b.PGWControlTEID != 0 && state != session.StateCleaningUp && state != session.StateDeleted
		if ok {
			ps = pgwSession{sess: sess, recovery: s2b.PGWRecovery, hasRecovery: s2b.PGWRecoveryPresent}
			if ip4 := s2b.PGWControlIP.To4(); ip4 != nil {
				ps.peerIP = append(net.IP(nil), ip4...)
				ps.peerKey = ip4.String()
			}
		}
		sess.RUnlock()
		if ok {
			out = append(out, ps)
		}
	}
	return out
}
