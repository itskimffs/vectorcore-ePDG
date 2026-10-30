// Added by itskimffs (2026-10), see NOTICE: Prometheus metrics per PDN type and QCI.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package gtpu

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
)

func TestTrafficTotalsByPDNTypeAndQCI(t *testing.T) {
	m, sess := newSyncTestManager()
	m.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	sess.APN = "ims"
	sess.IMSI = "001010000182739"
	sess.PAA = net.ParseIP("fd2e:8dd5:6c93:2004::5")
	sess.DefaultEBI = 5
	sess.Bearers[5].QoS.QCI = 5
	sess.Bearers[6] = &Bearer{EBI: 6, LocalRXTEID: 11, RemoteTXTEID: 21, QoS: BearerQoS{QCI: 1}}
	m.bearersByLocalTEID[11] = &BearerRef{SessionID: sess.ID, BearerEBI: 6}
	m.bearersByRemoteTEID[21] = &BearerRef{SessionID: sess.ID, BearerEBI: 6}

	dl := &fakeBearerCounterReader{counters: map[uint32][2]uint64{10: {10, 1000}, 11: {100, 20000}}}
	ul := &fakeBearerCounterReader{counters: map[uint32][2]uint64{20: {5, 500}, 21: {90, 18000}}}
	m.syncBearerCounters(dl, ul)

	// Second poll: only the growth is added.
	dl.counters[11] = [2]uint64{150, 30000}
	ul.counters[21] = [2]uint64{140, 28000}
	m.syncBearerCounters(dl, ul)

	got := m.TrafficTotals()
	want := map[TrafficKey]TrafficCounter{
		{APN: "ims", PDNType: PDNTypeIPv6, QCI: 5, Direction: DirectionDownlink}: {10, 1000},
		{APN: "ims", PDNType: PDNTypeIPv6, QCI: 5, Direction: DirectionUplink}:   {5, 500},
		{APN: "ims", PDNType: PDNTypeIPv6, QCI: 1, Direction: DirectionDownlink}: {150, 30000},
		{APN: "ims", PDNType: PDNTypeIPv6, QCI: 1, Direction: DirectionUplink}:   {140, 28000},
	}
	if len(got) != len(want) {
		t.Fatalf("totals = %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%+v = %+v, want %+v", k, got[k], v)
		}
	}

	// A removed bearer keeps its contribution; a recreated BPF entry (counter
	// went backwards) counts from zero.
	if err := m.RemoveBearer(context.Background(), sess.ID, 6); err != nil {
		t.Fatalf("RemoveBearer() error = %v", err)
	}
	dl.counters[10] = [2]uint64{3, 300}
	m.syncBearerCounters(dl, ul)
	got = m.TrafficTotals()
	if v := got[TrafficKey{"ims", PDNTypeIPv6, 1, DirectionUplink}]; v != (TrafficCounter{140, 28000}) {
		t.Errorf("QCI 1 uplink after bearer removal = %+v", v)
	}
	if v := got[TrafficKey{"ims", PDNTypeIPv6, 5, DirectionDownlink}]; v != (TrafficCounter{13, 1300}) {
		t.Errorf("QCI 5 downlink after counter reset = %+v, want {13 1300}", v)
	}

	bearers := m.Bearers()
	if len(bearers) != 1 || bearers[0] != (BearerInfo{IMSI: sess.IMSI, APN: "ims", PDNType: PDNTypeIPv6, EBI: 5, QCI: 5, Default: true}) {
		t.Fatalf("Bearers() = %+v", bearers)
	}
}

func TestPDNType(t *testing.T) {
	for in, want := range map[string]string{"10.41.201.6": PDNTypeIPv4, "fd2e::1": PDNTypeIPv6, "": ""} {
		if got := PDNType(net.ParseIP(in)); got != want {
			t.Errorf("PDNType(%q) = %q, want %q", in, got, want)
		}
	}
}
