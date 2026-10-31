// Added by itskimffs (2026-10), see NOTICE: Prometheus metrics per PDN type and QCI; IPv4v6 PDN connections.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package gtpu

import "net"

// Direction of user-plane traffic as seen from the UE.
const (
	DirectionUplink   = "uplink"
	DirectionDownlink = "downlink"
)

// PDN types as used in metric labels.
const (
	PDNTypeIPv4   = "ipv4"
	PDNTypeIPv6   = "ipv6"
	PDNTypeIPv4v6 = "ipv4v6"
)

// TrafficKey groups cumulative user-plane traffic for the metrics endpoint.
type TrafficKey struct {
	APN       string
	PDNType   string
	QCI       uint8
	Direction string
}

// TrafficCounter is a cumulative packet/byte count. It only grows: bearers
// that disappear keep their contribution.
type TrafficCounter struct {
	Packets uint64
	Bytes   uint64
}

// BearerInfo describes one active bearer for the metrics endpoint.
type BearerInfo struct {
	IMSI    string
	APN     string
	PDNType string
	EBI     uint8
	QCI     uint8
	Default bool
}

// PDNType returns "ipv4" or "ipv6" for a PAA ("" when unknown).
func PDNType(paa net.IP) string {
	switch {
	case paa == nil:
		return ""
	case paa.To4() != nil:
		return PDNTypeIPv4
	case paa.To16() != nil:
		return PDNTypeIPv6
	}
	return ""
}

// sessionPDNType returns the PDN type label of a GTP-U session.
func sessionPDNType(ds *Session) string {
	if ds.PAA6 != nil {
		return PDNTypeIPv4v6
	}
	return PDNType(ds.PAA)
}

// accountLocked adds the growth of a bearer's BPF counter since the last
// poll to the totals for its APN, PDN type and QCI. A counter that went
// backwards (BPF entry recreated) counts from zero. Caller holds m.mu.
func (m *Manager) accountLocked(ds *Session, b *Bearer, direction string, packets, bytes uint64) {
	var prevPackets, prevBytes uint64
	if direction == DirectionUplink {
		prevPackets, prevBytes = b.Counters.UplinkPackets, b.Counters.UplinkBytes
	} else {
		prevPackets, prevBytes = b.Counters.DownlinkPackets, b.Counters.DownlinkBytes
	}
	dp, db := packets, bytes
	if packets >= prevPackets && bytes >= prevBytes {
		dp, db = packets-prevPackets, bytes-prevBytes
	}
	if dp == 0 && db == 0 {
		return
	}
	if m.trafficTotals == nil {
		m.trafficTotals = make(map[TrafficKey]*TrafficCounter)
	}
	key := TrafficKey{APN: ds.APN, PDNType: sessionPDNType(ds), QCI: b.QoS.QCI, Direction: direction}
	t := m.trafficTotals[key]
	if t == nil {
		t = &TrafficCounter{}
		m.trafficTotals[key] = t
	}
	t.Packets += dp
	t.Bytes += db
}

// accountFinalLocked reads a bearer's BPF counters one last time before they
// are deleted, so traffic since the last poll is not lost. Caller holds m.mu.
func (m *Manager) accountFinalLocked(ds *Session, b *Bearer) {
	if m.bpf != nil {
		if packets, bytes, ok := m.bpf.BearerCounter(b.LocalRXTEID); ok {
			m.accountLocked(ds, b, DirectionDownlink, packets, bytes)
			b.Counters.DownlinkPackets, b.Counters.DownlinkBytes = packets, bytes
		}
	}
	if m.tc != nil {
		if packets, bytes, ok := m.tc.BearerCounter(b.RemoteTXTEID); ok {
			m.accountLocked(ds, b, DirectionUplink, packets, bytes)
			b.Counters.UplinkPackets, b.Counters.UplinkBytes = packets, bytes
		}
	}
}

// TrafficTotals returns a copy of the cumulative traffic per APN, PDN type,
// QCI and direction.
func (m *Manager) TrafficTotals() map[TrafficKey]TrafficCounter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[TrafficKey]TrafficCounter, len(m.trafficTotals))
	for k, v := range m.trafficTotals {
		out[k] = *v
	}
	return out
}

// Bearers returns the active bearers of all GTP-U sessions.
func (m *Manager) Bearers() []BearerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []BearerInfo
	for _, ds := range m.sessionsByID {
		pdnType := sessionPDNType(ds)
		for ebi, b := range ds.Bearers {
			out = append(out, BearerInfo{
				IMSI:    ds.IMSI,
				APN:     ds.APN,
				PDNType: pdnType,
				EBI:     ebi,
				QCI:     b.QoS.QCI,
				Default: ebi == ds.DefaultEBI,
			})
		}
	}
	return out
}
