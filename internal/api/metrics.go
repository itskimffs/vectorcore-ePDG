// Added by itskimffs (2026-10), see NOTICE: Prometheus metrics per PDN type and QCI.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package api

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/session"
)

// metricsStore is what /metrics reads from the GTP-U manager.
type metricsStore interface {
	Bearers() []gtpu.BearerInfo
	TrafficTotals() map[gtpu.TrafficKey]gtpu.TrafficCounter
}

// handleMetrics serves the Prometheus text exposition format (version 0.0.4).
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	ms, _ := s.gtpu.(metricsStore)
	writeMetrics(w, s.build, s.sessions.Snapshot(), ms, s.cfg.MetricsIMSILabel)
}

func writeMetrics(w io.Writer, build BuildInfo, sessions []*session.Session, ms metricsStore, imsiLabel bool) {
	header(w, "epdg_build_info", "gauge", "Build information.")
	sample(w, "epdg_build_info", labels("version", build.Version), 1)

	ikeSAs, childSAs := 0, 0
	for _, sess := range sessions {
		sess.RLock()
		if sess.IkeSPII != 0 {
			ikeSAs++
		}
		if sess.ESPInboundSPI != 0 {
			childSAs++
		}
		sess.RUnlock()
	}
	header(w, "epdg_ike_sas", "gauge", "IKE SAs (one per UE tunnel/PDN connection).")
	sample(w, "epdg_ike_sas", "", float64(ikeSAs))
	header(w, "epdg_child_sas", "gauge", "IPsec CHILD SAs.")
	sample(w, "epdg_child_sas", "", float64(childSAs))

	if ms == nil {
		return
	}

	type pdnKey struct{ imsi, apn, pdnType string }
	type bearerKey struct {
		imsi, apn, pdnType, kind string
		qci                      uint8
	}
	pdns := map[pdnKey]int{}
	bearers := map[bearerKey]int{}
	for _, b := range ms.Bearers() {
		imsi := ""
		if imsiLabel {
			imsi = b.IMSI
		}
		kind := "dedicated"
		if b.Default {
			kind = "default"
			pdns[pdnKey{imsi, b.APN, b.PDNType}]++
		}
		bearers[bearerKey{imsi, b.APN, b.PDNType, kind, b.QCI}]++
	}

	header(w, "epdg_pdn_sessions", "gauge", "Active PDN connections with an installed user plane, by APN and PDN type.")
	pdnKeys := make([]pdnKey, 0, len(pdns))
	for k := range pdns {
		pdnKeys = append(pdnKeys, k)
	}
	sort.Slice(pdnKeys, func(i, j int) bool {
		a, b := pdnKeys[i], pdnKeys[j]
		return a.imsi+"\x00"+a.apn+"\x00"+a.pdnType < b.imsi+"\x00"+b.apn+"\x00"+b.pdnType
	})
	for _, k := range pdnKeys {
		sample(w, "epdg_pdn_sessions", withIMSI(imsiLabel, k.imsi, "apn", k.apn, "pdn_type", k.pdnType), float64(pdns[k]))
	}

	header(w, "epdg_bearers", "gauge", "Active bearers by APN, PDN type, QCI and bearer type (default/dedicated).")
	bearerKeys := make([]bearerKey, 0, len(bearers))
	for k := range bearers {
		bearerKeys = append(bearerKeys, k)
	}
	sort.Slice(bearerKeys, func(i, j int) bool {
		a, b := bearerKeys[i], bearerKeys[j]
		if a.imsi+a.apn+a.pdnType+a.kind != b.imsi+b.apn+b.pdnType+b.kind {
			return a.imsi+"\x00"+a.apn+"\x00"+a.pdnType+"\x00"+a.kind < b.imsi+"\x00"+b.apn+"\x00"+b.pdnType+"\x00"+b.kind
		}
		return a.qci < b.qci
	})
	for _, k := range bearerKeys {
		sample(w, "epdg_bearers", withIMSI(imsiLabel, k.imsi,
			"apn", k.apn, "pdn_type", k.pdnType, "qci", strconv.Itoa(int(k.qci)), "type", k.kind), float64(bearers[k]))
	}

	totals := ms.TrafficTotals()
	keys := make([]gtpu.TrafficKey, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.APN != b.APN {
			return a.APN < b.APN
		}
		if a.PDNType != b.PDNType {
			return a.PDNType < b.PDNType
		}
		if a.QCI != b.QCI {
			return a.QCI < b.QCI
		}
		return a.Direction < b.Direction
	})
	header(w, "epdg_bearer_packets_total", "counter", "User-plane packets by APN, PDN type, QCI and direction (inner packets, polled from the BPF bearer counters).")
	for _, k := range keys {
		sample(w, "epdg_bearer_packets_total", trafficLabels(k), float64(totals[k].Packets))
	}
	header(w, "epdg_bearer_bytes_total", "counter", "User-plane bytes (inner IP) by APN, PDN type, QCI and direction.")
	for _, k := range keys {
		sample(w, "epdg_bearer_bytes_total", trafficLabels(k), float64(totals[k].Bytes))
	}
}

func trafficLabels(k gtpu.TrafficKey) string {
	return labels("apn", k.APN, "pdn_type", k.PDNType, "qci", strconv.Itoa(int(k.QCI)), "direction", k.Direction)
}

func withIMSI(enabled bool, imsi string, kv ...string) string {
	if enabled {
		kv = append([]string{"imsi", imsi}, kv...)
	}
	return labels(kv...)
}

func header(w io.Writer, name, kind, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

func sample(w io.Writer, name, lbls string, v float64) {
	fmt.Fprintf(w, "%s%s %s\n", name, lbls, strconv.FormatFloat(v, 'g', -1, 64))
}

// labels renders {k1="v1",k2="v2"} with values escaped per the text format.
func labels(kv ...string) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[i])
		b.WriteString(`="`)
		v := strings.ReplaceAll(kv[i+1], `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		v = strings.ReplaceAll(v, "\n", `\n`)
		b.WriteString(v)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}
