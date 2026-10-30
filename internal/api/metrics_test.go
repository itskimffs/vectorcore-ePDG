// Added by itskimffs (2026-10), see NOTICE: Prometheus metrics per PDN type and QCI.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/session"
)

type fakeMetricsStore struct {
	bearers []gtpu.BearerInfo
	totals  map[gtpu.TrafficKey]gtpu.TrafficCounter
}

func (f fakeMetricsStore) Bearers() []gtpu.BearerInfo { return f.bearers }
func (f fakeMetricsStore) TrafficTotals() map[gtpu.TrafficKey]gtpu.TrafficCounter {
	return f.totals
}

func metricsFixture() ([]*session.Session, fakeMetricsStore) {
	sessions := []*session.Session{
		{IMSI: "001010000182739", IkeSPII: 1, ESPInboundSPI: 2},
		{IMSI: "001010000182738", IkeSPII: 3, ESPInboundSPI: 4},
	}
	store := fakeMetricsStore{
		bearers: []gtpu.BearerInfo{
			{IMSI: "001010000182739", APN: "ims", PDNType: "ipv6", EBI: 5, QCI: 5, Default: true},
			{IMSI: "001010000182739", APN: "ims", PDNType: "ipv6", EBI: 6, QCI: 1},
			{IMSI: "001010000182738", APN: "ims", PDNType: "ipv4", EBI: 5, QCI: 5, Default: true},
		},
		totals: map[gtpu.TrafficKey]gtpu.TrafficCounter{
			{APN: "ims", PDNType: "ipv6", QCI: 1, Direction: "uplink"}: {Packets: 241, Bytes: 30848},
		},
	}
	return sessions, store
}

func TestWriteMetrics(t *testing.T) {
	sessions, store := metricsFixture()
	var buf bytes.Buffer
	writeMetrics(&buf, BuildInfo{Version: "test"}, sessions, store, false)
	out := buf.String()
	for _, line := range []string{
		`epdg_build_info{version="test"} 1`,
		`epdg_ike_sas 2`,
		`epdg_child_sas 2`,
		`epdg_pdn_sessions{apn="ims",pdn_type="ipv4"} 1`,
		`epdg_pdn_sessions{apn="ims",pdn_type="ipv6"} 1`,
		`epdg_bearers{apn="ims",pdn_type="ipv6",qci="1",type="dedicated"} 1`,
		`epdg_bearers{apn="ims",pdn_type="ipv6",qci="5",type="default"} 1`,
		`epdg_bearers{apn="ims",pdn_type="ipv4",qci="5",type="default"} 1`,
		`epdg_bearer_packets_total{apn="ims",pdn_type="ipv6",qci="1",direction="uplink"} 241`,
		`epdg_bearer_bytes_total{apn="ims",pdn_type="ipv6",qci="1",direction="uplink"} 30848`,
		`# TYPE epdg_bearer_bytes_total counter`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, out)
		}
	}
	if strings.Contains(out, "imsi=") {
		t.Errorf("imsi label present with metrics_imsi_label off:\n%s", out)
	}
}

func TestWriteMetricsIMSILabel(t *testing.T) {
	sessions, store := metricsFixture()
	var buf bytes.Buffer
	writeMetrics(&buf, BuildInfo{}, sessions, store, true)
	out := buf.String()
	for _, line := range []string{
		`epdg_pdn_sessions{imsi="001010000182739",apn="ims",pdn_type="ipv6"} 1`,
		`epdg_bearers{imsi="001010000182739",apn="ims",pdn_type="ipv6",qci="1",type="dedicated"} 1`,
		`epdg_bearers{imsi="001010000182738",apn="ims",pdn_type="ipv4",qci="5",type="default"} 1`,
		// traffic counters stay aggregated
		`epdg_bearer_packets_total{apn="ims",pdn_type="ipv6",qci="1",direction="uplink"} 241`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, out)
		}
	}
}

func TestLabelsEscaping(t *testing.T) {
	if got := labels("apn", `a"b\c`); got != `{apn="a\"b\\c"}` {
		t.Fatalf("labels() = %s", got)
	}
}

// fakeGTPUWithMetrics adds the metrics methods to fakeGTPU.
type fakeGTPUWithMetrics struct {
	*fakeGTPU
	fakeMetricsStore
}

func TestMetricsEndpoint(t *testing.T) {
	srv := newTestServer(t)
	_, store := metricsFixture()
	srv.gtpu = fakeGTPUWithMetrics{fakeGTPU: srv.gtpu.(*fakeGTPU), fakeMetricsStore: store}
	srv.cfg.MetricsIMSILabel = true

	rec := httptest.NewRecorder()
	srv.newMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, line := range []string{
		`epdg_ike_sas 1`,
		`epdg_bearers{imsi="001010000182739",apn="ims",pdn_type="ipv6",qci="1",type="dedicated"} 1`,
	} {
		if !strings.Contains(body, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, body)
		}
	}

	// The Huma API on the same mux still answers.
	rec = httptest.NewRecorder()
	srv.newMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/health status = %d", rec.Code)
	}
}
