package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func TestMiddleware_RecordsAllowedRequest(t *testing.T) {
	m := New("/metrics", func() int { return 7 })

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Chain(next, mw.AttachRecorder, m.Middleware())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := testutil.ToFloat64(m.requestsTotal.WithLabelValues("allowed"))
	if got != 1 {
		t.Errorf("requests_total{outcome=allowed} = %v, want 1", got)
	}
}

func TestMiddleware_RecordsBlockedRequestWithWAFLabels(t *testing.T) {
	m := New("/metrics", nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := mw.RecorderFrom(r.Context()); ok {
			rec.SetBlocked(mw.BlockReasonWAF)
			rec.SetWAFMatch(942100, "sqli")
		}
		w.WriteHeader(http.StatusForbidden)
	})
	handler := mw.Chain(next, mw.AttachRecorder, m.Middleware())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := testutil.ToFloat64(m.blockedTotal.WithLabelValues("waf", "942100", "sqli"))
	if got != 1 {
		t.Errorf("blocked_requests_total{reason=waf,rule_id=942100,category=sqli} = %v, want 1", got)
	}
}

func TestMiddleware_RecordsUpstreamError(t *testing.T) {
	m := New("/metrics", nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := mw.RecorderFrom(r.Context()); ok {
			rec.SetBlocked(mw.BlockReasonUpstreamError)
			rec.SetUpstream("10.0.1.10:8080", http.StatusBadGateway)
			rec.SetUpstreamErrorReason("timeout")
		}
		w.WriteHeader(http.StatusBadGateway)
	})
	handler := mw.Chain(next, mw.AttachRecorder, m.Middleware())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := testutil.ToFloat64(m.upstreamErrorTotal.WithLabelValues("10.0.1.10:8080", "timeout"))
	if got != 1 {
		t.Errorf("upstream_errors_total{upstream=10.0.1.10:8080,reason=timeout} = %v, want 1", got)
	}
}

func TestRateLimitBucketsGauge_ReflectsCallback(t *testing.T) {
	m := New("/metrics", func() int { return 42 })
	if got := testutil.ToFloat64(m.rateLimitBuckets); got != 42 {
		t.Errorf("rate_limit_buckets_active = %v, want 42", got)
	}
}

func TestHandler_ServesExpositionFormat(t *testing.T) {
	m := New("/metrics", func() int { return 0 })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := mw.Chain(next, mw.AttachRecorder, m.Middleware())
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("metrics handler status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "go_firewall_requests_total") {
		t.Errorf("expected exposition output to contain go_firewall_requests_total, got: %s", rec.Body.String())
	}
}
