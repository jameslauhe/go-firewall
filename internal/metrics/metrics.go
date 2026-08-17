// Package metrics exposes Prometheus counters/histograms/gauges for
// go-firewall, served on a private listener separate from public traffic.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

// Metrics holds every collector go-firewall exposes. Labels are kept to
// small, bounded value sets (reason/category/rule_id/upstream host) —
// never raw client IPs or full request paths — to avoid Prometheus
// cardinality blowups.
type Metrics struct {
	requestsTotal      *prometheus.CounterVec
	blockedTotal       *prometheus.CounterVec
	requestDuration    *prometheus.HistogramVec
	upstreamErrorTotal *prometheus.CounterVec
	activeConnections  prometheus.Gauge
	rateLimitBuckets   prometheus.GaugeFunc

	registry *prometheus.Registry
	path     string
}

// New registers all collectors against a fresh registry. activeBuckets is
// polled at scrape time (via GaugeFunc) rather than pushed, since the rate
// limiter already tracks this count internally.
func New(path string, activeBuckets func() int) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "go_firewall_requests_total",
			Help: "Total requests processed, by outcome.",
		}, []string{"outcome"}),

		blockedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "go_firewall_blocked_requests_total",
			Help: "Total blocked requests, by reason and (for WAF blocks) rule id/category.",
		}, []string{"reason", "rule_id", "category"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "go_firewall_request_duration_seconds",
			Help:    "End-to-end request latency, by outcome.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"outcome"}),

		upstreamErrorTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "go_firewall_upstream_errors_total",
			Help: "Total upstream proxying errors, by upstream host and error reason.",
		}, []string{"upstream", "reason"}),

		activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "go_firewall_active_connections",
			Help: "Requests currently in flight through go-firewall.",
		}),

		registry: reg,
		path:     path,
	}

	m.rateLimitBuckets = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "go_firewall_rate_limit_buckets_active",
		Help: "Number of currently tracked per-IP rate limit buckets.",
	}, func() float64 {
		if activeBuckets == nil {
			return 0
		}
		return float64(activeBuckets())
	})

	reg.MustRegister(
		m.requestsTotal,
		m.blockedTotal,
		m.requestDuration,
		m.upstreamErrorTotal,
		m.activeConnections,
		m.rateLimitBuckets,
	)

	return m
}

// Handler serves the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) Path() string {
	return m.path
}

// Middleware records per-request metrics. It should sit alongside (not
// necessarily adjacent to) the access-log middleware — both read the same
// Recorder snapshot after next() returns.
func (m *Metrics) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.activeConnections.Inc()
			defer m.activeConnections.Dec()

			start := time.Now()
			next.ServeHTTP(w, r)
			latency := time.Since(start).Seconds()

			var snap mw.Snapshot
			if rec, ok := mw.RecorderFrom(r.Context()); ok {
				snap = rec.Snapshot()
			}
			outcome := string(snap.Outcome)
			if outcome == "" {
				outcome = string(mw.OutcomeAllowed)
			}

			m.requestsTotal.WithLabelValues(outcome).Inc()
			m.requestDuration.WithLabelValues(outcome).Observe(latency)

			if snap.Outcome == mw.OutcomeBlocked {
				ruleID := ""
				if snap.WAFRuleID != 0 {
					ruleID = strconv.Itoa(snap.WAFRuleID)
				}
				m.blockedTotal.WithLabelValues(string(snap.BlockReason), ruleID, snap.WAFCategory).Inc()
			}

			if snap.BlockReason == mw.BlockReasonUpstreamError {
				m.upstreamErrorTotal.WithLabelValues(snap.Upstream, snap.UpstreamErrorReason).Inc()
			}
		})
	}
}
