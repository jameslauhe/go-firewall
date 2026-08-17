// Package log implements the structured JSON access log: one entry per
// request, written via slog and also retained in a bounded in-memory ring
// buffer the admin dashboard reads from.
package log

import "time"

// Entry is one request's access-log record.
type Entry struct {
	Timestamp      time.Time `json:"timestamp"`
	ClientIP       string    `json:"client_ip"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Query          string    `json:"query,omitempty"`
	Host           string    `json:"host"`
	Outcome        string    `json:"outcome"`
	BlockReason    string    `json:"block_reason,omitempty"`
	WAFRuleID      int       `json:"waf_rule_id,omitempty"`
	WAFCategory    string    `json:"waf_category,omitempty"`
	Upstream       string    `json:"upstream,omitempty"`
	UpstreamStatus int       `json:"upstream_status,omitempty"`
	StatusCode     int       `json:"status_code"`
	LatencyMS      float64   `json:"latency_ms"`
	RequestBytes   int64     `json:"request_bytes"`
	ResponseBytes  int64     `json:"response_bytes"`
	UserAgent      string    `json:"user_agent,omitempty"`
	TLSVersion     string    `json:"tls_version,omitempty"`
	RequestID      string    `json:"request_id"`
}
