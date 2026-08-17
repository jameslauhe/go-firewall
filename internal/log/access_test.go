package log

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func newTestAccessLog(t *testing.T) *AccessLog {
	t.Helper()
	a, err := New(config.LogConfig{Level: "info", AccessLogPath: "-", RingBufferSize: 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestAccessLog_RecordsAllowedRequest(t *testing.T) {
	a := newTestAccessLog(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	handler := mw.Chain(next, mw.AttachRecorder, a.Middleware())

	req := httptest.NewRequest(http.MethodGet, "/hello?x=1", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	entries := a.Recent(0, "", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 ring buffer entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Outcome != "allowed" {
		t.Errorf("outcome = %q, want allowed", e.Outcome)
	}
	if e.StatusCode != http.StatusOK {
		t.Errorf("status_code = %d, want 200", e.StatusCode)
	}
	if e.ClientIP != "1.2.3.4" {
		t.Errorf("client_ip = %q, want 1.2.3.4", e.ClientIP)
	}
	if e.Path != "/hello" || e.Query != "x=1" {
		t.Errorf("path/query = %q/%q, want /hello / x=1", e.Path, e.Query)
	}
	if e.RequestID == "" {
		t.Error("expected a non-empty request ID")
	}
	if rec.Header().Get("X-Request-ID") != e.RequestID {
		t.Errorf("X-Request-ID header = %q, want %q", rec.Header().Get("X-Request-ID"), e.RequestID)
	}
}

func TestAccessLog_RecordsBlockedRequest(t *testing.T) {
	a := newTestAccessLog(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := mw.RecorderFrom(r.Context()); ok {
			rec.SetBlocked(mw.BlockReasonWAF)
			rec.SetWAFMatch(942100, "sqli")
		}
		w.WriteHeader(http.StatusForbidden)
	})
	handler := mw.Chain(next, mw.AttachRecorder, a.Middleware())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "5.6.7.8:1111"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	entries := a.Recent(0, "", "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Outcome != "blocked" || e.BlockReason != "waf" {
		t.Errorf("outcome/reason = %q/%q, want blocked/waf", e.Outcome, e.BlockReason)
	}
	if e.WAFRuleID != 942100 || e.WAFCategory != "sqli" {
		t.Errorf("waf_rule_id/category = %d/%q, want 942100/sqli", e.WAFRuleID, e.WAFCategory)
	}
	if e.StatusCode != http.StatusForbidden {
		t.Errorf("status_code = %d, want 403", e.StatusCode)
	}
}

// TestAccessLog_JSONSchema is a golden-style check on the emitted JSON
// line's field set, to catch accidental schema drift.
func TestAccessLog_JSONSchema(t *testing.T) {
	var buf bytes.Buffer
	a := &AccessLog{
		logger: newTestLogger(&buf),
		ring:   NewRingBuffer(10),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Chain(next, mw.AttachRecorder, a.Middleware())

	req := httptest.NewRequest(http.MethodGet, "/x?a=1", nil)
	req.RemoteAddr = "1.1.1.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	line := strings.TrimSpace(buf.String())
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		t.Fatalf("emitted line is not valid JSON: %v\nline: %s", err, line)
	}

	wantKeys := []string{
		"timestamp", "client_ip", "method", "path", "host", "outcome",
		"status_code", "latency_ms", "request_bytes", "response_bytes",
		"request_id",
	}
	for _, k := range wantKeys {
		if _, ok := fields[k]; !ok {
			t.Errorf("missing expected field %q in access log line: %s", k, line)
		}
	}
}
