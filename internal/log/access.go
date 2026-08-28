package log

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

// AccessLog is the outermost pipeline stage: it wraps the response writer
// to observe the final status/byte count regardless of which inner
// middleware produced it, measures total latency, and — once next()
// returns — reads back whatever the Recorder accumulated to emit one JSON
// log line plus a ring-buffer entry for the admin dashboard.
type AccessLog struct {
	logger *slog.Logger
	ring   *RingBuffer
	closer io.Closer
}

func New(cfg config.LogConfig) (*AccessLog, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer
	if cfg.AccessLogPath != "" && cfg.AccessLogPath != "-" {
		f, err := os.OpenFile(cfg.AccessLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("log: open access log file: %w", err)
		}
		w = f
		closer = f
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parseLevel(cfg.Level)})
	return &AccessLog{
		logger: slog.New(handler),
		ring:   NewRingBuffer(cfg.RingBufferSize),
		closer: closer,
	}, nil
}

func (a *AccessLog) Close() error {
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// Recent returns recent ring-buffer entries for the admin dashboard,
// newest first, optionally filtered by outcome and/or block reason (empty
// string = no filter on that dimension).
func (a *AccessLog) Recent(limit int, outcome, reason string) []Entry {
	return a.ring.Recent(limit, func(e Entry) bool {
		if outcome != "" && e.Outcome != outcome {
			return false
		}
		if reason != "" && e.BlockReason != reason {
			return false
		}
		return true
	})
}

// Middleware must run after mw.ResolveClientIP so the logged client_ip
// reflects the resolved IP (honoring trusted-proxy X-Forwarded-For if
// configured), not just the raw RemoteAddr.
func (a *AccessLog) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			var requestID string
			if rec, ok := mw.RecorderFrom(r.Context()); ok {
				requestID = rec.RequestID()
				w.Header().Set("X-Request-ID", requestID)
			}

			sr := mw.WrapStatusRecorder(w)
			next.ServeHTTP(sr, r)

			latency := time.Since(start)

			var snap mw.Snapshot
			if rec, ok := mw.RecorderFrom(r.Context()); ok {
				snap = rec.Snapshot()
			}

			clientIP := ""
			if snap.ClientIP.IsValid() {
				clientIP = snap.ClientIP.String()
			}

			entry := Entry{
				Timestamp:      start.UTC(),
				ClientIP:       clientIP,
				Method:         r.Method,
				Path:           r.URL.Path,
				Query:          r.URL.RawQuery,
				Host:           r.Host,
				Outcome:        string(snap.Outcome),
				BlockReason:    string(snap.BlockReason),
				WAFRuleID:      snap.WAFRuleID,
				WAFCategory:    snap.WAFCategory,
				Upstream:       snap.Upstream,
				UpstreamStatus: snap.UpstreamStatus,
				StatusCode:     sr.Status,
				LatencyMS:      float64(latency.Microseconds()) / 1000.0,
				RequestBytes:   r.ContentLength,
				ResponseBytes:  sr.Bytes,
				UserAgent:      r.UserAgent(),
				RequestID:      requestID,
			}
			if r.TLS != nil {
				entry.TLSVersion = tls.VersionName(r.TLS.Version)
			}

			a.ring.Add(entry)
			a.logEntry(entry)
		})
	}
}

func (a *AccessLog) logEntry(e Entry) {
	a.logger.LogAttrs(context.Background(), slog.LevelInfo, "request",
		slog.Time("timestamp", e.Timestamp),
		slog.String("client_ip", e.ClientIP),
		slog.String("method", e.Method),
		slog.String("path", e.Path),
		slog.String("query", e.Query),
		slog.String("host", e.Host),
		slog.String("outcome", e.Outcome),
		slog.String("block_reason", e.BlockReason),
		slog.Int("waf_rule_id", e.WAFRuleID),
		slog.String("waf_category", e.WAFCategory),
		slog.String("upstream", e.Upstream),
		slog.Int("upstream_status", e.UpstreamStatus),
		slog.Int("status_code", e.StatusCode),
		slog.Float64("latency_ms", e.LatencyMS),
		slog.Int64("request_bytes", e.RequestBytes),
		slog.Int64("response_bytes", e.ResponseBytes),
		slog.String("user_agent", e.UserAgent),
		slog.String("tls_version", e.TLSVersion),
		slog.String("request_id", e.RequestID),
	)
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
