package ratelimit

import (
	"net/http"
	"strings"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

type routeLimiter struct {
	prefix  string
	limiter *shardedLimiter
}

// Limiter is the rate-limiting pipeline stage: a default per-IP limiter,
// plus optional per-route overrides matched by path prefix (first match
// wins; unmatched paths fall back to the default).
type Limiter struct {
	enabled bool
	def     *shardedLimiter
	routes  []routeLimiter
}

func New(cfg config.RateLimitConfig) *Limiter {
	if !cfg.Enabled {
		return &Limiter{enabled: false}
	}

	l := &Limiter{
		enabled: true,
		def:     newShardedLimiter(cfg.Default.RequestsPerSecond, cfg.Default.Burst, cfg.IdleTTL.Duration),
	}
	for _, r := range cfg.PerRoute {
		l.routes = append(l.routes, routeLimiter{
			prefix:  r.PathPrefix,
			limiter: newShardedLimiter(r.RequestsPerSecond, r.Burst, cfg.IdleTTL.Duration),
		})
	}
	return l
}

// Stop halts the background eviction goroutines. Safe to call even when
// rate limiting is disabled.
func (l *Limiter) Stop() {
	if !l.enabled {
		return
	}
	l.def.Stop()
	for _, r := range l.routes {
		r.limiter.Stop()
	}
}

// ActiveBuckets returns the number of currently tracked per-IP buckets
// across all limiters, for operational visibility (exposed as a metric).
func (l *Limiter) ActiveBuckets() int {
	if !l.enabled {
		return 0
	}
	n := l.def.activeCount()
	for _, r := range l.routes {
		n += r.limiter.activeCount()
	}
	return n
}

func (l *Limiter) limiterFor(path string) *shardedLimiter {
	for _, r := range l.routes {
		if strings.HasPrefix(path, r.prefix) {
			return r.limiter
		}
	}
	return l.def
}

// Middleware must run after mw.ResolveClientIP, since it buckets by the
// Recorder's resolved client IP rather than re-parsing RemoteAddr itself —
// this keeps rate limiting, IP filtering, and access logging all keyed to
// the same IP even when trusted-proxy X-Forwarded-For resolution is in
// play.
func (l *Limiter) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.enabled {
				next.ServeHTTP(w, r)
				return
			}

			rec, ok := mw.RecorderFrom(r.Context())
			if !ok {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}

			ip := rec.ClientIP()
			if !ip.IsValid() {
				rec.SetBlocked(mw.BlockReasonRateLimit)
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}

			if !l.limiterFor(r.URL.Path).Allow(ip) {
				rec.SetBlocked(mw.BlockReasonRateLimit)
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
