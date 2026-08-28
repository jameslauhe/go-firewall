package ratelimit

import (
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

type routeLimiter struct {
	prefix  string
	limiter *shardedLimiter
}

// limiterState is everything Reload swaps atomically: the default per-IP
// limiter plus per-route overrides, all built from one config snapshot.
type limiterState struct {
	enabled bool
	def     *shardedLimiter
	routes  []routeLimiter
}

func buildState(cfg config.RateLimitConfig) *limiterState {
	if !cfg.Enabled {
		return &limiterState{enabled: false}
	}

	s := &limiterState{
		enabled: true,
		def:     newShardedLimiter(cfg.Default.RequestsPerSecond, cfg.Default.Burst, cfg.IdleTTL.Duration),
	}
	for _, r := range cfg.PerRoute {
		s.routes = append(s.routes, routeLimiter{
			prefix:  r.PathPrefix,
			limiter: newShardedLimiter(r.RequestsPerSecond, r.Burst, cfg.IdleTTL.Duration),
		})
	}
	return s
}

func (s *limiterState) stop() {
	if !s.enabled {
		return
	}
	s.def.Stop()
	for _, r := range s.routes {
		r.limiter.Stop()
	}
}

func (s *limiterState) activeCount() int {
	if !s.enabled {
		return 0
	}
	n := s.def.activeCount()
	for _, r := range s.routes {
		n += r.limiter.activeCount()
	}
	return n
}

func (s *limiterState) limiterFor(path string) *shardedLimiter {
	for _, r := range s.routes {
		if strings.HasPrefix(path, r.prefix) {
			return r.limiter
		}
	}
	return s.def
}

// Limiter is the rate-limiting pipeline stage: a default per-IP limiter,
// plus optional per-route overrides matched by path prefix (first match
// wins; unmatched paths fall back to the default). Its state is held
// behind an atomic pointer so config-reload (SIGHUP) can swap in new
// thresholds without a lock on the per-request hot path.
type Limiter struct {
	state atomic.Pointer[limiterState]
}

func New(cfg config.RateLimitConfig) *Limiter {
	l := &Limiter{}
	l.state.Store(buildState(cfg))
	return l
}

// Reload atomically swaps in limiters built from a new config. The
// previous state's eviction goroutines are stopped only after the swap
// completes — not before — so no in-flight request is ever routed to a
// limiter that's already been told to stop (stopping first wouldn't
// break Allow()'s correctness, since it doesn't consult the stop
// channel, but stopping after is strictly safer and free).
func (l *Limiter) Reload(cfg config.RateLimitConfig) {
	next := buildState(cfg)
	old := l.state.Swap(next)
	old.stop()
}

// Stop halts the background eviction goroutines. Safe to call even when
// rate limiting is disabled.
func (l *Limiter) Stop() {
	l.state.Load().stop()
}

// ActiveBuckets returns the number of currently tracked per-IP buckets
// across all limiters, for operational visibility (exposed as a metric).
func (l *Limiter) ActiveBuckets() int {
	return l.state.Load().activeCount()
}

// Middleware must run after mw.ResolveClientIP, since it buckets by the
// Recorder's resolved client IP rather than re-parsing RemoteAddr itself —
// this keeps rate limiting, IP filtering, and access logging all keyed to
// the same IP even when trusted-proxy X-Forwarded-For resolution is in
// play.
func (l *Limiter) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state := l.state.Load()
			if !state.enabled {
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

			if !state.limiterFor(r.URL.Path).Allow(ip) {
				rec.SetBlocked(mw.BlockReasonRateLimit)
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
