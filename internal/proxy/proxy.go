// Package proxy builds the reverse proxy that forwards allowed requests to
// the configured upstream gateway(s).
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

// failureThreshold is the number of consecutive failures before an
// upstream is marked down for downCooldown.
const failureThreshold = 3

const downCooldown = 30 * time.Second

type upstream struct {
	url          *url.URL
	failureCount atomic.Int32
	downUntil    atomic.Int64 // unix nano; 0 or in the past means healthy
}

func (u *upstream) healthy() bool {
	until := u.downUntil.Load()
	return until == 0 || time.Now().UnixNano() >= until
}

func (u *upstream) recordSuccess() {
	u.failureCount.Store(0)
	u.downUntil.Store(0)
}

func (u *upstream) recordFailure() {
	n := u.failureCount.Add(1)
	if n >= failureThreshold {
		u.downUntil.Store(time.Now().Add(downCooldown).UnixNano())
	}
}

// Proxy round-robins across healthy upstreams and forwards requests via a
// shared httputil.ReverseProxy. Safe (idempotent) requests get a single
// retry against a different upstream on failure; requests with a body are
// not retried, since the incoming request body cannot be replayed without
// buffering it, and forwarding it unbuffered is required for large-body
// support.
type Proxy struct {
	upstreams []*upstream
	rp        *httputil.ReverseProxy
	next      atomic.Uint64
}

type upstreamCtxKey struct{}

func New(cfg config.UpstreamConfig) (*Proxy, error) {
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("proxy: at least one upstream address is required")
	}

	p := &Proxy{}
	for _, addr := range cfg.Addresses {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid upstream address %q: %w", addr, err)
		}
		p.upstreams = append(p.upstreams, &upstream{url: u})
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout: cfg.DialTimeout.Duration,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout.Duration,
		IdleConnTimeout:       cfg.IdleConnTimeout.Duration,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			target := pr.Out.Context().Value(upstreamCtxKey{}).(*upstream).url
			pr.SetURL(target)
			pr.SetXForwarded()
		},
		ModifyResponse: p.recordSuccess,
		ErrorHandler:   p.handleProxyError,
	}
	p.rp = rp

	return p, nil
}

func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.serveHTTP)
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	u := p.pick()
	if u == nil {
		p.writeUnavailable(w, r, "all upstreams unavailable")
		return
	}

	ctx := context.WithValue(r.Context(), upstreamCtxKey{}, u)
	ctx = context.WithValue(ctx, retryCtxKey{}, isRetryable(r))
	p.rp.ServeHTTP(w, r.WithContext(ctx))
}

type retryCtxKey struct{}

func isRetryable(r *http.Request) bool {
	if r.ContentLength == 0 && r.Body == http.NoBody {
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// pick returns the next healthy upstream in round-robin order, or falls
// back to any upstream (fail open) if all are currently marked down.
func (p *Proxy) pick() *upstream {
	if len(p.upstreams) == 0 {
		return nil
	}
	start := p.next.Add(1)
	for i := uint64(0); i < uint64(len(p.upstreams)); i++ {
		u := p.upstreams[(start+i)%uint64(len(p.upstreams))]
		if u.healthy() {
			return u
		}
	}
	// All marked down: fail open and try the next one anyway rather than
	// refusing outright, since the passive health check is a heuristic.
	return p.upstreams[start%uint64(len(p.upstreams))]
}

// recordSuccess is ReverseProxy's ModifyResponse hook: it clears the
// upstream's failure count and records the outcome for the access logger.
func (p *Proxy) recordSuccess(resp *http.Response) error {
	u, _ := resp.Request.Context().Value(upstreamCtxKey{}).(*upstream)
	if u != nil {
		u.recordSuccess()
	}
	if rec, ok := mw.RecorderFrom(resp.Request.Context()); ok {
		rec.SetUpstream(upstreamAddr(u), resp.StatusCode)
	}
	return nil
}

func (p *Proxy) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	u, _ := r.Context().Value(upstreamCtxKey{}).(*upstream)
	if u != nil {
		u.recordFailure()
	}

	retryable, _ := r.Context().Value(retryCtxKey{}).(bool)
	if retryable && len(p.upstreams) > 1 {
		if next := p.pickOtherThan(u); next != nil {
			ctx := context.WithValue(r.Context(), upstreamCtxKey{}, next)
			ctx = context.WithValue(ctx, retryCtxKey{}, false) // at most one retry
			p.rp.ServeHTTP(w, r.WithContext(ctx))
			return
		}
	}

	slog.Warn("upstream proxy error", "upstream", upstreamAddr(u), "error", err)
	if rec, ok := mw.RecorderFrom(r.Context()); ok {
		rec.SetBlocked(mw.BlockReasonUpstreamError)
		rec.SetUpstream(upstreamAddr(u), http.StatusBadGateway)
		rec.SetUpstreamErrorReason(classifyUpstreamError(err))
	}
	w.WriteHeader(http.StatusBadGateway)
}

// classifyUpstreamError buckets an upstream RoundTrip error into a small,
// fixed set of reasons — never the raw error string — since this feeds a
// Prometheus label and an unbounded label set would be a cardinality
// explosion.
func classifyUpstreamError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection-refused"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return "dial-error"
	}
	return "other"
}

func (p *Proxy) pickOtherThan(exclude *upstream) *upstream {
	for _, u := range p.upstreams {
		if u != exclude && u.healthy() {
			return u
		}
	}
	return nil
}

func (p *Proxy) writeUnavailable(w http.ResponseWriter, r *http.Request, reason string) {
	if rec, ok := mw.RecorderFrom(r.Context()); ok {
		rec.SetBlocked(mw.BlockReasonUpstreamError)
		rec.SetUpstreamErrorReason("no-upstream-available")
	}
	slog.Warn("no upstream available", "reason", reason)
	w.WriteHeader(http.StatusServiceUnavailable)
}

func upstreamAddr(u *upstream) string {
	if u == nil || u.url == nil {
		return ""
	}
	return u.url.Host
}
