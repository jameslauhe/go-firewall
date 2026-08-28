package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func rateLimitConfig(defaultRPS float64, defaultBurst int, perRoute ...config.RouteRateLimit) config.RateLimitConfig {
	return config.RateLimitConfig{
		Enabled:  true,
		Default:  config.RateLimitRule{RequestsPerSecond: defaultRPS, Burst: defaultBurst},
		PerRoute: perRoute,
		IdleTTL:  config.Duration{Duration: time.Hour},
	}
}

func newTestHandler(l *Limiter) http.Handler {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mw.Chain(next, mw.AttachRecorder, mw.ResolveClientIP(nil), l.Middleware())
}

func doRequest(t *testing.T, handler http.Handler, path, remoteAddr string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestMiddleware_BurstThenTooManyRequests(t *testing.T) {
	l := New(rateLimitConfig(1, 3))
	defer l.Stop()
	handler := newTestHandler(l)

	for i := 0; i < 3; i++ {
		if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, code)
		}
	}
	if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusTooManyRequests {
		t.Errorf("request beyond burst: status = %d, want 429", code)
	}
}

func TestMiddleware_UnaffectedTrafficStillFlows(t *testing.T) {
	l := New(rateLimitConfig(1, 2))
	defer l.Stop()
	handler := newTestHandler(l)

	// Exhaust one IP's burst.
	doRequest(t, handler, "/", "1.2.3.4:1111")
	doRequest(t, handler, "/", "1.2.3.4:1111")
	if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusTooManyRequests {
		t.Fatalf("expected first IP to be rate limited, got %d", code)
	}

	// A different IP is unaffected.
	if code := doRequest(t, handler, "/", "5.6.7.8:2222"); code != http.StatusOK {
		t.Errorf("expected different IP to be unaffected, got %d", code)
	}
}

func TestMiddleware_PerRouteOverride(t *testing.T) {
	l := New(rateLimitConfig(100, 100, config.RouteRateLimit{
		PathPrefix:    "/api/login",
		RateLimitRule: config.RateLimitRule{RequestsPerSecond: 1, Burst: 1},
	}))
	defer l.Stop()
	handler := newTestHandler(l)

	if code := doRequest(t, handler, "/api/login", "1.2.3.4:1111"); code != http.StatusOK {
		t.Fatalf("first /api/login request: status = %d, want 200", code)
	}
	if code := doRequest(t, handler, "/api/login", "1.2.3.4:1111"); code != http.StatusTooManyRequests {
		t.Errorf("second immediate /api/login request: status = %d, want 429 (tight route limit)", code)
	}

	// A non-matching path uses the much looser default limit.
	if code := doRequest(t, handler, "/other", "1.2.3.4:1111"); code != http.StatusOK {
		t.Errorf("/other request: status = %d, want 200 (default limit)", code)
	}
}

func TestMiddleware_Disabled(t *testing.T) {
	l := New(config.RateLimitConfig{Enabled: false})
	defer l.Stop()
	handler := newTestHandler(l)

	for i := 0; i < 50; i++ {
		if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusOK {
			t.Fatalf("request %d with rate limiting disabled: status = %d, want 200", i, code)
		}
	}
}

func TestLimiter_Reload_AppliesNewThresholds(t *testing.T) {
	l := New(rateLimitConfig(1, 2))
	defer l.Stop()
	handler := newTestHandler(l)

	// Exhaust the original burst of 2.
	doRequest(t, handler, "/", "1.2.3.4:1111")
	doRequest(t, handler, "/", "1.2.3.4:1111")
	if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusTooManyRequests {
		t.Fatalf("expected burst to be exhausted before reload, got %d", code)
	}

	l.Reload(rateLimitConfig(100, 100))

	// A fresh limiter state means a fresh bucket for this IP too.
	if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusOK {
		t.Errorf("expected request to succeed under the new, looser limit after reload, got %d", code)
	}
}

func TestLimiter_Reload_DisablesRateLimiting(t *testing.T) {
	l := New(rateLimitConfig(1, 1))
	defer l.Stop()
	handler := newTestHandler(l)

	doRequest(t, handler, "/", "1.2.3.4:1111")
	if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusTooManyRequests {
		t.Fatalf("expected burst to be exhausted before reload, got %d", code)
	}

	l.Reload(config.RateLimitConfig{Enabled: false})

	for i := 0; i < 10; i++ {
		if code := doRequest(t, handler, "/", "1.2.3.4:1111"); code != http.StatusOK {
			t.Errorf("request %d after reload-to-disabled: status = %d, want 200", i, code)
		}
	}
}

func TestLimiter_Reload_StopsOldEvictionGoroutine(t *testing.T) {
	l := New(rateLimitConfig(10, 10))
	defer l.Stop()

	oldState := l.state.Load()
	if oldState.def.done == nil {
		t.Fatal("test assumption broken: shardedLimiter.done was not initialized")
	}

	l.Reload(rateLimitConfig(20, 20))

	select {
	case <-oldState.def.done:
		// evictLoop actually exited, not just that Stop() was called.
	case <-time.After(2 * time.Second):
		t.Fatal("old limiter's eviction goroutine did not exit after Reload")
	}
}
