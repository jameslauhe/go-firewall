package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jameslauhe/go-firewall/internal/netmatch"
)

// ClientIP extracts the connecting client's address from r.RemoteAddr (the
// raw TCP peer address). This is the fallback/default used by
// ResolveClientIP, and — when no trusted_proxies are configured — the only
// source of client IP, since trusting a client-supplied header without a
// configured trust boundary would be spoofable.
func ClientIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // no port present, e.g. some test transports
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("clientip: parse remote addr %q: %w", r.RemoteAddr, err)
	}
	return addr.Unmap(), nil
}

// ResolveClientIP determines each request's real client IP exactly once —
// trusting X-Forwarded-For only when the raw TCP peer is itself a trusted
// proxy — and stores the result on the Recorder so every downstream stage
// (ipfilter, ratelimit, the access log) reads the same value instead of
// each independently re-parsing RemoteAddr. It must run after
// AttachRecorder. trustedProxies may be nil/empty (a Matcher that never
// matches, from netmatch.NewMatcher(nil)) — in that case every request
// resolves to its raw peer, identical to today's behavior.
func ResolveClientIP(trustedProxies netmatch.Matcher) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trustedProxies)
			if rec, ok := RecorderFrom(r.Context()); ok {
				rec.SetClientIP(ip)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolveClientIP implements the actual algorithm, split out so it's
// directly unit-testable without building an http.Handler chain.
func resolveClientIP(r *http.Request, trustedProxies netmatch.Matcher) netip.Addr {
	peer, err := ClientIP(r)
	if err != nil {
		return netip.Addr{} // invalid; callers must check .IsValid()
	}
	if trustedProxies == nil || !trustedProxies.Contains(peer) {
		return peer
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}

	// Walk right-to-left: the rightmost entries are the ones closer to us
	// in the proxy chain and thus the ones we can verify; the leftmost
	// entry is whatever the original client claimed and is never safe to
	// trust blindly. Return the first entry, from the right, that isn't
	// itself a trusted proxy.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue // malformed entry — skip, don't abort the walk
		}
		candidate = candidate.Unmap()
		if !trustedProxies.Contains(candidate) {
			return candidate
		}
	}
	// Every hop (including the leftmost) was itself a trusted proxy, or
	// every entry was malformed — fail safe to the raw peer.
	return peer
}
