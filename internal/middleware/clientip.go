package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
)

// ClientIP extracts the connecting client's address from r.RemoteAddr (the
// raw TCP peer address, not X-Forwarded-For — go-firewall is the first
// hop, so trusting a client-supplied header here would be spoofable).
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
