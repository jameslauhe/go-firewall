// Package ipfilter implements the first pipeline stage: CIDR allow/deny
// matching and optional geo-IP allow-listing.
package ipfilter

import (
	"fmt"
	"net/netip"
)

// Matcher reports whether an IP address is contained in a set of CIDR
// prefixes. It's an interface so the linear-scan implementation below can
// be swapped for a radix trie later without touching the middleware, if
// list sizes ever grow well beyond what a linear scan handles cheaply.
type Matcher interface {
	Contains(ip netip.Addr) bool
}

type linearMatcher struct {
	prefixes []netip.Prefix
}

// NewMatcher parses cidrs once and returns a Matcher backed by a linear
// scan. For realistic config-driven deny-list sizes (hundreds to low
// thousands of entries), scanning parsed netip.Prefix values is
// sub-microsecond and doesn't warrant a trie.
func NewMatcher(cidrs []string) (Matcher, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ipfilter: invalid CIDR %q: %w", c, err)
		}
		prefixes = append(prefixes, p)
	}
	return &linearMatcher{prefixes: prefixes}, nil
}

func (m *linearMatcher) Contains(ip netip.Addr) bool {
	for _, p := range m.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
