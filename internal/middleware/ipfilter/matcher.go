// Package ipfilter implements the first pipeline stage: CIDR allow/deny
// matching and optional geo-IP allow-listing.
package ipfilter

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
)

// radixThreshold is the CIDR-list size above which NewMatcher switches from
// a linear scan to a netipx.IPSet (binary search over sorted, non-
// overlapping ranges).
//
// Benchmarked (matcher_bench_test.go, BenchmarkMatcher_Contains) rather
// than guessed: netipx.IPSet.Contains costs a flat ~21ns/op regardless of
// list size, while linearMatcher.Contains costs roughly 5-6ns per entry
// scanned (6ns at n=1, 58ns at n=10, 462ns at n=100, 540µs at n=100000) —
// the two cross over around 3-4 entries. 16 keeps a small margin so
// trivially small lists (a handful of entries, where the two are within
// noise of each other) stay on the simpler linear path, while anything
// past that gets netipx's effectively size-independent lookup cost. This
// is deliberately not tuned to "hundreds to thousands," which is what an
// earlier, unbenchmarked design note assumed.
const radixThreshold = 16

// Matcher reports whether an IP address is contained in a set of CIDR
// prefixes. It's an interface so NewMatcher can choose its backing
// implementation by list size without callers caring.
type Matcher interface {
	Contains(ip netip.Addr) bool
}

type linearMatcher struct {
	prefixes []netip.Prefix
}

func (m *linearMatcher) Contains(ip netip.Addr) bool {
	for _, p := range m.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// netipxMatcher backs large lists: netipx.IPSet is an immutable, sorted set
// of non-overlapping ranges with O(log n) Contains via binary search,
// versus the linear matcher's O(n) scan.
type netipxMatcher struct {
	set *netipx.IPSet
}

func (m *netipxMatcher) Contains(ip netip.Addr) bool {
	return m.set.Contains(ip)
}

// NewMatcher parses cidrs once and returns a Matcher backed by whichever
// implementation is faster to look up at the given list size: a linear
// scan for trivially small lists, or a netipx.IPSet above radixThreshold
// entries — see radixThreshold's doc comment for the benchmark backing
// that choice.
func NewMatcher(cidrs []string) (Matcher, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ipfilter: invalid CIDR %q: %w", c, err)
		}
		prefixes = append(prefixes, p)
	}

	if len(prefixes) <= radixThreshold {
		return &linearMatcher{prefixes: prefixes}, nil
	}

	var b netipx.IPSetBuilder
	for _, p := range prefixes {
		b.AddPrefix(p)
	}
	set, err := b.IPSet()
	if err != nil {
		return nil, fmt.Errorf("ipfilter: build IP set: %w", err)
	}
	return &netipxMatcher{set: set}, nil
}
