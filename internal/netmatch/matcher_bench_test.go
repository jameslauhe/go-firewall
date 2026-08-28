package netmatch

import (
	"fmt"
	"net/netip"
	"testing"

	"go4.org/netipx"
)

// BenchmarkMatcher_Contains compares linearMatcher against the
// netipx-backed matcher across list sizes, to validate (or correct)
// radixThreshold rather than trusting it as a guess. Both backends are
// benchmarked at every size (bypassing NewMatcher's own threshold
// selection) for an apples-to-apples comparison point.
//
// Probing the first entry would only measure linear scan's best case
// (O(1), independent of list size) — the case that actually matters for
// choosing a threshold is a miss (the request IP isn't denied), since
// that's the common case in production and forces a linear scan to walk
// every entry. Run with:
//
//	go test ./internal/middleware/ipfilter/ -bench=Matcher_Contains -benchtime=1x
func BenchmarkMatcher_Contains(b *testing.B) {
	sizes := []int{1, 2, 5, 10, 20, 50, 100, 500, 1000, 10000, 100000}
	miss := netip.MustParseAddr("241.0.0.0") // outside every filler CIDR at every size

	for _, n := range sizes {
		cidrs := fillerCIDRs(n)
		lastHit := netip.MustParsePrefix(cidrs[n-1]).Addr() // forces a full scan on a match too

		prefixes := make([]netip.Prefix, 0, n)
		for _, c := range cidrs {
			prefixes = append(prefixes, netip.MustParsePrefix(c))
		}
		linear := &linearMatcher{prefixes: prefixes}

		var setBuilder netipx.IPSetBuilder
		for _, p := range prefixes {
			setBuilder.AddPrefix(p)
		}
		set, err := setBuilder.IPSet()
		if err != nil {
			b.Fatalf("IPSet: %v", err)
		}
		netipxM := &netipxMatcher{set: set}

		b.Run(fmt.Sprintf("linear/miss/n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				linear.Contains(miss)
			}
		})
		b.Run(fmt.Sprintf("netipx/miss/n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				netipxM.Contains(miss)
			}
		})
		b.Run(fmt.Sprintf("linear/hit-last/n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				linear.Contains(lastHit)
			}
		})
		b.Run(fmt.Sprintf("netipx/hit-last/n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				netipxM.Contains(lastHit)
			}
		})
	}
}
