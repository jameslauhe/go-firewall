package netmatch

import (
	"fmt"
	"net/netip"
	"testing"
)

type matcherCase struct {
	ip   string
	want bool
}

var baseMatcherCases = []matcherCase{
	{"203.0.113.1", true},
	{"203.0.113.255", true},
	{"203.0.114.1", false},
	{"198.51.100.7", true},  // exact /32
	{"198.51.100.8", false}, // one past the /32
	{"2001:db8::1", true},
	{"2001:db9::1", false},
	{"10.0.0.1", false},
}

var baseCIDRs = []string{
	"203.0.113.0/24",
	"198.51.100.7/32",
	"2001:db8::/32",
}

// fillerCIDRs returns n disjoint /32s (from a block none of baseCIDRs or
// baseMatcherCases touch) purely to push a matcher's input size over
// radixThreshold, forcing NewMatcher to select the netipx-backed
// implementation. Spans three octets (240.a.b.c/32), supporting up to
// 256^3 entries.
func fillerCIDRs(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("240.%d.%d.%d/32", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
	}
	return out
}

func runMatcherCases(t *testing.T, m Matcher) {
	t.Helper()
	for _, tt := range baseMatcherCases {
		t.Run(tt.ip, func(t *testing.T) {
			got := m.Contains(netip.MustParseAddr(tt.ip))
			if got != tt.want {
				t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestMatcher_Contains_Linear(t *testing.T) {
	m, err := NewMatcher(baseCIDRs)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if _, ok := m.(*linearMatcher); !ok {
		t.Fatalf("expected a small CIDR list to select linearMatcher, got %T", m)
	}
	runMatcherCases(t, m)
}

func TestMatcher_Contains_NetipxBackend(t *testing.T) {
	const fillerCount = radixThreshold + 100
	filler := fillerCIDRs(fillerCount)
	cidrs := append(append([]string{}, baseCIDRs...), filler...)
	m, err := NewMatcher(cidrs)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if _, ok := m.(*netipxMatcher); !ok {
		t.Fatalf("expected a CIDR list over radixThreshold to select netipxMatcher, got %T", m)
	}
	runMatcherCases(t, m)

	// Spot-check the first and last filler entries are actually matched.
	first := netip.MustParsePrefix(filler[0]).Addr()
	if !m.Contains(first) {
		t.Errorf("expected first filler CIDR (%s) to match", first)
	}
	last := netip.MustParsePrefix(filler[fillerCount-1]).Addr()
	if !m.Contains(last) {
		t.Errorf("expected last filler CIDR (%s) to match", last)
	}
	if m.Contains(netip.MustParseAddr("241.0.0.0")) {
		t.Error("expected an address outside every listed CIDR to not match")
	}
}

func TestMatcher_EmptyList(t *testing.T) {
	m, err := NewMatcher(nil)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if m.Contains(netip.MustParseAddr("1.2.3.4")) {
		t.Error("empty matcher should never match")
	}
}

func TestNewMatcher_InvalidCIDR(t *testing.T) {
	if _, err := NewMatcher([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestNewMatcher_InvalidCIDR_LargeList(t *testing.T) {
	cidrs := append(fillerCIDRs(radixThreshold+100), "not-a-cidr")
	if _, err := NewMatcher(cidrs); err == nil {
		t.Fatal("expected error for invalid CIDR even in a large list")
	}
}
