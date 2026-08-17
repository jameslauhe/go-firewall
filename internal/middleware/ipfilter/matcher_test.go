package ipfilter

import (
	"net/netip"
	"testing"
)

func TestMatcher_Contains(t *testing.T) {
	m, err := NewMatcher([]string{
		"203.0.113.0/24",
		"198.51.100.7/32",
		"2001:db8::/32",
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"203.0.113.255", true},
		{"203.0.114.1", false},
		{"198.51.100.7", true},  // exact /32
		{"198.51.100.8", false}, // one past the /32
		{"2001:db8::1", true},
		{"2001:db9::1", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := m.Contains(netip.MustParseAddr(tt.ip))
			if got != tt.want {
				t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
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
