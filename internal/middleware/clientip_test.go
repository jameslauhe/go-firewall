package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/netmatch"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
		wantErr    bool
	}{
		{"ipv4 with port", "203.0.113.5:54321", "203.0.113.5", false},
		{"ipv6 with port", "[2001:db8::1]:443", "2001:db8::1", false},
		{"bare ipv4 no port", "203.0.113.5", "203.0.113.5", false},
		{"ipv4-mapped ipv6 unmapped", "[::ffff:203.0.113.5]:1234", "203.0.113.5", false},
		{"garbage", "not-an-ip:1234", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.remoteAddr}
			got, err := ClientIP(r)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ClientIP(%q) error = %v, wantErr %v", tt.remoteAddr, err, tt.wantErr)
			}
			if err == nil && got.String() != tt.want {
				t.Errorf("ClientIP(%q) = %q, want %q", tt.remoteAddr, got.String(), tt.want)
			}
		})
	}
}

func mustMatcher(t *testing.T, cidrs ...string) netmatch.Matcher {
	t.Helper()
	m, err := netmatch.NewMatcher(cidrs)
	if err != nil {
		t.Fatalf("netmatch.NewMatcher: %v", err)
	}
	return m
}

func TestResolveClientIP(t *testing.T) {
	trusted := mustMatcher(t, "10.0.0.0/8")

	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		trustedProxies netmatch.Matcher
		want           string
	}{
		{
			name:       "untrusted peer with XFF is ignored",
			remoteAddr: "203.0.113.5:1111",
			xff:        "1.2.3.4",
			want:       "203.0.113.5",
		},
		{
			name:           "trusted peer, single XFF entry",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "198.51.100.7",
			trustedProxies: trusted,
			want:           "198.51.100.7",
		},
		{
			name:           "trusted peer, multi-hop XFF picks first untrusted from the right",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "198.51.100.7, 10.0.0.2, 10.0.0.3",
			trustedProxies: trusted,
			want:           "198.51.100.7", // 10.0.0.2 and 10.0.0.3 are both trusted proxies; the client is the leftmost, untrusted entry
		},
		{
			name:           "trusted peer, every XFF entry trusted fails safe to raw peer",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "10.0.0.2, 10.0.0.3",
			trustedProxies: trusted,
			want:           "10.0.0.1",
		},
		{
			name:           "trusted peer, malformed entries are skipped",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "not-an-ip, 198.51.100.7, also-bad",
			trustedProxies: trusted,
			want:           "198.51.100.7",
		},
		{
			name:           "trusted peer, no XFF header falls back to raw peer",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "",
			trustedProxies: trusted,
			want:           "10.0.0.1",
		},
		{
			name:           "nil trustedProxies matcher always uses raw peer",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "198.51.100.7",
			trustedProxies: nil,
			want:           "10.0.0.1",
		},
		{
			name:           "ipv4-mapped ipv6 XFF entry is unmapped",
			remoteAddr:     "10.0.0.1:1111",
			xff:            "::ffff:198.51.100.7",
			trustedProxies: trusted,
			want:           "198.51.100.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := resolveClientIP(r, tt.trustedProxies)
			if got.String() != tt.want {
				t.Errorf("resolveClientIP() = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

func TestResolveClientIP_InvalidRemoteAddrYieldsInvalidIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "not-an-address"
	got := resolveClientIP(r, nil)
	if got.IsValid() {
		t.Errorf("expected an invalid Addr for an unparsable RemoteAddr, got %v", got)
	}
}

func TestResolveClientIPMiddleware_SetsRecorderClientIP(t *testing.T) {
	trusted := mustMatcher(t, "10.0.0.0/8")

	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := RecorderFrom(r.Context()); ok {
			seen = rec.ClientIP().String()
		}
	})
	handler := Chain(next, AttachRecorder, ResolveClientIP(trusted))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1111"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	handler.ServeHTTP(httptest.NewRecorder(), r)

	if seen != "198.51.100.7" {
		t.Errorf("Recorder.ClientIP() = %q, want 198.51.100.7", seen)
	}
}
