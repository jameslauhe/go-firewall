package middleware

import (
	"net/http"
	"testing"
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
