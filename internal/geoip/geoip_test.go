package geoip

import (
	"net/netip"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/geoip/geoiptest"
)

func TestDB_Country(t *testing.T) {
	path := geoiptest.BuildMMDB(t, map[string]string{
		"1.2.3.0/24": "SG",
		"5.6.7.0/24": "US",
	})

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	tests := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		{"1.2.3.4", "SG", false},
		{"5.6.7.8", "US", false},
		{"9.9.9.9", "", true}, // not in the test database
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got, err := db.Country(netip.MustParseAddr(tt.ip))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Country(%s) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Country(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestOpen_MissingFile(t *testing.T) {
	if _, err := Open("/nonexistent/path.mmdb"); err == nil {
		t.Fatal("expected error opening missing database file")
	}
}
