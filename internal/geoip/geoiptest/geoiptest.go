// Package geoiptest builds tiny MaxMind .mmdb fixtures for tests. It is
// only ever imported from _test.go files.
package geoiptest

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// BuildMMDB writes a minimal GeoLite2-Country-compatible .mmdb file mapping
// each CIDR key in entries to its ISO 3166-1 alpha-2 country code value,
// returning the path to the generated file.
func BuildMMDB(t *testing.T, entries map[string]string) string {
	t.Helper()

	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country-Test",
		RecordSize:   24,
		IPVersion:    6, // dual-stack tree: accepts both IPv4 and IPv6 lookups
		// Test fixtures deliberately use RFC 5737/3849 documentation
		// ranges (e.g. 203.0.113.0/24), which mmdbwriter treats as
		// reserved by default.
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}

	for cidr, country := range entries {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", cidr, err)
		}
		value := mmdbtype.Map{
			"country": mmdbtype.Map{
				"iso_code": mmdbtype.String(country),
			},
		}
		if err := tree.Insert(network, value); err != nil {
			t.Fatalf("Insert(%q): %v", cidr, err)
		}
	}

	path := filepath.Join(t.TempDir(), "test.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create mmdb file: %v", err)
	}
	defer f.Close()

	if _, err := tree.WriteTo(f); err != nil {
		t.Fatalf("write mmdb: %v", err)
	}
	return path
}
