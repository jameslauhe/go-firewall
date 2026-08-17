// Package geoip resolves client IPs to ISO 3166-1 alpha-2 country codes
// using a MaxMind GeoLite2-Country (or compatible) .mmdb database.
package geoip

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"
)

type DB struct {
	reader *maxminddb.Reader
}

// Open loads and memory-maps the .mmdb file at path. A missing or corrupt
// database is a startup error the caller should fail fast on.
func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open database %q: %w", path, err)
	}
	return &DB{reader: r}, nil
}

func (db *DB) Close() error {
	return db.reader.Close()
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Country resolves ip to its ISO 3166-1 alpha-2 country code. It returns an
// error if the address has no country entry in the database (e.g. private
// or reserved ranges) — callers should treat that as "unknown" and apply
// their own allow/deny policy rather than assume a specific country.
func (db *DB) Country(ip netip.Addr) (string, error) {
	var rec countryRecord
	if err := db.reader.Lookup(net.IP(ip.AsSlice()), &rec); err != nil {
		return "", fmt.Errorf("geoip: lookup %s: %w", ip, err)
	}
	if rec.Country.ISOCode == "" {
		return "", fmt.Errorf("geoip: no country found for %s", ip)
	}
	return rec.Country.ISOCode, nil
}
