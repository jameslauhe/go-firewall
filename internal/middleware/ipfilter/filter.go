package ipfilter

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jameslauhe/go-firewall/internal/config"
	"github.com/jameslauhe/go-firewall/internal/geoip"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

// Filter is the first pipeline stage: CIDR allow/deny matching, optionally
// followed by a geo-IP allow-list check.
type Filter struct {
	allow Matcher // nil = allow-list mode disabled (deny list is authoritative)
	deny  Matcher

	geo            *geoip.DB
	allowCountries map[string]struct{} // nil/empty = geo check disabled
}

func New(cfg config.IPListConfig) (*Filter, error) {
	f := &Filter{}

	if len(cfg.Allow) > 0 {
		m, err := NewMatcher(cfg.Allow)
		if err != nil {
			return nil, err
		}
		f.allow = m
	}

	deny, err := NewMatcher(cfg.Deny)
	if err != nil {
		return nil, err
	}
	f.deny = deny

	if cfg.Geo.Enabled && len(cfg.Geo.AllowCountries) > 0 {
		db, err := geoip.Open(cfg.Geo.DBPath)
		if err != nil {
			return nil, fmt.Errorf("ipfilter: %w", err)
		}
		f.geo = db
		f.allowCountries = make(map[string]struct{}, len(cfg.Geo.AllowCountries))
		for _, c := range cfg.Geo.AllowCountries {
			f.allowCountries[strings.ToUpper(c)] = struct{}{}
		}
	}

	return f, nil
}

func (f *Filter) Close() error {
	if f.geo != nil {
		return f.geo.Close()
	}
	return nil
}

// Allowed reports whether ip may proceed, and if not, why.
func (f *Filter) Allowed(ip netip.Addr) (bool, mw.BlockReason) {
	if f.allow != nil && !f.allow.Contains(ip) {
		return false, mw.BlockReasonIPDeny
	}
	if f.deny.Contains(ip) {
		return false, mw.BlockReasonIPDeny
	}
	if f.geo != nil {
		country, err := f.geo.Country(ip)
		if err != nil {
			// Unresolvable IP (e.g. private/reserved range) is denied in
			// allow-list mode: fail closed rather than assume a country.
			return false, mw.BlockReasonGeoDeny
		}
		if _, ok := f.allowCountries[country]; !ok {
			return false, mw.BlockReasonGeoDeny
		}
	}
	return true, ""
}

// Middleware returns the http middleware enforcing this Filter. It must be
// the outermost filtering stage (cheapest checks first).
func (f *Filter) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, err := mw.ClientIP(r)
			if err != nil {
				if rec, ok := mw.RecorderFrom(r.Context()); ok {
					rec.SetBlocked(mw.BlockReasonIPDeny)
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if ok, reason := f.Allowed(ip); !ok {
				if rec, ok2 := mw.RecorderFrom(r.Context()); ok2 {
					rec.SetBlocked(reason)
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
