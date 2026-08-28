package ipfilter

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/jameslauhe/go-firewall/internal/config"
	"github.com/jameslauhe/go-firewall/internal/geoip"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
	"github.com/jameslauhe/go-firewall/internal/netmatch"
)

// listState pairs a compiled netmatch.Matcher with the raw CIDR strings it
// was built from, so the admin API can list the current contents without
// needing to decompile a Matcher back into strings.
type listState struct {
	cidrs   []string
	matcher netmatch.Matcher
}

// Filter is the first pipeline stage: CIDR allow/deny matching, optionally
// followed by a geo-IP allow-list check. The allow/deny lists are held
// behind atomic pointers so the admin dashboard can add or remove entries
// at runtime (copy-on-write: a mutation builds a new listState and
// compare-and-swaps it in, so concurrent requests never see a partially
// updated list).
type Filter struct {
	allow atomic.Pointer[listState] // nil contents = allow-list mode disabled (deny list is authoritative)
	deny  atomic.Pointer[listState]

	geo            *geoip.DB
	allowCountries map[string]struct{} // nil/empty = geo check disabled
}

func New(cfg config.IPListConfig) (*Filter, error) {
	f := &Filter{}

	allowState, err := newListState(cfg.Allow)
	if err != nil {
		return nil, err
	}
	f.allow.Store(allowState)

	denyState, err := newListState(cfg.Deny)
	if err != nil {
		return nil, err
	}
	f.deny.Store(denyState)

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

func newListState(cidrs []string) (*listState, error) {
	m, err := netmatch.NewMatcher(cidrs)
	if err != nil {
		return nil, err
	}
	cp := make([]string, len(cidrs))
	copy(cp, cidrs)
	return &listState{cidrs: cp, matcher: m}, nil
}

func (f *Filter) Close() error {
	if f.geo != nil {
		return f.geo.Close()
	}
	return nil
}

// Allowed reports whether ip may proceed, and if not, why.
func (f *Filter) Allowed(ip netip.Addr) (bool, mw.BlockReason) {
	if allow := f.allow.Load(); len(allow.cidrs) > 0 && !allow.matcher.Contains(ip) {
		return false, mw.BlockReasonIPDeny
	}
	if f.deny.Load().matcher.Contains(ip) {
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

// ListAllow and ListDeny return the current CIDR lists, for the admin API.
func (f *Filter) ListAllow() []string { return append([]string(nil), f.allow.Load().cidrs...) }
func (f *Filter) ListDeny() []string  { return append([]string(nil), f.deny.Load().cidrs...) }

// AddAllow, RemoveAllow, AddDeny, and RemoveDeny mutate the respective list
// at runtime via compare-and-swap, retrying if a concurrent mutation raced
// it. Adding an invalid CIDR or removing one not present is reported via
// the returned error/bool without touching the live list.
func (f *Filter) AddAllow(cidr string) error { return addCIDR(&f.allow, cidr) }
func (f *Filter) AddDeny(cidr string) error  { return addCIDR(&f.deny, cidr) }

func (f *Filter) RemoveAllow(cidr string) (bool, error) { return removeCIDR(&f.allow, cidr) }
func (f *Filter) RemoveDeny(cidr string) (bool, error)  { return removeCIDR(&f.deny, cidr) }

func addCIDR(p *atomic.Pointer[listState], cidr string) error {
	if _, err := netip.ParsePrefix(cidr); err != nil {
		return fmt.Errorf("ipfilter: invalid CIDR %q: %w", cidr, err)
	}
	for {
		old := p.Load()
		for _, c := range old.cidrs {
			if c == cidr {
				return nil // already present
			}
		}
		next := append(append([]string(nil), old.cidrs...), cidr)
		newState, err := newListState(next)
		if err != nil {
			return err
		}
		if p.CompareAndSwap(old, newState) {
			return nil
		}
	}
}

func removeCIDR(p *atomic.Pointer[listState], cidr string) (bool, error) {
	for {
		old := p.Load()
		next := make([]string, 0, len(old.cidrs))
		found := false
		for _, c := range old.cidrs {
			if c == cidr {
				found = true
				continue
			}
			next = append(next, c)
		}
		if !found {
			return false, nil
		}
		newState, err := newListState(next)
		if err != nil {
			return false, err
		}
		if p.CompareAndSwap(old, newState) {
			return true, nil
		}
	}
}

// Middleware returns the http middleware enforcing this Filter. It must run
// after mw.ResolveClientIP (which resolves and records the real client IP,
// honoring trusted-proxy X-Forwarded-For if configured) so every request
// is checked against the same IP the access log and rate limiter see.
func (f *Filter) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec, ok := mw.RecorderFrom(r.Context())
			if !ok {
				// No Recorder means mw.AttachRecorder/mw.ResolveClientIP
				// weren't wired ahead of this middleware — fail closed
				// rather than silently skip IP filtering.
				w.WriteHeader(http.StatusForbidden)
				return
			}

			ip := rec.ClientIP()
			if !ip.IsValid() {
				rec.SetBlocked(mw.BlockReasonIPDeny)
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if ok, reason := f.Allowed(ip); !ok {
				rec.SetBlocked(reason)
				w.WriteHeader(http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
