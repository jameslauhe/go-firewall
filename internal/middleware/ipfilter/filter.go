package ipfilter

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jameslauhe/go-firewall/internal/config"
	"github.com/jameslauhe/go-firewall/internal/geoip"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
	"github.com/jameslauhe/go-firewall/internal/netmatch"
)

// listState splits a CIDR list into a config-file base layer and an
// admin-dashboard overlay (adminAdded/adminRemoved), so Reload can replace
// just the base without disturbing live admin edits — the same "two
// independent layers" structure waf.Engine already uses for ruleSet vs.
// overrides. A CIDR is kept in at most one of adminAdded/adminRemoved at a
// time (enforced by addCIDR/removeCIDR), which makes the two sets
// commutative to apply — no ordering dependency, unlike a delta log.
type listState struct {
	base         []string
	adminAdded   []string
	adminRemoved []string
	effective    []string // (base ∪ adminAdded) \ adminRemoved — cached for ListXxx() and matcher construction
	matcher      netmatch.Matcher
}

func newListState(base, adminAdded, adminRemoved []string) (*listState, error) {
	effective := effectiveCIDRs(base, adminAdded, adminRemoved)
	m, err := netmatch.NewMatcher(effective)
	if err != nil {
		return nil, err
	}
	return &listState{
		base:         append([]string(nil), base...),
		adminAdded:   append([]string(nil), adminAdded...),
		adminRemoved: append([]string(nil), adminRemoved...),
		effective:    effective,
		matcher:      m,
	}, nil
}

func effectiveCIDRs(base, adminAdded, adminRemoved []string) []string {
	removed := make(map[string]bool, len(adminRemoved))
	for _, c := range adminRemoved {
		removed[c] = true
	}
	seen := make(map[string]bool, len(base)+len(adminAdded))
	out := make([]string, 0, len(base)+len(adminAdded))
	for _, c := range base {
		if removed[c] || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, c := range adminAdded {
		if removed[c] || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func removeStr(s []string, v string) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// geoState is the geo-IP allow-list configuration.
type geoState struct {
	db             *geoip.DB // nil = geo check disabled
	allowCountries map[string]struct{}
}

func buildGeoState(cfg config.GeoConfig) (*geoState, error) {
	if !cfg.Enabled || len(cfg.AllowCountries) == 0 {
		return &geoState{}, nil
	}
	db, err := geoip.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("ipfilter: %w", err)
	}
	allowCountries := make(map[string]struct{}, len(cfg.AllowCountries))
	for _, c := range cfg.AllowCountries {
		allowCountries[strings.ToUpper(c)] = struct{}{}
	}
	return &geoState{db: db, allowCountries: allowCountries}, nil
}

// Filter is the first pipeline stage: CIDR allow/deny matching, optionally
// followed by a geo-IP allow-list check. Allow/deny lists are held behind
// atomic pointers, lock-free on the request hot path (see listState's doc
// comment). Geo state instead sits behind a plain RWMutex — see Reload's
// doc comment for why an atomic pointer swap is not actually safe for a
// resource (a memory-mapped file) that must be closed, and why a mutex
// held across the full lookup is the correct fix rather than a
// probabilistic delay.
type Filter struct {
	allow atomic.Pointer[listState] // empty effective list = allow-list mode disabled (deny list is authoritative)
	deny  atomic.Pointer[listState]

	geoMu sync.RWMutex
	geo   *geoState
}

func New(cfg config.IPListConfig) (*Filter, error) {
	f := &Filter{}

	allowState, err := newListState(cfg.Allow, nil, nil)
	if err != nil {
		return nil, err
	}
	f.allow.Store(allowState)

	denyState, err := newListState(cfg.Deny, nil, nil)
	if err != nil {
		return nil, err
	}
	f.deny.Store(denyState)

	gs, err := buildGeoState(cfg.Geo)
	if err != nil {
		return nil, err
	}
	f.geo = gs

	return f, nil
}

// Reload atomically swaps in new allow/deny base lists and geo settings
// built from cfg. Any admin-dashboard overlay already applied via
// AddAllow/AddDeny/RemoveAllow/RemoveDeny is preserved — only the base
// layer changes, matching the precedent waf.Engine.Reload already
// established for per-rule overrides: config reload is "pick up my YAML
// edit," not "also revert my dashboard edits."
//
// Geo is built and validated first (the one part of this that can
// realistically fail post-config.Validate — a race where the mmdb file
// becomes unreadable between validation and reload), then allow, then
// deny; each step fails without touching anything not yet swapped. This
// isn't a full staged multi-object transaction — a failure after allow
// has already swapped but before deny does would leave allow reloaded and
// deny not — but that residual window requires a config file that passed
// validation moments earlier to then fail purely on CIDR-set
// construction, which cannot happen (parsing already succeeded during
// Validate).
//
// The old geoip.DB, if replaced, is closed only after f.geoMu's write
// lock is acquired and the swap under it completes. This matters more
// than it looks: an atomic-pointer swap (used for allow/deny above) only
// guarantees *new* reads see the new value — it does nothing to wait for
// a goroutine that already read the old pointer and is still mid-lookup
// against its memory-mapped file, so closing right after an atomic swap
// can race an in-flight Country() call (confirmed by go test -race, not
// theoretical). A write-locked swap is different: Lock() cannot succeed
// while any RLock is held, and Allowed() holds its RLock for the entire
// Country() call (not just the pointer read), so by the time Reload's
// Lock() returns, every goroutine that was using the old *geoState has
// already finished and released its RLock. Closing after Unlock is then
// genuinely race-free, not just unlikely to race.
func (f *Filter) Reload(cfg config.IPListConfig) error {
	newGeo, err := buildGeoState(cfg.Geo)
	if err != nil {
		return fmt.Errorf("ipfilter: reload geo: %w", err)
	}

	if err := reloadListState(&f.allow, cfg.Allow); err != nil {
		return fmt.Errorf("ipfilter: reload allow list: %w", err)
	}
	if err := reloadListState(&f.deny, cfg.Deny); err != nil {
		return fmt.Errorf("ipfilter: reload deny list: %w", err)
	}

	f.geoMu.Lock()
	oldGeo := f.geo
	f.geo = newGeo
	f.geoMu.Unlock()

	if oldGeo != nil && oldGeo.db != nil {
		oldGeo.db.Close()
	}
	return nil
}

// reloadListState replaces base while preserving whatever admin overlay is
// live at the moment of the swap — retrying (like addCIDR/removeCIDR) if a
// concurrent admin mutation races it, so a SIGHUP reload can never
// silently clobber an admin edit made at the same moment.
func reloadListState(p *atomic.Pointer[listState], base []string) error {
	for {
		old := p.Load()
		next, err := newListState(base, old.adminAdded, old.adminRemoved)
		if err != nil {
			return err
		}
		if p.CompareAndSwap(old, next) {
			return nil
		}
	}
}

func (f *Filter) Close() error {
	f.geoMu.RLock()
	defer f.geoMu.RUnlock()
	if f.geo != nil && f.geo.db != nil {
		return f.geo.db.Close()
	}
	return nil
}

// Allowed reports whether ip may proceed, and if not, why.
func (f *Filter) Allowed(ip netip.Addr) (bool, mw.BlockReason) {
	if allow := f.allow.Load(); len(allow.effective) > 0 && !allow.matcher.Contains(ip) {
		return false, mw.BlockReasonIPDeny
	}
	if f.deny.Load().matcher.Contains(ip) {
		return false, mw.BlockReasonIPDeny
	}

	// Held for the whole lookup, not just the pointer read — see Reload's
	// doc comment for why that distinction is what makes the close-after-
	// reload path actually race-free.
	f.geoMu.RLock()
	defer f.geoMu.RUnlock()
	if f.geo.db != nil {
		country, err := f.geo.db.Country(ip)
		if err != nil {
			// Unresolvable IP (e.g. private/reserved range) is denied in
			// allow-list mode: fail closed rather than assume a country.
			return false, mw.BlockReasonGeoDeny
		}
		if _, ok := f.geo.allowCountries[country]; !ok {
			return false, mw.BlockReasonGeoDeny
		}
	}
	return true, ""
}

// ListAllow and ListDeny return the current effective CIDR lists (base
// plus admin overlay applied), for the admin API.
func (f *Filter) ListAllow() []string { return append([]string(nil), f.allow.Load().effective...) }
func (f *Filter) ListDeny() []string  { return append([]string(nil), f.deny.Load().effective...) }

// AllowOverlay and DenyOverlay return the current admin-added/removed CIDR
// sets (independent of the config-file base layer), for persisting
// admin-dashboard edits to disk. See listState's doc comment for why these
// are two current sets rather than an ordered log.
func (f *Filter) AllowOverlay() (added, removed []string) { return overlayOf(&f.allow) }
func (f *Filter) DenyOverlay() (added, removed []string)  { return overlayOf(&f.deny) }

func overlayOf(p *atomic.Pointer[listState]) (added, removed []string) {
	s := p.Load()
	return append([]string(nil), s.adminAdded...), append([]string(nil), s.adminRemoved...)
}

// AddAllow, RemoveAllow, AddDeny, and RemoveDeny mutate the respective
// list's admin overlay at runtime via compare-and-swap, retrying if a
// concurrent mutation raced it. Adding an invalid CIDR or removing one not
// effectively present is reported via the returned error/bool without
// touching the live list.
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
		if containsStr(old.effective, cidr) {
			return nil // already effectively present
		}
		newAdminRemoved := removeStr(old.adminRemoved, cidr) // undo a prior removal of this CIDR, if any
		newAdminAdded := old.adminAdded
		if !containsStr(old.base, cidr) {
			// Only needs explicit tracking if base doesn't already cover it.
			newAdminAdded = append(append([]string(nil), old.adminAdded...), cidr)
		}
		next, err := newListState(old.base, newAdminAdded, newAdminRemoved)
		if err != nil {
			return err
		}
		if p.CompareAndSwap(old, next) {
			return nil
		}
	}
}

func removeCIDR(p *atomic.Pointer[listState], cidr string) (bool, error) {
	for {
		old := p.Load()
		if !containsStr(old.effective, cidr) {
			return false, nil
		}
		newAdminAdded := removeStr(old.adminAdded, cidr) // undo a prior admin-add of this CIDR, if any
		newAdminRemoved := old.adminRemoved
		if containsStr(old.base, cidr) {
			// Still present in base, so removal must be tracked explicitly.
			newAdminRemoved = append(append([]string(nil), old.adminRemoved...), cidr)
		}
		next, err := newListState(old.base, newAdminAdded, newAdminRemoved)
		if err != nil {
			return false, err
		}
		if p.CompareAndSwap(old, next) {
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
