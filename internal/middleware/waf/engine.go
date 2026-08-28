package waf

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

// override is a per-rule admin-dashboard adjustment layered on top of the
// loaded ruleset without touching the rules file: disable a rule, or force
// its action, for live tuning.
type override struct {
	enabled bool
	action  string // "" = keep the rule's own action
}

// Engine holds a hot-swappable RuleSet (atomic pointer, so SIGHUP-driven
// reloads never block a request in flight) and inspects requests against
// it.
type Engine struct {
	ruleSet       atomic.Pointer[RuleSet]
	overrides     atomic.Pointer[map[int]override] // admin-dashboard per-rule overrides, keyed by rule id
	maxBodyBytes  int64
	defaultAction string // "log-only" forces every rule to behave as log-only, for dry-run tuning
}

func NewEngine(cfg config.WAFConfig) (*Engine, error) {
	rs, err := LoadRuleSet(cfg.RulesFile)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		maxBodyBytes:  cfg.BodyInspection.MaxBytes,
		defaultAction: cfg.DefaultAction,
	}
	e.ruleSet.Store(rs)
	empty := map[int]override{}
	e.overrides.Store(&empty)
	return e, nil
}

// Reload atomically swaps in a freshly parsed ruleset. On error the
// previously loaded ruleset keeps serving unchanged — a malformed rules
// file must not take down a live WAF. Existing per-rule overrides are left
// as-is; overrides referencing rule ids no longer present are simply
// inert.
func (e *Engine) Reload(path string) error {
	rs, err := LoadRuleSet(path)
	if err != nil {
		return err
	}
	e.ruleSet.Store(rs)
	return nil
}

func (e *Engine) RuleCount() int {
	return e.ruleSet.Load().RuleCount()
}

// RuleInfo is a rule's effective (override-applied) state, for the admin
// dashboard.
type RuleInfo struct {
	ID          int      `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Targets     []string `json:"targets"`
	Action      string   `json:"action"`
	Enabled     bool     `json:"enabled"`
	Overridden  bool     `json:"overridden"`
}

// ListRules returns every loaded rule's effective state for the admin
// dashboard.
func (e *Engine) ListRules() []RuleInfo {
	rs := e.ruleSet.Load()
	overrides := e.overrides.Load()
	out := make([]RuleInfo, 0, len(rs.all))
	for _, r := range rs.all {
		info := RuleInfo{
			ID: r.ID, Category: r.Category, Severity: r.Severity,
			Description: r.Description, Targets: r.Targets,
			Action: r.Action, Enabled: true,
		}
		if o, ok := (*overrides)[r.ID]; ok {
			info.Enabled = o.enabled
			if o.action != "" {
				info.Action = o.action
			}
			info.Overridden = true
		}
		out = append(out, info)
	}
	return out
}

// SetOverride disables/enables a rule and/or forces its action, without
// touching the rules file. action == "" leaves the rule's own action in
// place. Returns an error if id doesn't match any loaded rule.
func (e *Engine) SetOverride(id int, enabled bool, action string) error {
	if action != "" && action != ActionBlock && action != ActionLog {
		return fmt.Errorf("waf: invalid action %q", action)
	}
	rs := e.ruleSet.Load()
	found := false
	for _, r := range rs.all {
		if r.ID == id {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("waf: unknown rule id %d", id)
	}

	for {
		old := e.overrides.Load()
		next := make(map[int]override, len(*old)+1)
		for k, v := range *old {
			next[k] = v
		}
		next[id] = override{enabled: enabled, action: action}
		if e.overrides.CompareAndSwap(old, &next) {
			return nil
		}
	}
}

// Override is a rule's raw admin-dashboard adjustment, for persistence.
// Unlike RuleInfo.Action (from ListRules), Action here may be "" — meaning
// "no action override, follow whatever the rules file says" — rather than
// the effective, already-resolved action. Persisting the raw form matters:
// if a caller instead saved ListRules' effective Action and replayed it
// later via SetOverride, an override that only touched Enabled would come
// back as an explicit Action override baking in whatever the rule's file-
// defined action happened to be at persist time, silently changing
// behavior if the rules file's own action for that rule changes later.
type Override struct {
	Enabled bool
	Action  string
}

// Overrides returns the current admin-dashboard overrides, keyed by rule
// id, in their raw (not effective-resolved) form — see Override's doc
// comment for why that distinction matters for persistence.
func (e *Engine) Overrides() map[int]Override {
	m := e.overrides.Load()
	out := make(map[int]Override, len(*m))
	for id, o := range *m {
		out[id] = Override{Enabled: o.enabled, Action: o.action}
	}
	return out
}

// ClearOverride removes a rule's admin-dashboard override, reverting it to
// the rules file's own action/enabled state.
func (e *Engine) ClearOverride(id int) {
	for {
		old := e.overrides.Load()
		if _, ok := (*old)[id]; !ok {
			return
		}
		next := make(map[int]override, len(*old))
		for k, v := range *old {
			if k != id {
				next[k] = v
			}
		}
		if e.overrides.CompareAndSwap(old, &next) {
			return
		}
	}
}

// Inspect checks r against the current ruleset and reports the first
// blocking match, if any. It stops at the first block-action match;
// log-action matches are logged for tuning visibility but never block.
func (e *Engine) Inspect(r *http.Request) (blocked bool, match *Rule, err error) {
	rs := e.ruleSet.Load()

	decodedPath, decErr := url.PathUnescape(r.URL.Path)
	if decErr != nil {
		decodedPath = r.URL.Path
	}
	decodedQuery, decErr := url.QueryUnescape(r.URL.RawQuery)
	if decErr != nil {
		decodedQuery = r.URL.RawQuery
	}

	line := r.Method + " " + decodedPath
	if decodedQuery != "" {
		line += "?" + decodedQuery
	}

	if m := e.check(rs.lineRules, line); m != nil {
		return true, m, nil
	}
	if m := e.check(rs.pathRules, decodedPath); m != nil {
		return true, m, nil
	}
	if decodedQuery != "" {
		if m := e.check(rs.queryRules, decodedQuery); m != nil {
			return true, m, nil
		}
	}

	for name, rules := range rs.headerRules {
		if name == "" {
			for _, values := range r.Header {
				for _, v := range values {
					if m := e.check(rules, v); m != nil {
						return true, m, nil
					}
				}
			}
			continue
		}
		for _, v := range r.Header.Values(name) {
			if m := e.check(rules, v); m != nil {
				return true, m, nil
			}
		}
	}

	if len(rs.bodyRules) > 0 && r.Body != nil && r.Body != http.NoBody {
		prefix, readErr := e.captureBodyPrefix(r)
		if readErr != nil {
			return false, nil, readErr
		}
		if m := e.check(rs.bodyRules, string(prefix)); m != nil {
			return true, m, nil
		}
	}

	return false, nil, nil
}

// check tests target against rules, returning the first block-action
// match. log-action matches are recorded but evaluation continues.
func (e *Engine) check(rules []Rule, target string) *Rule {
	overrides := e.overrides.Load()
	for i := range rules {
		r := &rules[i]

		action := r.Action
		if o, ok := (*overrides)[r.ID]; ok {
			if !o.enabled {
				continue
			}
			if o.action != "" {
				action = o.action
			}
		}
		if e.defaultAction == "log-only" {
			action = ActionLog
		}

		if !r.compiled.MatchString(target) {
			continue
		}
		if action == ActionBlock {
			return r
		}
		slog.Info("waf rule matched (log-only)", "rule_id", r.ID, "category", r.Category)
	}
	return nil
}

// captureBodyPrefix reads up to maxBodyBytes of the request body for
// inspection, then reconstructs r.Body so the full original body —
// including anything beyond the inspected prefix — is still forwarded to
// upstream unmodified.
func (e *Engine) captureBodyPrefix(r *http.Request) ([]byte, error) {
	prefix, err := io.ReadAll(io.LimitReader(r.Body, e.maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("waf: read request body: %w", err)
	}
	r.Body = &multiReadCloser{
		Reader: io.MultiReader(bytes.NewReader(prefix), r.Body),
		Closer: r.Body,
	}
	return prefix, nil
}

type multiReadCloser struct {
	io.Reader
	io.Closer
}

// Middleware returns the WAF pipeline stage. On an inspection error (e.g. a
// body read failure from a client that disconnected mid-upload) it fails
// open and lets the request proceed, since that's a transport hiccup, not
// evidence of an attack, and the proxy will independently fail on the same
// broken body if forwarding is attempted.
func (e *Engine) Middleware() mw.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			blocked, rule, err := e.Inspect(r)
			if err != nil {
				slog.Warn("waf inspection error, allowing request through", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if blocked {
				if rec, ok := mw.RecorderFrom(r.Context()); ok {
					rec.SetBlocked(mw.BlockReasonWAF)
					rec.SetWAFMatch(rule.ID, rule.Category)
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
