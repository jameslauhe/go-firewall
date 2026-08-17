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

// Engine holds a hot-swappable RuleSet (atomic pointer, so SIGHUP-driven
// reloads never block a request in flight) and inspects requests against
// it.
type Engine struct {
	ruleSet       atomic.Pointer[RuleSet]
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
	return e, nil
}

// Reload atomically swaps in a freshly parsed ruleset. On error the
// previously loaded ruleset keeps serving unchanged — a malformed rules
// file must not take down a live WAF.
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

func (e *Engine) effectiveAction(r Rule) string {
	if e.defaultAction == "log-only" {
		return ActionLog
	}
	return r.Action
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
	for i := range rules {
		if !rules[i].compiled.MatchString(target) {
			continue
		}
		if e.effectiveAction(rules[i]) == ActionBlock {
			return &rules[i]
		}
		slog.Info("waf rule matched (log-only)", "rule_id", rules[i].ID, "category", rules[i].Category)
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
