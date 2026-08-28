// Package admin implements the operator dashboard: a private HTTP surface
// (its own listener, off the public port) for viewing recent traffic and
// making live, in-memory adjustments to IP lists and WAF rules without a
// restart.
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
	accesslog "github.com/jameslauhe/go-firewall/internal/log"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/middleware/waf"
)

//go:embed static/index.html
var embeddedStatic embed.FS

// staticFS is embeddedStatic rooted at its static/ subdirectory, so
// http.FileServerFS serves "/admin/" as index.html rather than needing a
// "static/" prefix in every request.
var staticFS = func() fs.FS {
	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		panic("admin: embedded static assets missing static/ directory: " + err.Error())
	}
	return sub
}()

// Info is startup-time metadata the status endpoint reports; kept separate
// from config.Config so this package doesn't need to import the whole
// application config.
type Info struct {
	Version   string
	Listeners []string
	Upstreams []string
}

type Server struct {
	token     string
	startedAt time.Time
	info      Info

	accessLog  *accesslog.AccessLog
	ipFilter   *ipfilter.Filter
	wafEngine  *waf.Engine // nil if WAF is disabled
	stateStore *StateStore // nil if cfg.StateFile is unset (edits stay in-memory only)
}

// New reads the bearer token from the environment variable named by
// cfg.AuthTokenEnv. An empty/unset value is a startup error: an admin
// surface with no effective auth would be a silent security regression.
//
// If cfg.StateFile is set, New also loads and replays any previously
// persisted admin-dashboard edits onto ipFilter/wafEngine before
// returning, so a restart picks up where the dashboard left off. A
// corrupt or unreadable state file fails startup (the same fail-fast
// treatment as a bad config/rules file); an individual stale entry within
// an otherwise-valid state file (e.g. referencing a WAF rule id that no
// longer exists) is logged and skipped rather than failing startup — see
// replayState.
func New(cfg config.AdminConfig, info Info, accessLog *accesslog.AccessLog, ipFilter *ipfilter.Filter, wafEngine *waf.Engine) (*Server, error) {
	token := os.Getenv(cfg.AuthTokenEnv)
	if token == "" {
		return nil, fmt.Errorf("admin: environment variable %s is empty or unset", cfg.AuthTokenEnv)
	}

	s := &Server{
		token:     token,
		startedAt: time.Now(),
		info:      info,
		accessLog: accessLog,
		ipFilter:  ipFilter,
		wafEngine: wafEngine,
	}

	if cfg.StateFile != "" {
		store := NewStateStore(cfg.StateFile)
		state, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("admin: load state file: %w", err)
		}
		replayState(state, ipFilter, wafEngine)
		s.stateStore = store
	}

	return s, nil
}

// replayState applies a previously persisted State onto ipFilter/wafEngine.
// Individual entries that no longer apply cleanly (e.g. a WAF rule id from
// an old rules file) are logged and skipped rather than treated as fatal —
// state drift between what was persisted and what's now loaded from
// config/rules files is expected over time, not a startup error.
func replayState(state State, ipFilter *ipfilter.Filter, wafEngine *waf.Engine) {
	for _, cidr := range state.IPLists.AllowRemoved {
		if _, err := ipFilter.RemoveAllow(cidr); err != nil {
			slog.Warn("admin: state replay: allow removal failed", "cidr", cidr, "error", err)
		}
	}
	for _, cidr := range state.IPLists.AllowAdded {
		if err := ipFilter.AddAllow(cidr); err != nil {
			slog.Warn("admin: state replay: allow addition failed", "cidr", cidr, "error", err)
		}
	}
	for _, cidr := range state.IPLists.DenyRemoved {
		if _, err := ipFilter.RemoveDeny(cidr); err != nil {
			slog.Warn("admin: state replay: deny removal failed", "cidr", cidr, "error", err)
		}
	}
	for _, cidr := range state.IPLists.DenyAdded {
		if err := ipFilter.AddDeny(cidr); err != nil {
			slog.Warn("admin: state replay: deny addition failed", "cidr", cidr, "error", err)
		}
	}

	if wafEngine == nil {
		return
	}
	for id, o := range state.WAFOverrides {
		if err := wafEngine.SetOverride(id, o.Enabled, o.Action); err != nil {
			slog.Warn("admin: state replay: waf override failed", "rule_id", id, "error", err)
		}
	}
}

// currentState snapshots the live admin overlay for persistence.
func (s *Server) currentState() State {
	allowAdded, allowRemoved := s.ipFilter.AllowOverlay()
	denyAdded, denyRemoved := s.ipFilter.DenyOverlay()

	state := State{
		IPLists: IPListState{
			AllowAdded:   orEmpty(allowAdded),
			AllowRemoved: orEmpty(allowRemoved),
			DenyAdded:    orEmpty(denyAdded),
			DenyRemoved:  orEmpty(denyRemoved),
		},
		WAFOverrides: map[int]WAFOverride{},
	}
	if s.wafEngine != nil {
		for id, o := range s.wafEngine.Overrides() {
			state.WAFOverrides[id] = WAFOverride{Enabled: o.Enabled, Action: o.Action}
		}
	}
	return state
}

// persist saves the current admin overlay if a state file is configured.
// A save failure does not fail the caller's request — the in-memory
// mutation already took effect — but is logged loudly and surfaced via a
// response header, since a silently-unpersisted edit would be lost on the
// next restart with no other indication.
func (s *Server) persist(w http.ResponseWriter) {
	if s.stateStore == nil {
		return
	}
	if err := s.stateStore.Save(s.currentState()); err != nil {
		slog.Error("admin: failed to persist state", "error", err)
		w.Header().Set("X-Persistence-Warning", "change applied but not persisted to disk: "+err.Error())
	}
}

// Handler returns the full admin mux: an unauthenticated static UI shell
// (no data of its own — it prompts for a token client-side and attaches it
// to every API call) plus the bearer-token-gated JSON API.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /admin/api/status", s.handleStatus)
	api.HandleFunc("GET /admin/api/logs", s.handleLogs)
	api.HandleFunc("GET /admin/api/ip-lists", s.handleListIPLists)
	api.HandleFunc("POST /admin/api/ip-lists/{list}", s.handleAddIP)
	api.HandleFunc("DELETE /admin/api/ip-lists/{list}", s.handleRemoveIP)
	api.HandleFunc("GET /admin/api/waf-rules", s.handleListRules)
	api.HandleFunc("PATCH /admin/api/waf-rules/{id}", s.handlePatchRule)

	mux := http.NewServeMux()
	mux.Handle("/admin/api/", s.requireAuth(api))
	mux.Handle("/admin/", http.StripPrefix("/admin/", http.FileServerFS(staticFS)))
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
	return mux
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(s.token)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusResponse struct {
	Version       string   `json:"version"`
	UptimeSeconds float64  `json:"uptime_seconds"`
	Listeners     []string `json:"listeners"`
	Upstreams     []string `json:"upstreams"`
	WAFEnabled    bool     `json:"waf_enabled"`
	WAFRuleCount  int      `json:"waf_rule_count"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Version:       s.info.Version,
		UptimeSeconds: time.Since(s.startedAt).Seconds(),
		Listeners:     s.info.Listeners,
		Upstreams:     s.info.Upstreams,
		WAFEnabled:    s.wafEngine != nil,
	}
	if s.wafEngine != nil {
		resp.WAFRuleCount = s.wafEngine.RuleCount()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	entries := s.accessLog.Recent(limit, r.URL.Query().Get("outcome"), r.URL.Query().Get("reason"))
	writeJSON(w, http.StatusOK, entries)
}

type ipListsResponse struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

func (s *Server) handleListIPLists(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ipListsResponse{
		Allow: orEmpty(s.ipFilter.ListAllow()),
		Deny:  orEmpty(s.ipFilter.ListDeny()),
	})
}

type cidrRequest struct {
	CIDR string `json:"cidr"`
}

func (s *Server) handleAddIP(w http.ResponseWriter, r *http.Request) {
	var req cidrRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var err error
	switch r.PathValue("list") {
	case "allow":
		err = s.ipFilter.AddAllow(req.CIDR)
	case "deny":
		err = s.ipFilter.AddDeny(req.CIDR)
	default:
		http.Error(w, "list must be \"allow\" or \"deny\"", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.persist(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveIP(w http.ResponseWriter, r *http.Request) {
	var req cidrRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var found bool
	var err error
	switch r.PathValue("list") {
	case "allow":
		found, err = s.ipFilter.RemoveAllow(req.CIDR)
	case "deny":
		found, err = s.ipFilter.RemoveDeny(req.CIDR)
	default:
		http.Error(w, "list must be \"allow\" or \"deny\"", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.persist(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if s.wafEngine == nil {
		writeJSON(w, http.StatusOK, []waf.RuleInfo{})
		return
	}
	writeJSON(w, http.StatusOK, s.wafEngine.ListRules())
}

type patchRuleRequest struct {
	Enabled *bool   `json:"enabled"`
	Action  *string `json:"action"`
}

func (s *Server) handlePatchRule(w http.ResponseWriter, r *http.Request) {
	if s.wafEngine == nil {
		http.Error(w, "waf is disabled", http.StatusNotFound)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid rule id", http.StatusBadRequest)
		return
	}

	var req patchRuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// Start from the rule's current effective state so a request that only
	// sets one field doesn't clobber the other.
	enabled := true
	action := ""
	for _, info := range s.wafEngine.ListRules() {
		if info.ID == id {
			enabled = info.Enabled
			if info.Overridden {
				action = info.Action
			}
			break
		}
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Action != nil {
		action = *req.Action
	}

	if err := s.wafEngine.SetOverride(id, enabled, action); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.persist(w)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
