package admin

import (
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	accesslog "github.com/jameslauhe/go-firewall/internal/log"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/middleware/waf"
)

// newPersistentTestServer is like newTestServer but wires a state file, and
// returns the components separately so a test can simulate "restart" by
// constructing fresh ones against the same base config and state file.
func newPersistentTestServer(t *testing.T, statePath string) (*Server, string, *ipfilter.Filter, *waf.Engine) {
	t.Helper()
	const token = "s3cr3t"
	t.Setenv(testTokenEnv, token)

	al, err := accesslog.New(config.LogConfig{Level: "info", AccessLogPath: "-", RingBufferSize: 50})
	if err != nil {
		t.Fatalf("accesslog.New: %v", err)
	}

	ipf, err := ipfilter.New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("ipfilter.New: %v", err)
	}

	rulesPath := writeTestRules(t)
	wafEngine, err := waf.NewEngine(config.WAFConfig{
		RulesFile:      rulesPath,
		BodyInspection: config.BodyInspectionConfig{MaxBytes: 1024},
		DefaultAction:  "block",
	})
	if err != nil {
		t.Fatalf("waf.NewEngine: %v", err)
	}

	srv, err := New(
		config.AdminConfig{Enabled: true, AuthTokenEnv: testTokenEnv, StateFile: statePath},
		Info{Version: "test"},
		al, ipf, wafEngine,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, token, ipf, wafEngine
}

func TestServer_AddIPPersistsToStateFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	srv, token, _, _ := newPersistentTestServer(t, statePath)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodPost, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "198.51.100.0/24"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("add status = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if warn := rec.Header().Get("X-Persistence-Warning"); warn != "" {
		t.Errorf("unexpected persistence warning: %s", warn)
	}

	store := NewStateStore(statePath)
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(state.IPLists.DenyAdded) != 1 || state.IPLists.DenyAdded[0] != "198.51.100.0/24" {
		t.Errorf("DenyAdded = %v, want [198.51.100.0/24]", state.IPLists.DenyAdded)
	}
}

func TestServer_RemoveIPPersistsToStateFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	srv, token, _, _ := newPersistentTestServer(t, statePath)
	h := srv.Handler()

	// 203.0.113.0/24 is in the base config, not admin-added — removing it
	// must show up as an explicit removal in the persisted state.
	rec := doAdminRequest(t, h, http.MethodDelete, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "203.0.113.0/24"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remove status = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	store := NewStateStore(statePath)
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(state.IPLists.DenyRemoved) != 1 || state.IPLists.DenyRemoved[0] != "203.0.113.0/24" {
		t.Errorf("DenyRemoved = %v, want [203.0.113.0/24]", state.IPLists.DenyRemoved)
	}
}

func TestServer_PatchRulePersistsToStateFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	srv, token, _, _ := newPersistentTestServer(t, statePath)
	h := srv.Handler()

	disabled := false
	rec := doAdminRequest(t, h, http.MethodPatch, "/admin/api/waf-rules/1", token, patchRuleRequest{Enabled: &disabled})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("patch status = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	store := NewStateStore(statePath)
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	o, ok := state.WAFOverrides[1]
	if !ok {
		t.Fatalf("expected rule 1's override to be persisted, got %+v", state.WAFOverrides)
	}
	if o.Enabled {
		t.Errorf("persisted override Enabled = true, want false")
	}
	if o.Action != "" {
		t.Errorf("persisted override Action = %q, want empty (only Enabled was overridden)", o.Action)
	}
}

func TestServer_RestartReplaysAdminState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	// "First run": mutate via the API.
	srv1, token, ipf1, wafEngine1 := newPersistentTestServer(t, statePath)
	h1 := srv1.Handler()

	doAdminRequest(t, h1, http.MethodPost, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "198.51.100.0/24"})
	doAdminRequest(t, h1, http.MethodDelete, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "203.0.113.0/24"})
	disabled := false
	doAdminRequest(t, h1, http.MethodPatch, "/admin/api/waf-rules/1", token, patchRuleRequest{Enabled: &disabled})

	if ok, _ := ipf1.Allowed(netip.MustParseAddr("198.51.100.5")); ok {
		t.Fatal("sanity check: expected admin-added deny to be live in the first instance")
	}
	if ok, _ := ipf1.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Fatal("sanity check: expected admin-removed base deny to be lifted in the first instance")
	}
	if wafEngine1.ListRules()[0].Enabled {
		t.Fatal("sanity check: expected rule 1 to be disabled in the first instance")
	}

	// "Restart": fresh Filter/Engine built from the same base config, then
	// a fresh admin.New() pointed at the same state file should replay
	// every edit above without any further API calls.
	srv2, _, ipf2, wafEngine2 := newPersistentTestServer(t, statePath)
	_ = srv2

	if ok, _ := ipf2.Allowed(netip.MustParseAddr("198.51.100.5")); ok {
		t.Error("expected admin-added deny CIDR to survive a restart")
	}
	if ok, _ := ipf2.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Error("expected admin-removed base CIDR to stay removed after a restart")
	}
	if wafEngine2.ListRules()[0].Enabled {
		t.Error("expected rule 1's disabled override to survive a restart")
	}
}
