package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	accesslog "github.com/jameslauhe/go-firewall/internal/log"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/middleware/waf"
)

const testTokenEnv = "GOFIREWALL_TEST_ADMIN_TOKEN"

func newTestServer(t *testing.T, withWAF bool) (*Server, string) {
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

	var wafEngine *waf.Engine
	if withWAF {
		path := writeTestRules(t)
		wafEngine, err = waf.NewEngine(config.WAFConfig{
			RulesFile:      path,
			BodyInspection: config.BodyInspectionConfig{MaxBytes: 1024},
			DefaultAction:  "block",
		})
		if err != nil {
			t.Fatalf("waf.NewEngine: %v", err)
		}
	}

	srv, err := New(
		config.AdminConfig{Enabled: true, AuthTokenEnv: testTokenEnv},
		Info{Version: "test", Listeners: []string{"0.0.0.0:8443"}, Upstreams: []string{"http://10.0.0.1:8080"}},
		al, ipf, wafEngine,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, token
}

func writeTestRules(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/rules.yaml"
	contents := `
rules:
  - id: 1
    category: test
    severity: high
    action: block
    description: "test rule"
    targets: [query]
    pattern: "attack"
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	return path
}

func TestNew_MissingToken(t *testing.T) {
	t.Setenv("GOFIREWALL_TEST_EMPTY_TOKEN", "")
	al, _ := accesslog.New(config.LogConfig{Level: "info", AccessLogPath: "-", RingBufferSize: 10})
	ipf, _ := ipfilter.New(config.IPListConfig{})
	_, err := New(config.AdminConfig{AuthTokenEnv: "GOFIREWALL_TEST_EMPTY_TOKEN"}, Info{}, al, ipf, nil)
	if err == nil {
		t.Fatal("expected error when auth token env var is empty")
	}
}

func doAdminRequest(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHandler_RejectsUnauthenticatedAPIRequests(t *testing.T) {
	srv, _ := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/status", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestHandler_RejectsWrongToken(t *testing.T) {
	srv, _ := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/status", "wrong-token", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestHandler_StaticUIServedWithoutAuth(t *testing.T) {
	srv, _ := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty static UI body")
	}
}

func TestHandler_Status(t *testing.T) {
	srv, token := newTestServer(t, true)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/status", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Version != "test" || !resp.WAFEnabled || resp.WAFRuleCount != 1 {
		t.Errorf("unexpected status response: %+v", resp)
	}
}

func TestHandler_IPListsAddListRemove(t *testing.T) {
	srv, token := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/ip-lists", token, nil)
	var lists ipListsResponse
	json.Unmarshal(rec.Body.Bytes(), &lists)
	if len(lists.Deny) != 1 || lists.Deny[0] != "203.0.113.0/24" {
		t.Fatalf("unexpected initial deny list: %+v", lists)
	}

	addRec := doAdminRequest(t, h, http.MethodPost, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "198.51.100.0/24"})
	if addRec.Code != http.StatusNoContent {
		t.Fatalf("add status = %d, want 204: %s", addRec.Code, addRec.Body.String())
	}

	rec2 := doAdminRequest(t, h, http.MethodGet, "/admin/api/ip-lists", token, nil)
	var lists2 ipListsResponse
	json.Unmarshal(rec2.Body.Bytes(), &lists2)
	if len(lists2.Deny) != 2 {
		t.Fatalf("expected 2 deny entries after add, got %+v", lists2)
	}

	removeRec := doAdminRequest(t, h, http.MethodDelete, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "198.51.100.0/24"})
	if removeRec.Code != http.StatusNoContent {
		t.Fatalf("remove status = %d, want 204: %s", removeRec.Code, removeRec.Body.String())
	}

	removeAgainRec := doAdminRequest(t, h, http.MethodDelete, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "198.51.100.0/24"})
	if removeAgainRec.Code != http.StatusNotFound {
		t.Errorf("removing an already-gone CIDR: status = %d, want 404", removeAgainRec.Code)
	}
}

func TestHandler_IPLists_InvalidCIDR(t *testing.T) {
	srv, token := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodPost, "/admin/api/ip-lists/deny", token, cidrRequest{CIDR: "not-a-cidr"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandler_IPLists_UnknownListName(t *testing.T) {
	srv, token := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodPost, "/admin/api/ip-lists/bogus", token, cidrRequest{CIDR: "1.2.3.0/24"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandler_WAFRulesListAndPatch(t *testing.T) {
	srv, token := newTestServer(t, true)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/waf-rules", token, nil)
	var rules []waf.RuleInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rules) != 1 || rules[0].Enabled != true {
		t.Fatalf("unexpected rules list: %+v", rules)
	}

	disabled := false
	patchRec := doAdminRequest(t, h, http.MethodPatch, "/admin/api/waf-rules/1", token, patchRuleRequest{Enabled: &disabled})
	if patchRec.Code != http.StatusNoContent {
		t.Fatalf("patch status = %d, want 204: %s", patchRec.Code, patchRec.Body.String())
	}

	rec2 := doAdminRequest(t, h, http.MethodGet, "/admin/api/waf-rules", token, nil)
	var rules2 []waf.RuleInfo
	json.Unmarshal(rec2.Body.Bytes(), &rules2)
	if rules2[0].Enabled {
		t.Error("expected rule to be disabled after PATCH")
	}
}

func TestHandler_WAFRules_WhenWAFDisabled(t *testing.T) {
	srv, token := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/waf-rules", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var rules []waf.RuleInfo
	json.Unmarshal(rec.Body.Bytes(), &rules)
	if len(rules) != 0 {
		t.Errorf("expected empty rules list when WAF disabled, got %+v", rules)
	}

	patchRec := doAdminRequest(t, h, http.MethodPatch, "/admin/api/waf-rules/1", token, patchRuleRequest{})
	if patchRec.Code != http.StatusNotFound {
		t.Errorf("patch status = %d, want 404 when WAF disabled", patchRec.Code)
	}
}

func TestHandler_Logs(t *testing.T) {
	srv, token := newTestServer(t, false)
	h := srv.Handler()

	rec := doAdminRequest(t, h, http.MethodGet, "/admin/api/logs", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var entries []accesslog.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entries == nil {
		t.Error("expected an empty-but-non-null array for no log entries")
	}
}
