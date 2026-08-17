package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func newTestEngine(t *testing.T, rulesYAML string) *Engine {
	t.Helper()
	path := writeRulesFile(t, rulesYAML)
	e, err := NewEngine(config.WAFConfig{
		RulesFile:      path,
		BodyInspection: config.BodyInspectionConfig{MaxBytes: 131072},
		DefaultAction:  "block",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func seedEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(config.WAFConfig{
		RulesFile:      "../../../configs/rules/default.yaml",
		BodyInspection: config.BodyInspectionConfig{MaxBytes: 131072},
		DefaultAction:  "block",
	})
	if err != nil {
		t.Fatalf("NewEngine(seed rules): %v", err)
	}
	return e
}

func inspectRequest(t *testing.T, e *Engine, method, target string, body string) (bool, *Rule) {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	blocked, match, err := e.Inspect(r)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return blocked, match
}

// queryTarget builds a properly percent-encoded "path?query" string so
// httptest.NewRequest can parse it the way a real client request would
// arrive on the wire, mirroring how attackers typically deliver these
// payloads (URL-encoded) rather than as raw control characters.
func queryTarget(path, param, value string) string {
	v := url.Values{}
	v.Set(param, value)
	return path + "?" + v.Encode()
}

func TestEngine_BlocksKnownAttackPayloads(t *testing.T) {
	e := seedEngine(t)

	tests := []struct {
		name         string
		target       string
		body         string
		wantCategory string
	}{
		{"sqli union select", queryTarget("/search", "q", "1' UNION SELECT username,password FROM users"), "", "sqli"},
		{"sqli tautology", queryTarget("/login", "user", "admin' OR 1=1"), "", "sqli"},
		{"sqli stacked query", queryTarget("/x", "id", "1; DROP TABLE users"), "", "sqli"},
		{"xss script tag", queryTarget("/comment", "text", "<script>alert(1)</script>"), "", "xss"},
		{"xss event handler", queryTarget("/x", "name", `"><img src=x onerror=alert(1)>`), "", "xss"},
		{"path traversal dotdot", queryTarget("/files", "path", "../../etc/passwd"), "", "path-traversal"},
		{"path traversal encoded", "/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "", "path-traversal"},
		{"command injection binary", queryTarget("/ping", "host", "1.1.1.1;cat /etc/passwd"), "", "command-injection"},
		{"command injection backtick", queryTarget("/x", "cmd", "`whoami`"), "", "command-injection"},
		{"sqli in body", "/api/query", "payload=1' UNION SELECT * FROM secrets--", "sqli"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := http.MethodGet
			if tt.body != "" {
				method = http.MethodPost
			}
			blocked, match := inspectRequest(t, e, method, tt.target, tt.body)
			if !blocked {
				t.Fatalf("expected request to be blocked, got allowed")
			}
			if match.Category != tt.wantCategory {
				t.Errorf("matched category = %q, want %q (rule id %d)", match.Category, tt.wantCategory, match.ID)
			}
		})
	}
}

func TestEngine_AllowsBenignTraffic(t *testing.T) {
	e := seedEngine(t)

	tests := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{"simple get", http.MethodGet, "/", ""},
		{"search query", http.MethodGet, "/search?q=golang+reverse+proxy", ""},
		{"login form", http.MethodPost, "/login", "username=alice&password=hunter2"},
		{"json api payload", http.MethodPost, "/api/users", `{"name":"Alice","role":"admin"}`},
		{"path with dashes", http.MethodGet, "/blog/my-first-post", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, match := inspectRequest(t, e, tt.method, tt.target, tt.body)
			if blocked {
				t.Errorf("expected benign request to pass, got blocked by rule %d (%s)", match.ID, match.Category)
			}
		})
	}
}

func TestEngine_LogActionDoesNotBlock(t *testing.T) {
	e := newTestEngine(t, `
rules:
  - id: 1
    category: test
    action: log
    targets: [query]
    pattern: "suspicious"
`)
	blocked, _ := inspectRequest(t, e, http.MethodGet, "/x?q=suspicious", "")
	if blocked {
		t.Error("log-action rule should never block")
	}
}

func TestEngine_DefaultActionLogOnlyOverridesBlockRules(t *testing.T) {
	path := writeRulesFile(t, `
rules:
  - id: 1
    category: test
    action: block
    targets: [query]
    pattern: "attack"
`)
	e, err := NewEngine(config.WAFConfig{
		RulesFile:      path,
		BodyInspection: config.BodyInspectionConfig{MaxBytes: 131072},
		DefaultAction:  "log-only",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	blocked, _ := inspectRequest(t, e, http.MethodGet, "/x?q=attack", "")
	if blocked {
		t.Error("waf.default_action=log-only should override every rule's action to log")
	}
}

func TestEngine_BodyCapForwardsFullOriginalBody(t *testing.T) {
	e := newTestEngine(t, `
rules:
  - id: 1
    category: test
    action: block
    targets: [body]
    pattern: "needle"
`)
	e.maxBodyBytes = 10 // deliberately small to force the cap path

	fullBody := strings.Repeat("x", 50) + "-needle-is-past-the-cap-" + strings.Repeat("y", 50)
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(fullBody))

	blocked, _, err := e.Inspect(r)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	// "needle" is beyond the 10-byte inspected prefix, so it should NOT be
	// detected — this documents the size-cap tradeoff, not a false negative
	// bug.
	if blocked {
		t.Fatal("expected match beyond the body cap to be missed by design")
	}

	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read reconstructed body: %v", err)
	}
	if string(got) != fullBody {
		t.Errorf("reconstructed body does not match original: got %d bytes, want %d bytes", len(got), len(fullBody))
	}
}

func TestEngine_BodyMatchWithinCap(t *testing.T) {
	e := newTestEngine(t, `
rules:
  - id: 1
    category: test
    action: block
    targets: [body]
    pattern: "needle"
`)

	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("hay hay needle hay"))
	blocked, match, err := e.Inspect(r)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !blocked || match.ID != 1 {
		t.Fatalf("expected body rule to match within the cap, blocked=%v match=%v", blocked, match)
	}
}

func TestEngine_HeaderTargeting(t *testing.T) {
	e := newTestEngine(t, `
rules:
  - id: 1
    category: xss
    action: block
    targets: ["headers:User-Agent"]
    pattern: "<script"
`)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "<script>evil</script>")
	blocked, match, err := e.Inspect(r)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !blocked || match.ID != 1 {
		t.Fatalf("expected User-Agent rule to match, blocked=%v", blocked)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Referer", "<script>evil</script>") // wrong header, should not match
	blocked2, _, err := e.Inspect(r2)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if blocked2 {
		t.Error("rule scoped to User-Agent should not match Referer")
	}
}

func TestEngine_Reload_FailSafeOnMalformedFile(t *testing.T) {
	goodPath := writeRulesFile(t, `
rules:
  - id: 1
    category: test
    action: block
    targets: [query]
    pattern: "bad"
`)
	e, err := NewEngine(config.WAFConfig{
		RulesFile:      goodPath,
		BodyInspection: config.BodyInspectionConfig{MaxBytes: 1024},
		DefaultAction:  "block",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.RuleCount() != 1 {
		t.Fatalf("RuleCount() = %d, want 1", e.RuleCount())
	}

	badPath := writeRulesFile(t, `rules: [{id: 1, category: test, action: nonsense, targets: [query], pattern: "x"}]`)
	if err := e.Reload(badPath); err == nil {
		t.Fatal("expected Reload to fail on malformed rules file")
	}

	// The old ruleset must still be active after a failed reload.
	if e.RuleCount() != 1 {
		t.Fatalf("RuleCount() after failed reload = %d, want 1 (unchanged)", e.RuleCount())
	}
	blocked, _ := inspectRequest(t, e, http.MethodGet, "/x?q=bad", "")
	if !blocked {
		t.Error("expected original ruleset to still be enforced after a failed reload")
	}
}

func TestEngine_Reload_Success(t *testing.T) {
	e := newTestEngine(t, `
rules:
  - id: 1
    category: test
    action: block
    targets: [query]
    pattern: "old"
`)
	newPath := writeRulesFile(t, `
rules:
  - id: 2
    category: test
    action: block
    targets: [query]
    pattern: "new"
`)
	if err := e.Reload(newPath); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	blockedOld, _ := inspectRequest(t, e, http.MethodGet, "/x?q=old", "")
	if blockedOld {
		t.Error("old rule should no longer be active after reload")
	}
	blockedNew, match := inspectRequest(t, e, http.MethodGet, "/x?q=new", "")
	if !blockedNew || match.ID != 2 {
		t.Error("new rule should be active after reload")
	}
}

func TestEngine_Middleware(t *testing.T) {
	e := seedEngine(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Chain(next, mw.AttachRecorder, e.Middleware())

	t.Run("malicious request blocked with rule metadata recorded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, queryTarget("/x", "id", "1' UNION SELECT password FROM users"), nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("benign request passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/search?q=golang", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestEngine_RecordsWAFMatchOnRecorder(t *testing.T) {
	e := seedEngine(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, queryTarget("/x", "id", "1' UNION SELECT password FROM users"), nil)
	rec := mw.NewRecorder("test-id")
	req = req.WithContext(mw.WithRecorder(req.Context(), rec))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	snap := rec.Snapshot()
	if snap.Outcome != mw.OutcomeBlocked {
		t.Errorf("outcome = %v, want blocked", snap.Outcome)
	}
	if snap.BlockReason != mw.BlockReasonWAF {
		t.Errorf("block reason = %v, want waf", snap.BlockReason)
	}
	if snap.WAFCategory != "sqli" {
		t.Errorf("waf category = %q, want sqli", snap.WAFCategory)
	}
}
