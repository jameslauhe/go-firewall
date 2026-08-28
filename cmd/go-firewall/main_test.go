package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
	"github.com/jameslauhe/go-firewall/internal/middleware/ipfilter"
	"github.com/jameslauhe/go-firewall/internal/middleware/ratelimit"
	"github.com/jameslauhe/go-firewall/internal/middleware/waf"
)

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const rulesV1 = `
rules:
  - id: 1
    category: test
    action: block
    targets: [query]
    pattern: "v1only"
`

const rulesV2 = `
rules:
  - id: 1
    category: test
    action: block
    targets: [query]
    pattern: "v1only"
  - id: 2
    category: test
    action: block
    targets: [query]
    pattern: "v2only"
`

func upstreamsBlock(t *testing.T) string {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	return backend.URL
}

func configYAML(rulesPath, upstreamURL string, denyCIDR string, burst int) string {
	return `
listen:
  - address: "127.0.0.1:0"
upstreams:
  addresses: ["` + upstreamURL + `"]
ip_lists:
  deny: ["` + denyCIDR + `"]
rate_limit:
  enabled: true
  default:
    requests_per_second: 1000
    burst: ` + strconv.Itoa(burst) + `
  idle_ttl: "1h"
waf:
  enabled: true
  rules_file: "` + rulesPath + `"
  body_inspection:
    max_bytes: 65536
  default_action: "block"
`
}

func newTestComponents(t *testing.T, rulesPath, configPath string) (*ipfilter.Filter, *ratelimit.Limiter, *waf.Engine) {
	t.Helper()
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	ipFilter, err := ipfilter.New(cfg.IPLists)
	if err != nil {
		t.Fatalf("ipfilter.New: %v", err)
	}
	t.Cleanup(func() { ipFilter.Close() })

	rateLimiter := ratelimit.New(cfg.RateLimit)
	t.Cleanup(rateLimiter.Stop)

	wafEngine, err := waf.NewEngine(cfg.WAF)
	if err != nil {
		t.Fatalf("waf.NewEngine: %v", err)
	}

	return ipFilter, rateLimiter, wafEngine
}

func TestReloadOnce_ReloadsAllThreeComponents(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	writeFile(t, rulesPath, rulesV1)

	upstreamURL := upstreamsBlock(t)

	configV1 := filepath.Join(dir, "config-v1.yaml")
	writeFile(t, configV1, configYAML(rulesPath, upstreamURL, "203.0.113.0/24", 1))
	ipFilter, rateLimiter, wafEngine := newTestComponents(t, rulesPath, configV1)

	if got := wafEngine.RuleCount(); got != 1 {
		t.Fatalf("initial RuleCount() = %d, want 1", got)
	}
	if ok, _ := ipFilter.Allowed(netip.MustParseAddr("203.0.113.5")); ok {
		t.Fatal("expected initial deny list to block 203.0.113.5")
	}
	if ok, _ := ipFilter.Allowed(netip.MustParseAddr("198.51.100.5")); !ok {
		t.Fatal("expected 198.51.100.5 to be allowed initially")
	}

	// Reload with a config that: adds a second WAF rule, changes the deny
	// CIDR, and loosens the rate limit burst.
	writeFile(t, rulesPath, rulesV2)
	configV2 := filepath.Join(dir, "config-v2.yaml")
	writeFile(t, configV2, configYAML(rulesPath, upstreamURL, "198.51.100.0/24", 1000))

	if err := reloadOnce(configV2, wafEngine, ipFilter, rateLimiter); err != nil {
		t.Fatalf("reloadOnce: %v", err)
	}

	if got := wafEngine.RuleCount(); got != 2 {
		t.Errorf("RuleCount() after reload = %d, want 2", got)
	}
	if ok, _ := ipFilter.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Error("expected old deny CIDR to no longer be enforced after reload")
	}
	if ok, _ := ipFilter.Allowed(netip.MustParseAddr("198.51.100.5")); ok {
		t.Error("expected new deny CIDR to be enforced after reload")
	}

	// The rate limit was loosened from burst=1 to burst=1000: a burst of
	// 50 requests should now all succeed.
	handler := mw.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		mw.AttachRecorder, mw.ResolveClientIP(nil), rateLimiter.Middleware(),
	)
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "9.9.9.9:1111"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d after reload: status = %d, want 200 (rate limit should be loosened)", i, rec.Code)
		}
	}
}

func TestReloadOnce_InvalidConfigLeavesStateUnchanged(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	writeFile(t, rulesPath, rulesV1)

	upstreamURL := upstreamsBlock(t)

	configV1 := filepath.Join(dir, "config-v1.yaml")
	writeFile(t, configV1, configYAML(rulesPath, upstreamURL, "203.0.113.0/24", 1))
	ipFilter, rateLimiter, wafEngine := newTestComponents(t, rulesPath, configV1)

	if err := reloadOnce(filepath.Join(dir, "does-not-exist.yaml"), wafEngine, ipFilter, rateLimiter); err == nil {
		t.Fatal("expected reloadOnce to fail for a nonexistent config file")
	}

	if got := wafEngine.RuleCount(); got != 1 {
		t.Errorf("RuleCount() after failed reload = %d, want unchanged 1", got)
	}
	if ok, _ := ipFilter.Allowed(netip.MustParseAddr("203.0.113.5")); ok {
		t.Error("expected original deny list to still be enforced after a failed reload")
	}
}

func TestReloadOnce_NilWAFEngineSkipsWAFReload(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	writeFile(t, rulesPath, rulesV1)

	upstreamURL := upstreamsBlock(t)

	configV1 := filepath.Join(dir, "config-v1.yaml")
	writeFile(t, configV1, configYAML(rulesPath, upstreamURL, "203.0.113.0/24", 1))
	cfg, err := config.Load(configV1)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ipFilter, err := ipfilter.New(cfg.IPLists)
	if err != nil {
		t.Fatalf("ipfilter.New: %v", err)
	}
	defer ipFilter.Close()
	rateLimiter := ratelimit.New(cfg.RateLimit)
	defer rateLimiter.Stop()

	configV2 := filepath.Join(dir, "config-v2.yaml")
	writeFile(t, configV2, configYAML(rulesPath, upstreamURL, "198.51.100.0/24", 1000))

	if err := reloadOnce(configV2, nil, ipFilter, rateLimiter); err != nil {
		t.Fatalf("reloadOnce with nil wafEngine: %v", err)
	}
	if ok, _ := ipFilter.Allowed(netip.MustParseAddr("198.51.100.5")); ok {
		t.Error("expected ip list reload to still apply when wafEngine is nil")
	}
}
