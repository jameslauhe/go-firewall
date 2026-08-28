package ipfilter

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	"github.com/jameslauhe/go-firewall/internal/geoip/geoiptest"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func TestFilter_DenyList(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if ok, reason := f.Allowed(netip.MustParseAddr("203.0.113.5")); ok || reason != mw.BlockReasonIPDeny {
		t.Errorf("expected denied IP to be blocked with ip-deny, got ok=%v reason=%v", ok, reason)
	}
	if ok, _ := f.Allowed(netip.MustParseAddr("8.8.8.8")); !ok {
		t.Error("expected non-denied IP to be allowed")
	}
}

func TestFilter_AllowListMode(t *testing.T) {
	f, err := New(config.IPListConfig{Allow: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if ok, _ := f.Allowed(netip.MustParseAddr("10.1.2.3")); !ok {
		t.Error("expected allow-listed IP to be allowed")
	}
	if ok, reason := f.Allowed(netip.MustParseAddr("8.8.8.8")); ok || reason != mw.BlockReasonIPDeny {
		t.Errorf("expected non-allow-listed IP to be blocked in allow-list mode, got ok=%v reason=%v", ok, reason)
	}
}

// TestFilter_GeoBlocking_SingaporeOnly exercises the config example from
// configs/config.example.yaml: allow_countries: ["SG"] should let only
// Singapore-geolocated traffic through and deny everyone else.
func TestFilter_GeoBlocking_SingaporeOnly(t *testing.T) {
	dbPath := geoiptest.BuildMMDB(t, map[string]string{
		"203.0.113.0/24":  "SG",
		"198.51.100.0/24": "US",
	})

	f, err := New(config.IPListConfig{
		Geo: config.GeoConfig{
			Enabled:        true,
			DBPath:         dbPath,
			AllowCountries: []string{"SG"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer f.Close()

	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.1")); !ok {
		t.Error("expected Singapore-geolocated IP to be allowed")
	}
	if ok, reason := f.Allowed(netip.MustParseAddr("198.51.100.1")); ok || reason != mw.BlockReasonGeoDeny {
		t.Errorf("expected US-geolocated IP to be geo-denied, got ok=%v reason=%v", ok, reason)
	}
	if ok, reason := f.Allowed(netip.MustParseAddr("1.2.3.4")); ok || reason != mw.BlockReasonGeoDeny {
		t.Errorf("expected unresolvable IP to be geo-denied (fail closed), got ok=%v reason=%v", ok, reason)
	}
}

func TestFilter_CIDRDenyRunsBeforeGeoLookup(t *testing.T) {
	dbPath := geoiptest.BuildMMDB(t, map[string]string{
		"203.0.113.0/24": "SG",
	})

	f, err := New(config.IPListConfig{
		Deny: []string{"203.0.113.5/32"},
		Geo: config.GeoConfig{
			Enabled:        true,
			DBPath:         dbPath,
			AllowCountries: []string{"SG"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer f.Close()

	// This IP would pass the geo check (it's SG) but is explicitly denied
	// by CIDR, which must take effect regardless.
	if ok, reason := f.Allowed(netip.MustParseAddr("203.0.113.5")); ok || reason != mw.BlockReasonIPDeny {
		t.Errorf("expected CIDR-denied IP to be blocked with ip-deny even though geo would allow it, got ok=%v reason=%v", ok, reason)
	}
}

func TestFilter_Middleware(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	// f.Middleware() reads the resolved client IP off the Recorder, so it
	// must sit behind mw.AttachRecorder + mw.ResolveClientIP in the chain,
	// exactly as it's wired in production.
	handler := mw.Chain(next, mw.AttachRecorder, mw.ResolveClientIP(nil), f.Middleware())

	t.Run("denied IP never reaches next handler", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.5:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if nextCalled {
			t.Error("expected next handler not to be called for denied IP")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("allowed IP reaches next handler", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "8.8.8.8:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("expected next handler to be called for allowed IP")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}
