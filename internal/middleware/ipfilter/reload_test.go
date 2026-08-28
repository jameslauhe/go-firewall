package ipfilter

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jameslauhe/go-firewall/internal/config"
	"github.com/jameslauhe/go-firewall/internal/geoip/geoiptest"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func TestFilter_Reload_PreservesAdminOverlay(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := f.AddDeny("198.51.100.0/24"); err != nil {
		t.Fatalf("AddDeny: %v", err)
	}

	// Reload with a config that no longer mentions the admin-added CIDR at
	// all — it must still be denied afterward.
	if err := f.Reload(config.IPListConfig{Deny: []string{"203.0.113.0/24"}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if ok, _ := f.Allowed(netip.MustParseAddr("198.51.100.5")); ok {
		t.Error("expected admin-added deny CIDR to survive a config reload")
	}
	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); ok {
		t.Error("expected base deny CIDR to still be enforced after reload")
	}
}

func TestFilter_Reload_ReplacesBase(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); ok {
		t.Fatal("expected base deny CIDR to be enforced before reload")
	}

	// Reload with a config that drops the old base CIDR entirely (not an
	// admin removal — a legitimate base-layer change).
	if err := f.Reload(config.IPListConfig{Deny: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Error("expected old base CIDR to no longer be denied after reload replaced the base")
	}
	if ok, _ := f.Allowed(netip.MustParseAddr("198.51.100.5")); ok {
		t.Error("expected new base CIDR to be denied after reload")
	}
}

func TestFilter_Reload_AdminRemovalOfBaseCIDRSurvivesReload(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	removed, err := f.RemoveDeny("203.0.113.0/24")
	if err != nil || !removed {
		t.Fatalf("RemoveDeny: removed=%v err=%v", removed, err)
	}
	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Fatal("expected admin-removed base CIDR to be allowed before reload")
	}

	// Reload with the SAME config that originally included the CIDR the
	// admin explicitly removed — the removal must stick.
	if err := f.Reload(config.IPListConfig{Deny: []string{"203.0.113.0/24"}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Error("expected admin removal of a base CIDR to survive reload of the same base config")
	}
}

func TestFilter_Reload_InvalidCIDRKeepsOldState(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = f.Reload(config.IPListConfig{Deny: []string{"not-a-cidr"}})
	if err == nil {
		t.Fatal("expected Reload to fail on a malformed CIDR")
	}

	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); ok {
		t.Error("expected the original deny list to still be enforced after a failed reload")
	}
	if got := f.ListDeny(); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("ListDeny() = %v, want unchanged [203.0.113.0/24] after failed reload", got)
	}
}

func TestFilter_Reload_GeoSettingsChange(t *testing.T) {
	dbPath := geoiptest.BuildMMDB(t, map[string]string{
		"203.0.113.0/24": "SG",
	})

	f, err := New(config.IPListConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer f.Close()

	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Fatal("expected traffic to be allowed before geo is enabled")
	}

	if err := f.Reload(config.IPListConfig{
		Geo: config.GeoConfig{Enabled: true, DBPath: dbPath, AllowCountries: []string{"SG"}},
	}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if ok, _ := f.Allowed(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Error("expected SG-geolocated IP to still be allowed after enabling geo via reload")
	}
	if ok, reason := f.Allowed(netip.MustParseAddr("8.8.8.8")); ok || reason != mw.BlockReasonGeoDeny {
		t.Errorf("expected unresolvable IP to be geo-denied after enabling geo via reload, got ok=%v reason=%v", ok, reason)
	}
}

// TestFilter_Reload_GeoDBSwapNoRaceWithInFlightLookup hammers Allowed()
// concurrently with Reload() swapping in a new geo database, under -race.
// geoip.DB wraps a memory-mapped file; closing the old one before an
// in-flight lookup against it completes would be a use-after-close bug —
// this is the highest-severity failure mode in the whole reload feature,
// so it gets a dedicated stress test rather than relying on the ordinary
// correctness tests above to happen to catch it.
func TestFilter_Reload_GeoDBSwapNoRaceWithInFlightLookup(t *testing.T) {
	dbA := geoiptest.BuildMMDB(t, map[string]string{"203.0.113.0/24": "SG"})
	dbB := geoiptest.BuildMMDB(t, map[string]string{"203.0.113.0/24": "US"})

	f, err := New(config.IPListConfig{
		Geo: config.GeoConfig{Enabled: true, DBPath: dbA, AllowCountries: []string{"SG", "US"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer f.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr("203.0.113.5")
			for {
				select {
				case <-stop:
					return
				default:
					f.Allowed(ip)
				}
			}
		}()
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	toggle := dbA
	for time.Now().Before(deadline) {
		if toggle == dbA {
			toggle = dbB
		} else {
			toggle = dbA
		}
		if err := f.Reload(config.IPListConfig{
			Geo: config.GeoConfig{Enabled: true, DBPath: toggle, AllowCountries: []string{"SG", "US"}},
		}); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}

	close(stop)
	wg.Wait()
}
