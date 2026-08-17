package ipfilter

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"github.com/jameslauhe/go-firewall/internal/config"
	mw "github.com/jameslauhe/go-firewall/internal/middleware"
)

func TestFilter_AddDeny_TakesEffectImmediately(t *testing.T) {
	f, err := New(config.IPListConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip := netip.MustParseAddr("203.0.113.5")
	if ok, _ := f.Allowed(ip); !ok {
		t.Fatal("expected IP to be allowed before any deny rule")
	}

	if err := f.AddDeny("203.0.113.0/24"); err != nil {
		t.Fatalf("AddDeny: %v", err)
	}

	if ok, reason := f.Allowed(ip); ok || reason != mw.BlockReasonIPDeny {
		t.Errorf("expected IP to be denied immediately after AddDeny, got ok=%v reason=%v", ok, reason)
	}
	if got := f.ListDeny(); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("ListDeny() = %v, want [203.0.113.0/24]", got)
	}
}

func TestFilter_AddDeny_InvalidCIDR(t *testing.T) {
	f, err := New(config.IPListConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := f.AddDeny("not-a-cidr"); err == nil {
		t.Fatal("expected error adding invalid CIDR")
	}
	if got := f.ListDeny(); len(got) != 0 {
		t.Errorf("ListDeny() = %v, want empty after failed add", got)
	}
}

func TestFilter_AddDeny_Idempotent(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := f.AddDeny("203.0.113.0/24"); err != nil {
		t.Fatalf("AddDeny (duplicate): %v", err)
	}
	if got := f.ListDeny(); len(got) != 1 {
		t.Errorf("ListDeny() = %v, want a single entry (no duplicate)", got)
	}
}

func TestFilter_RemoveDeny(t *testing.T) {
	f, err := New(config.IPListConfig{Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip := netip.MustParseAddr("203.0.113.5")
	if ok, _ := f.Allowed(ip); ok {
		t.Fatal("expected IP to be denied before removal")
	}

	removed, err := f.RemoveDeny("203.0.113.0/24")
	if err != nil {
		t.Fatalf("RemoveDeny: %v", err)
	}
	if !removed {
		t.Error("expected RemoveDeny to report the entry was found and removed")
	}
	if ok, _ := f.Allowed(ip); !ok {
		t.Error("expected IP to be allowed immediately after RemoveDeny")
	}

	removedAgain, err := f.RemoveDeny("203.0.113.0/24")
	if err != nil {
		t.Fatalf("RemoveDeny (already gone): %v", err)
	}
	if removedAgain {
		t.Error("expected second RemoveDeny of the same CIDR to report not-found")
	}
}

func TestFilter_ConcurrentAddDeny(t *testing.T) {
	f, err := New(config.IPListConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cidr := "10.0." + strconv.Itoa(i) + ".0/24"
			if err := f.AddDeny(cidr); err != nil {
				t.Errorf("AddDeny(%s): %v", cidr, err)
			}
		}(i)
	}
	wg.Wait()

	if got := len(f.ListDeny()); got != 50 {
		t.Errorf("ListDeny() has %d entries, want 50 (concurrent adds should not lose entries)", got)
	}
}
