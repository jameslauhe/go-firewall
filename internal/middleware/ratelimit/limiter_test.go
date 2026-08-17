package ratelimit

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestShardedLimiter_BurstThenRefill(t *testing.T) {
	sl := newShardedLimiter(1 /* rps */, 3 /* burst */, time.Hour)
	defer sl.Stop()

	ip := netip.MustParseAddr("1.2.3.4")
	base := time.Now()

	for i := 0; i < 3; i++ {
		if !sl.allowAt(ip, base) {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if sl.allowAt(ip, base) {
		t.Fatal("request beyond burst should be denied")
	}

	// One second later, one token has refilled at 1 rps.
	if !sl.allowAt(ip, base.Add(time.Second)) {
		t.Fatal("expected a refilled token 1s later")
	}
	if sl.allowAt(ip, base.Add(time.Second)) {
		t.Fatal("expected only one refilled token to be available")
	}
}

func TestShardedLimiter_IndependentPerIP(t *testing.T) {
	sl := newShardedLimiter(1, 1, time.Hour)
	defer sl.Stop()

	now := time.Now()
	a := netip.MustParseAddr("1.1.1.1")
	b := netip.MustParseAddr("2.2.2.2")

	if !sl.allowAt(a, now) {
		t.Fatal("first request from a should be allowed")
	}
	if sl.allowAt(a, now) {
		t.Fatal("second immediate request from a should be denied")
	}
	if !sl.allowAt(b, now) {
		t.Fatal("first request from b should be allowed independently of a's bucket")
	}
}

func TestShardedLimiter_ConcurrentDifferentIPs(t *testing.T) {
	sl := newShardedLimiter(1000, 1000, time.Hour)
	defer sl.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
			for j := 0; j < 20; j++ {
				sl.Allow(ip)
			}
		}(i)
	}
	wg.Wait()

	if got := sl.activeCount(); got != 200 {
		t.Errorf("activeCount() = %d, want 200", got)
	}
}

func TestShardedLimiter_EvictsIdleEntries(t *testing.T) {
	sl := newShardedLimiter(10, 10, time.Hour)
	defer sl.Stop()

	ip := netip.MustParseAddr("9.9.9.9")
	sl.allowAt(ip, time.Now())
	if got := sl.activeCount(); got != 1 {
		t.Fatalf("activeCount() = %d, want 1 before eviction", got)
	}

	// Backdate the entry's lastSeen past the idle TTL and sweep directly,
	// rather than waiting on the background ticker.
	sh := sl.shards[shardIndex(ip)]
	sh.mu.Lock()
	sh.buckets[ip].lastSeen.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	sh.mu.Unlock()

	sl.evictIdle()

	if got := sl.activeCount(); got != 0 {
		t.Errorf("activeCount() = %d, want 0 after eviction", got)
	}
}
