// Package ratelimit implements per-IP (and optionally per-route) token
// bucket rate limiting.
package ratelimit

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const numShards = 32

type bucketEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // unix nanos
}

type shard struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*bucketEntry
}

// shardedLimiter is a token-bucket rate limiter keyed by client IP, sharded
// across numShards independently-locked maps so concurrent requests from
// different IPs don't contend on a single mutex. A sharded map is used
// instead of sync.Map because this workload — a constantly churning set of
// client IPs, read-and-mutated on every request, with periodic deletion —
// is exactly the write/delete-heavy pattern sync.Map is not optimized for.
type shardedLimiter struct {
	shards  []*shard
	rps     float64
	burst   int
	idleTTL time.Duration
	stopCh  chan struct{}
	stopped sync.Once
}

func newShardedLimiter(rps float64, burst int, idleTTL time.Duration) *shardedLimiter {
	sl := &shardedLimiter{
		shards:  make([]*shard, numShards),
		rps:     rps,
		burst:   burst,
		idleTTL: idleTTL,
		stopCh:  make(chan struct{}),
	}
	for i := range sl.shards {
		sl.shards[i] = &shard{buckets: make(map[netip.Addr]*bucketEntry)}
	}
	go sl.evictLoop()
	return sl
}

// Allow reports whether a request from ip may proceed, consuming a token
// from its bucket if so.
func (sl *shardedLimiter) Allow(ip netip.Addr) bool {
	return sl.allowAt(ip, time.Now())
}

// allowAt is Allow with an explicit clock, so tests can exercise
// burst/refill behavior deterministically without sleeping.
func (sl *shardedLimiter) allowAt(ip netip.Addr, now time.Time) bool {
	sh := sl.shards[shardIndex(ip)]
	sh.mu.Lock()
	entry, ok := sh.buckets[ip]
	if !ok {
		entry = &bucketEntry{limiter: rate.NewLimiter(rate.Limit(sl.rps), sl.burst)}
		sh.buckets[ip] = entry
	}
	sh.mu.Unlock()

	entry.lastSeen.Store(now.UnixNano())
	return entry.limiter.AllowN(now, 1)
}

func (sl *shardedLimiter) evictLoop() {
	interval := sl.idleTTL / 2
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sl.evictIdle()
		case <-sl.stopCh:
			return
		}
	}
}

func (sl *shardedLimiter) evictIdle() {
	cutoff := time.Now().Add(-sl.idleTTL).UnixNano()
	for _, sh := range sl.shards {
		sh.mu.Lock()
		for ip, entry := range sh.buckets {
			if entry.lastSeen.Load() < cutoff {
				delete(sh.buckets, ip)
			}
		}
		sh.mu.Unlock()
	}
}

func (sl *shardedLimiter) activeCount() int {
	n := 0
	for _, sh := range sl.shards {
		sh.mu.Lock()
		n += len(sh.buckets)
		sh.mu.Unlock()
	}
	return n
}

func (sl *shardedLimiter) Stop() {
	sl.stopped.Do(func() { close(sl.stopCh) })
}

func shardIndex(ip netip.Addr) uint32 {
	const offset32 = 2166136261
	const prime32 = 16777619
	h := uint32(offset32)
	for _, b := range ip.AsSlice() {
		h ^= uint32(b)
		h *= prime32
	}
	return h % numShards
}
