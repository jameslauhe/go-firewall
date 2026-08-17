package log

import "sync"

// RingBuffer is a fixed-capacity, thread-safe circular buffer of Entry
// values. It exists so the admin dashboard can show recent requests
// without tailing wherever the JSON log stream is actually written to
// (stdout, a file, a log shipper).
type RingBuffer struct {
	mu      sync.Mutex
	entries []Entry
	next    int
	size    int
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &RingBuffer{entries: make([]Entry, capacity)}
}

func (rb *RingBuffer) Add(e Entry) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	cap := len(rb.entries)
	rb.entries[rb.next] = e
	rb.next = (rb.next + 1) % cap
	if rb.size < cap {
		rb.size++
	}
}

// Recent returns up to limit entries newest-first, optionally restricted
// by filter. A non-positive limit returns all retained entries.
func (rb *RingBuffer) Recent(limit int, filter func(Entry) bool) []Entry {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	cap := len(rb.entries)
	out := make([]Entry, 0, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.next - 1 - i + cap) % cap
		e := rb.entries[idx]
		if filter != nil && !filter(e) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}
