package log

import "testing"

func TestRingBuffer_RecentNewestFirst(t *testing.T) {
	rb := NewRingBuffer(3)
	rb.Add(Entry{RequestID: "1"})
	rb.Add(Entry{RequestID: "2"})
	rb.Add(Entry{RequestID: "3"})

	got := rb.Recent(0, nil)
	want := []string{"3", "2", "1"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i, e := range got {
		if e.RequestID != want[i] {
			t.Errorf("entry[%d] = %q, want %q", i, e.RequestID, want[i])
		}
	}
}

func TestRingBuffer_WrapsAtCapacity(t *testing.T) {
	rb := NewRingBuffer(2)
	rb.Add(Entry{RequestID: "1"})
	rb.Add(Entry{RequestID: "2"})
	rb.Add(Entry{RequestID: "3"}) // evicts "1"

	got := rb.Recent(0, nil)
	want := []string{"3", "2"}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	for i, e := range got {
		if e.RequestID != want[i] {
			t.Errorf("entry[%d] = %q, want %q", i, e.RequestID, want[i])
		}
	}
}

func TestRingBuffer_LimitAndFilter(t *testing.T) {
	rb := NewRingBuffer(10)
	rb.Add(Entry{RequestID: "1", Outcome: "allowed"})
	rb.Add(Entry{RequestID: "2", Outcome: "blocked"})
	rb.Add(Entry{RequestID: "3", Outcome: "blocked"})

	got := rb.Recent(1, func(e Entry) bool { return e.Outcome == "blocked" })
	if len(got) != 1 || got[0].RequestID != "3" {
		t.Errorf("got %+v, want single most-recent blocked entry (id 3)", got)
	}
}
