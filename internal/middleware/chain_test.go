package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestChain_OrderingOutermostFirst(t *testing.T) {
	var order []string
	mkMiddleware := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name+":before")
				next.ServeHTTP(w, r)
				order = append(order, name+":after")
			})
		}
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	h := Chain(final, mkMiddleware("a"), mkMiddleware("b"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"a:before", "b:before", "handler", "b:after", "a:after"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("order[%d] = %q, want %q", i, order[i], want[i])
		}
	}
}

func TestChain_NoMiddlewares(t *testing.T) {
	called := false
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	Chain(final).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("expected final handler to run with zero middlewares")
	}
}

func TestRecorder_DefaultsToAllowed(t *testing.T) {
	rec := NewRecorder("req-1")
	snap := rec.Snapshot()
	if snap.Outcome != OutcomeAllowed {
		t.Errorf("default outcome = %v, want allowed", snap.Outcome)
	}
	if snap.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want req-1", snap.RequestID)
	}
	if rec.RequestID() != "req-1" {
		t.Errorf("RequestID() accessor = %q, want req-1", rec.RequestID())
	}
}

func TestRecorder_SetBlockedAndWAFMatch(t *testing.T) {
	rec := NewRecorder("req-2")
	rec.SetBlocked(BlockReasonWAF)
	rec.SetWAFMatch(942100, "sqli")

	snap := rec.Snapshot()
	if snap.Outcome != OutcomeBlocked || snap.BlockReason != BlockReasonWAF {
		t.Errorf("outcome/reason = %v/%v, want blocked/waf", snap.Outcome, snap.BlockReason)
	}
	if snap.WAFRuleID != 942100 || snap.WAFCategory != "sqli" {
		t.Errorf("waf match = %d/%q, want 942100/sqli", snap.WAFRuleID, snap.WAFCategory)
	}
}

func TestRecorder_SetUpstreamAndErrorReason(t *testing.T) {
	rec := NewRecorder("req-3")
	rec.SetUpstream("10.0.0.1:8080", 502)
	rec.SetUpstreamErrorReason("timeout")

	snap := rec.Snapshot()
	if snap.Upstream != "10.0.0.1:8080" || snap.UpstreamStatus != 502 {
		t.Errorf("upstream/status = %q/%d, want 10.0.0.1:8080/502", snap.Upstream, snap.UpstreamStatus)
	}
	if snap.UpstreamErrorReason != "timeout" {
		t.Errorf("upstream error reason = %q, want timeout", snap.UpstreamErrorReason)
	}
}

func TestRecorder_ConcurrentAccess(t *testing.T) {
	rec := NewRecorder("req-4")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec.SetBlocked(BlockReasonRateLimit)
			_ = rec.Snapshot()
		}()
	}
	wg.Wait() // must complete without the race detector flagging anything
}

func TestWithRecorder_RoundTrip(t *testing.T) {
	rec := NewRecorder("req-5")
	ctx := WithRecorder(t.Context(), rec)

	got, ok := RecorderFrom(ctx)
	if !ok || got != rec {
		t.Fatal("expected RecorderFrom to return the same Recorder pointer stored by WithRecorder")
	}
}

func TestRecorderFrom_AbsentInContext(t *testing.T) {
	_, ok := RecorderFrom(t.Context())
	if ok {
		t.Error("expected RecorderFrom to report false when no Recorder was attached")
	}
}

func TestAttachRecorder_CreatesFreshRecorderPerRequest(t *testing.T) {
	var seen []*Recorder
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, ok := RecorderFrom(r.Context())
		if !ok {
			t.Fatal("expected AttachRecorder to have set a Recorder in context")
		}
		seen = append(seen, rec)
	})
	h := AttachRecorder(next)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if len(seen) != 2 || seen[0] == seen[1] {
		t.Fatal("expected two distinct Recorder instances, one per request")
	}
	if seen[0].RequestID() == seen[1].RequestID() {
		t.Error("expected distinct request IDs across requests")
	}
}
