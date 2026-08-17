// Package middleware provides the shared handler-chaining helper and the
// Recorder inner middlewares use to report a request's outcome back up to
// the outermost logging middleware.
package middleware

import (
	"context"
	"net/http"
	"sync"
)

type Middleware func(http.Handler) http.Handler

// Chain wraps h with mws in order, so mws[0] is outermost (runs first).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Outcome is the final allowed/blocked disposition of a request.
type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeBlocked Outcome = "blocked"
)

// BlockReason identifies which pipeline stage blocked a request.
type BlockReason string

const (
	BlockReasonIPDeny        BlockReason = "ip-deny"
	BlockReasonGeoDeny       BlockReason = "geo-deny"
	BlockReasonRateLimit     BlockReason = "rate-limit"
	BlockReasonWAF           BlockReason = "waf"
	BlockReasonUpstreamError BlockReason = "upstream-error"
)

// Recorder is a per-request, mutable sink that inner middlewares write
// outcome information into as they make decisions. Because a plain
// context.Context value set deeper in a call chain is never visible to an
// ancestor caller, the outermost logging middleware instead creates one
// Recorder, stores a pointer to it in the context it passes downstream, and
// reads the same pointer's fields back after ServeHTTP returns.
type Recorder struct {
	mu             sync.Mutex
	outcome        Outcome
	blockReason    BlockReason
	wafRuleID      int
	wafCategory    string
	upstream       string
	upstreamStatus int
	requestID      string
}

func NewRecorder(requestID string) *Recorder {
	return &Recorder{outcome: OutcomeAllowed, requestID: requestID}
}

func (r *Recorder) SetBlocked(reason BlockReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outcome = OutcomeBlocked
	r.blockReason = reason
}

func (r *Recorder) SetWAFMatch(ruleID int, category string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wafRuleID = ruleID
	r.wafCategory = category
}

func (r *Recorder) SetUpstream(addr string, status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upstream = addr
	r.upstreamStatus = status
}

// Snapshot is a point-in-time, race-free copy of a Recorder's fields.
type Snapshot struct {
	Outcome        Outcome
	BlockReason    BlockReason
	WAFRuleID      int
	WAFCategory    string
	Upstream       string
	UpstreamStatus int
	RequestID      string
}

func (r *Recorder) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Snapshot{
		Outcome:        r.outcome,
		BlockReason:    r.blockReason,
		WAFRuleID:      r.wafRuleID,
		WAFCategory:    r.wafCategory,
		Upstream:       r.upstream,
		UpstreamStatus: r.upstreamStatus,
		RequestID:      r.requestID,
	}
}

type recorderCtxKey struct{}

func WithRecorder(ctx context.Context, rec *Recorder) context.Context {
	return context.WithValue(ctx, recorderCtxKey{}, rec)
}

func RecorderFrom(ctx context.Context) (*Recorder, bool) {
	rec, ok := ctx.Value(recorderCtxKey{}).(*Recorder)
	return rec, ok
}
