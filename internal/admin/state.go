package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// State is the persisted form of every admin-dashboard edit: IP-list
// overlay entries and WAF per-rule overrides. It mirrors, rather than
// replaces, the in-memory structures ipfilter.Filter and waf.Engine
// already track — persistence is purely a side effect layered on top of
// their existing mutation methods.
type State struct {
	IPLists      IPListState         `json:"ip_lists"`
	WAFOverrides map[int]WAFOverride `json:"waf_overrides"`
}

// IPListState is the current admin-added/removed CIDR sets — not an
// ordered log of operations. ipfilter.Filter maintains the invariant that
// a CIDR lives in at most one of an "added" and "removed" set at a time,
// which makes those sets commutative to replay in any order (no need to
// track "remove X then re-add X" as a sequence — the current sets already
// capture the correct end state).
type IPListState struct {
	AllowAdded   []string `json:"allow_added"`
	AllowRemoved []string `json:"allow_removed"`
	DenyAdded    []string `json:"deny_added"`
	DenyRemoved  []string `json:"deny_removed"`
}

// WAFOverride mirrors waf.RuleInfo's override-relevant fields for one rule.
type WAFOverride struct {
	Enabled bool   `json:"enabled"`
	Action  string `json:"action"`
}

// StateStore reads and writes admin state to a JSON file.
type StateStore struct {
	path string
}

func NewStateStore(path string) *StateStore {
	return &StateStore{path: path}
}

// Load reads the state file, returning a zero State (not an error) if the
// file doesn't exist yet — the common case for a first-ever run with
// state_file newly configured.
func (s *StateStore) Load() (State, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("admin: read state file: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("admin: parse state file: %w", err)
	}
	return state, nil
}

// Save atomically writes state to disk: it writes to a temp file in the
// same directory, then renames over the target, so a reader (or a crash
// mid-write) never observes a partially written file.
func (s *StateStore) Save(state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("admin: marshal state: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("admin: create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("admin: write temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("admin: close temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("admin: rename temp state file into place: %w", err)
	}
	return nil
}
