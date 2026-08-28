package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateStore_SaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStateStore(path)

	want := State{
		IPLists: IPListState{
			AllowAdded:   []string{"10.0.0.0/8"},
			AllowRemoved: []string{},
			DenyAdded:    []string{"203.0.113.0/24", "198.51.100.0/24"},
			DenyRemoved:  []string{"192.0.2.0/24"},
		},
		WAFOverrides: map[int]WAFOverride{
			1: {Enabled: false, Action: ""},
			2: {Enabled: true, Action: "log"},
		},
	}

	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(got.IPLists.AllowAdded) != 1 || got.IPLists.AllowAdded[0] != "10.0.0.0/8" {
		t.Errorf("AllowAdded = %v, want [10.0.0.0/8]", got.IPLists.AllowAdded)
	}
	if len(got.IPLists.DenyAdded) != 2 {
		t.Errorf("DenyAdded = %v, want 2 entries", got.IPLists.DenyAdded)
	}
	if len(got.IPLists.DenyRemoved) != 1 || got.IPLists.DenyRemoved[0] != "192.0.2.0/24" {
		t.Errorf("DenyRemoved = %v, want [192.0.2.0/24]", got.IPLists.DenyRemoved)
	}
	if len(got.WAFOverrides) != 2 {
		t.Fatalf("WAFOverrides = %v, want 2 entries", got.WAFOverrides)
	}
	if o := got.WAFOverrides[1]; o.Enabled || o.Action != "" {
		t.Errorf("WAFOverrides[1] = %+v, want {Enabled:false Action:\"\"}", o)
	}
	if o := got.WAFOverrides[2]; !o.Enabled || o.Action != "log" {
		t.Errorf("WAFOverrides[2] = %+v, want {Enabled:true Action:log}", o)
	}
}

func TestStateStore_LoadMissingFileReturnsZeroState(t *testing.T) {
	store := NewStateStore(filepath.Join(t.TempDir(), "does-not-exist.json"))
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: unexpected error for a missing file: %v", err)
	}
	if len(state.IPLists.AllowAdded) != 0 || len(state.WAFOverrides) != 0 {
		t.Errorf("expected a zero State for a missing file, got %+v", state)
	}
}

func TestStateStore_LoadCorruptFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt state file: %v", err)
	}
	store := NewStateStore(path)
	if _, err := store.Load(); err == nil {
		t.Fatal("expected an error loading a corrupt state file")
	}
}

func TestStateStore_SaveLeavesNoTempFilesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store := NewStateStore(path)

	if err := store.Save(State{WAFOverrides: map[int]WAFOverride{}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory contents = %v, want only state.json (no leftover temp files)", names)
	}
}

func TestStateStore_SaveOverwritesPreviousContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStateStore(path)

	if err := store.Save(State{IPLists: IPListState{DenyAdded: []string{"1.2.3.0/24"}}, WAFOverrides: map[int]WAFOverride{}}); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := store.Save(State{IPLists: IPListState{DenyAdded: []string{"5.6.7.0/24"}}, WAFOverrides: map[int]WAFOverride{}}); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.IPLists.DenyAdded) != 1 || got.IPLists.DenyAdded[0] != "5.6.7.0/24" {
		t.Errorf("DenyAdded = %v, want [5.6.7.0/24] (second save should fully replace the first)", got.IPLists.DenyAdded)
	}
}
