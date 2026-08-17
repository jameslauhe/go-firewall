package waf

import (
	"net/http"
	"testing"
)

func overrideTestEngine(t *testing.T) *Engine {
	t.Helper()
	return newTestEngine(t, `
rules:
  - id: 1
    category: test
    action: block
    targets: [query]
    pattern: "attack"
  - id: 2
    category: test
    action: log
    targets: [query]
    pattern: "suspicious"
`)
}

func TestEngine_SetOverride_DisableRule(t *testing.T) {
	e := overrideTestEngine(t)

	blocked, _ := inspectRequest(t, e, http.MethodGet, "/x?q=attack", "")
	if !blocked {
		t.Fatal("expected rule 1 to block before any override")
	}

	if err := e.SetOverride(1, false, ""); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	blockedAfter, _ := inspectRequest(t, e, http.MethodGet, "/x?q=attack", "")
	if blockedAfter {
		t.Error("expected disabled rule to no longer block")
	}
}

func TestEngine_SetOverride_ForceAction(t *testing.T) {
	e := overrideTestEngine(t)

	// Rule 2 defaults to log (never blocks). Force it to block.
	if err := e.SetOverride(2, true, ActionBlock); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	blocked, match := inspectRequest(t, e, http.MethodGet, "/x?q=suspicious", "")
	if !blocked || match.ID != 2 {
		t.Fatalf("expected rule 2 to block after forcing action=block, blocked=%v", blocked)
	}
}

func TestEngine_SetOverride_UnknownRuleID(t *testing.T) {
	e := overrideTestEngine(t)
	if err := e.SetOverride(999, true, ""); err == nil {
		t.Fatal("expected error overriding an unknown rule id")
	}
}

func TestEngine_SetOverride_InvalidAction(t *testing.T) {
	e := overrideTestEngine(t)
	if err := e.SetOverride(1, true, "nonsense"); err == nil {
		t.Fatal("expected error for an invalid action override")
	}
}

func TestEngine_ClearOverride_RevertsToOriginal(t *testing.T) {
	e := overrideTestEngine(t)

	if err := e.SetOverride(1, false, ""); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	blocked, _ := inspectRequest(t, e, http.MethodGet, "/x?q=attack", "")
	if blocked {
		t.Fatal("expected rule to be disabled")
	}

	e.ClearOverride(1)
	blockedAfterClear, _ := inspectRequest(t, e, http.MethodGet, "/x?q=attack", "")
	if !blockedAfterClear {
		t.Error("expected rule to block again after clearing its override")
	}
}

func TestEngine_ListRules_ReflectsOverrides(t *testing.T) {
	e := overrideTestEngine(t)
	if err := e.SetOverride(1, false, ""); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	rules := e.ListRules()
	if len(rules) != 2 {
		t.Fatalf("ListRules() returned %d rules, want 2", len(rules))
	}
	var rule1 *RuleInfo
	for i := range rules {
		if rules[i].ID == 1 {
			rule1 = &rules[i]
		}
	}
	if rule1 == nil {
		t.Fatal("rule 1 missing from ListRules()")
	}
	if rule1.Enabled {
		t.Error("expected rule 1 to show as disabled")
	}
	if !rule1.Overridden {
		t.Error("expected rule 1 to show as overridden")
	}
}
