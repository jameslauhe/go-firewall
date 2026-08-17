package waf

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRulesFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	return path
}

func TestLoadRuleSet_Valid(t *testing.T) {
	path := writeRulesFile(t, `
rules:
  - id: 1
    category: sqli
    severity: high
    action: block
    targets: [query]
    pattern: "union select"
  - id: 2
    category: xss
    severity: medium
    action: log
    targets: ["headers:User-Agent"]
    pattern: "<script"
`)
	rs, err := LoadRuleSet(path)
	if err != nil {
		t.Fatalf("LoadRuleSet: %v", err)
	}
	if rs.RuleCount() != 2 {
		t.Errorf("RuleCount() = %d, want 2", rs.RuleCount())
	}
	if len(rs.queryRules) != 1 {
		t.Errorf("expected 1 query rule, got %d", len(rs.queryRules))
	}
	if len(rs.headerRules["User-Agent"]) != 1 {
		t.Errorf("expected 1 User-Agent header rule, got %d", len(rs.headerRules["User-Agent"]))
	}
}

func TestLoadRuleSet_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"missing id", `rules: [{category: sqli, action: block, targets: [query], pattern: "x"}]`, true},
		{"duplicate id", `
rules:
  - {id: 1, category: sqli, action: block, targets: [query], pattern: "x"}
  - {id: 1, category: xss, action: block, targets: [query], pattern: "y"}
`, true},
		{"invalid action", `rules: [{id: 1, category: sqli, action: deny, targets: [query], pattern: "x"}]`, true},
		{"no targets", `rules: [{id: 1, category: sqli, action: block, targets: [], pattern: "x"}]`, true},
		{"unknown target", `rules: [{id: 1, category: sqli, action: block, targets: [cookie], pattern: "x"}]`, true},
		{"invalid regex", `rules: [{id: 1, category: sqli, action: block, targets: [query], pattern: "("}]`, true},
		{"valid minimal", `rules: [{id: 1, category: sqli, action: block, targets: [query], pattern: "x"}]`, false},
		{"unknown field rejected", `rules: [{id: 1, category: sqli, action: block, targets: [query], pattern: "x", bogus: true}]`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeRulesFile(t, tt.yaml)
			_, err := LoadRuleSet(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadRuleSet() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRuleSet_MissingFile(t *testing.T) {
	if _, err := LoadRuleSet("/nonexistent/rules.yaml"); err == nil {
		t.Fatal("expected error for missing rules file")
	}
}

func TestLoadRuleSet_SeedRuleSetLoads(t *testing.T) {
	rs, err := LoadRuleSet("../../../configs/rules/default.yaml")
	if err != nil {
		t.Fatalf("LoadRuleSet(default.yaml): %v", err)
	}
	if rs.RuleCount() < 15 {
		t.Errorf("expected at least 15 seed rules, got %d", rs.RuleCount())
	}
}
