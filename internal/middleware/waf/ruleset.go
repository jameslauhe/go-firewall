package waf

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// RuleSet is a compiled, immutable snapshot of the WAF ruleset, grouped by
// target so matching does one pass per request field rather than testing
// every rule against every field.
type RuleSet struct {
	all         []Rule
	lineRules   []Rule
	pathRules   []Rule
	queryRules  []Rule
	bodyRules   []Rule
	headerRules map[string][]Rule // canonical header name, "" = all headers
}

const (
	ActionBlock = "block"
	ActionLog   = "log"
)

// LoadRuleSet reads, parses, and compiles the rules file at path. Every
// pattern is compiled with the stdlib RE2 engine (regexp), not a
// backtracking engine — RE2's linear-time matching guarantee means the WAF
// itself can't be turned into a ReDoS vector by attacker-controlled input.
func LoadRuleSet(path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("waf: open rules file: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var rf ruleFile
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("waf: parse rules file: %w", err)
	}

	rs := &RuleSet{headerRules: map[string][]Rule{}}
	seen := map[int]bool{}

	for _, r := range rf.Rules {
		if r.ID == 0 {
			return nil, fmt.Errorf("waf: rule missing id")
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("waf: duplicate rule id %d", r.ID)
		}
		seen[r.ID] = true

		if r.Action != ActionBlock && r.Action != ActionLog {
			return nil, fmt.Errorf("waf: rule %d: action must be %q or %q, got %q", r.ID, ActionBlock, ActionLog, r.Action)
		}
		if len(r.Targets) == 0 {
			return nil, fmt.Errorf("waf: rule %d: at least one target is required", r.ID)
		}

		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("waf: rule %d: invalid pattern: %w", r.ID, err)
		}
		r.compiled = compiled

		rs.all = append(rs.all, r)

		for _, t := range r.Targets {
			switch {
			case t == "line":
				rs.lineRules = append(rs.lineRules, r)
			case t == "path":
				rs.pathRules = append(rs.pathRules, r)
			case t == "query":
				rs.queryRules = append(rs.queryRules, r)
			case t == "body":
				rs.bodyRules = append(rs.bodyRules, r)
			case t == "headers":
				rs.headerRules[""] = append(rs.headerRules[""], r)
			case strings.HasPrefix(t, "headers:"):
				name := http.CanonicalHeaderKey(strings.TrimPrefix(t, "headers:"))
				rs.headerRules[name] = append(rs.headerRules[name], r)
			default:
				return nil, fmt.Errorf("waf: rule %d: unknown target %q", r.ID, t)
			}
		}
	}

	return rs, nil
}

func (rs *RuleSet) RuleCount() int {
	return len(rs.all)
}
