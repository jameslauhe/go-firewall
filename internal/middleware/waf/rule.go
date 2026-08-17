// Package waf implements the signature-based rule matching engine: the
// last, most expensive pipeline stage, run only against requests that
// already passed IP filtering and rate limiting.
package waf

import "regexp"

// Rule is a single WAF signature, loaded from YAML and compiled once at
// load time.
type Rule struct {
	ID          int      `yaml:"id"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Action      string   `yaml:"action"` // block | log
	Description string   `yaml:"description"`
	Targets     []string `yaml:"targets"`
	Pattern     string   `yaml:"pattern"`

	compiled *regexp.Regexp
}
