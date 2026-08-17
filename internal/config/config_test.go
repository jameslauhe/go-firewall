package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

const minimalValidConfig = `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
`

func TestLoad_ValidMinimalConfig(t *testing.T) {
	path := writeTempConfig(t, minimalValidConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if len(cfg.Listen) != 1 || cfg.Listen[0].Address != "0.0.0.0:8080" {
		t.Errorf("unexpected listen config: %+v", cfg.Listen)
	}
	if cfg.Upstreams.DialTimeout.Duration.Seconds() != 2 {
		t.Errorf("expected default dial_timeout of 2s, got %v", cfg.Upstreams.DialTimeout.Duration)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("expected default log level info, got %q", cfg.Log.Level)
	}
}

func TestLoad_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"missing listen", `
upstreams:
  addresses: ["http://127.0.0.1:9999"]
`, true},
		{"missing upstreams", `
listen:
  - address: "0.0.0.0:8080"
`, true},
		{"invalid upstream url", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["not-a-url"]
`, true},
		{"unsupported upstream scheme", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["ftp://127.0.0.1:9999"]
`, true},
		{"tls enabled without cert", `
listen:
  - address: "0.0.0.0:8443"
    tls:
      enabled: true
upstreams:
  addresses: ["http://127.0.0.1:9999"]
`, true},
		{"invalid deny cidr", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
ip_lists:
  deny: ["not-a-cidr"]
`, true},
		{"valid deny cidr", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
ip_lists:
  deny: ["203.0.113.0/24"]
`, false},
		{"geo enabled without db_path", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
ip_lists:
  geo:
    enabled: true
    allow_countries: ["SG"]
`, true},
		{"geo lowercase country code rejected", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
ip_lists:
  geo:
    enabled: true
    db_path: "/tmp/does-not-matter.mmdb"
    allow_countries: ["sg"]
`, true},
		{"rate limit enabled with zero rps", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
rate_limit:
  enabled: true
  default:
    requests_per_second: 0
    burst: 10
`, true},
		{"waf enabled without rules file", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
waf:
  enabled: true
`, true},
		{"admin enabled without auth token env", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
admin:
  enabled: true
`, true},
		{"unknown field rejected", `
listen:
  - address: "0.0.0.0:8080"
upstreams:
  addresses: ["http://127.0.0.1:9999"]
totally_unknown_field: true
`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, tt.yaml)
			_, err := Load(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
}
