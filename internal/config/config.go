// Package config loads and validates go-firewall's YAML configuration.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    []ListenConfig  `yaml:"listen"`
	Upstreams UpstreamConfig  `yaml:"upstreams"`
	IPLists   IPListConfig    `yaml:"ip_lists"`
	Admin     AdminConfig     `yaml:"admin"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	WAF       WAFConfig       `yaml:"waf"`
	Log       LogConfig       `yaml:"log"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Shutdown  ShutdownConfig  `yaml:"shutdown"`
}

type ListenConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type UpstreamConfig struct {
	Addresses             []string `yaml:"addresses"`
	DialTimeout           Duration `yaml:"dial_timeout"`
	ResponseHeaderTimeout Duration `yaml:"response_header_timeout"`
	IdleConnTimeout       Duration `yaml:"idle_conn_timeout"`
	MaxIdleConnsPerHost   int      `yaml:"max_idle_conns_per_host"`
}

type IPListConfig struct {
	Allow []string  `yaml:"allow"`
	Deny  []string  `yaml:"deny"`
	Geo   GeoConfig `yaml:"geo"`
}

type GeoConfig struct {
	Enabled        bool     `yaml:"enabled"`
	DBPath         string   `yaml:"db_path"`
	AllowCountries []string `yaml:"allow_countries"`
}

type AdminConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Address      string `yaml:"address"`
	AuthTokenEnv string `yaml:"auth_token_env"`
}

type RateLimitConfig struct {
	Enabled  bool             `yaml:"enabled"`
	Default  RateLimitRule    `yaml:"default"`
	PerRoute []RouteRateLimit `yaml:"per_route"`
	IdleTTL  Duration         `yaml:"idle_ttl"`
}

type RateLimitRule struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type RouteRateLimit struct {
	PathPrefix string `yaml:"path_prefix"`
	RateLimitRule `yaml:",inline"`
}

type WAFConfig struct {
	Enabled        bool                 `yaml:"enabled"`
	RulesFile      string               `yaml:"rules_file"`
	BodyInspection BodyInspectionConfig `yaml:"body_inspection"`
	DefaultAction  string               `yaml:"default_action"`
}

type BodyInspectionConfig struct {
	MaxBytes int64 `yaml:"max_bytes"`
}

type LogConfig struct {
	Level          string `yaml:"level"`
	AccessLogPath  string `yaml:"access_log_path"`
	Format         string `yaml:"format"`
	RingBufferSize int    `yaml:"ring_buffer_size"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Path    string `yaml:"path"`
}

type ShutdownConfig struct {
	DrainTimeout Duration `yaml:"drain_timeout"`
}

// Load reads, parses, defaults, and validates the config at path. It fails
// fast: any parse or validation error is returned before the caller can
// bind a socket.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Upstreams.DialTimeout.Duration == 0 {
		c.Upstreams.DialTimeout.Duration = 2 * time.Second
	}
	if c.Upstreams.ResponseHeaderTimeout.Duration == 0 {
		c.Upstreams.ResponseHeaderTimeout.Duration = 10 * time.Second
	}
	if c.Upstreams.IdleConnTimeout.Duration == 0 {
		c.Upstreams.IdleConnTimeout.Duration = 90 * time.Second
	}
	if c.Upstreams.MaxIdleConnsPerHost == 0 {
		c.Upstreams.MaxIdleConnsPerHost = 100
	}
	if c.RateLimit.IdleTTL.Duration == 0 {
		c.RateLimit.IdleTTL.Duration = 10 * time.Minute
	}
	if c.WAF.BodyInspection.MaxBytes == 0 {
		c.WAF.BodyInspection.MaxBytes = 131072
	}
	if c.WAF.DefaultAction == "" {
		c.WAF.DefaultAction = "block"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	if c.Log.AccessLogPath == "" {
		c.Log.AccessLogPath = "-"
	}
	if c.Log.RingBufferSize == 0 {
		c.Log.RingBufferSize = 1000
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = "127.0.0.1:9090"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.Admin.Address == "" {
		c.Admin.Address = "127.0.0.1:9091"
	}
	if c.Shutdown.DrainTimeout.Duration == 0 {
		c.Shutdown.DrainTimeout.Duration = 30 * time.Second
	}
}

// Validate performs structural, self-contained checks that don't require
// pulling in other subsystems (rules-file parsing, geo-DB opening, etc. are
// validated by their owning packages at startup so config stays a leaf
// package with no cross-subsystem imports).
func (c *Config) Validate() error {
	if len(c.Listen) == 0 {
		return fmt.Errorf("listen: at least one listener is required")
	}
	for i, l := range c.Listen {
		if l.Address == "" {
			return fmt.Errorf("listen[%d]: address is required", i)
		}
		if l.TLS.Enabled {
			if l.TLS.CertFile == "" || l.TLS.KeyFile == "" {
				return fmt.Errorf("listen[%d]: tls.cert_file and tls.key_file are required when tls.enabled is true", i)
			}
		}
	}

	if len(c.Upstreams.Addresses) == 0 {
		return fmt.Errorf("upstreams.addresses: at least one upstream is required")
	}
	for _, addr := range c.Upstreams.Addresses {
		u, err := url.Parse(addr)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("upstreams.addresses: invalid upstream URL %q", addr)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("upstreams.addresses: unsupported scheme in %q (want http or https)", addr)
		}
	}

	if err := validateCIDRs("ip_lists.allow", c.IPLists.Allow); err != nil {
		return err
	}
	if err := validateCIDRs("ip_lists.deny", c.IPLists.Deny); err != nil {
		return err
	}
	if c.IPLists.Geo.Enabled && len(c.IPLists.Geo.AllowCountries) > 0 {
		if c.IPLists.Geo.DBPath == "" {
			return fmt.Errorf("ip_lists.geo: db_path is required when geo.enabled is true")
		}
		for _, cc := range c.IPLists.Geo.AllowCountries {
			if len(cc) != 2 || strings.ToUpper(cc) != cc {
				return fmt.Errorf("ip_lists.geo.allow_countries: %q is not a valid uppercase ISO 3166-1 alpha-2 code", cc)
			}
		}
	}

	if c.RateLimit.Enabled {
		if c.RateLimit.Default.RequestsPerSecond <= 0 {
			return fmt.Errorf("rate_limit.default.requests_per_second must be > 0")
		}
		if c.RateLimit.Default.Burst <= 0 {
			return fmt.Errorf("rate_limit.default.burst must be > 0")
		}
		for i, r := range c.RateLimit.PerRoute {
			if r.PathPrefix == "" {
				return fmt.Errorf("rate_limit.per_route[%d]: path_prefix is required", i)
			}
			if r.RequestsPerSecond <= 0 || r.Burst <= 0 {
				return fmt.Errorf("rate_limit.per_route[%d]: requests_per_second and burst must be > 0", i)
			}
		}
	}

	if c.WAF.Enabled {
		if c.WAF.RulesFile == "" {
			return fmt.Errorf("waf.rules_file is required when waf.enabled is true")
		}
		if _, err := os.Stat(c.WAF.RulesFile); err != nil {
			return fmt.Errorf("waf.rules_file: %w", err)
		}
		if c.WAF.DefaultAction != "block" && c.WAF.DefaultAction != "log-only" {
			return fmt.Errorf("waf.default_action must be %q or %q", "block", "log-only")
		}
	}

	if c.Admin.Enabled && c.Admin.AuthTokenEnv == "" {
		return fmt.Errorf("admin.auth_token_env is required when admin.enabled is true")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level must be one of debug|info|warn|error, got %q", c.Log.Level)
	}

	return nil
}

func validateCIDRs(field string, cidrs []string) error {
	for _, c := range cidrs {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("%s: invalid CIDR %q: %w", field, c, err)
		}
	}
	return nil
}
