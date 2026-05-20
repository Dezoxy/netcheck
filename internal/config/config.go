// Package config loads netcheck's optional YAML config file and applies
// environment-variable overrides. Every field is optional — missing files,
// missing keys, and parse errors all degrade to compiled-in defaults so the
// CLI keeps working without a config.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the user-overridable defaults for a netcheck run.
type Config struct {
	Timeout         time.Duration   `yaml:"timeout"`
	UserAgent       string          `yaml:"user_agent"`
	FollowRedirects bool            `yaml:"follow_redirects"`
	MaxRedirects    int             `yaml:"max_redirects"`
	PreferIPv6      bool            `yaml:"prefer_ipv6"`
	Resolvers       []ResolverEntry `yaml:"resolvers"`

	// Source records where the config came from, for `netcheck config show`
	// and debugging. Empty when no file loaded — built-in defaults only.
	Source string `yaml:"-"`
}

// ResolverEntry is one named DNS resolver loaded from config.
//
// Type is one of "udp" (default), "tcp", "dot", or "doh".
// For udp/tcp/dot, Address is "host" or "host:port"; for doh, it's a full URL.
type ResolverEntry struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Type    string `yaml:"type,omitempty"`
}

// Defaults returns the compile-time built-in values used when no config and no
// env vars are present. These match the existing per-command flag defaults
// to keep behavior identical for users who never write a config.
func Defaults() *Config {
	return &Config{
		Timeout:         10 * time.Second,
		UserAgent:       "", // empty → callers fill in "netcheck/<version>"
		FollowRedirects: true,
		MaxRedirects:    10,
		PreferIPv6:      false,
	}
}

// Load returns the merged config from (in order of precedence, lowest first):
// 1. compiled-in defaults
// 2. YAML file at the first existing default-search path (or `path` if given)
// 3. environment variables NETCHECK_TIMEOUT, NETCHECK_USER_AGENT
//
// A missing config file is not an error. Parse errors return a Config equal to
// defaults plus the error, so callers can warn but continue.
func Load(explicitPath string) (*Config, error) {
	cfg := Defaults()

	path := resolvePath(explicitPath)
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return cfg, fmt.Errorf("parsing %s: %w", path, err)
			}
			cfg.Source = path
			// yaml.Unmarshal of a partial doc leaves defaults intact only for
			// pointer/slice fields. Re-apply default booleans/ints if the doc
			// didn't set them — we detect this by re-parsing into a map.
			cfg = applyDefaultsForMissingScalars(cfg, data)
		}
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// resolvePath returns the path to read, or "" if no candidate exists.
// Search order: explicit arg → NETCHECK_CONFIG env → $XDG_CONFIG_HOME/netcheck/config.yaml → ~/.config/netcheck/config.yaml.
func resolvePath(explicitPath string) string {
	if explicitPath != "" {
		if exists(explicitPath) {
			return explicitPath
		}
		return "" // explicit path missing → fall back to no file (don't search)
	}
	if v := os.Getenv("NETCHECK_CONFIG"); v != "" && exists(v) {
		return v
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		p := filepath.Join(xdg, "netcheck", "config.yaml")
		if exists(p) {
			return p
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".config", "netcheck", "config.yaml")
		if exists(p) {
			return p
		}
	}
	return ""
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("NETCHECK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Timeout = d
		}
	}
	if v := os.Getenv("NETCHECK_USER_AGENT"); v != "" {
		cfg.UserAgent = v
	}
}

// applyDefaultsForMissingScalars re-fills boolean/int defaults that YAML
// unmarshalling overrode with zero values when the key wasn't present.
// This is the standard Go-config gotcha: yaml.Unmarshal sets unset bools to
// false, not "leave alone". We peek at the raw doc to see which keys exist.
func applyDefaultsForMissingScalars(cfg *Config, data []byte) *Config {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return cfg
	}
	defaults := Defaults()
	if _, ok := raw["follow_redirects"]; !ok {
		cfg.FollowRedirects = defaults.FollowRedirects
	}
	if _, ok := raw["max_redirects"]; !ok {
		cfg.MaxRedirects = defaults.MaxRedirects
	}
	if _, ok := raw["prefer_ipv6"]; !ok {
		cfg.PreferIPv6 = defaults.PreferIPv6
	}
	if _, ok := raw["timeout"]; !ok {
		cfg.Timeout = defaults.Timeout
	}
	return cfg
}
