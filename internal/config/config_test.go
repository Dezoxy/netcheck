package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsApplied(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}
	if !cfg.FollowRedirects {
		t.Errorf("FollowRedirects = false, want true")
	}
	if cfg.MaxRedirects != 10 {
		t.Errorf("MaxRedirects = %d, want 10", cfg.MaxRedirects)
	}
}

func TestLoadYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
timeout: 7s
user_agent: my-netcheck/1.0
follow_redirects: false
max_redirects: 3
resolvers:
  - name: cloudflare-doh
    address: https://cloudflare-dns.com/dns-query
    type: doh
  - name: quad9
    address: 9.9.9.9
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source != path {
		t.Errorf("Source = %q, want %q", cfg.Source, path)
	}
	if cfg.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s", cfg.Timeout)
	}
	if cfg.UserAgent != "my-netcheck/1.0" {
		t.Errorf("UserAgent = %q", cfg.UserAgent)
	}
	if cfg.FollowRedirects {
		t.Errorf("FollowRedirects = true, want false (explicitly set)")
	}
	if cfg.MaxRedirects != 3 {
		t.Errorf("MaxRedirects = %d, want 3", cfg.MaxRedirects)
	}
	if len(cfg.Resolvers) != 2 {
		t.Fatalf("Resolvers len = %d, want 2", len(cfg.Resolvers))
	}
	if cfg.Resolvers[0].Type != "doh" || cfg.Resolvers[0].Address != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("Resolvers[0] = %+v", cfg.Resolvers[0])
	}
	if cfg.Resolvers[1].Type != "" {
		// Type omitted → callers treat as "udp"
		t.Errorf("Resolvers[1].Type = %q, want empty (default udp)", cfg.Resolvers[1].Type)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("NETCHECK_TIMEOUT", "3s")
	t.Setenv("NETCHECK_USER_AGENT", "ci-runner/2")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", cfg.Timeout)
	}
	if cfg.UserAgent != "ci-runner/2" {
		t.Errorf("UserAgent = %q, want ci-runner/2", cfg.UserAgent)
	}
}

func TestEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("timeout: 7s\nuser_agent: from-file\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETCHECK_TIMEOUT", "2s")
	t.Setenv("NETCHECK_USER_AGENT", "from-env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 2*time.Second {
		t.Errorf("env override didn't win on Timeout: %v", cfg.Timeout)
	}
	if cfg.UserAgent != "from-env" {
		t.Errorf("env override didn't win on UserAgent: %q", cfg.UserAgent)
	}
}

func TestMissingFileNotAnError(t *testing.T) {
	cfg, err := Load("/nonexistent/path/to/config.yaml")
	if err != nil {
		t.Fatalf("Load returned error for missing file: %v", err)
	}
	if cfg.Source != "" {
		t.Errorf("Source = %q, want empty", cfg.Source)
	}
}

func TestLoadParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Malformed YAML: opening bracket without close.
	os.WriteFile(path, []byte("resolvers: [\n  - name: cf\n"), 0644)
	cfg, err := Load(path)
	if err == nil {
		t.Errorf("expected parse error, got nil")
	}
	// Even on parse error we return non-nil cfg with defaults.
	if cfg == nil {
		t.Errorf("cfg = nil on parse error, expected defaults")
	}
}

func TestResolvePathXDG(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "netcheck")
	os.MkdirAll(cfgDir, 0755)
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	os.WriteFile(cfgPath, []byte("user_agent: from-xdg\n"), 0644)

	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("NETCHECK_CONFIG", "")       // ensure NETCHECK_CONFIG isn't set
	t.Setenv("HOME", "/tmp/no-such-home") // ensure ~/.config fallback misses

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserAgent != "from-xdg" {
		t.Errorf("UserAgent = %q, want from-xdg", cfg.UserAgent)
	}
	if cfg.Source != cfgPath {
		t.Errorf("Source = %q, want %q", cfg.Source, cfgPath)
	}
}

func TestResolvePathNETCHECK_CONFIG(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "explicit.yaml")
	os.WriteFile(cfgPath, []byte("user_agent: from-env\n"), 0644)

	t.Setenv("NETCHECK_CONFIG", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/tmp/no-such-home")

	cfg, _ := Load("")
	if cfg.UserAgent != "from-env" {
		t.Errorf("UserAgent = %q, want from-env (NETCHECK_CONFIG should win)", cfg.UserAgent)
	}
}

func TestResolvePathExplicitMissingFallsToDefaults(t *testing.T) {
	t.Setenv("NETCHECK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/tmp/no-such-home")

	cfg, _ := Load("/definitely/not/here.yaml")
	if cfg.Source != "" {
		t.Errorf("Source = %q, want empty (explicit missing should fall back)", cfg.Source)
	}
	if cfg.Timeout == 0 {
		t.Errorf("Timeout = 0, want defaults")
	}
}
