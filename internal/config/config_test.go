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
