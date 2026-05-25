package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dezoxy/netcheck/internal/config"
	"github.com/Dezoxy/netcheck/pkg/check"
	"github.com/Dezoxy/netcheck/pkg/ipinfo"
)

// ─── output.go ────────────────────────────────────────────────────────────

// (ParseFormat is already covered in output_test.go; nothing extra here.)

// ─── out.go ──────────────────────────────────────────────────────────────

func TestOpenOutEmptyPathReturnsStdout(t *testing.T) {
	w, closer, err := openOut("")
	if err != nil {
		t.Fatal(err)
	}
	if w != os.Stdout {
		t.Errorf("empty path should return os.Stdout")
	}
	closer() // must be a no-op
}

func TestOpenOutCreatesParentDirs(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "nested", "subdir", "out.txt")
	w, closer, err := openOut(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	// Redirect stderr to capture the "Saved to" message the closer prints.
	r, fakeStderr, _ := os.Pipe()
	origStderr := os.Stderr
	os.Stderr = fakeStderr
	closer()
	fakeStderr.Close()
	os.Stderr = origStderr

	got, _ := os.ReadFile(path)
	if string(got) != "hello" {
		t.Errorf("file contents = %q, want hello", got)
	}

	var stderrBuf bytes.Buffer
	_, _ = stderrBuf.ReadFrom(r)
	if !strings.Contains(stderrBuf.String(), "Saved to") {
		t.Errorf("stderr missing 'Saved to': %q", stderrBuf.String())
	}
}

func TestOpenOutFailsOnUnwritableDir(t *testing.T) {
	// A path under a file (not a dir) — MkdirAll will fail.
	tmp := t.TempDir()
	blockingFile := filepath.Join(tmp, "blocker")
	os.WriteFile(blockingFile, []byte("x"), 0644)
	_, _, err := openOut(filepath.Join(blockingFile, "out.txt"))
	if err == nil {
		t.Errorf("expected error opening child of a file path")
	}
}

// ─── menu_save.go helper tests already in menu_save_test.go ──────────────

func TestPromptFormatDefaults(t *testing.T) {
	cases := map[string]Format{
		"":     FormatJSON,
		"\n":   FormatJSON,
		"1":    FormatText,
		"2":    FormatJSON,
		"3":    FormatMarkdown,
		"4":    FormatHTML,
		"json": FormatJSON,
		"text": FormatText,
		"md":   FormatMarkdown,
		"html": FormatHTML,
		"MD\n": FormatMarkdown,
	}
	for input, want := range cases {
		in := bufio.NewReader(strings.NewReader(input + "\n"))
		var out bytes.Buffer
		got, ok := promptFormat(in, &out)
		if !ok {
			t.Errorf("promptFormat(%q) returned ok=false", input)
			continue
		}
		if got != want {
			t.Errorf("promptFormat(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestPromptFormatUnknownReturnsFalse(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("yaml\n"))
	var out bytes.Buffer
	_, ok := promptFormat(in, &out)
	if ok {
		t.Errorf("unknown format should return ok=false")
	}
}

// ─── root.go: UserAgent + applyConfigOverride + LoadedConfig ─────────────

func TestUserAgentDefault(t *testing.T) {
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = config.Defaults()
	got := UserAgent()
	if !strings.HasPrefix(got, "github.com/Dezoxy/netcheck/") {
		t.Errorf("UserAgent = %q, want prefix netcheck/", got)
	}
}

func TestUserAgentConfigOverride(t *testing.T) {
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = &config.Config{UserAgent: "custom/2.0"}
	if got := UserAgent(); got != "custom/2.0" {
		t.Errorf("UserAgent = %q, want custom/2.0", got)
	}
}

func TestLoadedConfigReturnsPointer(t *testing.T) {
	if LoadedConfig() == nil {
		t.Errorf("LoadedConfig returned nil")
	}
}

func TestApplyConfigOverrideNoOpOnEmpty(t *testing.T) {
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = &config.Config{Source: "before"}
	applyConfigOverride("")
	if loadedConfig.Source != "before" {
		t.Errorf("Source = %q, want unchanged 'before'", loadedConfig.Source)
	}
}

func TestApplyConfigOverrideLoadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte("user_agent: from-applyConfigOverride\n"), 0644)

	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = config.Defaults()

	applyConfigOverride(path)
	if loadedConfig.UserAgent != "from-applyConfigOverride" {
		t.Errorf("UserAgent = %q, want from-applyConfigOverride", loadedConfig.UserAgent)
	}
}

// ─── annotateDNS ─────────────────────────────────────────────────────────

func TestAnnotateDNSSkipsOnError(t *testing.T) {
	d := &check.DNSResult{Err: net.UnknownNetworkError("oops")}
	annotateDNS(context.Background(), d, nil)
	if d.IPInfo != nil {
		t.Errorf("IPInfo should be nil when DNS errored, got %v", d.IPInfo)
	}
}

func TestAnnotateDNSSkipsOnEmpty(t *testing.T) {
	d := &check.DNSResult{}
	annotateDNS(context.Background(), d, nil)
	if d.IPInfo != nil {
		t.Errorf("IPInfo should be nil when no IPs, got %v", d.IPInfo)
	}
}

func TestAnnotateDNSPopulatesPrivate(t *testing.T) {
	// Private IPs: ASN+CDN+PTR will all be nil/empty, but the map should still
	// have an entry per IP.
	d := &check.DNSResult{
		A: []net.IP{net.IPv4(192, 168, 1, 1)},
	}
	annotateDNS(context.Background(), d, ipinfo.NewASNCache())
	if d.IPInfo == nil {
		t.Fatal("IPInfo should be populated")
	}
	entry, ok := d.IPInfo["192.168.1.1"]
	if !ok {
		t.Errorf("expected entry for 192.168.1.1, got %v", d.IPInfo)
	}
	if entry.ASN != nil {
		t.Errorf("ASN should be nil for private IP, got %+v", entry.ASN)
	}
}

// ─── route.go helpers (joinTabs, renderRouteText) ────────────────────────

func TestJoinTabs(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{}, ""},
		{[]string{"only"}, "only"},
		{[]string{"a", "b", "c"}, "a\tb\tc"},
	}
	for _, c := range cases {
		if got := joinTabs(c.in); got != c.want {
			t.Errorf("joinTabs(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ─── config show JSON projection ─────────────────────────────────────────

func TestWriteConfigJSON(t *testing.T) {
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = &config.Config{
		Source:          "/tmp/test.yaml",
		Timeout:         5_000_000_000, // 5s
		UserAgent:       "test/1.0",
		FollowRedirects: false,
		MaxRedirects:    3,
		PreferIPv6:      true,
		Resolvers: []config.ResolverEntry{
			{Name: "cf", Address: "1.1.1.1", Type: "udp"},
		},
	}
	var buf bytes.Buffer
	if err := writeConfigJSON(&buf); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got["kind"] != "config" {
		t.Errorf("kind = %v, want config", got["kind"])
	}
	if got["source"] != "/tmp/test.yaml" {
		t.Errorf("source = %v", got["source"])
	}
	if got["max_redirects"].(float64) != 3 {
		t.Errorf("max_redirects = %v", got["max_redirects"])
	}
}

func TestWriteConfigTextWithDefaults(t *testing.T) {
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = config.Defaults()
	var buf bytes.Buffer
	writeConfigText(&buf)
	out := buf.String()
	if !strings.Contains(out, "CONFIG") {
		t.Errorf("missing CONFIG header: %s", out)
	}
	if !strings.Contains(out, "defaults") {
		t.Errorf("expected 'defaults' for empty source, got: %s", out)
	}
}

func TestWriteConfigTextWithResolvers(t *testing.T) {
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	loadedConfig = &config.Config{
		Source: "/x.yaml",
		Resolvers: []config.ResolverEntry{
			{Name: "cf-doh", Address: "https://x/dns", Type: "doh"},
			{Address: "1.1.1.1"}, // unnamed, default type
		},
	}
	var buf bytes.Buffer
	writeConfigText(&buf)
	out := buf.String()
	if !strings.Contains(out, "cf-doh") {
		t.Errorf("missing resolver name: %s", out)
	}
	if !strings.Contains(out, "(unnamed)") {
		t.Errorf("missing unnamed marker: %s", out)
	}
	if !strings.Contains(out, "doh") {
		t.Errorf("missing type: %s", out)
	}
}

// ─── ResolveIPInput non-network paths (already partially tested) ─────────

func TestResolveIPInputEmpty(t *testing.T) {
	_, _, _, err := ResolveIPInput(context.Background(), "  ")
	if err == nil {
		t.Errorf("expected error for empty input")
	}
}

func TestResolveIPInputIPv6Bare(t *testing.T) {
	target, ips, fromHost, err := ResolveIPInput(context.Background(), "2606:4700:4700::1111")
	if err != nil {
		t.Fatal(err)
	}
	if fromHost {
		t.Errorf("fromHost = true, want false for direct IPv6")
	}
	if target != "2606:4700:4700::1111" || len(ips) != 1 {
		t.Errorf("target=%q ips=%v", target, ips)
	}
}

// ─── stdinIsTTY ──────────────────────────────────────────────────────────

func TestStdinIsTTYInTests(t *testing.T) {
	// During `go test`, stdin is generally NOT a TTY. Just verify the function
	// runs without panicking; the return value depends on the runner.
	_ = stdinIsTTY()
}
