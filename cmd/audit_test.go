package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dezoxy/netcheck/pkg/reverseip"
	"github.com/Dezoxy/netcheck/pkg/subenum"
	"github.com/Dezoxy/netcheck/pkg/wayback"
)

// =============================================================================
// classifyAuditTarget
// =============================================================================

func TestClassifyAuditTarget(t *testing.T) {
	cases := []struct {
		in        string
		host      string
		tlsTarget string
		url       string
		isIP      bool
		err       bool
	}{
		// Bare hostnames.
		{"example.com", "example.com", "example.com", "https://example.com", false, false},
		{"example.com:8443", "example.com", "example.com:8443", "https://example.com", false, false},
		// URL-shaped targets.
		{"https://example.com/path", "example.com", "example.com", "https://example.com/path", false, false},
		{"http://example.com:8080/x", "example.com", "example.com:8080", "http://example.com:8080/x", false, false},
		// Codex P2 #1 — TLS sub-check must honour an explicit URL port.
		{"https://target:8443", "target", "target:8443", "https://target:8443", false, false},
		// IP literals (bare).
		{"1.2.3.4", "1.2.3.4", "1.2.3.4", "", true, false},
		{"::1", "::1", "::1", "", true, false},
		// URL @ IPv4 host.
		{"http://1.2.3.4/foo", "1.2.3.4", "1.2.3.4", "http://1.2.3.4/foo", true, false},
		{"http://1.2.3.4:8080", "1.2.3.4", "1.2.3.4:8080", "http://1.2.3.4:8080", true, false},
		// URL @ IPv6 host with port — preserved bracketed form for tlsTarget.
		{"https://[::1]:8443", "::1", "[::1]:8443", "https://[::1]:8443", true, false},
		// Codex P2 #2 — bracketed IPv6 with port (no scheme) classifies as IP.
		{"[::1]:8443", "::1", "[::1]:8443", "", true, false},
		// IP with port (no scheme).
		{"1.2.3.4:9000", "1.2.3.4", "1.2.3.4:9000", "", true, false},
		// Errors.
		{"", "", "", "", false, true},
		{"   ", "", "", "", false, true},
		{"http://", "", "", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			host, tlsTarget, url, isIP, err := classifyAuditTarget(c.in)
			if c.err {
				if err == nil {
					t.Errorf("expected error, got host=%q tlsTarget=%q url=%q isIP=%v",
						host, tlsTarget, url, isIP)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != c.host {
				t.Errorf("host = %q, want %q", host, c.host)
			}
			if tlsTarget != c.tlsTarget {
				t.Errorf("tlsTarget = %q, want %q", tlsTarget, c.tlsTarget)
			}
			if url != c.url {
				t.Errorf("url = %q, want %q", url, c.url)
			}
			if isIP != c.isIP {
				t.Errorf("isIP = %v, want %v", isIP, c.isIP)
			}
		})
	}
}

// =============================================================================
// BuildAudit happy path against mocked sub-sources
// =============================================================================

// pointAuditSourcesAt redirects the external HTTP-based sub-checks to local
// httptest servers so BuildAudit can run end-to-end without leaving the box.
// We don't stub IP / tech / headers because they hit DNS / the target server
// which would be the loopback host the test passes in.
func pointAuditSourcesAt(t *testing.T) func() {
	t.Helper()
	subsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	cdxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[["timestamp","original","statuscode"]]`))
	}))
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(""))
	}))
	restoreSubs := subenum.SetSourceURLsForTest(subsSrv.URL, subsSrv.URL)
	restoreCdx := wayback.SetSourceURLForTest(cdxSrv.URL)
	restoreReverse := reverseip.SetSourceURLsForTest(htSrv.URL, "")
	return func() {
		restoreReverse()
		restoreCdx()
		restoreSubs()
		subsSrv.Close()
		cdxSrv.Close()
		htSrv.Close()
	}
}

func TestBuildAuditPassiveURLAtIPRunsURLChecks(t *testing.T) {
	// Target is http://127.0.0.1:port — a URL whose host is an IP.
	// URL-based checks (headers, tech) SHOULD run; domain-based ones
	// (subs, arch) should NOT (you can't enumerate CT-log subdomains
	// for an IP).
	defer pointAuditSourcesAt(t)()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	res := BuildAudit(context.Background(), srv.URL, AuditOptions{}, 30*time.Second)
	if res.Error != "" {
		t.Fatalf("unexpected top-level error: %s", res.Error)
	}
	if res.Kind != "audit" {
		t.Errorf("kind = %q, want audit", res.Kind)
	}
	if res.Active {
		t.Errorf("active = true, want false (no --active)")
	}
	if res.Headers == nil {
		t.Error("Headers should be populated for URL target")
	}
	if res.Tech == nil {
		t.Error("Tech should be populated for URL target")
	}
	// Domain-based checks should NOT fire for IP-hosted URLs.
	if res.Subs != nil {
		t.Errorf("Subs should NOT run when URL host is an IP")
	}
	if res.Arch != nil {
		t.Errorf("Arch should NOT run when URL host is an IP")
	}
	// Active blocks should NOT be set.
	if res.TLS != nil {
		t.Errorf("TLS should NOT run without --active")
	}
	if res.Ports != nil {
		t.Errorf("Ports should NOT run without --active")
	}
}

func TestBuildAuditPassiveBareHostnameRunsAll(t *testing.T) {
	// Bare hostname → URL is synthesised → all passive checks fire
	// (including domain-based ones). We use a TLD that won't resolve, so
	// every sub-check will error, but they should all have ATTEMPTED to
	// run — meaning the result struct has each pointer populated (with
	// an error inside its payload) OR an entry in Errors.
	defer pointAuditSourcesAt(t)()
	res := BuildAudit(context.Background(), "test.invalid.netcheck-audit", AuditOptions{}, 10*time.Second)
	if res.Error != "" {
		t.Fatalf("unexpected top-level error: %s", res.Error)
	}
	// All 5 passive sub-reports should have at least attempted to run.
	attempted := map[string]bool{
		"subs":    res.Subs != nil,
		"arch":    res.Arch != nil,
		"headers": res.Headers != nil,
		"tech":    res.Tech != nil,
	}
	// `ip` is special — BuildIPInfo returns an error on resolution failure,
	// which lands in res.Errors instead of res.IP.
	if res.IP == nil && res.Errors["ip"] == "" {
		t.Error("ip should have attempted to run (result OR error)")
	}
	for name, ok := range attempted {
		if !ok {
			t.Errorf("%s should have attempted to run", name)
		}
	}
}

func TestBuildAuditIPTargetFallsBackToReverse(t *testing.T) {
	defer pointAuditSourcesAt(t)()
	res := BuildAudit(context.Background(), "127.0.0.1", AuditOptions{}, 5*time.Second)
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	// IP target: only ip + reverse should run.
	if res.Reverse == nil {
		t.Error("Reverse should populate for IP target")
	}
	if res.Subs != nil {
		t.Error("Subs should NOT populate for IP target")
	}
	if res.Headers != nil {
		t.Error("Headers should NOT populate for IP target")
	}
}

func TestBuildAuditBadTarget(t *testing.T) {
	res := BuildAudit(context.Background(), "", AuditOptions{}, time.Second)
	if res.Error == "" {
		t.Error("expected top-level error on empty target")
	}
}

// =============================================================================
// Output format dispatch
// =============================================================================

func TestRunAuditFormatAllFormats(t *testing.T) {
	defer pointAuditSourcesAt(t)()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	cases := []struct {
		format     Format
		wantSubstr string
	}{
		{FormatText, "NETCHECK AUDIT"},
		{FormatJSON, `"kind": "audit"`},
		{FormatMarkdown, "# netcheck audit"},
		{FormatHTML, "<h1>netcheck audit</h1>"},
	}
	for _, c := range cases {
		t.Run(c.wantSubstr, func(t *testing.T) {
			var buf bytes.Buffer
			code := runAuditFormat(&buf, srv.URL, AuditOptions{}, 10*time.Second, c.format)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(buf.String(), c.wantSubstr) {
				t.Errorf("output missing %q:\n%s", c.wantSubstr, buf.String())
			}
		})
	}
}

func TestRunAuditFormatJSONIsValid(t *testing.T) {
	defer pointAuditSourcesAt(t)()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	var buf bytes.Buffer
	if code := runAuditFormat(&buf, srv.URL, AuditOptions{}, 10*time.Second, FormatJSON); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got["kind"] != "audit" {
		t.Errorf("kind = %v, want audit", got["kind"])
	}
}

// =============================================================================
// CLI flag + auth gate
// =============================================================================

func TestRunAuditMissingTarget(t *testing.T) {
	if code := RunAudit([]string{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunAuditBadFormat(t *testing.T) {
	if code := RunAudit([]string{"--output", "yaml", "example.com"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunAuditActiveRequiresAuth(t *testing.T) {
	// --active without authorization → exit 2 + refusal banner on stderr.
	// We can't easily capture stderr here without more plumbing; just check
	// the exit code.
	t.Setenv(AuthzEnvVar, "")
	if code := RunAudit([]string{"--active", "example.com"}); code != 2 {
		t.Errorf("exit code = %d, want 2 (--active without authorization)", code)
	}
}

func TestRunAuditActiveAuthorizedViaEnv(t *testing.T) {
	// With NETCHECK_AUTHORIZED=1, the gate passes. Any subsequent failure
	// against an unresolvable target should be exit 1 (top-level run error),
	// not exit 2 (bad invocation / gate refusal). This proves the gate
	// isn't what failed.
	t.Setenv(AuthzEnvVar, "1")
	code := RunAudit([]string{"--active", "definitely-not-a-real-tld.invalid.netcheck-test"})
	if code == 2 {
		t.Errorf("exit code = 2 — the auth gate refused even though NETCHECK_AUTHORIZED=1 is set")
	}
}

// =============================================================================
// auditDefaultTimeout
// =============================================================================

func TestAuditDefaultTimeout(t *testing.T) {
	if got := auditDefaultTimeout(5 * time.Second); got != 90*time.Second {
		t.Errorf("got %v, want 90s floor", got)
	}
	if got := auditDefaultTimeout(120 * time.Second); got != 120*time.Second {
		t.Errorf("got %v, want passthrough", got)
	}
}
