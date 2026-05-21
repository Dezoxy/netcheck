package cmd

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout, runs fn, and returns whatever was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = buf.ReadFrom(r)
		close(done)
	}()
	fn()
	w.Close()
	<-done
	return buf.String()
}

// captureStderr is the same for os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = buf.ReadFrom(r)
		close(done)
	}()
	fn()
	w.Close()
	<-done
	return buf.String()
}

// ─── RunFull ──────────────────────────────────────────────────────────────

func TestRunFullSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var exit int
	out := captureStdout(t, func() {
		exit = RunFull([]string{srv.URL})
	})
	if exit != 0 {
		t.Errorf("RunFull exit = %d, want 0", exit)
	}
	if !strings.Contains(out, "NETCHECK REPORT") {
		t.Errorf("missing report header: %q", out)
	}
	if !strings.Contains(out, "HTTP") {
		t.Errorf("missing HTTP section: %q", out)
	}
}

func TestRunFullJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var exit int
	out := captureStdout(t, func() {
		exit = RunFull([]string{"--output", "json", srv.URL})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	if !strings.Contains(out, `"kind": "full"`) {
		t.Errorf("missing kind:full in JSON output: %q", out)
	}
}

func TestRunFullWriteToFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "report.html")
	var exit int
	_ = captureStderr(t, func() {
		exit = RunFull([]string{"--output", "html", "--out", path, srv.URL})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<!doctype html>") {
		t.Errorf("HTML output missing doctype: %s", data[:80])
	}
}

func TestRunFullBadInput(t *testing.T) {
	cases := [][]string{
		nil,                                // no args
		{"too", "many"},                    // 2 positionals
		{"--unknown-flag", "google.com"},   // unknown flag
		{"--output", "yaml", "google.com"}, // bad format
		{"ftp://nope.example.com"},         // unsupported scheme
	}
	for _, args := range cases {
		exit := -1
		_ = captureStderr(t, func() {
			exit = RunFull(args)
		})
		if exit != 2 {
			t.Errorf("RunFull(%v) exit = %d, want 2", args, exit)
		}
	}
}

func TestRunFullCheckFailure(t *testing.T) {
	// Bind+close to grab a guaranteed-unused port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	var exit int
	_ = captureStdout(t, func() {
		exit = RunFull([]string{"http://" + addr})
	})
	if exit != 1 {
		t.Errorf("expected exit 1 for connection refused, got %d", exit)
	}
}

// ─── RunDNS ───────────────────────────────────────────────────────────────

func TestRunDNSAllFormats(t *testing.T) {
	for _, format := range []string{"text", "json", "markdown", "html"} {
		var exit int
		out := captureStdout(t, func() {
			exit = RunDNS([]string{
				"--no-system", "--no-defaults", "--no-config-resolvers",
				"--resolver", "1.1.1.1",
				"--timeout", "1s",
				"--output", format,
				"this-shouldnt-resolve-anywhere.invalid",
			})
		})
		// Resolver will error (timeout/SERVFAIL), so exit=1 expected.
		if exit != 1 {
			t.Errorf("format=%s exit = %d, want 1 (resolver errors expected)", format, exit)
		}
		// Output produced something appropriate for the format.
		if format == "json" && !strings.Contains(out, `"kind": "dns"`) {
			t.Errorf("JSON output missing kind: %q", out)
		}
		if format == "text" && !strings.Contains(out, "DNS COMPARE") {
			t.Errorf("text output missing header: %q", out)
		}
	}
}

func TestRunDNSBadArgs(t *testing.T) {
	cases := [][]string{
		nil,
		{"--type", "BOGUS", "google.com"},
		{"--resolver", "ftp://nope", "google.com"},
		{"--no-system", "--no-defaults", "--no-config-resolvers", "google.com"}, // no resolvers
	}
	for _, args := range cases {
		exit := -1
		_ = captureStderr(t, func() {
			exit = RunDNS(args)
		})
		if exit != 2 {
			t.Errorf("RunDNS(%v) exit = %d, want 2", args, exit)
		}
	}
}

// ─── RunIP ────────────────────────────────────────────────────────────────

func TestRunIPDirectAddress(t *testing.T) {
	var exit int
	out := captureStdout(t, func() {
		exit = RunIP([]string{"--timeout", "5s", "192.168.1.1"})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	if !strings.Contains(out, "IP INFO") {
		t.Errorf("missing IP INFO header: %q", out)
	}
}

func TestRunIPBadArgs(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}, {"--output", "yaml", "1.1.1.1"}} {
		exit := -1
		_ = captureStderr(t, func() {
			exit = RunIP(args)
		})
		if exit != 2 {
			t.Errorf("RunIP(%v) exit = %d, want 2", args, exit)
		}
	}
}

func TestRunIPHostnameThatDoesntResolve(t *testing.T) {
	var exit int
	_ = captureStderr(t, func() {
		exit = RunIP([]string{"this-host-should-never-exist.invalid"})
	})
	if exit != 1 {
		t.Errorf("expected exit 1 for unresolvable host, got %d", exit)
	}
}

// ─── RunConfigShow ────────────────────────────────────────────────────────

func TestRunConfigShowDefault(t *testing.T) {
	var exit int
	out := captureStdout(t, func() {
		exit = RunConfigShow(nil)
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	if !strings.Contains(out, "CONFIG") {
		t.Errorf("missing CONFIG header: %q", out)
	}
}

func TestRunConfigShowJSON(t *testing.T) {
	var exit int
	out := captureStdout(t, func() {
		exit = RunConfigShow([]string{"--output", "json"})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	if !strings.Contains(out, `"kind": "config"`) {
		t.Errorf("missing kind:config: %q", out)
	}
}

func TestRunConfigShowBadFormat(t *testing.T) {
	exit := -1
	_ = captureStderr(t, func() {
		exit = RunConfigShow([]string{"--output", "csv"})
	})
	if exit != 2 {
		t.Errorf("expected exit 2 for bad format, got %d", exit)
	}
}

func TestRunConfigShowWritesToFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	var exit int
	_ = captureStderr(t, func() {
		exit = RunConfigShow([]string{"--output", "json", "--out", path})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

// ─── runConfigCmd dispatch ────────────────────────────────────────────────

func TestRunConfigCmdDefaultsToShow(t *testing.T) {
	var exit int
	_ = captureStdout(t, func() {
		exit = runConfigCmd(nil)
	})
	if exit != 0 {
		t.Errorf("bare `config` should default to show, got exit %d", exit)
	}
}

func TestRunConfigCmdShowExplicit(t *testing.T) {
	var exit int
	_ = captureStdout(t, func() {
		exit = runConfigCmd([]string{"show"})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
}

func TestRunConfigCmdHelp(t *testing.T) {
	var exit int
	_ = captureStderr(t, func() {
		exit = runConfigCmd([]string{"-h"})
	})
	if exit != 0 {
		t.Errorf("help should exit 0, got %d", exit)
	}
}

func TestRunConfigCmdUnknown(t *testing.T) {
	var exit int
	_ = captureStderr(t, func() {
		exit = runConfigCmd([]string{"bogus"})
	})
	if exit != 2 {
		t.Errorf("unknown subcommand should exit 2, got %d", exit)
	}
}

// ─── Server-side URL handling sanity ─────────────────────────────────────

func TestRunFullURLFromHTTPTestServer(t *testing.T) {
	// httptest.NewServer returns URLs like http://127.0.0.1:port — make sure
	// our target parser accepts those and the full check completes happily.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	if u.Scheme != "http" {
		t.Fatal("httptest changed schemes — test needs update")
	}

	var exit int
	out := captureStdout(t, func() {
		exit = RunFull([]string{srv.URL})
	})
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if !strings.Contains(out, "Status:    200") {
		t.Errorf("missing 200 status line: %q", out)
	}
}
