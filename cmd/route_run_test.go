package cmd

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeTraceroute installs a tiny shell script named "traceroute" at the
// front of $PATH that prints canned output and exits 0. Returns the directory
// it was installed into.
func installFakeTraceroute(t *testing.T, output string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake traceroute harness uses shell script; tracert wire format differs")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "traceroute")
	script := "#!/bin/sh\ncat <<'EOF'\n" + output + "\nEOF\n"
	if err := os.WriteFile(stub, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

const fakeRouteOutput = `traceroute to example.com (1.2.3.4), 30 hops max
 1  192.168.1.1  1.234 ms  1.123 ms  1.045 ms
 2  edge.example.net (1.2.3.4)  10.5 ms  9.8 ms  10.1 ms`

func TestRunRouteEndToEnd(t *testing.T) {
	installFakeTraceroute(t, fakeRouteOutput)

	var exit int
	out := captureStdout(t, func() {
		exit = RunRoute([]string{
			"--no-asn", "--no-resolve", "--wait", "1",
			"example.com",
		})
	})
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if !strings.Contains(out, "ROUTE") {
		t.Errorf("missing ROUTE header: %q", out)
	}
	if !strings.Contains(out, "192.168.1.1") {
		t.Errorf("missing hop 1 IP: %q", out)
	}
	if !strings.Contains(out, "edge.example.net") {
		t.Errorf("missing hop 2 host: %q", out)
	}
}

func TestRunRouteJSON(t *testing.T) {
	installFakeTraceroute(t, fakeRouteOutput)
	var exit int
	out := captureStdout(t, func() {
		exit = RunRoute([]string{
			"--no-asn", "--no-resolve", "--wait", "1",
			"--output", "json", "example.com",
		})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	if !strings.Contains(out, `"kind": "route"`) {
		t.Errorf("missing kind:route: %q", out)
	}
}

func TestRunRouteWriteToFile(t *testing.T) {
	installFakeTraceroute(t, fakeRouteOutput)

	tmp := t.TempDir()
	path := filepath.Join(tmp, "route.html")
	var exit int
	_ = captureStderr(t, func() {
		exit = RunRoute([]string{
			"--no-asn", "--no-resolve", "--wait", "1",
			"--output", "html", "--out", path,
			"example.com",
		})
	})
	if exit != 0 {
		t.Errorf("exit = %d", exit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<!doctype html>") {
		t.Errorf("HTML file missing doctype: %s", data[:80])
	}
}

func TestRunRouteBadFlags(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"a", "b"},
		{"--output", "yaml", "example.com"},
		{"--unknown", "example.com"},
	} {
		exit := -1
		_ = captureStderr(t, func() {
			exit = RunRoute(args)
		})
		if exit != 2 {
			t.Errorf("RunRoute(%v) exit = %d, want 2", args, exit)
		}
	}
}

func TestRunRouteNoTraceroute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path manipulation differs on windows")
	}
	// Empty PATH so route.Find returns an error.
	t.Setenv("PATH", "")
	var exit int
	_ = captureStderr(t, func() {
		exit = RunRoute([]string{"--wait", "1", "example.com"})
	})
	if exit != 2 {
		t.Errorf("expected exit 2 when traceroute missing, got %d", exit)
	}
}

func TestMenuRouteEndToEnd(t *testing.T) {
	installFakeTraceroute(t, fakeRouteOutput)

	in := bufio.NewReader(strings.NewReader("example.com\n"))
	var out bytes.Buffer

	// menuRoute writes the header to os.Stdout (not the passed writer) because
	// it wants live progress feedback. Redirect os.Stdout so the test stays clean.
	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	s, err := menuRoute(in, &out)
	w.Close()
	io.Copy(io.Discard, r) // drain the captured stdout

	if err != nil {
		t.Fatalf("menuRoute error: %v", err)
	}
	if s == nil || s.Kind != "route" {
		t.Errorf("kind = %q, want route", s.Kind)
	}

	// Exercise the save closures for all four formats.
	for _, f := range []Format{FormatText, FormatJSON, FormatMarkdown, FormatHTML} {
		var rendered bytes.Buffer
		if err := s.Render(&rendered, f); err != nil {
			t.Errorf("Render(%v) error: %v", f, err)
		}
		if rendered.Len() == 0 {
			t.Errorf("Render(%v) wrote nothing", f)
		}
	}
}

func TestMenuRouteBadInput(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("\n"))
	var out bytes.Buffer
	_, err := menuRoute(in, &out)
	if err == nil {
		t.Errorf("expected error for empty host")
	}
}

// ─── trivial: usage(), LoadConfig() ──────────────────────────────────────

func TestUsage(t *testing.T) {
	got := captureStderr(t, func() {
		usage()
	})
	for _, want := range []string{"netcheck", "route", "dns", "ip", "menu", "config show"} {
		if !strings.Contains(got, want) {
			t.Errorf("usage missing %q in:\n%s", want, got)
		}
	}
}

func TestLoadConfigDoesntPanic(t *testing.T) {
	// Save+restore loadedConfig so we don't pollute other tests.
	prev := loadedConfig
	defer func() { loadedConfig = prev }()
	_ = LoadConfig()
	if loadedConfig == nil {
		t.Errorf("loadedConfig is nil after LoadConfig")
	}
}

// ─── RunMenu happy path: type 'q' immediately ────────────────────────────

func TestRunMenuQuitsOnQ(t *testing.T) {
	// Override os.Stdin with a pipe whose contents make the menu quit.
	r, w, _ := os.Pipe()
	w.WriteString("q\n")
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	// RunMenu writes to os.Stdout — capture it.
	stdout := captureStdout(t, func() {
		RunMenu(nil)
	})
	if !strings.Contains(stdout, "Bye") {
		t.Errorf("expected 'Bye' on quit, got:\n%s", stdout)
	}
}

func TestRunMenuEmptyInputContinues(t *testing.T) {
	// Empty line → menu re-prompts. Then 'q' → quits.
	r, w, _ := os.Pipe()
	w.WriteString("\nq\n")
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	stdout := captureStdout(t, func() {
		RunMenu(nil)
	})
	if !strings.Contains(stdout, "Bye") {
		t.Errorf("expected 'Bye' after empty + q, got:\n%s", stdout)
	}
}

func TestRunMenuUnknownChoice(t *testing.T) {
	r, w, _ := os.Pipe()
	w.WriteString("99\nq\n")
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	stdout := captureStdout(t, func() {
		RunMenu(nil)
	})
	if !strings.Contains(stdout, "unknown") {
		t.Errorf("expected 'unknown choice' message, got:\n%s", stdout)
	}
}
