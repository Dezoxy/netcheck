package route

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeFakeTraceroute writes a tiny shell script (or .bat on Windows) into
// tempdir that prints canned traceroute output and exits 0. Returns the path.
func writeFakeTraceroute(t *testing.T, dir string, output string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "fake.bat")
		body := "@echo off\r\n"
		for _, line := range strings.Split(output, "\n") {
			body += "echo " + line + "\r\n"
		}
		if err := os.WriteFile(path, []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(dir, "fake.sh")
	script := "#!/bin/sh\ncat <<'EOF'\n" + output + "\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStreamParsesCannedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script harness; tracert wire format differs anyway")
	}
	canned := `traceroute to example.com (1.2.3.4), 30 hops max
 1  192.168.1.1  1.234 ms  1.123 ms  1.045 ms
 2  * * *
 3  edge.example.net (1.2.3.4)  10.5 ms  9.8 ms  10.1 ms`

	dir := t.TempDir()
	bin := writeFakeTraceroute(t, dir, canned)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hopsCh, errCh := Stream(ctx, bin, []string{"example.com"})

	var hops []*Hop
	for h := range hopsCh {
		hops = append(hops, h)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Stream error: %v", err)
	}
	if len(hops) != 3 {
		t.Fatalf("got %d hops, want 3", len(hops))
	}
	if hops[0].N != 1 || hops[0].Timeout {
		t.Errorf("hop[0] = %+v, want N=1 not timeout", hops[0])
	}
	if !hops[1].Timeout {
		t.Errorf("hop[1] should be timeout, got %+v", hops[1])
	}
	if hops[2].N != 3 || len(hops[2].Probes) != 3 {
		t.Errorf("hop[2] = %+v, want N=3 with 3 probes", hops[2])
	}
	// Last hop should carry the IP and the hostname.
	if hops[2].Probes[0].IP != "1.2.3.4" {
		t.Errorf("hop[2] IP = %q, want 1.2.3.4", hops[2].Probes[0].IP)
	}
	if hops[2].Probes[0].Host != "edge.example.net" {
		t.Errorf("hop[2] Host = %q, want edge.example.net", hops[2].Probes[0].Host)
	}
}

func TestStreamHandlesNoOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script harness")
	}
	dir := t.TempDir()
	// Write a script that exits immediately without printing anything.
	bin := filepath.Join(dir, "empty.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hopsCh, errCh := Stream(ctx, bin, nil)
	var n int
	for range hopsCh {
		n++
	}
	if err := <-errCh; err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d hops, want 0", n)
	}
}

func TestStreamMissingBinary(t *testing.T) {
	hopsCh, errCh := Stream(context.Background(), "/nonexistent/binary", nil)
	// Drain hops first (channel will close immediately).
	for range hopsCh {
	}
	if err := <-errCh; err == nil {
		t.Errorf("expected error for missing binary")
	}
}

// ─── Find ────────────────────────────────────────────────────────────────

func TestFindFindsTraceroute(t *testing.T) {
	// We don't assert that traceroute is present on the host (it may not be
	// in CI). We just verify Find doesn't panic and returns either a valid
	// path or a non-nil error.
	got, err := Find()
	if err != nil && got != "" {
		t.Errorf("err = %v but path = %q (should be empty on error)", err, got)
	}
	if err == nil && got == "" {
		t.Errorf("nil err but path is empty")
	}
}

func TestFindWithStubbed(t *testing.T) {
	// Put a fake "traceroute" early in PATH and confirm Find picks it up.
	if runtime.GOOS == "windows" {
		t.Skip("shell script harness")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "traceroute")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+origPath)

	got, err := Find()
	if err != nil {
		t.Fatalf("Find returned error: %v", err)
	}
	// exec.LookPath may resolve symlinks or return absolute; just check our
	// stub directory appears.
	if !strings.Contains(got, dir) {
		t.Errorf("Find returned %q, expected something under %q", got, dir)
	}
}

// ─── HopSummary, RTTSummary, FmtMS ───────────────────────────────────────

func TestHopSummaryTimeout(t *testing.T) {
	h := &Hop{N: 5, Timeout: true}
	if got := HopSummary(h); got != "* * *" {
		t.Errorf("HopSummary timeout = %q, want '* * *'", got)
	}
}

func TestHopSummaryNoAddresses(t *testing.T) {
	h := &Hop{N: 5}
	if got := HopSummary(h); got != "(no addresses)" {
		t.Errorf("HopSummary no probes = %q", got)
	}
}

func TestHopSummaryWithHost(t *testing.T) {
	h := &Hop{Probes: []HopProbe{{Host: "edge.example.net", IP: "1.2.3.4", RTT: time.Millisecond}}}
	got := HopSummary(h)
	if !strings.Contains(got, "edge.example.net") || !strings.Contains(got, "1.2.3.4") {
		t.Errorf("HopSummary = %q, want both host and IP", got)
	}
}

func TestRTTSummaryTimeoutPad(t *testing.T) {
	h := &Hop{Timeout: true}
	got := RTTSummary(h, 3)
	if !strings.Contains(got, "*") {
		t.Errorf("RTTSummary timeout = %q, want stars", got)
	}
}

func TestRTTSummaryPartial(t *testing.T) {
	h := &Hop{Probes: []HopProbe{
		{RTT: 1500 * time.Microsecond},
	}}
	got := RTTSummary(h, 3)
	// One real probe + two `*` placeholders.
	if strings.Count(got, "*") != 2 {
		t.Errorf("RTTSummary partial = %q, want exactly 2 stars", got)
	}
}

func TestFmtMS(t *testing.T) {
	cases := map[time.Duration]string{
		1500 * time.Microsecond: "1.50ms",
		12 * time.Millisecond:   "12.0ms",
		150 * time.Millisecond:  "150.0ms",
		0:                       "-",
	}
	for d, want := range cases {
		if got := FmtMS(d); got != want {
			t.Errorf("FmtMS(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestResolveTargetLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := ResolveTarget(ctx, "localhost")
	if got == "" {
		t.Errorf("ResolveTarget(localhost) returned empty")
	}
}

func TestResolveTargetInvalid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := ResolveTarget(ctx, "this-should-not-exist.invalid")
	if got != "" {
		t.Errorf("ResolveTarget(invalid) = %q, want empty", got)
	}
}

func TestInstallHintForCurrentOS(t *testing.T) {
	got := InstallHint()
	if got == "" {
		t.Errorf("InstallHint empty for GOOS=%s", runtime.GOOS)
	}
	// On macOS the hint should mention traceroute; on linux similarly.
	want := map[string]string{
		"darwin":  "traceroute",
		"linux":   "traceroute",
		"windows": "tracert",
	}
	if needle, ok := want[runtime.GOOS]; ok {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(needle)) {
			t.Errorf("InstallHint = %q, expected to mention %q", got, needle)
		}
	}
	// Silence the unused-import linter — exec is used elsewhere in the file.
	_ = exec.Command
}

func TestInstallHintForAllOSes(t *testing.T) {
	cases := map[string]string{
		"darwin":  "traceroute",
		"linux":   "traceroute",
		"windows": "tracert",
		"freebsd": "Install the system",
		"":        "Install the system",
	}
	for goos, needle := range cases {
		got := installHintFor(goos)
		if got == "" {
			t.Errorf("installHintFor(%q) empty", goos)
		}
		if !strings.Contains(strings.ToLower(got), strings.ToLower(needle)) {
			t.Errorf("installHintFor(%q) = %q, expected to mention %q", goos, got, needle)
		}
	}
}

func TestBuildArgsForAllOSes(t *testing.T) {
	opts := Options{MaxHops: 30, Probes: 3, WaitSec: 2, NoResolve: true}

	// Unix variants.
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		got := buildArgsFor(goos, opts, "google.com")
		want := []string{"-n", "-m", "30", "-q", "3", "-w", "2", "google.com"}
		if !sliceEq(got, want) {
			t.Errorf("buildArgsFor(%q): got %v, want %v", goos, got, want)
		}
	}

	// Windows uses different flags and milliseconds for wait.
	got := buildArgsFor("windows", opts, "google.com")
	want := []string{"-d", "-h", "30", "-w", "2000", "google.com"}
	if !sliceEq(got, want) {
		t.Errorf("buildArgsFor(windows): got %v, want %v", got, want)
	}

	// Zero values omit their flags entirely.
	got = buildArgsFor("linux", Options{}, "h")
	if len(got) != 1 || got[0] != "h" {
		t.Errorf("zero opts: got %v, want [h]", got)
	}
}
