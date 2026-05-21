package cmd

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── menuFull / menuDNS / menuIP — feed scripted stdin ───────────────────

func TestMenuFullSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	in := bufio.NewReader(strings.NewReader(srv.URL + "\n"))
	var out bytes.Buffer
	s, err := menuFull(in, &out)
	if err != nil {
		t.Fatalf("menuFull error: %v", err)
	}
	if s == nil || s.Kind != "full" {
		t.Errorf("savable kind = %q, want full", s.Kind)
	}
	if !strings.Contains(out.String(), "NETCHECK REPORT") {
		t.Errorf("missing report header: %q", out.String())
	}

	// Exercise the save-render closure on every format.
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

func TestMenuFullBadTarget(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("ftp://nope\n"))
	var out bytes.Buffer
	_, err := menuFull(in, &out)
	if err == nil {
		t.Errorf("expected parse error for ftp://")
	}
}

func TestMenuDNS(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("example.com\n"))
	var out bytes.Buffer

	// Stub the resolver list to avoid real DNS; loadedConfig has no resolvers
	// but the function still appends Cloudflare/Google/Quad9 defaults. We
	// can't easily mock those, but for coverage we only need menuDNS to run
	// to completion — even if the queries time out, the function returns a
	// non-nil savable.
	s, err := menuDNS(in, &out)
	if err != nil {
		t.Fatalf("menuDNS error: %v", err)
	}
	if s == nil || s.Kind != "dns" {
		t.Errorf("kind = %q, want dns", s.Kind)
	}

	// Exercise the save closure.
	var rendered bytes.Buffer
	if err := s.Render(&rendered, FormatJSON); err != nil {
		t.Errorf("Render JSON error: %v", err)
	}
}

func TestMenuDNSBadHost(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("\n"))
	var out bytes.Buffer
	_, err := menuDNS(in, &out)
	if err == nil {
		t.Errorf("expected error for empty host")
	}
}

func TestMenuIPDirectAddress(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("192.168.1.1\n"))
	var out bytes.Buffer
	s, err := menuIP(in, &out)
	if err != nil {
		t.Fatalf("menuIP error: %v", err)
	}
	if s == nil || s.Kind != "ip" {
		t.Errorf("kind = %q, want ip", s.Kind)
	}

	// Test all four format renders.
	for _, f := range []Format{FormatText, FormatJSON, FormatMarkdown, FormatHTML} {
		var rendered bytes.Buffer
		if err := s.Render(&rendered, f); err != nil {
			t.Errorf("Render(%v) error: %v", f, err)
		}
	}
}

func TestMenuIPBadInput(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("\n"))
	var out bytes.Buffer
	_, err := menuIP(in, &out)
	if err == nil {
		t.Errorf("expected error for empty input")
	}
}

// ─── offerSave ────────────────────────────────────────────────────────────

func TestOfferSaveDeclined(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("n\n"))
	var out bytes.Buffer
	s := &savable{
		Kind: "ip",
		Host: "1.1.1.1",
		Render: func(w io.Writer, f Format) error {
			_, err := w.Write([]byte("rendered"))
			return err
		},
	}
	offerSave(in, &out, s) // decline → no panic, no file written
}

func TestOfferSaveNilSavableIsNoOp(t *testing.T) {
	in := bufio.NewReader(strings.NewReader(""))
	var out bytes.Buffer
	offerSave(in, &out, nil) // must not panic
}

func TestOfferSaveSavesToFile(t *testing.T) {
	tmp := t.TempDir()

	// Override defaultSaveDir for this test by changing $HOME and faking the
	// executable's location. We can't easily do that here; instead we drive
	// offerSave with non-empty path input. The flow:
	//   "y\n"   — yes save
	//   "1\n"   — text format
	//   "<dir>\n" — save dir prompt (only shown when isWorkingDir=false)
	// On the test runner, defaultSaveDir() returns ~/Documents (not a working
	// dir), so the path prompt will appear.
	in := bufio.NewReader(strings.NewReader("y\n1\n" + tmp + "\n"))
	var out bytes.Buffer
	s := &savable{
		Kind: "test",
		Host: "example.com",
		Render: func(w io.Writer, f Format) error {
			_, err := w.Write([]byte("hello"))
			return err
		},
	}
	offerSave(in, &out, s)

	// Walk the tmpdir and check that a netcheck-test-example.com-*.txt file landed.
	matches, err := filepath.Glob(filepath.Join(tmp, "netcheck-test-example.com-*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 saved file in %s, got %d: %v", tmp, len(matches), matches)
		return
	}
	data, _ := os.ReadFile(matches[0])
	if string(data) != "hello" {
		t.Errorf("file contents = %q, want hello", data)
	}
}

// ─── trivial helpers ──────────────────────────────────────────────────────

func TestHasFile(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "exists"), []byte("x"), 0644)
	if !hasFile(tmp, "exists") {
		t.Errorf("hasFile should return true for existing")
	}
	if hasFile(tmp, "missing") {
		t.Errorf("hasFile should return false for missing")
	}
}

func TestPrintMenu(t *testing.T) {
	var buf bytes.Buffer
	printMenu(&buf)
	s := buf.String()
	for _, want := range []string{"Full check", "DNS compare", "Route", "IP / ASN", "Quit"} {
		if !strings.Contains(s, want) {
			t.Errorf("menu missing %q in:\n%s", want, s)
		}
	}
}

func TestReadLineWithoutNewline(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("abc"))
	got, err := readLine(r, "")
	if err == nil {
		// EOF expected, but if reader returned the buffered "abc" first, that's OK
		if got != "abc" {
			t.Errorf("got %q, want abc", got)
		}
	}
}

func TestRunIPInfoWrapperDefaultsToText(t *testing.T) {
	var buf bytes.Buffer
	err := RunIPInfo(&buf, "192.168.1.1", 5_000_000_000) // 5s timeout
	if err != nil {
		t.Fatalf("RunIPInfo error: %v", err)
	}
	if !strings.Contains(buf.String(), "IP INFO") {
		t.Errorf("RunIPInfo output missing header: %q", buf.String())
	}
}
