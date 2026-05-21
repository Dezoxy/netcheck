package cmd

import (
	"strings"
	"testing"
)

func TestSanitizeForFilename(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"google.com", "google.com"},
		{"example.com:8080", "example.com-8080"},
		{"https://x.com/path", "https---x.com-path"},
		{"with spaces", "with-spaces"},
		{`awkward<>chars|*?"`, "awkward--chars----"},
		{"", "result"},
		{".", "result"},
		{"..", "result"},
		{"trailing space ", "trailing-space"},
	}
	for _, c := range cases {
		if got := sanitizeForFilename(c.in); got != c.want {
			t.Errorf("sanitizeForFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultFilenameAllFormats(t *testing.T) {
	cases := map[Format]string{
		FormatText:     ".txt",
		FormatJSON:     ".json",
		FormatMarkdown: ".md",
		FormatHTML:     ".html",
	}
	for f, ext := range cases {
		got := defaultFilename("ip", "1.1.1.1", f)
		if !strings.HasPrefix(got, "netcheck-ip-1.1.1.1-") {
			t.Errorf("missing prefix for format %v: %q", f, got)
		}
		if !strings.HasSuffix(got, ext) {
			t.Errorf("missing %q suffix for format %v: %q", ext, f, got)
		}
	}
}

func TestExpandPath(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	cases := map[string]string{
		"~":             "/Users/test",
		"~/Documents":   "/Users/test/Documents",
		"~/a/b/c":       "/Users/test/a/b/c",
		"/abs/path":     "/abs/path",
		"relative/path": "relative/path",
		"~no-expand":    "~no-expand",
	}
	for in, want := range cases {
		if got := expandPath(in); got != want {
			t.Errorf("expandPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultSaveDir(t *testing.T) {
	// We can't easily mock os.Executable from a unit test, but we can at least
	// confirm the function never panics and returns a sensible result.
	dir, _ := defaultSaveDir()
	if dir == "" {
		t.Errorf("defaultSaveDir returned empty path")
	}
}
