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

	"netcheck/internal/report"
)

func TestBuildHeadersAgainstTestServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	j := BuildHeaders(context.Background(), srv.URL, 5*time.Second, false)
	if j.Status != 200 {
		t.Errorf("status = %d, want 200", j.Status)
	}
	if j.Kind != "headers" {
		t.Errorf("kind = %q, want headers", j.Kind)
	}
	if j.Summary.Pass != 2 {
		t.Errorf("pass = %d, want 2 (CSP + XFO)", j.Summary.Pass)
	}
	if j.Summary.Missing == 0 {
		t.Errorf("missing = %d, want >0 (HSTS, XCTO, Referrer-Policy, Permissions-Policy)", j.Summary.Missing)
	}
}

// runHeadersFormat smoke-test against an httptest server, verifying:
// - non-zero exit code on transport error
// - zero exit code with content even when grades are bad
// - each format writes something distinctive
func TestRunHeadersFormatAllFormats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cases := []struct {
		format     Format
		wantSubstr string
	}{
		{FormatText, "SECURITY HEADERS"},
		{FormatJSON, `"kind": "headers"`},
		{FormatMarkdown, "# netcheck headers"},
		{FormatHTML, "<h1>netcheck headers</h1>"},
	}
	for _, c := range cases {
		t.Run(c.wantSubstr, func(t *testing.T) {
			var buf bytes.Buffer
			code := runHeadersFormat(&buf, srv.URL, 5*time.Second, false, c.format)
			if code != 0 {
				t.Errorf("exit code = %d, want 0 (grades being bad shouldn't fail the run)", code)
			}
			if !strings.Contains(buf.String(), c.wantSubstr) {
				t.Errorf("output for format=%v missing %q:\n%s", c.format, c.wantSubstr, buf.String())
			}
		})
	}
}

func TestRunHeadersFormatJSONIsValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	if code := runHeadersFormat(&buf, srv.URL, 5*time.Second, false, FormatJSON); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var got report.HeadersJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Kind != "headers" {
		t.Errorf("kind = %q, want headers", got.Kind)
	}
	if got.NetcheckVersion == "" {
		t.Errorf("netcheck_version is empty")
	}
}

func TestRunHeadersFormatTransportError(t *testing.T) {
	// Tight timeout against a closed port — should produce a transport error
	// and exit code 1.
	var buf bytes.Buffer
	code := runHeadersFormat(&buf, "http://127.0.0.1:1/", 200*time.Millisecond, false, FormatText)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 on transport error", code)
	}
	if !strings.Contains(buf.String(), "audit failed") {
		t.Errorf("text output should explain the failure:\n%s", buf.String())
	}
}

func TestRunHeadersTopLevelBadFormat(t *testing.T) {
	// Calling the top-level CLI entry with a bad --output should exit 2.
	code := RunHeaders([]string{"--output", "yaml", "https://example.com"})
	if code != 2 {
		t.Errorf("exit code = %d, want 2 on bad --output", code)
	}
}

func TestRunHeadersTopLevelMissingURL(t *testing.T) {
	code := RunHeaders([]string{})
	if code != 2 {
		t.Errorf("exit code = %d, want 2 on missing URL", code)
	}
}
