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

	"github.com/Dezoxy/netcheck/pkg/report"
)

func TestBuildTechAgainstTestServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<meta name="generator" content="WordPress 6.4.2">`))
	}))
	defer srv.Close()

	j := BuildTech(context.Background(), srv.URL, 5*time.Second, false)
	if j.Status != 200 {
		t.Errorf("status = %d, want 200", j.Status)
	}
	if j.Kind != "tech" {
		t.Errorf("kind = %q, want tech", j.Kind)
	}
	names := make(map[string]bool)
	for _, m := range j.Matches {
		names[m.Name] = true
	}
	for _, want := range []string{"WordPress", "PHP", "nginx"} {
		if !names[want] {
			t.Errorf("expected match %q, got %v", want, names)
		}
	}
}

func TestRunTechFormatAllFormats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cases := []struct {
		format     Format
		wantSubstr string
	}{
		{FormatText, "TECH FINGERPRINT"},
		{FormatJSON, `"kind": "tech"`},
		{FormatMarkdown, "# netcheck tech"},
		{FormatHTML, "<h1>netcheck tech</h1>"},
	}
	for _, c := range cases {
		t.Run(c.wantSubstr, func(t *testing.T) {
			var buf bytes.Buffer
			code := runTechFormat(&buf, srv.URL, 5*time.Second, false, c.format)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(buf.String(), c.wantSubstr) {
				t.Errorf("output missing %q:\n%s", c.wantSubstr, buf.String())
			}
		})
	}
}

func TestRunTechFormatJSONIsValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "abc")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	if code := runTechFormat(&buf, srv.URL, 5*time.Second, false, FormatJSON); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var got report.TechJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Kind != "tech" {
		t.Errorf("kind = %q, want tech", got.Kind)
	}
	if len(got.Matches) == 0 {
		t.Errorf("expected at least one match (CF-Ray = Cloudflare)")
	}
}

func TestRunTechFormatTransportError(t *testing.T) {
	var buf bytes.Buffer
	code := runTechFormat(&buf, "http://127.0.0.1:1/", 200*time.Millisecond, false, FormatText)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(buf.String(), "detect failed") {
		t.Errorf("text error path should say 'detect failed':\n%s", buf.String())
	}
}

func TestRunTechTopLevelBadFormat(t *testing.T) {
	if code := RunTech([]string{"--output", "yaml", "https://example.com"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunTechTopLevelMissingURL(t *testing.T) {
	if code := RunTech([]string{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}
