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
	"netcheck/internal/reverseip"
)

func pointReverseAt(t *testing.T, htBody, shBody string) func() {
	t.Helper()
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(htBody))
	}))
	shSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(shBody))
	}))
	restore := reverseip.SetSourceURLsForTest(htSrv.URL, shSrv.URL)
	return func() {
		restore()
		htSrv.Close()
		shSrv.Close()
	}
}

func TestBuildReverseAgainstMockSources(t *testing.T) {
	defer pointReverseAt(t, "host1.example.com\nhost2.example.com\n", `{"hostnames":["host3.example.com"]}`)()
	prev := loadedConfig.APIs.ShodanAPIKey
	loadedConfig.APIs.ShodanAPIKey = "test-key"
	defer func() { loadedConfig.APIs.ShodanAPIKey = prev }()

	j := BuildReverse(context.Background(), "1.1.1.1", 5*time.Second)
	if j.Kind != "reverse" {
		t.Errorf("kind = %q", j.Kind)
	}
	names := map[string]bool{}
	for _, h := range j.Hostnames {
		names[h.Name] = true
	}
	for _, want := range []string{"host1.example.com", "host2.example.com", "host3.example.com"} {
		if !names[want] {
			t.Errorf("missing %q; got %v", want, names)
		}
	}
}

func TestRunReverseShodanDisabledWithoutKey(t *testing.T) {
	defer pointReverseAt(t, "host1.example.com\n", "")()
	prev := loadedConfig.APIs.ShodanAPIKey
	loadedConfig.APIs.ShodanAPIKey = ""
	defer func() { loadedConfig.APIs.ShodanAPIKey = prev }()

	var buf bytes.Buffer
	code := runReverseFormat(&buf, "1.1.1.1", 5*time.Second, FormatJSON)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	var got report.ReverseJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	foundShodanDisabled := false
	for _, d := range got.SourceDisabled {
		if d == "shodan" {
			foundShodanDisabled = true
		}
	}
	if !foundShodanDisabled {
		t.Errorf("shodan should be in source_disabled when no API key, got %v", got.SourceDisabled)
	}
}

func TestRunReverseFormatAllFormats(t *testing.T) {
	defer pointReverseAt(t, "host1.example.com\n", "")()
	cases := []struct {
		format     Format
		wantSubstr string
	}{
		{FormatText, "REVERSE IP LOOKUP"},
		{FormatJSON, `"kind": "reverse"`},
		{FormatMarkdown, "# netcheck reverse"},
		{FormatHTML, "<h1>netcheck reverse</h1>"},
	}
	for _, c := range cases {
		t.Run(c.wantSubstr, func(t *testing.T) {
			var buf bytes.Buffer
			code := runReverseFormat(&buf, "1.1.1.1", 5*time.Second, c.format)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(buf.String(), c.wantSubstr) {
				t.Errorf("output missing %q:\n%s", c.wantSubstr, buf.String())
			}
		})
	}
}

func TestRunReverseTopLevelBadInput(t *testing.T) {
	if code := RunReverse([]string{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if code := RunReverse([]string{"--output", "yaml", "1.1.1.1"}); code != 2 {
		t.Errorf("exit code = %d, want 2 on bad format", code)
	}
}

func TestReverseDefaultTimeout(t *testing.T) {
	if got := reverseDefaultTimeout(5 * time.Second); got != 30*time.Second {
		t.Errorf("got %v, want 30s floor", got)
	}
	if got := reverseDefaultTimeout(45 * time.Second); got != 45*time.Second {
		t.Errorf("got %v, want passthrough", got)
	}
}
