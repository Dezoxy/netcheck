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
	"github.com/Dezoxy/netcheck/pkg/subenum"
)

// pointSubsAt swaps the subenum source URLs to httptest servers and returns a
// cleanup callback. Each handler is fixed-body for the test.
func pointSubsAt(t *testing.T, crtBody, csBody string) func() {
	t.Helper()
	crtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(crtBody))
	}))
	csSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(csBody))
	}))
	restore := subenum.SetSourceURLsForTest(crtSrv.URL, csSrv.URL)
	return func() {
		restore()
		crtSrv.Close()
		csSrv.Close()
	}
}

const fixtureCrt = `[{"name_value":"example.com\n*.example.com","common_name":"example.com"},{"name_value":"api.example.com","common_name":"api.example.com"}]`
const fixtureCS = `[{"dns_names":["www.example.com","api.example.com"]}]`

func TestBuildSubsAgainstMockSources(t *testing.T) {
	defer pointSubsAt(t, fixtureCrt, fixtureCS)()

	j := BuildSubs(context.Background(), "example.com", 5*time.Second)
	if j.Kind != "subs" {
		t.Errorf("kind = %q, want subs", j.Kind)
	}
	if j.Error != "" {
		t.Errorf("unexpected top-level error: %s", j.Error)
	}
	names := map[string]bool{}
	for _, s := range j.Subdomains {
		names[s.Name] = true
	}
	for _, want := range []string{"example.com", "*.example.com", "api.example.com", "www.example.com"} {
		if !names[want] {
			t.Errorf("missing %q in subdomains; got %v", want, names)
		}
	}
}

func TestRunSubsFormatAllFormats(t *testing.T) {
	defer pointSubsAt(t, fixtureCrt, fixtureCS)()

	cases := []struct {
		format     Format
		wantSubstr string
	}{
		{FormatText, "SUBDOMAIN ENUMERATION"},
		{FormatJSON, `"kind": "subs"`},
		{FormatMarkdown, "# netcheck subs"},
		{FormatHTML, "<h1>netcheck subs</h1>"},
	}
	for _, c := range cases {
		t.Run(c.wantSubstr, func(t *testing.T) {
			var buf bytes.Buffer
			code := runSubsFormat(&buf, "example.com", 5*time.Second, c.format)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(buf.String(), c.wantSubstr) {
				t.Errorf("output missing %q:\n%s", c.wantSubstr, buf.String())
			}
		})
	}
}

func TestRunSubsFormatJSONIsValid(t *testing.T) {
	defer pointSubsAt(t, fixtureCrt, fixtureCS)()

	var buf bytes.Buffer
	if code := runSubsFormat(&buf, "example.com", 5*time.Second, FormatJSON); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var got report.SubsJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Kind != "subs" {
		t.Errorf("kind = %q, want subs", got.Kind)
	}
	if len(got.Subdomains) == 0 {
		t.Errorf("expected at least one subdomain")
	}
}

func TestRunSubsAllSourcesFail(t *testing.T) {
	// Both mock servers return 500 → every source errors → exit 1.
	crtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	csSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer crtSrv.Close()
	defer csSrv.Close()
	restore := subenum.SetSourceURLsForTest(crtSrv.URL, csSrv.URL)
	defer restore()

	var buf bytes.Buffer
	if code := runSubsFormat(&buf, "example.com", 5*time.Second, FormatText); code != 1 {
		t.Errorf("exit code = %d, want 1 (all sources failed)", code)
	}
}

func TestRunSubsTopLevelBadDomain(t *testing.T) {
	if code := RunSubs([]string{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if code := RunSubs([]string{"--output", "yaml", "example.com"}); code != 2 {
		t.Errorf("exit code = %d, want 2 on bad format", code)
	}
}

func TestSubsDefaultTimeout(t *testing.T) {
	// Short config timeout — floor at 30s.
	if got := subsDefaultTimeout(5 * time.Second); got != 30*time.Second {
		t.Errorf("got %v, want 30s floor", got)
	}
	// Long config timeout — pass through.
	if got := subsDefaultTimeout(60 * time.Second); got != 60*time.Second {
		t.Errorf("got %v, want 60s passthrough", got)
	}
}
