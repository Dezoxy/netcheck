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
	"github.com/Dezoxy/netcheck/pkg/wayback"
)

const cdxFixture = `[
  ["timestamp","original","statuscode"],
  ["20100101000000","https://example.com/","200"],
  ["20200101000000","https://example.com/about","200"]
]`

func pointArchAt(t *testing.T, body string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	restore := wayback.SetSourceURLForTest(srv.URL)
	return func() {
		restore()
		srv.Close()
	}
}

func TestBuildArchAgainstMockSource(t *testing.T) {
	defer pointArchAt(t, cdxFixture)()

	j := BuildArch(context.Background(), "example.com", 5*time.Second)
	if j.Kind != "arch" {
		t.Errorf("kind = %q, want arch", j.Kind)
	}
	if j.Total != 2 {
		t.Errorf("total = %d, want 2", j.Total)
	}
	if j.First == nil || j.First.Year() != 2010 {
		t.Errorf("first = %v, want 2010", j.First)
	}
	if j.Last == nil || j.Last.Year() != 2020 {
		t.Errorf("last = %v, want 2020", j.Last)
	}
}

func TestRunArchFormatAllFormats(t *testing.T) {
	defer pointArchAt(t, cdxFixture)()
	cases := []struct {
		format     Format
		wantSubstr string
	}{
		{FormatText, "WAYBACK ARCHIVE"},
		{FormatJSON, `"kind": "arch"`},
		{FormatMarkdown, "# netcheck arch"},
		{FormatHTML, "<h1>netcheck arch</h1>"},
	}
	for _, c := range cases {
		t.Run(c.wantSubstr, func(t *testing.T) {
			var buf bytes.Buffer
			code := runArchFormat(&buf, "example.com", 5*time.Second, c.format)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(buf.String(), c.wantSubstr) {
				t.Errorf("output missing %q:\n%s", c.wantSubstr, buf.String())
			}
		})
	}
}

func TestRunArchFormatJSONIsValid(t *testing.T) {
	defer pointArchAt(t, cdxFixture)()
	var buf bytes.Buffer
	if code := runArchFormat(&buf, "example.com", 5*time.Second, FormatJSON); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	var got report.ArchJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Total != 2 {
		t.Errorf("total = %d, want 2", got.Total)
	}
}

func TestRunArchTopLevelBadInput(t *testing.T) {
	if code := RunArch([]string{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if code := RunArch([]string{"--output", "yaml", "example.com"}); code != 2 {
		t.Errorf("exit code = %d, want 2 on bad format", code)
	}
}

func TestArchDefaultTimeout(t *testing.T) {
	if got := archDefaultTimeout(10 * time.Second); got != 60*time.Second {
		t.Errorf("got %v, want 60s floor", got)
	}
	if got := archDefaultTimeout(90 * time.Second); got != 90*time.Second {
		t.Errorf("got %v, want passthrough", got)
	}
}
