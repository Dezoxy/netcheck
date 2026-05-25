package wayback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"example.com", "example.com", false},
		{"EXAMPLE.COM.", "example.com", false},
		{"https://example.com/path", "example.com", false},
		{"example.com:8080", "example.com", false},
		{"", "", true},
		{"nodot", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := normalizeDomain(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseCDXTimestamp(t *testing.T) {
	got := parseCDXTimestamp("20210815120000")
	want := time.Date(2021, 8, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// Bad input → zero time, no panic.
	if !parseCDXTimestamp("garbage").IsZero() {
		t.Error("garbage should parse to zero time")
	}
}

func TestParseStatus(t *testing.T) {
	if parseStatus("200") != 200 {
		t.Error("200")
	}
	if parseStatus("-") != 0 {
		t.Error("- should be 0")
	}
	if parseStatus("") != 0 {
		t.Error("empty should be 0")
	}
}

const cdxFixture = `[
  ["timestamp","original","statuscode"],
  ["20100101000000","https://example.com/","200"],
  ["20150601120000","https://example.com/about","200"],
  ["20230101180000","https://example.com/foo","404"]
]`

func TestLookupAggregates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query parameters look right.
		q := r.URL.Query()
		if q.Get("matchType") != "domain" {
			t.Errorf("matchType = %q, want domain", q.Get("matchType"))
		}
		if q.Get("output") != "json" {
			t.Errorf("output = %q, want json", q.Get("output"))
		}
		if q.Get("collapse") != "urlkey" {
			t.Errorf("collapse = %q, want urlkey", q.Get("collapse"))
		}
		_, _ = w.Write([]byte(cdxFixture))
	}))
	defer srv.Close()
	defer SetSourceURLForTest(srv.URL)()

	res := Lookup(context.Background(), "example.com", 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Total != 3 {
		t.Errorf("total = %d, want 3", res.Total)
	}
	if res.First.Year() != 2010 {
		t.Errorf("first year = %d, want 2010", res.First.Year())
	}
	if res.Last.Year() != 2023 {
		t.Errorf("last year = %d, want 2023", res.Last.Year())
	}
	if len(res.RecentSamples) != 3 {
		t.Errorf("samples = %d, want 3", len(res.RecentSamples))
	}
	// Most recent should be first.
	if res.RecentSamples[0].URL != "https://example.com/foo" {
		t.Errorf("first sample URL = %q, want %q", res.RecentSamples[0].URL, "https://example.com/foo")
	}
}

func TestLookupEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just the header row.
		_, _ = w.Write([]byte(`[["timestamp","original","statuscode"]]`))
	}))
	defer srv.Close()
	defer SetSourceURLForTest(srv.URL)()

	res := Lookup(context.Background(), "example.com", 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Total != 0 {
		t.Errorf("total = %d, want 0", res.Total)
	}
	if len(res.RecentSamples) != 0 {
		t.Errorf("samples = %d, want 0", len(res.RecentSamples))
	}
}

func TestLookupHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":"down"}`))
	}))
	defer srv.Close()
	defer SetSourceURLForTest(srv.URL)()

	res := Lookup(context.Background(), "example.com", 5*time.Second)
	if res.Err == nil {
		t.Fatal("expected error on 503")
	}
	if !strings.Contains(res.Err.Error(), "down") {
		t.Errorf("err should include body snippet: %v", res.Err)
	}
}

func TestLookupBadDomain(t *testing.T) {
	res := Lookup(context.Background(), "", time.Second)
	if res.Err == nil {
		t.Error("expected err on empty domain")
	}
}

func TestSetUserAgentEmptyNoop(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	userAgent = "before"
	SetUserAgent("")
	if userAgent != "before" {
		t.Errorf("got %q", userAgent)
	}
}

func TestSetUserAgentSet(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	SetUserAgent("netcheck-test/0.0")
	seen := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()
	defer SetSourceURLForTest(srv.URL)()
	_ = Lookup(context.Background(), "example.com", 5*time.Second)
	if seen != "netcheck-test/0.0" {
		t.Errorf("UA = %q", seen)
	}
}
