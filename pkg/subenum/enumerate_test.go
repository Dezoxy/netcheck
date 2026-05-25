package subenum

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withMockSources spins up two httptest servers and returns a cleanup func.
// The handlers are the crt.sh and CertSpotter responses respectively.
func withMockSources(t *testing.T, crtBody, certSpotterBody string, crtStatus, csStatus int) func() {
	t.Helper()
	prevCrt, prevCS := crtShBase, certSpotterBase

	crtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if crtStatus != 0 {
			w.WriteHeader(crtStatus)
		}
		_, _ = w.Write([]byte(crtBody))
	}))
	csSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if csStatus != 0 {
			w.WriteHeader(csStatus)
		}
		_, _ = w.Write([]byte(certSpotterBody))
	}))

	crtShBase = crtSrv.URL
	certSpotterBase = csSrv.URL

	return func() {
		crtSrv.Close()
		csSrv.Close()
		crtShBase = prevCrt
		certSpotterBase = prevCS
	}
}

// =============================================================================
// normalizeDomain / normalizeName / belongsTo
// =============================================================================

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com", false},
		{"EXAMPLE.com", "example.com", false},
		{"example.com.", "example.com", false},
		{"  example.com  ", "example.com", false},
		{"https://example.com/path", "example.com", false},
		{"http://example.com:8080/", "example.com", false},
		{"", "", true},
		{"no-dot", "", true},
		{"://broken", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := normalizeDomain(c.in)
			if c.wantErr && err == nil {
				t.Errorf("want error, got %q", got)
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"API.Example.COM", "api.example.com"},
		{"  api.example.com.  ", "api.example.com"},
		{"foo@example.com", ""}, // email — filtered
		{"a b c", ""},           // space — filtered
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeName(c.in); got != c.want {
			t.Errorf("normalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBelongsTo(t *testing.T) {
	cases := []struct {
		name, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"deep.api.example.com", "example.com", true},
		{"*.example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"example.com.evil.com", "example.com", false},
		{"evil.com", "example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name+"_"+c.domain, func(t *testing.T) {
			if got := belongsTo(c.name, c.domain); got != c.want {
				t.Errorf("belongsTo(%q, %q) = %v, want %v", c.name, c.domain, got, c.want)
			}
		})
	}
}

// =============================================================================
// Enumerate — full integration through both mock sources
// =============================================================================

const crtShFixture = `[
  {"name_value": "example.com\n*.example.com", "common_name": "example.com"},
  {"name_value": "api.example.com", "common_name": "api.example.com"},
  {"name_value": "shared.example.com\nunrelated.evil.com", "common_name": "shared.example.com"},
  {"name_value": "Foo@Example.com", "common_name": ""}
]`

const certSpotterFixture = `[
  {"dns_names": ["example.com", "www.example.com", "api.example.com"]},
  {"dns_names": ["shared.example.com", "DOCS.EXAMPLE.COM"]}
]`

func TestEnumerateMergesSources(t *testing.T) {
	defer withMockSources(t, crtShFixture, certSpotterFixture, 0, 0)()

	res := Enumerate(context.Background(), "example.com", 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if len(res.SourceErrors) != 0 {
		t.Errorf("expected no source errors, got %v", res.SourceErrors)
	}

	// Expected set: example.com, *.example.com, api.example.com,
	// shared.example.com, www.example.com, docs.example.com — 6 entries.
	gotNames := map[string]Subdomain{}
	for _, s := range res.Subdomains {
		gotNames[s.Name] = s
	}
	for _, want := range []string{"example.com", "*.example.com", "api.example.com", "shared.example.com", "www.example.com", "docs.example.com"} {
		if _, ok := gotNames[want]; !ok {
			t.Errorf("missing expected subdomain %q in result; got %v", want, gotNames)
		}
	}
	// Unrelated SAN should be dropped.
	if _, ok := gotNames["unrelated.evil.com"]; ok {
		t.Error("unrelated.evil.com should have been filtered")
	}

	// shared.example.com appears in both sources — should have len(Sources)==2.
	shared := gotNames["shared.example.com"]
	if len(shared.Sources) != 2 {
		t.Errorf("shared.example.com sources = %v, want 2", shared.Sources)
	}

	// Wildcard ordering: *.example.com should be first.
	if !res.Subdomains[0].Wildcard {
		t.Errorf("first entry should be the wildcard, got %+v", res.Subdomains[0])
	}
}

func TestEnumerateOneSourceFails(t *testing.T) {
	defer withMockSources(t, "not json at all", certSpotterFixture, 0, 0)()

	res := Enumerate(context.Background(), "example.com", 5*time.Second)
	if res.Err != nil {
		t.Fatalf("top-level err = %v, want nil", res.Err)
	}
	if _, ok := res.SourceErrors["crt.sh"]; !ok {
		t.Errorf("expected crt.sh error, got %v", res.SourceErrors)
	}
	// Still got names from CertSpotter.
	if len(res.Subdomains) == 0 {
		t.Error("expected at least one subdomain from the surviving source")
	}
}

func TestEnumerateBothSourcesFail(t *testing.T) {
	defer withMockSources(t, `boom`, `boom`, 500, 500)()

	res := Enumerate(context.Background(), "example.com", 5*time.Second)
	if res.Err != nil {
		t.Errorf("top-level err = %v, want nil (per-source errors should not promote)", res.Err)
	}
	if len(res.SourceErrors) != 2 {
		t.Errorf("expected 2 source errors, got %v", res.SourceErrors)
	}
	if len(res.Subdomains) != 0 {
		t.Errorf("expected zero subdomains, got %d", len(res.Subdomains))
	}
}

func TestEnumerateBadInput(t *testing.T) {
	res := Enumerate(context.Background(), "", time.Second)
	if res.Err == nil {
		t.Error("expected top-level error on empty domain")
	}
}

func TestEnumerateBadDomain(t *testing.T) {
	res := Enumerate(context.Background(), "nodot", time.Second)
	if res.Err == nil {
		t.Error("expected error for domain without a dot")
	}
}

// =============================================================================
// httpGet
// =============================================================================

func TestHTTPGetSendsUserAgent(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	SetUserAgent("netcheck-test/1.0")

	seen := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	if _, err := httpGet(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if seen != "netcheck-test/1.0" {
		t.Errorf("UA = %q, want netcheck-test/1.0", seen)
	}
}

func TestHTTPGetErrorIncludesBodySnippet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer srv.Close()

	_, err := httpGet(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("err should include body snippet: %v", err)
	}
}

func TestHTTPGetRespectsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := httpGet(ctx, srv.URL)
	if err == nil {
		t.Error("expected context cancellation error")
	}
}

// Sanity: SetUserAgent("") is a no-op.
func TestSetUserAgentEmptyNoop(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	userAgent = "before"
	SetUserAgent("")
	if userAgent != "before" {
		t.Errorf("SetUserAgent(\"\") should be no-op, got %q", userAgent)
	}
}

// =============================================================================
// crt.sh / CertSpotter source-specific paths
// =============================================================================

func TestCrtShQueryFormat(t *testing.T) {
	gotQ := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQ = r.URL.RawQuery
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()
	prev := crtShBase
	crtShBase = srv.URL
	defer func() { crtShBase = prev }()

	if _, err := (crtShSource{}).Fetch(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// crt.sh expects q=%.<domain> (with literal "%.") and output=json. We
	// URL-encode the % as %25, so the raw query starts with q=%25.
	if !strings.Contains(gotQ, "q=%25.example.com") {
		t.Errorf("crt.sh query missing %%-wildcard prefix: %s", gotQ)
	}
	if !strings.Contains(gotQ, "output=json") {
		t.Errorf("crt.sh query missing output=json: %s", gotQ)
	}
}

func TestCertSpotterQueryFormat(t *testing.T) {
	gotQ := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQ = r.URL.RawQuery
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()
	prev := certSpotterBase
	certSpotterBase = srv.URL
	defer func() { certSpotterBase = prev }()

	if _, err := (certSpotterSource{}).Fetch(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"domain=example.com", "include_subdomains=true", "expand=dns_names"} {
		if !strings.Contains(gotQ, want) {
			t.Errorf("certspotter query missing %q: %s", want, gotQ)
		}
	}
}

// Sanity that a fixture-shaped response actually parses into names.
func TestCrtShFetchParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, crtShFixture)
	}))
	defer srv.Close()
	prev := crtShBase
	crtShBase = srv.URL
	defer func() { crtShBase = prev }()

	names, err := (crtShSource{}).Fetch(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("expected names")
	}
}

func TestCertSpotterFetchParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, certSpotterFixture)
	}))
	defer srv.Close()
	prev := certSpotterBase
	certSpotterBase = srv.URL
	defer func() { certSpotterBase = prev }()

	names, err := (certSpotterSource{}).Fetch(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("expected names")
	}
}
