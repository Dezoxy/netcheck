package takeover

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stubResolver swaps the package-level resolveCNAME for the duration of a
// test. Returns a restore func.
func stubResolver(cname string, err error) func() {
	prev := resolveCNAME
	resolveCNAME = func(ctx context.Context, host string) (string, error) {
		return cname, err
	}
	return func() { resolveCNAME = prev }
}

// stubProbe swaps the HTTP probe.
func stubProbe(status int, body string, err error) func() {
	prev := httpGet
	httpGet = func(ctx context.Context, url string) (int, string, error) {
		return status, body, err
	}
	return func() { httpGet = prev }
}

// =============================================================================
// normalizeDomain
// =============================================================================

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"example.com", "example.com", false},
		{"EXAMPLE.COM.", "example.com", false},
		{"foo.example.com:8080", "foo.example.com", false},
		{"  bar.example.com  ", "bar.example.com", false},
		{"", "", true},
		{"https://example.com", "", true}, // URL rejected
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
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// =============================================================================
// matchProvider — every catalog entry
// =============================================================================

func TestMatchProviderCatalog(t *testing.T) {
	cases := []struct {
		cname string
		want  string // expected Provider.Name, "" for no match
	}{
		{"foo.github.io", "GitHub Pages"},
		{"foo.github.io.", "GitHub Pages"},
		{"my-bucket.s3.amazonaws.com", "Amazon S3 (website)"},
		{"my-bucket.s3-website-us-east-1.amazonaws.com", "Amazon S3 (website)"},
		{"my-app.herokuapp.com", "Heroku"},
		{"foo.herokudns.com", "Heroku"},
		{"my-app.azurewebsites.net", "Azure App Service"},
		{"my-app.cloudapp.net", "Azure App Service"},
		{"my-app.trafficmanager.net", "Azure App Service"},
		{"my-store.myshopify.com", "Shopify"},
		{"foo.fastly.net", "Fastly"},
		{"foo.bitbucket.io", "Bitbucket Cloud"},
		{"foo.ghost.io", "Ghost"},
		{"unrelated.example.com", ""},
		{"github.io.evil.com", ""}, // suffix matters
	}
	for _, c := range cases {
		t.Run(c.cname, func(t *testing.T) {
			got := matchProvider(c.cname)
			if c.want == "" {
				if got != nil {
					t.Errorf("expected no match, got %s", got.Name)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %s, got nil", c.want)
			}
			if got.Name != c.want {
				t.Errorf("got %s, want %s", got.Name, c.want)
			}
		})
	}
}

// =============================================================================
// matchesSignature / matchesStatus
// =============================================================================

func TestMatchesSignature(t *testing.T) {
	if !matchesSignature("There isn't a GitHub Pages site here", []string{"There isn't a GitHub Pages site here"}) {
		t.Error("exact match should hit")
	}
	if !matchesSignature("THERE ISN'T A GITHUB PAGES SITE HERE", []string{"there isn't a github pages site here"}) {
		t.Error("case-insensitive")
	}
	if matchesSignature("hello world", []string{"NoSuchBucket"}) {
		t.Error("should not match")
	}
	if matchesSignature("anything", nil) {
		t.Error("empty signatures shouldn't match")
	}
}

func TestMatchesStatus(t *testing.T) {
	if !matchesStatus(404, []int{404}) {
		t.Error("404 should match")
	}
	if matchesStatus(200, []int{404}) {
		t.Error("200 should not match")
	}
	if matchesStatus(404, nil) {
		t.Error("empty list shouldn't match anything")
	}
}

// =============================================================================
// Check — verdict matrix
// =============================================================================

func TestCheckNoCNAME(t *testing.T) {
	// LookupCNAME returns the queried name itself when no CNAME exists.
	defer stubResolver("example.com.", nil)()
	res := Check(context.Background(), "example.com", time.Second)
	if res.HasCNAME {
		t.Error("HasCNAME should be false when CNAME equals the queried name")
	}
	if len(res.Findings) != 0 {
		t.Errorf("no findings expected, got %d", len(res.Findings))
	}
}

func TestCheckCNAMEUnknownProvider(t *testing.T) {
	defer stubResolver("some-random-host.example.net.", nil)()
	// No provider match → no probe needed; finding is "unknown".
	res := Check(context.Background(), "foo.example.com", time.Second)
	if !res.HasCNAME {
		t.Error("should have CNAME")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown", res.Findings[0].Verdict)
	}
	if res.Findings[0].Provider != "" {
		t.Errorf("provider should be empty, got %q", res.Findings[0].Provider)
	}
}

func TestCheckVulnerableViaSignature(t *testing.T) {
	defer stubResolver("unclaimed.github.io.", nil)()
	defer stubProbe(404, "There isn't a GitHub Pages site here", nil)()
	res := Check(context.Background(), "foo.example.com", time.Second)
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding")
	}
	f := res.Findings[0]
	if f.Verdict != VerdictVulnerable {
		t.Errorf("verdict = %q, want vulnerable", f.Verdict)
	}
	if f.Provider != "GitHub Pages" {
		t.Errorf("provider = %q, want GitHub Pages", f.Provider)
	}
	if !strings.Contains(f.Detail, "GitHub Pages") {
		t.Errorf("detail should mention provider: %s", f.Detail)
	}
}

func TestCheckVulnerableViaStatus(t *testing.T) {
	// GitHub Pages: 404 also triggers vuln verdict even without signature.
	defer stubResolver("unclaimed.github.io.", nil)()
	defer stubProbe(404, "totally unrelated body", nil)()
	res := Check(context.Background(), "foo.example.com", time.Second)
	if res.Findings[0].Verdict != VerdictVulnerable {
		t.Errorf("verdict = %q, want vulnerable (via 404 status)", res.Findings[0].Verdict)
	}
}

func TestCheckSafeWhenClaimed(t *testing.T) {
	defer stubResolver("claimed.github.io.", nil)()
	defer stubProbe(200, "<html>Welcome to my site!</html>", nil)()
	res := Check(context.Background(), "foo.example.com", time.Second)
	if res.Findings[0].Verdict != VerdictSafe {
		t.Errorf("verdict = %q, want safe", res.Findings[0].Verdict)
	}
}

func TestCheckUnverifiableOnProbeError(t *testing.T) {
	defer stubResolver("unclaimed.github.io.", nil)()
	defer stubProbe(0, "", errors.New("connection refused"))()
	res := Check(context.Background(), "foo.example.com", time.Second)
	if res.Findings[0].Verdict != VerdictUnverifiable {
		t.Errorf("verdict = %q, want unverifiable", res.Findings[0].Verdict)
	}
	if !strings.Contains(res.Findings[0].Detail, "connection refused") {
		t.Errorf("detail should include probe error: %s", res.Findings[0].Detail)
	}
}

func TestCheckS3NoSuchBucket(t *testing.T) {
	defer stubResolver("my-bucket.s3.amazonaws.com.", nil)()
	defer stubProbe(404, "<Error><Code>NoSuchBucket</Code></Error>", nil)()
	res := Check(context.Background(), "files.example.com", time.Second)
	if res.Findings[0].Verdict != VerdictVulnerable {
		t.Errorf("verdict = %q, want vulnerable (S3 NoSuchBucket)", res.Findings[0].Verdict)
	}
	if res.Findings[0].Provider != "Amazon S3 (website)" {
		t.Errorf("provider = %q", res.Findings[0].Provider)
	}
}

func TestCheckTopLevelBadInput(t *testing.T) {
	res := Check(context.Background(), "", time.Second)
	if res.Err == nil {
		t.Error("expected err on empty domain")
	}
	res = Check(context.Background(), "nodot", time.Second)
	if res.Err == nil {
		t.Error("expected err on no-dot input")
	}
	res = Check(context.Background(), "https://example.com", time.Second)
	if res.Err == nil {
		t.Error("expected err on URL input")
	}
}

// =============================================================================
// Catalog API
// =============================================================================

func TestProvidersReturnsCopy(t *testing.T) {
	ps := Providers()
	if len(ps) == 0 {
		t.Fatal("catalog should not be empty")
	}
	// Mutating the returned slice must not affect internal state.
	original := ps[0].Name
	ps[0].Name = "MUTATED"
	if Providers()[0].Name != original {
		t.Error("Providers() must return an independent copy")
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
	SetUserAgent("test-ua/1.0")
	if userAgent != "test-ua/1.0" {
		t.Errorf("got %q", userAgent)
	}
}
