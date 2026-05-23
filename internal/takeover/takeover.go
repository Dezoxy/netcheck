// Package takeover detects dangling CNAME records that point at unclaimed
// third-party services (GitHub Pages, S3, Heroku, Azure App Service, etc.) —
// the typical subdomain-takeover vulnerability class.
//
// Hybrid passive/active: the CNAME resolution itself is benign (no different
// from `dig`), but the verification probe (an HTTP GET against the CNAME
// target) is active. Gated behind the v1.5 authorization flag at the cmd
// layer because the OUTPUT identifies a vulnerability with exploit-ready
// detail.
//
// Catalog is intentionally small — we focus on the common, high-signal
// providers documented at github.com/EdOverflow/can-i-take-over-xyz. Adding
// more is one struct literal in the providers list.
package takeover

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// userAgent is wired by main.go at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent string used by the verification probe.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// resolveCNAME is the DNS hook. Overridable for tests.
var resolveCNAME = func(ctx context.Context, host string) (string, error) {
	r := &net.Resolver{}
	return r.LookupCNAME(ctx, host)
}

// httpGet is the HTTP probe hook. Overridable for tests.
var httpGet = func(ctx context.Context, url string) (status int, body string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	// Cap body — vuln signatures appear in the first KB of error pages.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	return resp.StatusCode, string(b), nil
}

// Provider is one fingerprinted third-party service.
type Provider struct {
	Name           string
	CNAMEPattern   *regexp.Regexp
	ProbeScheme    string   // "https" | "http" — most providers serve HTTPS, some don't.
	VulnSignatures []string // case-insensitive body substrings indicating "unclaimed"
	VulnStatuses   []int    // status codes that, combined with no rebuttal, indicate vuln (e.g. 404 on GitHub Pages root)
	Notes          string
}

// providers is the built-in catalog. Order matters only for the first match
// (most CNAME targets only fit one).
var providers = []Provider{
	{
		Name:           "GitHub Pages",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.github\.io$|^[a-z0-9-]+\.github\.io\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"},
		VulnStatuses:   []int{404},
		Notes:          "GitHub Pages serves a generic 404 with the signature text when the repo or user/org is missing.",
	},
	{
		Name:           "Amazon S3 (website)",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.s3(?:[.-]website)?[.-][a-z0-9-]+\.amazonaws\.com\.?$|\.s3\.amazonaws\.com\.?$`),
		ProbeScheme:    "http",
		VulnSignatures: []string{"NoSuchBucket", "The specified bucket does not exist"},
		Notes:          "S3 returns NoSuchBucket in the XML body when the bucket is unclaimed. Anyone with an AWS account can claim it.",
	},
	{
		Name:           "Heroku",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.herokuapp\.com\.?$|\.herokudns\.com\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		Notes:          "Heroku serves an explicit 'No such app' page when the app name is unclaimed.",
	},
	{
		Name:           "Azure App Service",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.azurewebsites\.net\.?$|\.cloudapp\.net\.?$|\.trafficmanager\.net\.?$|\.blob\.core\.windows\.net\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"404 Web Site not found", "The web app you have attempted to reach", "Web App - Unavailable"},
		Notes:          "Azure App Service returns a distinct 'Web Site not found' page when the resource is unclaimed.",
	},
	{
		Name:           "Shopify",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.myshopify\.com\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"Sorry, this shop is currently unavailable", "Only one step left!"},
		Notes:          "Shopify shows 'Sorry, this shop is currently unavailable' when the storefront is unclaimed.",
	},
	{
		Name:           "Fastly",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.fastly\.net\.?$|\.fastlylb\.net\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"Fastly error: unknown domain"},
		Notes:          "Fastly returns 'unknown domain' when the host header doesn't map to a configured service.",
	},
	{
		Name:           "Bitbucket Cloud",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.bitbucket\.io\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"Repository not found"},
		Notes:          "Bitbucket Pages serves 'Repository not found' when the source repo is missing.",
	},
	{
		Name:           "Ghost",
		CNAMEPattern:   regexp.MustCompile(`(?i)\.ghost\.io\.?$`),
		ProbeScheme:    "https",
		VulnSignatures: []string{"Domain error", "The thing you were looking for is no longer here"},
		Notes:          "Ghost-hosted blogs show 'Domain error' when the domain isn't configured on a Ghost site.",
	},
}

// Verdict is the takeover-readiness for one finding.
type Verdict string

const (
	VerdictVulnerable    Verdict = "vulnerable"     // matches signature → can be taken over
	VerdictUnverifiable  Verdict = "unverifiable"   // CNAME matches provider but probe didn't confirm or failed
	VerdictSafe          Verdict = "safe"           // CNAME matches provider but service responded with content
	VerdictUnknown       Verdict = "unknown"        // no provider match (the CNAME points at something we don't track)
)

// Finding is the takeover-check result for one CNAME chain.
type Finding struct {
	CNAME    string // the resolved CNAME target (without trailing dot)
	Provider string // matched Provider.Name, or "" when no match
	Verdict  Verdict
	Status   int    // HTTP status from the probe (0 if no probe)
	Detail   string // human-readable explanation
	Notes    string // copied from Provider.Notes when verdict != unknown
}

// Result is the full lookup.
type Result struct {
	Domain    string
	HasCNAME  bool
	Findings  []Finding
	StartedAt time.Time
	Took      time.Duration
	Err       error
}

// Check resolves the CNAME for domain and probes each provider match.
// Returns Result with Err set on input-validation failure. DNS failure
// (no CNAME) is NOT an error — that's just the common case.
func Check(ctx context.Context, domain string, timeout time.Duration) Result {
	started := time.Now()
	out := Result{Domain: domain, StartedAt: started}

	d, err := normalizeDomain(domain)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	out.Domain = d

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cname, err := resolveCNAME(c, d)
	cname = strings.TrimSuffix(cname, ".")
	if err != nil || cname == "" || cname == d {
		// No CNAME (LookupCNAME returns the queried name itself when there
		// isn't one). No takeover surface.
		out.Took = time.Since(started)
		return out
	}
	out.HasCNAME = true

	f := Finding{CNAME: cname, Verdict: VerdictUnknown}
	if p := matchProvider(cname); p != nil {
		f.Provider = p.Name
		f.Notes = p.Notes
		probeURL := p.ProbeScheme + "://" + cname + "/"
		status, body, err := httpGet(c, probeURL)
		f.Status = status
		switch {
		case err != nil:
			f.Verdict = VerdictUnverifiable
			f.Detail = "CNAME points at " + p.Name + " but the verification probe failed: " + err.Error()
		case matchesSignature(body, p.VulnSignatures) || matchesStatus(status, p.VulnStatuses):
			f.Verdict = VerdictVulnerable
			f.Detail = fmt.Sprintf("CNAME points at %s and the response matches a known 'unclaimed' signature. Anyone able to claim a %s resource for `%s` can serve content for your domain.", p.Name, p.Name, cname)
		default:
			f.Verdict = VerdictSafe
			f.Detail = fmt.Sprintf("CNAME points at %s and the resource appears to be claimed (status %d, no vulnerability signature in response body).", p.Name, status)
		}
	} else {
		f.Detail = fmt.Sprintf("CNAME points at %s, which is not in netcheck's takeover catalog. That doesn't mean it's safe — just that we have no fingerprint for it.", cname)
	}
	out.Findings = append(out.Findings, f)
	out.Took = time.Since(started)
	return out
}

// matchProvider returns the first Provider whose CNAMEPattern matches the
// given target, or nil.
func matchProvider(cname string) *Provider {
	for i := range providers {
		if providers[i].CNAMEPattern.MatchString(cname) {
			return &providers[i]
		}
	}
	return nil
}

// matchesSignature checks the body for any of the case-insensitive substrings.
func matchesSignature(body string, signatures []string) bool {
	if len(signatures) == 0 {
		return false
	}
	low := strings.ToLower(body)
	for _, s := range signatures {
		if strings.Contains(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// matchesStatus reports whether status is in the expected vuln-status list.
func matchesStatus(status int, expected []int) bool {
	for _, e := range expected {
		if status == e {
			return true
		}
	}
	return false
}

func normalizeDomain(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return "", errors.New("empty domain")
	}
	if strings.Contains(s, "://") {
		return "", errors.New("pass a bare hostname, not a URL")
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if !strings.Contains(s, ".") {
		return "", fmt.Errorf("%q does not look like a domain (no dot)", raw)
	}
	return s, nil
}

// Providers returns a copy of the built-in catalog. Useful for `--list` style
// commands or for users who want to see what the fingerprint coverage is.
func Providers() []Provider {
	out := make([]Provider, len(providers))
	copy(out, providers)
	return out
}
