// Package subenum enumerates subdomains of a target domain by querying public
// Certificate Transparency log aggregators (crt.sh and CertSpotter). Passive —
// no DNS lookups, no port probes, no traffic to the target. Findings are
// limited to what's been published in CT logs by certificate authorities.
package subenum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// userAgent is the User-Agent sent on source requests. main.go wires the
// canonical "netcheck/<version>" via SetUserAgent at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent string used for source requests. Safe to
// call once at startup before any enumeration runs.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// Base URLs are package vars so tests can point them at httptest servers.
var (
	crtShBase       = "https://crt.sh"
	certSpotterBase = "https://api.certspotter.com"
)

// SetSourceURLsForTest redirects both source base URLs. Calling with empty
// strings restores the defaults. Exported so cmd integration tests can stand
// up httptest servers without reaching into package internals.
//
// Test-only — callers shouldn't use this in production code paths.
func SetSourceURLsForTest(crtSh, certSpotter string) (restore func()) {
	prevCrt, prevCS := crtShBase, certSpotterBase
	if crtSh == "" {
		crtShBase = "https://crt.sh"
	} else {
		crtShBase = crtSh
	}
	if certSpotter == "" {
		certSpotterBase = "https://api.certspotter.com"
	} else {
		certSpotterBase = certSpotter
	}
	return func() {
		crtShBase = prevCrt
		certSpotterBase = prevCS
	}
}

// maxBodyBytes caps how much JSON we read from any one source. crt.sh can
// return megabytes for popular domains; 8 MiB is enough for ~50k SAN entries
// without risking OOM.
const maxBodyBytes = 8 << 20

// Source is one CT-log aggregator.
type Source interface {
	Name() string
	Fetch(ctx context.Context, domain string) ([]string, error)
}

// Subdomain is one dedup'd finding plus which sources reported it.
type Subdomain struct {
	Name     string   // e.g. "api.example.com" or "*.example.com"
	Sources  []string // ["crt.sh", "certspotter"] — sorted, unique
	Wildcard bool     // true if Name starts with "*."
}

// Result is the full enumeration output.
type Result struct {
	Domain       string
	Subdomains   []Subdomain
	SourceErrors map[string]string // source name → error string (when fetch failed)
	StartedAt    time.Time
	Took         time.Duration
	Err          error // top-level error (e.g. bad input). Per-source errors live in SourceErrors.
}

// Enumerate queries every configured source in parallel and merges the
// results. Per-source failures are recorded in SourceErrors; the run only
// fails outright on input validation errors.
func Enumerate(ctx context.Context, domain string, timeout time.Duration) Result {
	started := time.Now()
	out := Result{Domain: domain, StartedAt: started, SourceErrors: map[string]string{}}

	d, err := normalizeDomain(domain)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	out.Domain = d

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sources := []Source{
		&crtShSource{},
		&certSpotterSource{},
	}

	type sourceResult struct {
		name  string
		names []string
		err   error
	}
	ch := make(chan sourceResult, len(sources))
	var wg sync.WaitGroup
	for _, s := range sources {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			names, err := s.Fetch(c, d)
			ch <- sourceResult{name: s.Name(), names: names, err: err}
		}()
	}
	wg.Wait()
	close(ch)

	// Merge: name → set of sources.
	merged := map[string]map[string]bool{}
	for sr := range ch {
		if sr.err != nil {
			out.SourceErrors[sr.name] = sr.err.Error()
			continue
		}
		for _, raw := range sr.names {
			n := normalizeName(raw)
			if n == "" || !belongsTo(n, d) {
				continue
			}
			if merged[n] == nil {
				merged[n] = map[string]bool{}
			}
			merged[n][sr.name] = true
		}
	}

	out.Subdomains = sortSubdomains(merged)
	out.Took = time.Since(started)
	return out
}

// sortSubdomains turns the name→sources map into a sorted []Subdomain.
// Wildcards float to the top; remaining entries are alphabetical.
func sortSubdomains(merged map[string]map[string]bool) []Subdomain {
	out := make([]Subdomain, 0, len(merged))
	for n, sources := range merged {
		s := Subdomain{Name: n, Wildcard: strings.HasPrefix(n, "*.")}
		for src := range sources {
			s.Sources = append(s.Sources, src)
		}
		sort.Strings(s.Sources)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Wildcard != out[j].Wildcard {
			return out[i].Wildcard // wildcards first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// normalizeDomain trims, lowers, strips a trailing dot, and rejects URLs/blank
// input.
func normalizeDomain(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return "", errors.New("empty domain")
	}
	// Tolerate "https://example.com/foo" by extracting the host.
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", err
		}
		s = u.Host
	}
	// Strip :port if present.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	// Drop trailing dot.
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("could not extract domain from %q", raw)
	}
	if !strings.Contains(s, ".") {
		return "", fmt.Errorf("%q does not look like a domain (no dot)", raw)
	}
	return s, nil
}

// normalizeName lowercases and trims a CT-log name.
func normalizeName(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimSuffix(s, ".")
	// Some CT-log entries embed emails (e.g. "smime certificates"). Filter
	// anything that isn't a plausible hostname.
	if strings.Contains(s, "@") || strings.Contains(s, " ") {
		return ""
	}
	return s
}

// belongsTo reports whether name is the domain itself, a subdomain of it, or
// a wildcard underneath it. Rejects unrelated SANs that happen to appear on
// the same certificate.
func belongsTo(name, domain string) bool {
	if name == domain {
		return true
	}
	if strings.HasSuffix(name, "."+domain) {
		return true
	}
	// "*.example.com" belongs to "example.com".
	if name == "*."+domain {
		return true
	}
	return false
}

// =============================================================================
// crt.sh
// =============================================================================

type crtShSource struct{}

func (crtShSource) Name() string { return "crt.sh" }

// crtShEntry is one row from `?q=%25.<domain>&output=json`. Only the fields
// we use are unmarshalled.
type crtShEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

func (s crtShSource) Fetch(ctx context.Context, domain string) ([]string, error) {
	// %25 is "%" url-encoded; `q=%.example.com` matches the domain + all
	// subdomains. `output=json` is undocumented but stable.
	u := crtShBase + "/?q=%25." + url.QueryEscape(domain) + "&output=json"
	body, err := httpGet(ctx, u)
	if err != nil {
		return nil, err
	}
	var rows []crtShEntry
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh: parse JSON: %w", err)
	}
	out := make([]string, 0, len(rows)*2)
	for _, r := range rows {
		// name_value can hold multiple newline-separated SANs.
		for _, n := range strings.Split(r.NameValue, "\n") {
			if n = strings.TrimSpace(n); n != "" {
				out = append(out, n)
			}
		}
		if r.CommonName != "" {
			out = append(out, r.CommonName)
		}
	}
	return out, nil
}

// =============================================================================
// CertSpotter
// =============================================================================

type certSpotterSource struct{}

func (certSpotterSource) Name() string { return "certspotter" }

// certSpotterEntry is one row from
// `/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names`.
type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

func (s certSpotterSource) Fetch(ctx context.Context, domain string) ([]string, error) {
	u := certSpotterBase + "/v1/issuances?domain=" + url.QueryEscape(domain) +
		"&include_subdomains=true&expand=dns_names"
	body, err := httpGet(ctx, u)
	if err != nil {
		return nil, err
	}
	var rows []certSpotterEntry
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("certspotter: parse JSON: %w", err)
	}
	out := make([]string, 0, len(rows)*2)
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out, nil
}

// httpGet performs a GET against u, enforces the body cap, and returns the
// raw bytes. Status >= 400 returns a typed error so callers can include it
// in the per-source error map.
func httpGet(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		// Surface a slice of the response body for context. Many APIs use
		// JSON error envelopes; truncate to keep the error readable.
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("%s returned %d: %s", u, resp.StatusCode, snippet)
	}
	return body, nil
}
