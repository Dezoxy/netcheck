// Package reverseip enumerates other hostnames pointing at a given IP by
// querying public reverse-IP sources (system reverse DNS, Hackertarget, and
// optionally Shodan when an API key is configured). Passive — never talks to
// the target host itself.
package reverseip

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// userAgent is wired by main.go at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent string used for source requests.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// Base URLs are pkg vars for test redirection.
var (
	hackertargetBase = "https://api.hackertarget.com"
	shodanBase       = "https://api.shodan.io"
)

// SetSourceURLsForTest redirects both source base URLs. Empty string restores
// the production default. Returns a restore func.
func SetSourceURLsForTest(hackertarget, shodan string) (restore func()) {
	prevHT, prevSH := hackertargetBase, shodanBase
	if hackertarget != "" {
		hackertargetBase = hackertarget
	}
	if shodan != "" {
		shodanBase = shodan
	}
	return func() {
		hackertargetBase = prevHT
		shodanBase = prevSH
	}
}

// maxBodyBytes caps how much we'll read from any one source.
const maxBodyBytes = 8 << 20

// Source is one reverse-IP aggregator.
type Source interface {
	Name() string
	Fetch(ctx context.Context, ip string) ([]string, error)
}

// Options control which sources participate.
type Options struct {
	// ShodanAPIKey enables the Shodan source. Empty = disabled.
	ShodanAPIKey string
}

// Hostname is one finding plus which sources reported it.
type Hostname struct {
	Name    string
	Sources []string // sorted, unique
}

// Result is the full enumeration output.
type Result struct {
	IP             string
	Hostnames      []Hostname
	SourceErrors   map[string]string // source name → error string
	SourceDisabled []string          // source name → reason "(no API key)"
	StartedAt      time.Time
	Took           time.Duration
	Err            error
}

// Enumerate queries every available source in parallel and merges the
// results. Per-source failures are recorded in SourceErrors; the run only
// fails outright on input validation errors.
func Enumerate(ctx context.Context, rawIP string, opts Options, timeout time.Duration) Result {
	started := time.Now()
	out := Result{IP: rawIP, StartedAt: started, SourceErrors: map[string]string{}}

	ip, err := normalizeIP(rawIP)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	out.IP = ip

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Always-on sources.
	sources := []Source{
		&systemPTRSource{},
		&hackertargetSource{},
	}
	// Optional sources gated by config.
	if opts.ShodanAPIKey != "" {
		sources = append(sources, &shodanSource{apiKey: opts.ShodanAPIKey})
	} else {
		out.SourceDisabled = append(out.SourceDisabled, "shodan")
	}

	type sr struct {
		name  string
		names []string
		err   error
	}
	ch := make(chan sr, len(sources))
	var wg sync.WaitGroup
	for _, s := range sources {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			names, err := s.Fetch(c, ip)
			ch <- sr{name: s.Name(), names: names, err: err}
		}()
	}
	wg.Wait()
	close(ch)

	merged := map[string]map[string]bool{}
	for r := range ch {
		if r.err != nil {
			out.SourceErrors[r.name] = r.err.Error()
			continue
		}
		for _, raw := range r.names {
			n := normalizeName(raw)
			if n == "" {
				continue
			}
			if merged[n] == nil {
				merged[n] = map[string]bool{}
			}
			merged[n][r.name] = true
		}
	}

	out.Hostnames = sortHostnames(merged)
	out.Took = time.Since(started)
	return out
}

func sortHostnames(merged map[string]map[string]bool) []Hostname {
	out := make([]Hostname, 0, len(merged))
	for n, srcs := range merged {
		h := Hostname{Name: n}
		for s := range srcs {
			h.Sources = append(h.Sources, s)
		}
		sort.Strings(h.Sources)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// normalizeIP trims and validates the input is a literal IPv4/IPv6.
// Hostnames are rejected — `netcheck reverse` is IP-only by design; for
// hostname → IPs the user wants `netcheck dns` or `netcheck ip`.
func normalizeIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty IP")
	}
	// Strip brackets / port for "[::1]:443" style.
	s = strings.TrimPrefix(s, "[")
	if i := strings.Index(s, "]"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		// Only strip when it looks like host:port, not part of IPv6.
		if !strings.Contains(s[:i], ":") {
			s = s[:i]
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("%q is not a valid IP address", raw)
}

func normalizeName(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.Contains(s, " ") || strings.Contains(s, "@") {
		return ""
	}
	return s
}

// =============================================================================
// System PTR source
// =============================================================================

type systemPTRSource struct{}

func (systemPTRSource) Name() string { return "ptr" }

func (s systemPTRSource) Fetch(ctx context.Context, ip string) ([]string, error) {
	r := &net.Resolver{}
	names, err := r.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}
	return names, nil
}

// =============================================================================
// Hackertarget
// =============================================================================

type hackertargetSource struct{}

func (hackertargetSource) Name() string { return "hackertarget" }

func (s hackertargetSource) Fetch(ctx context.Context, ip string) ([]string, error) {
	u := hackertargetBase + "/reverseiplookup/?q=" + url.QueryEscape(ip)
	body, err := httpGet(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	text := string(body)
	// Hackertarget signals "no results" with this exact body. Treat as empty.
	if strings.HasPrefix(strings.TrimSpace(text), "No DNS A records") ||
		strings.HasPrefix(strings.TrimSpace(text), "error") {
		// Many error variants — be conservative.
		if strings.Contains(strings.ToLower(text), "error") {
			return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(text))
		}
		return nil, nil
	}

	var out []string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// =============================================================================
// Shodan
// =============================================================================

type shodanSource struct {
	apiKey string
}

func (shodanSource) Name() string { return "shodan" }

// shodanHost is the subset of /shodan/host/<ip> we read.
type shodanHost struct {
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
}

func (s shodanSource) Fetch(ctx context.Context, ip string) ([]string, error) {
	u := shodanBase + "/shodan/host/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(s.apiKey)
	body, err := httpGet(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	var h shodanHost
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, fmt.Errorf("shodan: parse JSON: %w", err)
	}
	return append([]string{}, h.Hostnames...), nil
}

// httpGet issues a GET with a body cap. headers map is reserved for callers
// that want to send Authorization etc.; nil is fine.
func httpGet(ctx context.Context, u string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("%s returned %d: %s", u, resp.StatusCode, snippet)
	}
	return body, nil
}
