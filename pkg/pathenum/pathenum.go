// Package pathenum performs HTTP path enumeration against a base URL —
// requests each path in a wordlist and reports the responses that aren't
// 404s. Active: opens many HTTP connections to the target.
//
// Gated behind the v1.5 authorization flag at the cmd layer.
package pathenum

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// userAgent is wired by main.go at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent for path requests.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// httpDo is the request hook. Overridable in tests.
var httpDo = func(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}

// Result is the full enumeration.
type Result struct {
	BaseURL   string
	Findings  []Finding
	Stats     Stats
	StartedAt time.Time
	Took      time.Duration
	Err       error
}

// Finding is one HTTP path that returned an interesting response.
type Finding struct {
	Path     string // path as it was requested (e.g. "robots.txt")
	URL      string // full URL after joining base + path
	Status   int
	Length   int64  // Content-Length (0 if unset)
	Redirect string // Location header on 3xx
	Category string // "found" | "redirect" | "blocked" | "auth-required" | "server-error"
}

// Stats summarises the run.
type Stats struct {
	Total       int // wordlist length
	Interesting int // findings emitted
	NotFound    int // 404 / 410
	Errors      int // request errors (timeouts, transport)
}

// Options control the enumeration.
type Options struct {
	Wordlist        []string      // exact list. If nil, falls back to DefaultWordlist().
	Concurrency     int           // parallel requests. 0/<0 → 10.
	PerPathTimeout  time.Duration // per-request timeout. 0/<0 → 5s.
	Insecure        bool          // skip TLS verification
	FollowRedirects bool          // when false, 3xx is reported and not followed
}

// Enumerate requests every path in opts.Wordlist (or the builtin) under
// baseURL, returning the response details for paths that returned anything
// other than 404 / 410 (and request failures, counted in Stats).
func Enumerate(ctx context.Context, baseURL string, opts Options, overallTimeout time.Duration) Result {
	started := time.Now()
	out := Result{BaseURL: baseURL, StartedAt: started}

	base, err := normalizeBase(baseURL)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	out.BaseURL = base

	c, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	words := opts.Wordlist
	if len(words) == 0 {
		words = DefaultWordlist()
	}
	out.Stats.Total = len(words)

	conc := opts.Concurrency
	if conc <= 0 {
		conc = 10
	}
	perPath := opts.PerPathTimeout
	if perPath <= 0 {
		perPath = 5 * time.Second
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure},
		},
		Timeout: perPath,
	}
	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	type pathRes struct {
		f    Finding
		err  error
		miss bool // 404 / 410
	}
	results := make([]pathRes, len(words))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, word := range words {
		i, word := i, word
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fullURL := joinPath(base, word)
			req, err := http.NewRequestWithContext(c, "GET", fullURL, nil)
			if err != nil {
				results[i] = pathRes{err: err}
				return
			}
			req.Header.Set("User-Agent", userAgent)
			resp, err := httpDo(client, req)
			if err != nil {
				results[i] = pathRes{err: err}
				return
			}
			defer resp.Body.Close()
			// Drain a small slice of body to free the connection.
			// Read errors here aren't actionable — the body is being
			// thrown away regardless.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))

			if resp.StatusCode == 404 || resp.StatusCode == 410 {
				results[i] = pathRes{miss: true}
				return
			}
			cat := categorize(resp.StatusCode)
			if cat == "" {
				// Not classified — treat as not interesting (e.g. 5xx run-of-the-mill,
				// 1xx, etc.) Don't emit but don't count as miss either.
				return
			}
			f := Finding{
				Path:     word,
				URL:      fullURL,
				Status:   resp.StatusCode,
				Length:   resp.ContentLength,
				Category: cat,
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				f.Redirect = loc
			}
			results[i] = pathRes{f: f}
		}()
	}
	wg.Wait()

	for _, r := range results {
		switch {
		case r.err != nil:
			out.Stats.Errors++
		case r.miss:
			out.Stats.NotFound++
		case r.f.Status > 0:
			out.Stats.Interesting++
			out.Findings = append(out.Findings, r.f)
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Status != out.Findings[j].Status {
			return out.Findings[i].Status < out.Findings[j].Status
		}
		return out.Findings[i].Path < out.Findings[j].Path
	})
	out.Took = time.Since(started)
	return out
}

// categorize returns the Finding.Category for an HTTP status, or "" when
// the response isn't interesting enough to surface.
func categorize(status int) string {
	switch {
	case status == 200:
		return "found"
	case status == 401:
		return "auth-required"
	case status == 403:
		return "blocked"
	case status >= 300 && status < 400:
		return "redirect"
	case status >= 500 && status < 600:
		return "server-error"
	default:
		return ""
	}
}

// normalizeBase ensures the URL has a scheme (defaults to https://) and a
// non-empty host.
func normalizeBase(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty URL")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("no host in %q", raw)
	}
	// Strip query/fragment — we replace the path per request.
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// joinPath appends path to baseURL, handling leading-slash collisions.
func joinPath(baseURL, path string) string {
	if path == "" {
		return baseURL
	}
	// Strip a leading slash on the path to avoid the "double slash" trap
	// (https://example.com//foo).
	path = strings.TrimPrefix(path, "/")
	if strings.HasSuffix(baseURL, "/") {
		return baseURL + path
	}
	return baseURL + "/" + path
}

// LoadWordlist reads paths from a file, one per line. Lines starting with
// "#" or that are blank are skipped. Leading/trailing whitespace is trimmed.
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// DefaultWordlist returns the small built-in wordlist. ~50 high-signal
// paths covering exposed-config, exposed-VCS, auth, admin, common APIs,
// and dev artifacts. The goal is "quick smoke test" not "comprehensive
// scan" — point --wordlist at SecLists for the latter.
func DefaultWordlist() []string {
	out := make([]string, len(builtinPaths))
	copy(out, builtinPaths)
	return out
}

var builtinPaths = []string{
	// Crawl/SEO hints — finding these tells you what the target *wants* indexed
	"robots.txt",
	"sitemap.xml",
	"sitemap_index.xml",
	"humans.txt",
	"ads.txt",
	"crossdomain.xml",

	// .well-known
	".well-known/security.txt",
	".well-known/change-password",
	".well-known/openid-configuration",

	// Exposed VCS / build artifacts — very common, very dangerous
	".git/HEAD",
	".git/config",
	".gitignore",
	".svn/entries",
	".hg/hgrc",
	".bzr/branch/branch.conf",

	// Environment / secrets in webroot
	".env",
	".env.local",
	".env.production",
	".env.dev",
	"config.json",
	"config.yaml",

	// Dev artifacts left behind
	".DS_Store",
	"Thumbs.db",
	"composer.json",
	"composer.lock",
	"package.json",
	"yarn.lock",
	"Gemfile",
	"Gemfile.lock",
	"requirements.txt",

	// Admin / login
	"admin",
	"admin/",
	"admin.php",
	"administrator",
	"administrator/",
	"login",
	"login.php",
	"signin",
	"wp-admin",
	"wp-login.php",

	// CMS
	"wp-config.php",
	"wp-content/uploads/",
	"phpmyadmin",
	"phpmyadmin/",
	"pma/",

	// API / docs
	"api",
	"api/",
	"api/v1",
	"api/v2",
	"api/docs",
	"swagger",
	"swagger-ui",
	"swagger.json",
	"openapi.json",
	"graphql",

	// Backup / dump
	"backup",
	"backup.zip",
	"backup.tar.gz",
	"backup.sql",
	"db.sql",
	"dump.sql",

	// Info / debug
	"info.php",
	"phpinfo.php",
	"server-status",
	"debug",
	"_debug",

	// Generic dirs that often expose listings
	"backup/",
	"logs/",
	"log/",
	"tmp/",
	"upload/",
	"uploads/",
}
