// Package wayback queries archive.org's CDX API for historical snapshots of a
// domain. Passive — no traffic to the target. Returns first/last snapshot
// dates, total snapshot count, and a sample of the most-recent unique URLs
// the Wayback Machine has indexed for the domain.
package wayback

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

// cdxBase is the archive.org CDX API. Exported through SetSourceURLForTest
// for tests.
var cdxBase = "https://web.archive.org"

// SetSourceURLForTest swaps the CDX base URL. Empty restores default.
func SetSourceURLForTest(s string) (restore func()) {
	prev := cdxBase
	if s != "" {
		cdxBase = s
	}
	return func() { cdxBase = prev }
}

const maxBodyBytes = 16 << 20 // 16 MiB — CDX can be chunky for popular domains.

// defaultSampleLimit caps how many most-recent unique URLs we surface in the
// rendered output. The user always gets the total count regardless.
const defaultSampleLimit = 100

// Snapshot is one indexed capture.
type Snapshot struct {
	Timestamp time.Time // parsed from "20210815120000"
	URL       string    // captured URL
	Status    int       // HTTP status at capture time, 0 if unknown
}

// Result is the full lookup.
type Result struct {
	Domain        string
	Total         int       // total snapshots returned by the CDX query
	First         time.Time // earliest snapshot
	Last          time.Time // most recent snapshot
	UniqueURLs    int       // count of distinct URLs (post collapse=urlkey)
	RecentSamples []Snapshot
	StartedAt     time.Time
	Took          time.Duration
	Err           error
}

// Lookup queries CDX for `*.<domain>/*` (i.e. the domain and all subdomains)
// and aggregates the response into a Result.
func Lookup(ctx context.Context, domain string, timeout time.Duration) Result {
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

	// CDX query: prefix-match by domain, JSON output, collapse to one row per
	// urlkey (so we get distinct URLs not every capture), limit to a sane cap.
	// matchType=domain returns the domain + all subdomains.
	q := url.Values{}
	q.Set("url", d)
	q.Set("matchType", "domain")
	q.Set("output", "json")
	q.Set("fl", "timestamp,original,statuscode")
	q.Set("collapse", "urlkey")
	q.Set("limit", "5000")

	u := cdxBase + "/cdx/search/cdx?" + q.Encode()

	rows, err := fetchCDX(c, u)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}

	// CDX with output=json returns: first row = column names, subsequent rows
	// = data. The "fl" param above pins the columns; trust the order.
	if len(rows) <= 1 {
		out.Took = time.Since(started)
		return out
	}
	data := rows[1:]
	out.Total = len(data)
	out.UniqueURLs = len(data) // collapse=urlkey already dedupes by URL key.

	snapshots := make([]Snapshot, 0, len(data))
	for _, r := range data {
		if len(r) < 2 {
			continue
		}
		ts := parseCDXTimestamp(r[0])
		url := r[1]
		status := 0
		if len(r) >= 3 {
			status = parseStatus(r[2])
		}
		snapshots = append(snapshots, Snapshot{Timestamp: ts, URL: url, Status: status})
	}

	// First / last span.
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].Timestamp.Before(snapshots[j].Timestamp) })
	if len(snapshots) > 0 {
		out.First = snapshots[0].Timestamp
		out.Last = snapshots[len(snapshots)-1].Timestamp
	}

	// Recent sample: last N entries, newest first.
	limit := defaultSampleLimit
	if len(snapshots) < limit {
		limit = len(snapshots)
	}
	sample := snapshots[len(snapshots)-limit:]
	// Reverse so most-recent is first.
	for i, j := 0, len(sample)-1; i < j; i, j = i+1, j-1 {
		sample[i], sample[j] = sample[j], sample[i]
	}
	out.RecentSamples = sample
	out.Took = time.Since(started)
	return out
}

// fetchCDX issues the JSON CDX query and parses the doubly-nested array.
func fetchCDX(ctx context.Context, u string) ([][]string, error) {
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
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("wayback CDX returned %d: %s", resp.StatusCode, snippet)
	}
	if len(body) == 0 {
		return nil, nil
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback CDX: parse JSON: %w", err)
	}
	return rows, nil
}

// parseCDXTimestamp parses the 14-digit YYYYMMDDhhmmss form CDX returns.
// Returns the zero time on parse failure (the row will sort last, which is
// fine).
func parseCDXTimestamp(s string) time.Time {
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func parseStatus(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// normalizeDomain trims, lowers, accepts bare hosts or URLs.
func normalizeDomain(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return "", errors.New("empty domain")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", err
		}
		s = u.Host
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("could not extract domain from %q", raw)
	}
	if !strings.Contains(s, ".") {
		return "", fmt.Errorf("%q does not look like a domain (no dot)", raw)
	}
	return s, nil
}
