// Package secheaders fetches a URL and grades the security-relevant response
// headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
// Permissions-Policy) plus information-disclosure headers (Server,
// X-Powered-By). Passive — one HTTP GET, no active probing.
package secheaders

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// userAgent is the User-Agent sent on the audit request. main.go wires the
// canonical "netcheck/<version>" via SetUserAgent at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent string used for audit requests. Safe to
// call once at startup before any audit runs.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// Grade is the per-header verdict.
type Grade string

const (
	GradePass    Grade = "pass"
	GradeWeak    Grade = "weak"
	GradeMissing Grade = "missing"
	GradeInfo    Grade = "info" // informational, not graded (e.g. Server header content)
)

// Finding is the result for one header (or related signal).
type Finding struct {
	Name    string // header name, canonical case (e.g. "Strict-Transport-Security")
	Value   string // raw header value, empty when missing
	Grade   Grade
	Comment string // human-readable explanation of the verdict
}

// Result is the full audit output.
type Result struct {
	URL       string    // request URL (input, before redirects)
	FinalURL  string    // last URL in the redirect chain (matches resp.Request.URL)
	Status    int       // final HTTP status
	Findings  []Finding // ordered: graded headers first, info findings last
	StartedAt time.Time
	Took      time.Duration
	Err       error // transport / connection / context error, if any
}

// minimum HSTS max-age we consider a pass: 6 months in seconds. Matches what
// most hardening guides recommend as the floor (the preload list requires 1y).
const hstsMinPass = 15_768_000

// Audit fetches rawURL with a GET (insecure-TLS optional) and grades the
// response headers. Returns Result with Err set on connect/transport failure.
func Audit(ctx context.Context, rawURL string, insecure bool, timeout time.Duration) Result {
	started := time.Now()
	out := Result{URL: rawURL, StartedAt: started}

	parsed, err := normalizeURL(rawURL)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequestWithContext(c, "GET", parsed, nil)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	out.FinalURL = resp.Request.URL.String()
	out.Status = resp.StatusCode
	out.Findings = grade(resp.Request.URL, resp.Header)
	out.Took = time.Since(started)
	return out
}

// normalizeURL ensures the input has a scheme. Defaults to https:// when none.
func normalizeURL(raw string) (string, error) {
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
	return u.String(), nil
}

// grade runs every header check and returns a stable-ordered list of Findings.
func grade(reqURL *url.URL, h http.Header) []Finding {
	var out []Finding

	// HSTS only meaningful over HTTPS.
	httpsScheme := reqURL != nil && reqURL.Scheme == "https"
	out = append(out, gradeHSTS(h.Get("Strict-Transport-Security"), httpsScheme))
	out = append(out, gradeCSP(h.Get("Content-Security-Policy")))
	out = append(out, gradeXFO(h.Get("X-Frame-Options")))
	out = append(out, gradeXCTO(h.Get("X-Content-Type-Options")))
	out = append(out, gradeReferrer(h.Get("Referrer-Policy")))
	out = append(out, gradePermissions(h.Get("Permissions-Policy")))

	// Information disclosure (info-only, not graded against a "should pass"
	// bar — just call out what the server is telling the world).
	if v := h.Get("Server"); v != "" {
		out = append(out, Finding{
			Name: "Server", Value: v, Grade: GradeInfo,
			Comment: "Server header exposes software identification — consider stripping or making it generic in production.",
		})
	}
	if v := h.Get("X-Powered-By"); v != "" {
		out = append(out, Finding{
			Name: "X-Powered-By", Value: v, Grade: GradeWeak,
			Comment: "X-Powered-By leaks the application stack — remove this header.",
		})
	}

	return out
}

func gradeHSTS(v string, https bool) Finding {
	f := Finding{Name: "Strict-Transport-Security", Value: v}
	if v == "" {
		f.Grade = GradeMissing
		if !https {
			f.Comment = "Missing — HSTS is only honoured over HTTPS, so this is expected on a plain-HTTP URL but the site should redirect to HTTPS and set HSTS there."
		} else {
			f.Comment = "Missing — protects against protocol-downgrade and cookie-hijacking attacks. Set `max-age=31536000; includeSubDomains; preload` once you're committed to HTTPS-only."
		}
		return f
	}
	maxAge, ok := hstsMaxAge(v)
	hasIncludeSub := containsToken(v, "includeSubDomains")
	hasPreload := containsToken(v, "preload")

	switch {
	case !ok:
		f.Grade = GradeWeak
		f.Comment = "Present but no parseable max-age — browsers may ignore this header."
	case maxAge < hstsMinPass:
		f.Grade = GradeWeak
		f.Comment = fmt.Sprintf("max-age=%d is too short (under 6 months). Bump to at least 31536000 (1y).", maxAge)
	case !hasIncludeSub:
		f.Grade = GradeWeak
		f.Comment = "max-age is long enough, but no `includeSubDomains` — subdomains aren't protected."
	default:
		f.Grade = GradePass
		if hasPreload {
			f.Comment = "Long max-age, includeSubDomains, preload directive present."
		} else {
			f.Comment = "Long max-age and includeSubDomains. Add `preload` and submit to hstspreload.org for browser-bundled protection."
		}
	}
	return f
}

func gradeCSP(v string) Finding {
	f := Finding{Name: "Content-Security-Policy", Value: v}
	if v == "" {
		f.Grade = GradeMissing
		f.Comment = "Missing — CSP is the strongest defence against XSS. Even a basic `default-src 'self'` policy raises the bar significantly."
		return f
	}
	lower := strings.ToLower(v)
	unsafe := []string{}
	if strings.Contains(lower, "'unsafe-inline'") {
		unsafe = append(unsafe, "'unsafe-inline'")
	}
	if strings.Contains(lower, "'unsafe-eval'") {
		unsafe = append(unsafe, "'unsafe-eval'")
	}
	if len(unsafe) > 0 {
		f.Grade = GradeWeak
		f.Comment = "Present but allows " + strings.Join(unsafe, " and ") + " — these weaken the XSS protection. Use nonces or hashes where possible."
		return f
	}
	f.Grade = GradePass
	f.Comment = "Present and avoids the obvious foot-guns (no unsafe-inline / unsafe-eval)."
	return f
}

func gradeXFO(v string) Finding {
	f := Finding{Name: "X-Frame-Options", Value: v}
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		f.Grade = GradeMissing
		f.Comment = "Missing — clickjacking protection. Set `DENY` or `SAMEORIGIN`. Modern browsers honour CSP `frame-ancestors` instead, but XFO still covers legacy clients."
	case "DENY", "SAMEORIGIN":
		f.Grade = GradePass
		f.Comment = "Set to a safe value."
	default:
		if strings.HasPrefix(strings.ToUpper(v), "ALLOW-FROM") {
			f.Grade = GradeWeak
			f.Comment = "ALLOW-FROM is deprecated and ignored by Chrome/Edge/Safari. Use CSP `frame-ancestors` instead."
		} else {
			f.Grade = GradeWeak
			f.Comment = "Unrecognised value — browsers may treat it as missing."
		}
	}
	return f
}

func gradeXCTO(v string) Finding {
	f := Finding{Name: "X-Content-Type-Options", Value: v}
	if strings.EqualFold(strings.TrimSpace(v), "nosniff") {
		f.Grade = GradePass
		f.Comment = "nosniff — disables MIME-type sniffing."
	} else if v == "" {
		f.Grade = GradeMissing
		f.Comment = "Missing — set `X-Content-Type-Options: nosniff` to prevent browsers from re-interpreting response bodies."
	} else {
		f.Grade = GradeWeak
		f.Comment = "Value other than `nosniff` is ignored by browsers."
	}
	return f
}

// strict referrer policies that don't leak full URLs cross-origin.
var strictReferrerValues = map[string]bool{
	"no-referrer":                     true,
	"same-origin":                     true,
	"strict-origin":                   true,
	"strict-origin-when-cross-origin": true,
	"origin":                          true,
	"origin-when-cross-origin":        true,
}

func gradeReferrer(v string) Finding {
	f := Finding{Name: "Referrer-Policy", Value: v}
	if v == "" {
		f.Grade = GradeMissing
		f.Comment = "Missing — browsers default to `strict-origin-when-cross-origin` on modern engines, but set this explicitly to control referrer leakage. `strict-origin-when-cross-origin` or stricter is a safe pick."
		return f
	}
	// Multiple comma-separated policies are allowed (fallback chain). Grade
	// the most permissive — that's the one the browser will actually use if
	// it understands all of them.
	parts := strings.Split(strings.ToLower(v), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	worst := ""
	for _, p := range parts {
		if p == "unsafe-url" || p == "no-referrer-when-downgrade" {
			worst = p
		}
	}
	if worst != "" {
		f.Grade = GradeWeak
		f.Comment = fmt.Sprintf("`%s` leaks the full URL across origins under at least some conditions. Switch to `strict-origin-when-cross-origin`.", worst)
		return f
	}
	for _, p := range parts {
		if strictReferrerValues[p] {
			f.Grade = GradePass
			f.Comment = "Set to a value that limits cross-origin referrer leakage."
			return f
		}
	}
	f.Grade = GradeWeak
	f.Comment = "Unrecognised value — browsers may fall back to their default."
	return f
}

func gradePermissions(v string) Finding {
	f := Finding{Name: "Permissions-Policy", Value: v}
	if v == "" {
		f.Grade = GradeMissing
		f.Comment = "Missing — controls which browser features (camera, geolocation, etc.) a page can use. Set even a permissive policy to make the surface explicit."
		return f
	}
	f.Grade = GradePass
	f.Comment = "Present. Content quality not graded — review your policy to ensure it disables features you don't use."
	return f
}

// hstsMaxAge parses the max-age directive value out of an HSTS header.
// Returns (value, true) on success.
func hstsMaxAge(v string) (int, bool) {
	for _, tok := range strings.Split(v, ";") {
		tok = strings.TrimSpace(tok)
		if !strings.HasPrefix(strings.ToLower(tok), "max-age") {
			continue
		}
		eq := strings.IndexByte(tok, '=')
		if eq < 0 {
			return 0, false
		}
		raw := strings.TrimSpace(tok[eq+1:])
		raw = strings.Trim(raw, `"`)
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// containsToken reports whether a directive list contains an exact token
// (case-insensitive, semicolon-separated).
func containsToken(v, token string) bool {
	target := strings.ToLower(token)
	for _, tok := range strings.Split(v, ";") {
		if strings.EqualFold(strings.TrimSpace(tok), target) {
			return true
		}
	}
	return false
}

// Summary returns counts by grade. Helpers for renderers/tests.
func (r Result) Summary() (pass, weak, missing, info int) {
	for _, f := range r.Findings {
		switch f.Grade {
		case GradePass:
			pass++
		case GradeWeak:
			weak++
		case GradeMissing:
			missing++
		case GradeInfo:
			info++
		}
	}
	return
}
