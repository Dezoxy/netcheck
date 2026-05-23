// Package techdetect fetches a URL and identifies the web technologies behind
// it from response headers, cookies, and HTML body — Wappalyzer-style
// fingerprinting. Passive: one HTTP GET, body capped at 1 MiB, no active
// probing.
package techdetect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// userAgent is the User-Agent sent on the detect request. main.go wires the
// canonical "netcheck/<version>" via SetUserAgent at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent string used for detect requests. Safe to
// call once at startup before any detect runs.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// maxBodyBytes caps how much HTML we read. Most fingerprints sit in the first
// 200 KB (head + early body); 1 MiB is generous and prevents OOM on giant
// pages.
const maxBodyBytes = 1 << 20

// Category groups related technologies in the report.
type Category string

const (
	CatCMS         Category = "cms"
	CatFramework   Category = "framework"
	CatJSFramework Category = "js-framework"
	CatLanguage    Category = "language"
	CatServer      Category = "server"
	CatCDN         Category = "cdn"
	CatEcommerce   Category = "ecommerce"
	CatLibrary     Category = "library"
	CatAnalytics   Category = "analytics"
	CatOther       Category = "other"
)

// Confidence tier: how sure are we?
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Match is one detected technology.
type Match struct {
	Name       string   // "WordPress", "Next.js"
	Category   Category // CatCMS, CatJSFramework, ...
	Version    string   // optional, when extractable
	Confidence string   // "high" | "medium" | "low"
	Evidence   string   // short human-readable: "X-Powered-By: WordPress"
}

// Result is the full audit output.
type Result struct {
	URL       string
	FinalURL  string
	Status    int
	Matches   []Match
	StartedAt time.Time
	Took      time.Duration
	Err       error
}

// Detect fetches rawURL with a GET, reads up to maxBodyBytes of the body, and
// runs every fingerprint. Returns Result with Err set on transport failure.
func Detect(ctx context.Context, rawURL string, insecure bool, timeout time.Duration) Result {
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
	// Tell servers we want HTML so they don't reach for an alternate format.
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	out.FinalURL = resp.Request.URL.String()
	out.Status = resp.StatusCode
	d := &detector{
		headers: resp.Header,
		cookies: resp.Cookies(),
		body:    string(body),
	}
	out.Matches = d.detectAll()
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

// detector bundles the response surfaces we fingerprint against.
type detector struct {
	headers http.Header
	cookies []*http.Cookie
	body    string
}

func (d *detector) hasCookie(name string) (string, bool) {
	for _, c := range d.cookies {
		if strings.EqualFold(c.Name, name) {
			return c.Value, true
		}
	}
	return "", false
}

// hasCookiePrefix matches cookies whose name starts with prefix
// (case-insensitive). Returns the first match.
func (d *detector) hasCookiePrefix(prefix string) (string, string, bool) {
	lp := strings.ToLower(prefix)
	for _, c := range d.cookies {
		if strings.HasPrefix(strings.ToLower(c.Name), lp) {
			return c.Name, c.Value, true
		}
	}
	return "", "", false
}

// detectAll runs every fingerprint and returns matches in a stable order
// (the order detectors are registered below).
func (d *detector) detectAll() []Match {
	var ms []Match
	add := func(m *Match) {
		if m != nil {
			ms = append(ms, *m)
		}
	}

	// CMS
	add(d.detectWordPress())
	add(d.detectDrupal())
	add(d.detectGhost())
	add(d.detectJoomla())
	add(d.detectMagento())

	// E-commerce
	add(d.detectShopify())
	add(d.detectWooCommerce())

	// JS frameworks
	add(d.detectNextJS())
	add(d.detectNuxt())
	add(d.detectReact())
	add(d.detectVue())
	add(d.detectAngular())

	// Web frameworks / languages
	add(d.detectLaravel())
	add(d.detectDjango())
	add(d.detectRails())
	add(d.detectASPNet())
	add(d.detectPHP()) // generic — runs last among lang detectors

	// Servers
	add(d.detectNginx())
	add(d.detectApache())
	add(d.detectCaddy())
	add(d.detectIIS())
	add(d.detectLiteSpeed())

	// CDNs
	add(d.detectCloudflare())
	add(d.detectFastly())
	add(d.detectCloudFront())
	add(d.detectAkamai())
	add(d.detectBunnyCDN())

	// Libraries (best-effort)
	add(d.detectJQuery())
	add(d.detectBootstrap())

	// Generic <meta name="generator"> as a fallback if nothing CMS-specific hit
	add(d.detectGeneratorFallback(ms))

	return ms
}

// =============================================================================
// CMS
// =============================================================================

func (d *detector) detectWordPress() *Match {
	if hasMeta(d.body, "generator", `(?i)wordpress\s*([\d.]+)?`) {
		ver := captureMeta(d.body, "generator", `(?i)wordpress\s*([\d.]+)`)
		return &Match{Name: "WordPress", Category: CatCMS, Version: ver, Confidence: ConfHigh, Evidence: `<meta name="generator" content="WordPress ...">`}
	}
	if strings.Contains(d.body, "/wp-content/") || strings.Contains(d.body, "/wp-includes/") {
		return &Match{Name: "WordPress", Category: CatCMS, Confidence: ConfMedium, Evidence: "wp-content / wp-includes path in HTML"}
	}
	if _, _, ok := d.hasCookiePrefix("wp-settings-"); ok {
		return &Match{Name: "WordPress", Category: CatCMS, Confidence: ConfMedium, Evidence: "wp-settings-* cookie"}
	}
	return nil
}

func (d *detector) detectDrupal() *Match {
	if h := d.headers.Get("X-Generator"); strings.HasPrefix(strings.ToLower(h), "drupal") {
		return &Match{Name: "Drupal", Category: CatCMS, Confidence: ConfHigh, Evidence: "X-Generator: " + h, Version: extractVersionTail(h)}
	}
	if d.headers.Get("X-Drupal-Cache") != "" || d.headers.Get("X-Drupal-Dynamic-Cache") != "" {
		return &Match{Name: "Drupal", Category: CatCMS, Confidence: ConfHigh, Evidence: "X-Drupal-Cache header"}
	}
	if strings.Contains(d.body, "/sites/default/files/") || strings.Contains(d.body, "Drupal.settings") {
		return &Match{Name: "Drupal", Category: CatCMS, Confidence: ConfMedium, Evidence: "Drupal-specific path or JS global in HTML"}
	}
	return nil
}

func (d *detector) detectGhost() *Match {
	if hasMeta(d.body, "generator", `(?i)ghost`) {
		ver := captureMeta(d.body, "generator", `(?i)ghost\s*([\d.]+)`)
		return &Match{Name: "Ghost", Category: CatCMS, Version: ver, Confidence: ConfHigh, Evidence: `<meta name="generator" content="Ghost">`}
	}
	return nil
}

func (d *detector) detectJoomla() *Match {
	if hasMeta(d.body, "generator", `(?i)joomla`) {
		ver := captureMeta(d.body, "generator", `(?i)joomla\D+([\d.]+)`)
		return &Match{Name: "Joomla", Category: CatCMS, Version: ver, Confidence: ConfHigh, Evidence: `<meta name="generator" content="Joomla">`}
	}
	return nil
}

func (d *detector) detectMagento() *Match {
	if _, ok := d.hasCookie("X-Magento-Vary"); ok {
		return &Match{Name: "Magento", Category: CatEcommerce, Confidence: ConfHigh, Evidence: "X-Magento-Vary cookie"}
	}
	if strings.Contains(d.body, "Mage.Cookies") || strings.Contains(d.body, "/skin/frontend/") {
		return &Match{Name: "Magento", Category: CatEcommerce, Confidence: ConfMedium, Evidence: "Magento-specific markup"}
	}
	return nil
}

// =============================================================================
// E-commerce
// =============================================================================

func (d *detector) detectShopify() *Match {
	if d.headers.Get("X-Shopify-Stage") != "" || d.headers.Get("X-ShopId") != "" || d.headers.Get("X-Shardid") != "" {
		return &Match{Name: "Shopify", Category: CatEcommerce, Confidence: ConfHigh, Evidence: "X-Shopify-Stage / X-ShopId header"}
	}
	if strings.Contains(d.body, "cdn.shopify.com") || strings.Contains(d.body, "Shopify.theme") {
		return &Match{Name: "Shopify", Category: CatEcommerce, Confidence: ConfMedium, Evidence: "cdn.shopify.com or Shopify.theme in HTML"}
	}
	return nil
}

func (d *detector) detectWooCommerce() *Match {
	if hasMeta(d.body, "generator", `(?i)woocommerce`) {
		return &Match{Name: "WooCommerce", Category: CatEcommerce, Confidence: ConfHigh, Evidence: `<meta name="generator" content="WooCommerce ...">`}
	}
	if strings.Contains(d.body, "woocommerce-no-js") || strings.Contains(d.body, "/plugins/woocommerce/") {
		return &Match{Name: "WooCommerce", Category: CatEcommerce, Confidence: ConfMedium, Evidence: "WooCommerce markup in HTML"}
	}
	return nil
}

// =============================================================================
// JavaScript frameworks
// =============================================================================

func (d *detector) detectNextJS() *Match {
	if strings.Contains(d.body, "__NEXT_DATA__") || strings.Contains(d.body, "/_next/static/") {
		return &Match{Name: "Next.js", Category: CatJSFramework, Confidence: ConfHigh, Evidence: "__NEXT_DATA__ / /_next/ assets in HTML"}
	}
	return nil
}

func (d *detector) detectNuxt() *Match {
	if strings.Contains(d.body, "__NUXT__") || strings.Contains(d.body, "/_nuxt/") {
		return &Match{Name: "Nuxt.js", Category: CatJSFramework, Confidence: ConfHigh, Evidence: "__NUXT__ / /_nuxt/ assets in HTML"}
	}
	return nil
}

func (d *detector) detectReact() *Match {
	// Loose — explicit signal patterns. Next.js will fire first if it's a Next site.
	if regexp.MustCompile(`(?i)react(?:-dom)?[.-]?(\d+\.\d+\.\d+)?\.min\.js`).MatchString(d.body) {
		return &Match{Name: "React", Category: CatJSFramework, Confidence: ConfMedium, Evidence: "react.min.js / react-dom.min.js in HTML"}
	}
	return nil
}

func (d *detector) detectVue() *Match {
	if regexp.MustCompile(`(?i)vue(?:\.runtime)?[.-]?(\d+\.\d+\.\d+)?\.min\.js`).MatchString(d.body) {
		return &Match{Name: "Vue.js", Category: CatJSFramework, Confidence: ConfMedium, Evidence: "vue.min.js in HTML"}
	}
	if strings.Contains(d.body, "data-server-rendered=\"true\"") {
		return &Match{Name: "Vue.js", Category: CatJSFramework, Confidence: ConfLow, Evidence: "data-server-rendered attribute"}
	}
	return nil
}

func (d *detector) detectAngular() *Match {
	if strings.Contains(d.body, "ng-version=") {
		ver := captureRegex(d.body, `ng-version="([\d.]+)"`)
		return &Match{Name: "Angular", Category: CatJSFramework, Version: ver, Confidence: ConfHigh, Evidence: "ng-version attribute"}
	}
	if strings.Contains(d.body, "ng-app=") {
		return &Match{Name: "AngularJS", Category: CatJSFramework, Confidence: ConfMedium, Evidence: "ng-app directive (AngularJS, pre-2.x)"}
	}
	return nil
}

// =============================================================================
// Web frameworks / languages
// =============================================================================

func (d *detector) detectLaravel() *Match {
	if _, ok := d.hasCookie("laravel_session"); ok {
		return &Match{Name: "Laravel", Category: CatFramework, Confidence: ConfHigh, Evidence: "laravel_session cookie"}
	}
	if _, ok := d.hasCookie("XSRF-TOKEN"); ok && hasPHPHint(d.headers, d.cookies) {
		return &Match{Name: "Laravel", Category: CatFramework, Confidence: ConfLow, Evidence: "XSRF-TOKEN + PHP — possibly Laravel"}
	}
	return nil
}

func (d *detector) detectDjango() *Match {
	if _, ok := d.hasCookie("csrftoken"); ok {
		if _, ok2 := d.hasCookie("sessionid"); ok2 {
			return &Match{Name: "Django", Category: CatFramework, Confidence: ConfHigh, Evidence: "csrftoken + sessionid cookies"}
		}
		return &Match{Name: "Django", Category: CatFramework, Confidence: ConfMedium, Evidence: "csrftoken cookie"}
	}
	return nil
}

func (d *detector) detectRails() *Match {
	if _, ok := d.hasCookie("_session_id"); ok {
		return &Match{Name: "Ruby on Rails", Category: CatFramework, Confidence: ConfMedium, Evidence: "_session_id cookie"}
	}
	if d.headers.Get("X-Powered-By") != "" && strings.Contains(strings.ToLower(d.headers.Get("X-Powered-By")), "phusion passenger") {
		return &Match{Name: "Ruby on Rails", Category: CatFramework, Confidence: ConfMedium, Evidence: "X-Powered-By: Phusion Passenger"}
	}
	return nil
}

func (d *detector) detectASPNet() *Match {
	if v := d.headers.Get("X-AspNet-Version"); v != "" {
		return &Match{Name: "ASP.NET", Category: CatFramework, Version: v, Confidence: ConfHigh, Evidence: "X-AspNet-Version: " + v}
	}
	if v := d.headers.Get("X-Powered-By"); strings.Contains(strings.ToLower(v), "asp.net") {
		return &Match{Name: "ASP.NET", Category: CatFramework, Confidence: ConfHigh, Evidence: "X-Powered-By: " + v}
	}
	if _, ok := d.hasCookie("ASP.NET_SessionId"); ok {
		return &Match{Name: "ASP.NET", Category: CatFramework, Confidence: ConfMedium, Evidence: "ASP.NET_SessionId cookie"}
	}
	return nil
}

func (d *detector) detectPHP() *Match {
	if v := d.headers.Get("X-Powered-By"); strings.HasPrefix(strings.ToLower(v), "php/") {
		return &Match{Name: "PHP", Category: CatLanguage, Version: strings.TrimPrefix(strings.ToLower(v), "php/"), Confidence: ConfHigh, Evidence: "X-Powered-By: " + v}
	}
	if _, ok := d.hasCookie("PHPSESSID"); ok {
		return &Match{Name: "PHP", Category: CatLanguage, Confidence: ConfHigh, Evidence: "PHPSESSID cookie"}
	}
	return nil
}

// =============================================================================
// Servers
// =============================================================================

func (d *detector) detectNginx() *Match {
	if v := d.headers.Get("Server"); strings.HasPrefix(strings.ToLower(v), "nginx") {
		return &Match{Name: "nginx", Category: CatServer, Version: extractVersionTail(v), Confidence: ConfHigh, Evidence: "Server: " + v}
	}
	return nil
}

func (d *detector) detectApache() *Match {
	if v := d.headers.Get("Server"); strings.HasPrefix(strings.ToLower(v), "apache") {
		return &Match{Name: "Apache HTTP Server", Category: CatServer, Version: extractVersionTail(v), Confidence: ConfHigh, Evidence: "Server: " + v}
	}
	return nil
}

func (d *detector) detectCaddy() *Match {
	if v := d.headers.Get("Server"); strings.HasPrefix(strings.ToLower(v), "caddy") {
		return &Match{Name: "Caddy", Category: CatServer, Confidence: ConfHigh, Evidence: "Server: " + v}
	}
	return nil
}

func (d *detector) detectIIS() *Match {
	if v := d.headers.Get("Server"); strings.Contains(strings.ToLower(v), "iis") {
		return &Match{Name: "Microsoft IIS", Category: CatServer, Version: extractVersionTail(v), Confidence: ConfHigh, Evidence: "Server: " + v}
	}
	return nil
}

func (d *detector) detectLiteSpeed() *Match {
	if v := d.headers.Get("Server"); strings.Contains(strings.ToLower(v), "litespeed") {
		return &Match{Name: "LiteSpeed", Category: CatServer, Confidence: ConfHigh, Evidence: "Server: " + v}
	}
	return nil
}

// =============================================================================
// CDN
// =============================================================================

func (d *detector) detectCloudflare() *Match {
	if d.headers.Get("CF-Ray") != "" {
		return &Match{Name: "Cloudflare", Category: CatCDN, Confidence: ConfHigh, Evidence: "CF-Ray header"}
	}
	if strings.EqualFold(d.headers.Get("Server"), "cloudflare") {
		return &Match{Name: "Cloudflare", Category: CatCDN, Confidence: ConfHigh, Evidence: "Server: cloudflare"}
	}
	return nil
}

func (d *detector) detectFastly() *Match {
	if v := d.headers.Get("X-Served-By"); strings.Contains(strings.ToLower(v), "cache-") {
		return &Match{Name: "Fastly", Category: CatCDN, Confidence: ConfMedium, Evidence: "X-Served-By: " + v}
	}
	if d.headers.Get("Fastly-Debug-Digest") != "" || strings.Contains(strings.ToLower(d.headers.Get("Via")), "varnish") {
		return &Match{Name: "Fastly", Category: CatCDN, Confidence: ConfMedium, Evidence: "Fastly-Debug-Digest or Varnish Via header"}
	}
	return nil
}

func (d *detector) detectCloudFront() *Match {
	if v := d.headers.Get("Via"); strings.Contains(strings.ToLower(v), "cloudfront") {
		return &Match{Name: "Amazon CloudFront", Category: CatCDN, Confidence: ConfHigh, Evidence: "Via: " + v}
	}
	if d.headers.Get("X-Amz-Cf-Id") != "" {
		return &Match{Name: "Amazon CloudFront", Category: CatCDN, Confidence: ConfHigh, Evidence: "X-Amz-Cf-Id header"}
	}
	return nil
}

func (d *detector) detectAkamai() *Match {
	if d.headers.Get("X-Akamai-Transformed") != "" || strings.Contains(strings.ToLower(d.headers.Get("Server")), "akamai") {
		return &Match{Name: "Akamai", Category: CatCDN, Confidence: ConfHigh, Evidence: "Akamai-specific header"}
	}
	return nil
}

func (d *detector) detectBunnyCDN() *Match {
	if v := d.headers.Get("Server"); strings.Contains(strings.ToLower(v), "bunnycdn") {
		return &Match{Name: "BunnyCDN", Category: CatCDN, Confidence: ConfHigh, Evidence: "Server: " + v}
	}
	return nil
}

// =============================================================================
// Libraries
// =============================================================================

func (d *detector) detectJQuery() *Match {
	if re := regexp.MustCompile(`(?i)jquery[.-]?(\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js`); re.MatchString(d.body) {
		match := re.FindStringSubmatch(d.body)
		ver := ""
		if len(match) > 1 {
			ver = match[1]
		}
		return &Match{Name: "jQuery", Category: CatLibrary, Version: ver, Confidence: ConfMedium, Evidence: "jquery*.js in HTML"}
	}
	return nil
}

func (d *detector) detectBootstrap() *Match {
	if regexp.MustCompile(`(?i)bootstrap[.-]?(\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.css`).MatchString(d.body) {
		return &Match{Name: "Bootstrap", Category: CatLibrary, Confidence: ConfMedium, Evidence: "bootstrap*.css in HTML"}
	}
	return nil
}

// =============================================================================
// Fallback
// =============================================================================

// detectGeneratorFallback emits a CatOther match for any non-empty
// <meta name="generator"> content that hasn't already been claimed by a
// CMS-specific detector above. Lets users see the literal `Hugo 0.x` or
// `Hexo 6.x` etc. without us having to enumerate every static-site generator.
func (d *detector) detectGeneratorFallback(prior []Match) *Match {
	gen := extractMetaContent(d.body, "generator")
	if gen == "" {
		return nil
	}
	for _, m := range prior {
		// If a CMS-specific detector already mentioned this generator, skip.
		if strings.Contains(strings.ToLower(gen), strings.ToLower(m.Name)) {
			return nil
		}
	}
	return &Match{Name: gen, Category: CatOther, Confidence: ConfMedium, Evidence: `<meta name="generator" content="` + gen + `">`}
}

// =============================================================================
// Helpers
// =============================================================================

// hasMeta returns true when the document contains a <meta name="generator"
// content="..."> whose content matches the given regex.
func hasMeta(body, name, contentPattern string) bool {
	v := extractMetaContent(body, name)
	if v == "" {
		return false
	}
	return regexp.MustCompile(contentPattern).MatchString(v)
}

// captureMeta returns the first regex group on the matched <meta>.
func captureMeta(body, name, contentPattern string) string {
	v := extractMetaContent(body, name)
	if v == "" {
		return ""
	}
	m := regexp.MustCompile(contentPattern).FindStringSubmatch(v)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractMetaContent finds the first <meta name="<name>" content="..."> tag
// and returns the content. Tolerates attribute order and single/double quotes.
func extractMetaContent(body, name string) string {
	// Look for both attribute orders: name first or content first.
	re1 := regexp.MustCompile(`(?is)<meta[^>]+name=["']` + regexp.QuoteMeta(name) + `["'][^>]+content=["']([^"']*)["']`)
	if m := re1.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	re2 := regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']*)["'][^>]+name=["']` + regexp.QuoteMeta(name) + `["']`)
	if m := re2.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

// captureRegex returns the first regex group from body, or "" if no match.
func captureRegex(body, pattern string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractVersionTail picks the trailing X.Y.Z from a header like
// "nginx/1.25.3" or "Apache/2.4.41 (Ubuntu)".
func extractVersionTail(s string) string {
	m := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`).FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// hasPHPHint reports whether headers or cookies suggest PHP — used by
// detectors that need a "this is likely PHP" pre-condition.
func hasPHPHint(h http.Header, cs []*http.Cookie) bool {
	if strings.Contains(strings.ToLower(h.Get("X-Powered-By")), "php") {
		return true
	}
	for _, c := range cs {
		if strings.EqualFold(c.Name, "PHPSESSID") {
			return true
		}
	}
	return false
}
