package techdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mkDetector builds a detector with the given response surfaces — convenience
// for the detector-level unit tests.
func mkDetector(headers http.Header, cookies []*http.Cookie, body string) *detector {
	return &detector{headers: headers, cookies: cookies, body: body}
}

func cookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}

// matchesNames pulls the names out of a []Match for easier assertions.
func matchesNames(ms []Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func hasName(ms []Match, name string) bool {
	for _, m := range ms {
		if m.Name == name {
			return true
		}
	}
	return false
}

// =============================================================================
// CMS
// =============================================================================

func TestDetectWordPress(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		cookies     []*http.Cookie
		wantMatch   bool
		wantVersion string
		wantConf    string
	}{
		{
			name:        "meta generator with version",
			body:        `<meta name="generator" content="WordPress 6.4.2">`,
			wantMatch:   true,
			wantVersion: "6.4.2",
			wantConf:    ConfHigh,
		},
		{
			name:      "wp-content path",
			body:      `<link rel="stylesheet" href="/wp-content/themes/foo/style.css">`,
			wantMatch: true,
			wantConf:  ConfMedium,
		},
		{
			name:      "wp-settings cookie",
			cookies:   []*http.Cookie{cookie("wp-settings-1", "x")},
			wantMatch: true,
			wantConf:  ConfMedium,
		},
		{
			name:      "no WordPress signals",
			body:      `<html><body>hello</body></html>`,
			wantMatch: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mkDetector(http.Header{}, c.cookies, c.body)
			m := d.detectWordPress()
			if c.wantMatch && m == nil {
				t.Fatalf("expected WordPress match, got nil")
			}
			if !c.wantMatch && m != nil {
				t.Fatalf("expected no match, got %+v", m)
			}
			if m == nil {
				return
			}
			if c.wantVersion != "" && m.Version != c.wantVersion {
				t.Errorf("version = %q, want %q", m.Version, c.wantVersion)
			}
			if m.Confidence != c.wantConf {
				t.Errorf("confidence = %q, want %q", m.Confidence, c.wantConf)
			}
		})
	}
}

func TestDetectDrupal(t *testing.T) {
	h := http.Header{}
	h.Set("X-Generator", "Drupal 10 (https://www.drupal.org)")
	d := mkDetector(h, nil, "")
	m := d.detectDrupal()
	if m == nil || m.Name != "Drupal" {
		t.Fatalf("X-Generator should detect Drupal, got %+v", m)
	}
	if m.Confidence != ConfHigh {
		t.Errorf("confidence = %q, want high", m.Confidence)
	}

	// X-Drupal-Cache header alone
	h2 := http.Header{}
	h2.Set("X-Drupal-Cache", "HIT")
	if mkDetector(h2, nil, "").detectDrupal() == nil {
		t.Error("X-Drupal-Cache header should detect Drupal")
	}

	// Body signal alone (medium confidence)
	if m := mkDetector(http.Header{}, nil, `<script>Drupal.settings = {};</script>`).detectDrupal(); m == nil || m.Confidence != ConfMedium {
		t.Errorf("body-only Drupal should be medium confidence, got %+v", m)
	}

	if mkDetector(http.Header{}, nil, "").detectDrupal() != nil {
		t.Error("empty input should NOT detect Drupal")
	}
}

func TestDetectGhostJoomlaMagento(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<meta name="generator" content="Ghost 5.2.1">`).detectGhost() == nil {
		t.Error("Ghost generator should detect")
	}
	if mkDetector(http.Header{}, nil, `<meta name="generator" content="Joomla! 4.2.7 - Open Source Content Management">`).detectJoomla() == nil {
		t.Error("Joomla generator should detect")
	}
	if mkDetector(http.Header{}, []*http.Cookie{cookie("X-Magento-Vary", "x")}, "").detectMagento() == nil {
		t.Error("Magento cookie should detect")
	}
	if mkDetector(http.Header{}, nil, `<script>Mage.Cookies.set("x")</script>`).detectMagento() == nil {
		t.Error("Magento body should detect")
	}
}

// =============================================================================
// E-commerce
// =============================================================================

func TestDetectShopify(t *testing.T) {
	h := http.Header{}
	h.Set("X-Shopify-Stage", "production")
	if mkDetector(h, nil, "").detectShopify() == nil {
		t.Error("X-Shopify-Stage should detect")
	}
	if mkDetector(http.Header{}, nil, `<link href="https://cdn.shopify.com/x.css">`).detectShopify() == nil {
		t.Error("cdn.shopify.com should detect (medium)")
	}
}

func TestDetectWooCommerce(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<meta name="generator" content="WooCommerce 8.2.0">`).detectWooCommerce() == nil {
		t.Error("WooCommerce generator should detect")
	}
	if mkDetector(http.Header{}, nil, `<body class="woocommerce-no-js">`).detectWooCommerce() == nil {
		t.Error("woocommerce-no-js class should detect (medium)")
	}
}

// =============================================================================
// JavaScript frameworks
// =============================================================================

func TestDetectNextJS(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<script id="__NEXT_DATA__" type="application/json">`).detectNextJS() == nil {
		t.Error("__NEXT_DATA__ should detect Next.js")
	}
	if mkDetector(http.Header{}, nil, `<link href="/_next/static/css/app.css">`).detectNextJS() == nil {
		t.Error("/_next/ path should detect Next.js")
	}
}

func TestDetectNuxt(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<script>window.__NUXT__={}</script>`).detectNuxt() == nil {
		t.Error("__NUXT__ should detect Nuxt.js")
	}
}

func TestDetectAngular(t *testing.T) {
	m := mkDetector(http.Header{}, nil, `<app-root ng-version="16.2.0"></app-root>`).detectAngular()
	if m == nil {
		t.Fatal("ng-version should detect Angular")
	}
	if m.Version != "16.2.0" {
		t.Errorf("version = %q, want 16.2.0", m.Version)
	}
	if m.Confidence != ConfHigh {
		t.Errorf("confidence = %q, want high", m.Confidence)
	}
	// Pre-2.x AngularJS
	if m := mkDetector(http.Header{}, nil, `<div ng-app="myApp">`).detectAngular(); m == nil || m.Name != "AngularJS" {
		t.Errorf("ng-app should detect AngularJS, got %+v", m)
	}
}

func TestDetectReact(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<script src="/static/js/react-dom.min.js">`).detectReact() == nil {
		t.Error("react-dom.min.js should detect React")
	}
}

func TestDetectVue(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<script src="/js/vue.min.js">`).detectVue() == nil {
		t.Error("vue.min.js should detect Vue")
	}
	if mkDetector(http.Header{}, nil, `<div data-server-rendered="true">`).detectVue() == nil {
		t.Error("data-server-rendered should detect Vue (low confidence)")
	}
}

// =============================================================================
// Frameworks / languages
// =============================================================================

func TestDetectLaravel(t *testing.T) {
	if mkDetector(http.Header{}, []*http.Cookie{cookie("laravel_session", "x")}, "").detectLaravel() == nil {
		t.Error("laravel_session should detect Laravel")
	}
}

func TestDetectDjango(t *testing.T) {
	m := mkDetector(http.Header{}, []*http.Cookie{cookie("csrftoken", "x"), cookie("sessionid", "y")}, "").detectDjango()
	if m == nil || m.Confidence != ConfHigh {
		t.Errorf("csrftoken+sessionid should be high-confidence Django, got %+v", m)
	}
	m2 := mkDetector(http.Header{}, []*http.Cookie{cookie("csrftoken", "x")}, "").detectDjango()
	if m2 == nil || m2.Confidence != ConfMedium {
		t.Errorf("csrftoken alone should be medium-confidence Django, got %+v", m2)
	}
}

func TestDetectRails(t *testing.T) {
	if mkDetector(http.Header{}, []*http.Cookie{cookie("_session_id", "x")}, "").detectRails() == nil {
		t.Error("_session_id should detect Rails")
	}
	h := http.Header{}
	h.Set("X-Powered-By", "Phusion Passenger 5.3.0")
	if mkDetector(h, nil, "").detectRails() == nil {
		t.Error("Phusion Passenger should detect Rails")
	}
}

func TestDetectASPNet(t *testing.T) {
	h := http.Header{}
	h.Set("X-AspNet-Version", "4.0.30319")
	m := mkDetector(h, nil, "").detectASPNet()
	if m == nil || m.Version != "4.0.30319" {
		t.Errorf("X-AspNet-Version should detect ASP.NET with version, got %+v", m)
	}
	h2 := http.Header{}
	h2.Set("X-Powered-By", "ASP.NET")
	if mkDetector(h2, nil, "").detectASPNet() == nil {
		t.Error("X-Powered-By: ASP.NET should detect")
	}
	if mkDetector(http.Header{}, []*http.Cookie{cookie("ASP.NET_SessionId", "x")}, "").detectASPNet() == nil {
		t.Error("ASP.NET_SessionId cookie should detect")
	}
}

func TestDetectPHP(t *testing.T) {
	h := http.Header{}
	h.Set("X-Powered-By", "PHP/8.2.1")
	m := mkDetector(h, nil, "").detectPHP()
	if m == nil || m.Version != "8.2.1" {
		t.Errorf("X-Powered-By PHP/8.2.1 should detect PHP w/ version, got %+v", m)
	}
	if mkDetector(http.Header{}, []*http.Cookie{cookie("PHPSESSID", "x")}, "").detectPHP() == nil {
		t.Error("PHPSESSID should detect PHP")
	}
}

// =============================================================================
// Servers
// =============================================================================

func TestDetectServers(t *testing.T) {
	cases := []struct {
		server string
		name   string
		want   string // expected matched .Name
	}{
		{"nginx/1.25.3", "nginx", "nginx"},
		{"Apache/2.4.41 (Ubuntu)", "apache", "Apache HTTP Server"},
		{"Caddy", "caddy", "Caddy"},
		{"Microsoft-IIS/10.0", "iis", "Microsoft IIS"},
		{"LiteSpeed", "litespeed", "LiteSpeed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Server", c.server)
			d := mkDetector(h, nil, "")
			ms := d.detectAll()
			if !hasName(ms, c.want) {
				t.Errorf("Server=%q should detect %q, got %v", c.server, c.want, matchesNames(ms))
			}
		})
	}
}

// =============================================================================
// CDNs
// =============================================================================

func TestDetectCDNs(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"cloudflare via CF-Ray", map[string]string{"CF-Ray": "abc123"}, "Cloudflare"},
		{"cloudflare via Server", map[string]string{"Server": "cloudflare"}, "Cloudflare"},
		{"fastly via X-Served-By", map[string]string{"X-Served-By": "cache-fra1234"}, "Fastly"},
		{"cloudfront via Via", map[string]string{"Via": "1.1 d12345.cloudfront.net (CloudFront)"}, "Amazon CloudFront"},
		{"cloudfront via X-Amz-Cf-Id", map[string]string{"X-Amz-Cf-Id": "abc"}, "Amazon CloudFront"},
		{"akamai via X-Akamai-Transformed", map[string]string{"X-Akamai-Transformed": "9"}, "Akamai"},
		{"bunnycdn via Server", map[string]string{"Server": "BunnyCDN-DE1-1234"}, "BunnyCDN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range c.headers {
				h.Set(k, v)
			}
			d := mkDetector(h, nil, "")
			ms := d.detectAll()
			if !hasName(ms, c.want) {
				t.Errorf("expected %q in matches, got %v", c.want, matchesNames(ms))
			}
		})
	}
}

// =============================================================================
// Libraries
// =============================================================================

func TestDetectJQueryWithVersion(t *testing.T) {
	m := mkDetector(http.Header{}, nil, `<script src="/js/jquery-3.6.0.min.js">`).detectJQuery()
	if m == nil {
		t.Fatal("jquery-3.6.0.min.js should detect")
	}
	if m.Version != "3.6.0" {
		t.Errorf("version = %q, want 3.6.0", m.Version)
	}
}

func TestDetectBootstrap(t *testing.T) {
	if mkDetector(http.Header{}, nil, `<link href="/css/bootstrap-5.3.0.min.css">`).detectBootstrap() == nil {
		t.Error("bootstrap-5.3.0.min.css should detect")
	}
}

// =============================================================================
// Generator fallback
// =============================================================================

func TestGeneratorFallback(t *testing.T) {
	// Hugo isn't in our catalog — fallback should fire with the literal name.
	d := mkDetector(http.Header{}, nil, `<meta name="generator" content="Hugo 0.119.0">`)
	ms := d.detectAll()
	found := false
	for _, m := range ms {
		if m.Name == "Hugo 0.119.0" && m.Category == CatOther {
			found = true
		}
	}
	if !found {
		t.Errorf("Hugo fallback should fire, got %v", matchesNames(ms))
	}
}

func TestGeneratorFallbackSkipsKnown(t *testing.T) {
	// WordPress detector fires high-confidence; fallback should NOT also fire.
	d := mkDetector(http.Header{}, nil, `<meta name="generator" content="WordPress 6.4">`)
	ms := d.detectAll()
	count := 0
	for _, m := range ms {
		if m.Category == CatOther {
			count++
		}
	}
	if count > 0 {
		t.Errorf("WordPress should suppress CatOther fallback; got %d", count)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func TestExtractMetaContent(t *testing.T) {
	cases := []struct {
		body, name, want string
	}{
		{`<meta name="generator" content="Hugo">`, "generator", "Hugo"},
		{`<meta content="Hugo" name="generator">`, "generator", "Hugo"},
		{`<META NAME='generator' CONTENT='Ghost'>`, "generator", "Ghost"},
		{`<meta charset="utf-8">`, "generator", ""},
		{``, "generator", ""},
	}
	for _, c := range cases {
		if got := extractMetaContent(c.body, c.name); got != c.want {
			t.Errorf("extractMetaContent(%q, %q) = %q, want %q", c.body, c.name, got, c.want)
		}
	}
}

func TestExtractVersionTail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"nginx/1.25.3", "1.25.3"},
		{"Apache/2.4.41 (Ubuntu)", "2.4.41"},
		{"Caddy", ""},
		{"Microsoft-IIS/10.0", "10.0"},
	}
	for _, c := range cases {
		if got := extractVersionTail(c.in); got != c.want {
			t.Errorf("extractVersionTail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	if _, err := normalizeURL(""); err == nil {
		t.Error("empty URL should error")
	}
	// Some bad URLs Go's parser accepts as opaque — we don't assert
	// either outcome, just that the call doesn't panic.
	_, _ = normalizeURL("::badurl")
	got, err := normalizeURL("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("got %q, want https:// prefix", got)
	}
}

// =============================================================================
// End-to-end through Detect()
// =============================================================================

func TestDetectAgainstTestServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		w.Header().Set("CF-Ray", "abc123-DXB")
		w.Header().Set("Set-Cookie", "PHPSESSID=abc; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><link href="/wp-content/themes/x/style.css"></body></html>`))
	}))
	defer srv.Close()

	res := Detect(context.Background(), srv.URL, false, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	names := matchesNames(res.Matches)
	for _, want := range []string{"WordPress", "PHP", "nginx", "Cloudflare"} {
		if !hasName(res.Matches, want) {
			t.Errorf("expected %q in matches, got %v", want, names)
		}
	}
}

func TestDetectBadURL(t *testing.T) {
	res := Detect(context.Background(), "", false, time.Second)
	if res.Err == nil {
		t.Error("expected error on empty URL")
	}
}

func TestDetectSetUserAgent(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	SetUserAgent("netcheck-test/0.0")

	seen := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	_ = Detect(context.Background(), srv.URL, false, 5*time.Second)
	if seen != "netcheck-test/0.0" {
		t.Errorf("UA seen by server = %q, want netcheck-test/0.0", seen)
	}

	// Empty SetUserAgent is a no-op.
	SetUserAgent("")
	if userAgent != "netcheck-test/0.0" {
		t.Errorf("SetUserAgent(\"\") should be no-op, got %q", userAgent)
	}
}
