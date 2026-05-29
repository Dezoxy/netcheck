package report

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Dezoxy/netcheck/pkg/check"
	"github.com/Dezoxy/netcheck/pkg/dnscompare"
	"github.com/Dezoxy/netcheck/pkg/ipinfo"
	"github.com/Dezoxy/netcheck/pkg/route"
	"github.com/Dezoxy/netcheck/pkg/target"
)

// -update regenerates golden files. Run `go test ./internal/report -update`
// after intentional output changes.
var updateGolden = flag.Bool("update", false, "regenerate golden files")

// assertGolden compares got to the file at testdata/<name> and fails the test
// if they differ. With -update set, the golden file is rewritten instead.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden missing: %v (run `go test -update` to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output mismatch for %s\n\n--- got ---\n%s\n--- want ---\n%s",
			name, got, want)
	}
}

// fixedTime is the time stamped into all fixtures so output is deterministic.
var fixedTime = time.Date(2026, 5, 21, 19, 30, 45, 0, time.UTC)

// Pin the package-level clock for the whole test binary so renderers that
// reach for "now" (only the text IP info header today) produce stable output.
func init() {
	nowFn = func() time.Time { return fixedTime }
}

// fixtureReport returns a fully populated Report exercising every render
// branch — A + AAAA with IPInfo (asn + cdn), both TCP families, healthy TLS,
// HTTP 200 with one redirect.
func fixtureReport() *Report {
	t, _ := target.Parse("https://example.com")

	dnsRes := check.DNSResult{
		Took: 14 * time.Millisecond,
		A:    []net.IP{net.IPv4(142, 250, 184, 206).To4()},
		AAAA: []net.IP{net.ParseIP("2a00:1450:400d:80e::200e")},
		IPInfo: map[string]ipinfo.DNSIPInfo{
			"142.250.184.206": {
				ASN: &ipinfo.ASNInfo{ASN: "15169", Org: "GOOGLE, US"},
				CDN: ipinfo.CDNMatch{Provider: "Google"},
			},
			"2a00:1450:400d:80e::200e": {
				ASN: &ipinfo.ASNInfo{ASN: "15169", Org: "GOOGLE, US"},
				CDN: ipinfo.CDNMatch{Provider: "Google"},
			},
		},
	}

	tcpV4 := check.TCPResult{Addr: "142.250.184.206:443", Took: 21 * time.Millisecond}
	tcpV6 := check.TCPResult{Addr: "[2a00:1450:400d:80e::200e]:443", Took: 24 * time.Millisecond}

	leaf := &x509.Certificate{
		Issuer:    pkix.Name{CommonName: "WR2"},
		Subject:   pkix.Name{CommonName: "*.example.com"},
		DNSNames:  []string{"*.example.com", "example.com"},
		NotBefore: fixedTime.AddDate(0, -3, 0),
		NotAfter:  fixedTime.AddDate(0, 2, 0),
	}
	tlsRes := check.TLSResult{
		Version:     0x0304, // TLS 1.3
		CipherSuite: 0x1301, // TLS_AES_128_GCM_SHA256
		Issuer:      leaf.Issuer.CommonName,
		Subject:     leaf.Subject.CommonName,
		DNSNames:    leaf.DNSNames,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Chain:       []*x509.Certificate{leaf},
		Took:        53 * time.Millisecond,
	}

	finalURL, _ := url.Parse("https://www.example.com/")
	httpRes := check.HTTPResult{
		Status:      200,
		FinalURL:    finalURL.String(),
		Server:      "gws",
		Proto:       "HTTP/1.1",
		Hops:        []check.HTTPHop{{URL: "https://example.com", Status: 301}},
		DNSTime:     6 * time.Millisecond,
		ConnectTime: 17 * time.Millisecond,
		TLSTime:     40 * time.Millisecond,
		TTFB:        328 * time.Millisecond,
		Total:       774 * time.Millisecond,
	}

	return &Report{
		Target:    t,
		StartedAt: fixedTime,
		DNS:       dnsRes,
		TCPv4:     &tcpV4,
		TCPv6:     &tcpV6,
		TLS:       &tlsRes,
		HTTP:      httpRes,
	}
}

// fixtureFailedReport exercises the error branches in every renderer.
func fixtureFailedReport() *Report {
	t, _ := target.Parse("https://broken.invalid")
	return &Report{
		Target:    t,
		StartedAt: fixedTime,
		DNS:       check.DNSResult{Err: errors.New("no such host"), Took: 12 * time.Millisecond},
		HTTP:      check.HTTPResult{Err: errors.New("dial tcp: connection refused")},
	}
}

// fixtureDNSCompare returns a multi-resolver dns compare result where two
// resolvers agree and one returns a different answer.
func fixtureDNSCompare() DNSCompareJSON {
	results := []dnscompare.Result{
		{
			Host:  "example.com",
			QType: "A",
			Results: []dnscompare.ResolverResult{
				{Resolver: dnscompare.Resolver{Name: "Cloudflare", Address: "1.1.1.1:53"}, Records: []string{"1.1.1.1"}, Took: 12 * time.Millisecond},
				{Resolver: dnscompare.Resolver{Name: "Google", Address: "8.8.8.8:53"}, Records: []string{"1.1.1.1"}, Took: 18 * time.Millisecond},
				{Resolver: dnscompare.Resolver{Name: "Quad9", Address: "9.9.9.9:53"}, Records: []string{"2.2.2.2"}, Took: 14 * time.Millisecond},
				{Resolver: dnscompare.Resolver{Name: "Failing", Address: "0.0.0.0:53"}, Err: errors.New("timeout"), Took: 5000 * time.Millisecond},
			},
		},
	}
	return ToDNSCompareJSON("example.com", fixedTime, results)
}

// fixtureRoute returns a 3-hop traceroute with one timeout.
func fixtureRoute() RouteJSON {
	host := "example.com"
	destIP := "1.2.3.4"
	hops := []*route.Hop{
		{N: 1, Probes: []route.HopProbe{
			{IP: "192.168.1.1", RTT: 1200 * time.Microsecond},
			{IP: "192.168.1.1", RTT: 1100 * time.Microsecond},
			{IP: "192.168.1.1", RTT: 1300 * time.Microsecond},
		}},
		{N: 2, Timeout: true},
		{N: 3, Probes: []route.HopProbe{
			{Host: "edge.example.net", IP: "1.2.3.4", RTT: 18500 * time.Microsecond},
			{Host: "edge.example.net", IP: "1.2.3.4", RTT: 18700 * time.Microsecond},
		}},
	}
	return ToRouteJSON(host, destIP, "/usr/sbin/traceroute", []string{"-m", "30"}, fixedTime, hops, nil)
}

// fixtureIPInfo returns a single-IP enrichment result.
func fixtureIPInfo() IPInfoJSON {
	details := []ipinfo.IPDetails{{
		IP:      net.IPv4(1, 1, 1, 1).To4(),
		Reverse: []string{"one.one.one.one"},
		ASN:     &ipinfo.ASNInfo{ASN: "13335", Org: "CLOUDFLARENET", Country: "US", Prefix: "1.1.1.0/24", Registry: "apnic"},
		RDAP:    &ipinfo.RDAPInfo{Name: "Cloudflare, Inc.", Registry: "apnic", Country: "AU", AbuseEmail: "abuse@cloudflare.com"},
		CDN:     ipinfo.CDNMatch{Provider: "Cloudflare", Confidence: "high", Reason: "ASN match + cloudflare PTR"},
	}}
	return ToIPInfoJSON("1.1.1.1", fixedTime, false, 0, details)
}

// ─── Full report ──────────────────────────────────────────────────────────

func TestRenderFullText(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, fixtureReport())
	assertGolden(t, "full.txt", buf.Bytes())
}

func TestRenderFullMD(t *testing.T) {
	var buf bytes.Buffer
	RenderFullMD(&buf, fixtureReport())
	assertGolden(t, "full.md", buf.Bytes())
}

func TestRenderFullHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderFullHTML(&buf, fixtureReport())
	assertGolden(t, "full.html", buf.Bytes())
}

func TestRenderFullFailedText(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, fixtureFailedReport())
	assertGolden(t, "full_failed.txt", buf.Bytes())
}

// ─── DNS compare ──────────────────────────────────────────────────────────

func TestRenderDNSCompareText(t *testing.T) {
	d := fixtureDNSCompare()
	var buf bytes.Buffer
	for _, q := range d.Queries {
		// Project back to internal Result so RenderDNSCompare can render it.
		// The wire types don't expose the inverse, so we re-build a Result.
		r := dnscompare.Result{Host: d.Host, QType: q.QType}
		for _, rr := range q.Results {
			var err error
			if rr.Error != "" {
				err = errors.New(rr.Error)
			}
			r.Results = append(r.Results, dnscompare.ResolverResult{
				Resolver: dnscompare.Resolver{Name: rr.Name, Address: rr.Address},
				Records:  rr.Records,
				Err:      err,
				Took:     time.Duration(rr.TookMS) * time.Millisecond,
			})
		}
		RenderDNSCompare(&buf, &r)
	}
	assertGolden(t, "dns_compare.txt", buf.Bytes())
}

func TestRenderDNSCompareMD(t *testing.T) {
	var buf bytes.Buffer
	RenderDNSCompareMD(&buf, fixtureDNSCompare())
	assertGolden(t, "dns_compare.md", buf.Bytes())
}

func TestRenderDNSCompareHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderDNSCompareHTML(&buf, fixtureDNSCompare())
	assertGolden(t, "dns_compare.html", buf.Bytes())
}

// ─── Route ────────────────────────────────────────────────────────────────

func TestRenderRouteMD(t *testing.T) {
	var buf bytes.Buffer
	RenderRouteMD(&buf, fixtureRoute())
	assertGolden(t, "route.md", buf.Bytes())
}

func TestRenderRouteHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderRouteHTML(&buf, fixtureRoute())
	assertGolden(t, "route.html", buf.Bytes())
}

// ─── IP info ──────────────────────────────────────────────────────────────

func TestRenderIPInfoText(t *testing.T) {
	d := fixtureIPInfo()
	// Build IPDetails back from the JSON (only one entry) to call the
	// in-package renderer that consumes IPDetails.
	details := []ipinfo.IPDetails{{
		IP:      net.ParseIP("1.1.1.1"),
		Reverse: d.Details[0].Reverse,
		ASN: &ipinfo.ASNInfo{
			ASN:      d.Details[0].ASN.ASN,
			Org:      d.Details[0].ASN.Org,
			Country:  d.Details[0].ASN.Country,
			Prefix:   d.Details[0].ASN.Prefix,
			Registry: d.Details[0].ASN.Registry,
		},
		RDAP: &ipinfo.RDAPInfo{
			Name:       d.Details[0].RDAP.Name,
			Registry:   d.Details[0].RDAP.Registry,
			Country:    d.Details[0].RDAP.Country,
			AbuseEmail: d.Details[0].RDAP.AbuseEmail,
		},
		CDN: ipinfo.CDNMatch{
			Provider:   d.Details[0].CDN.Provider,
			Confidence: d.Details[0].CDN.Confidence,
			Reason:     d.Details[0].CDN.Reason,
		},
	}}
	var buf bytes.Buffer
	RenderIPInfo(&buf, "1.1.1.1", details, false, 0)
	assertGolden(t, "ip_info.txt", buf.Bytes())
}

func TestRenderIPInfoMD(t *testing.T) {
	var buf bytes.Buffer
	RenderIPInfoMD(&buf, fixtureIPInfo())
	assertGolden(t, "ip_info.md", buf.Bytes())
}

func TestRenderIPInfoHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderIPInfoHTML(&buf, fixtureIPInfo())
	assertGolden(t, "ip_info.html", buf.Bytes())
}

// ─── Headers ──────────────────────────────────────────────────────────────

// fixtureHeaders returns a HeadersJSON exercising every grade tier (pass,
// weak, missing, info) so the renderers cover all branches.
func fixtureHeaders() HeadersJSON {
	return HeadersJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "headers",
		URL:             "https://example.com/",
		FinalURL:        "https://example.com/",
		Status:          200,
		StartedAt:       fixedTime,
		TookMS:          145,
		Findings: []FindingJSON{
			{Name: "Strict-Transport-Security", Value: "max-age=31536000; includeSubDomains; preload", Grade: "pass", Comment: "Long max-age, includeSubDomains, preload directive present."},
			{Name: "Content-Security-Policy", Value: "default-src 'self'; script-src 'unsafe-inline'", Grade: "weak", Comment: "Present but allows 'unsafe-inline' — these weaken the XSS protection. Use nonces or hashes where possible."},
			{Name: "X-Frame-Options", Value: "DENY", Grade: "pass", Comment: "Set to a safe value."},
			{Name: "X-Content-Type-Options", Value: "", Grade: "missing", Comment: "Missing — set `X-Content-Type-Options: nosniff` to prevent browsers from re-interpreting response bodies."},
			{Name: "Referrer-Policy", Value: "strict-origin-when-cross-origin", Grade: "pass", Comment: "Set to a value that limits cross-origin referrer leakage."},
			{Name: "Permissions-Policy", Value: "", Grade: "missing", Comment: "Missing — controls which browser features (camera, geolocation, etc.) a page can use. Set even a permissive policy to make the surface explicit."},
			{Name: "Server", Value: "nginx/1.25.3", Grade: "info", Comment: "Server header exposes software identification — consider stripping or making it generic in production."},
			{Name: "X-Powered-By", Value: "PHP/8.1.0", Grade: "weak", Comment: "X-Powered-By leaks the application stack — remove this header."},
		},
		Summary: HeadersSummaryJSON{Pass: 3, Weak: 2, Missing: 2, Info: 1},
	}
}

func TestRenderHeadersText(t *testing.T) {
	var buf bytes.Buffer
	RenderHeaders(&buf, fixtureHeaders())
	assertGolden(t, "headers.txt", buf.Bytes())
}

func TestRenderHeadersMD(t *testing.T) {
	var buf bytes.Buffer
	RenderHeadersMD(&buf, fixtureHeaders())
	assertGolden(t, "headers.md", buf.Bytes())
}

func TestRenderHeadersHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderHeadersHTML(&buf, fixtureHeaders())
	assertGolden(t, "headers.html", buf.Bytes())
}

func TestRenderHeadersTextErr(t *testing.T) {
	d := HeadersJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "headers",
		URL:             "https://nope.invalid/",
		StartedAt:       fixedTime,
		TookMS:          12,
		Error:           "dial tcp: lookup nope.invalid: no such host",
	}
	var buf bytes.Buffer
	RenderHeaders(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("audit failed")) {
		t.Errorf("text error path should mention 'audit failed':\n%s", buf.String())
	}
}

func TestRenderHeadersMDErr(t *testing.T) {
	d := HeadersJSON{URL: "https://nope.invalid/", StartedAt: fixedTime, Error: "boom"}
	var buf bytes.Buffer
	RenderHeadersMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Audit failed")) {
		t.Errorf("md error path should mention 'Audit failed':\n%s", buf.String())
	}
}

func TestRenderHeadersHTMLErr(t *testing.T) {
	d := HeadersJSON{URL: "https://nope.invalid/", StartedAt: fixedTime, Error: "boom"}
	var buf bytes.Buffer
	RenderHeadersHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Audit failed")) {
		t.Errorf("html error path should mention 'Audit failed':\n%s", buf.String())
	}
}

// ─── Tech ─────────────────────────────────────────────────────────────────

func fixtureTech() TechJSON {
	return TechJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "tech",
		URL:             "https://example.com/",
		FinalURL:        "https://example.com/",
		Status:          200,
		StartedAt:       fixedTime,
		TookMS:          312,
		Matches: []TechMatch{
			{Name: "WordPress", Category: "cms", Version: "6.4.2", Confidence: "high", Evidence: `<meta name="generator" content="WordPress ...">`},
			{Name: "PHP", Category: "language", Version: "8.2.1", Confidence: "high", Evidence: "X-Powered-By: PHP/8.2.1"},
			{Name: "nginx", Category: "server", Version: "1.25.3", Confidence: "high", Evidence: "Server: nginx/1.25.3"},
			{Name: "Cloudflare", Category: "cdn", Confidence: "high", Evidence: "CF-Ray header"},
			{Name: "jQuery", Category: "library", Version: "3.6.0", Confidence: "medium", Evidence: "jquery*.js in HTML"},
		},
	}
}

func TestRenderTechText(t *testing.T) {
	var buf bytes.Buffer
	RenderTech(&buf, fixtureTech())
	assertGolden(t, "tech.txt", buf.Bytes())
}

func TestRenderTechMD(t *testing.T) {
	var buf bytes.Buffer
	RenderTechMD(&buf, fixtureTech())
	assertGolden(t, "tech.md", buf.Bytes())
}

func TestRenderTechHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderTechHTML(&buf, fixtureTech())
	assertGolden(t, "tech.html", buf.Bytes())
}

func TestRenderTechEmpty(t *testing.T) {
	d := TechJSON{URL: "https://nothing.example/", StartedAt: fixedTime}
	var buf bytes.Buffer
	RenderTech(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no known technologies")) {
		t.Errorf("empty text path should say 'no known technologies':\n%s", buf.String())
	}
	buf.Reset()
	RenderTechMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no known technologies")) {
		t.Errorf("empty md path should say so:\n%s", buf.String())
	}
	buf.Reset()
	RenderTechHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no known technologies")) {
		t.Errorf("empty html path should say so:\n%s", buf.String())
	}
}

func TestRenderTechErr(t *testing.T) {
	d := TechJSON{URL: "https://nope.invalid/", StartedAt: fixedTime, Error: "boom"}
	var buf bytes.Buffer
	RenderTech(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("detect failed")) {
		t.Errorf("text error path should mention 'detect failed':\n%s", buf.String())
	}
	buf.Reset()
	RenderTechMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Detect failed")) {
		t.Errorf("md error path should mention 'Detect failed':\n%s", buf.String())
	}
	buf.Reset()
	RenderTechHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Detect failed")) {
		t.Errorf("html error path should mention 'Detect failed':\n%s", buf.String())
	}
}

// ─── Subs ─────────────────────────────────────────────────────────────────

func fixtureSubs() SubsJSON {
	return SubsJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "subs",
		Domain:          "example.com",
		StartedAt:       fixedTime,
		TookMS:          1234,
		Subdomains: []SubdomainJSON{
			{Name: "*.example.com", Wildcard: true, Sources: []string{"crt.sh"}},
			{Name: "api.example.com", Sources: []string{"certspotter", "crt.sh"}},
			{Name: "docs.example.com", Sources: []string{"certspotter"}},
			{Name: "example.com", Sources: []string{"certspotter", "crt.sh"}},
			{Name: "www.example.com", Sources: []string{"certspotter"}},
		},
	}
}

func TestRenderSubsText(t *testing.T) {
	var buf bytes.Buffer
	RenderSubs(&buf, fixtureSubs())
	assertGolden(t, "subs.txt", buf.Bytes())
}

func TestRenderSubsMD(t *testing.T) {
	var buf bytes.Buffer
	RenderSubsMD(&buf, fixtureSubs())
	assertGolden(t, "subs.md", buf.Bytes())
}

func TestRenderSubsHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderSubsHTML(&buf, fixtureSubs())
	assertGolden(t, "subs.html", buf.Bytes())
}

func TestRenderSubsEmpty(t *testing.T) {
	d := SubsJSON{Domain: "example.com", StartedAt: fixedTime, Kind: "subs"}
	var buf bytes.Buffer
	RenderSubs(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no subdomains found in CT logs")) {
		t.Errorf("empty text path:\n%s", buf.String())
	}
	buf.Reset()
	RenderSubsMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no subdomains found")) {
		t.Errorf("empty md path:\n%s", buf.String())
	}
	buf.Reset()
	RenderSubsHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no subdomains found")) {
		t.Errorf("empty html path:\n%s", buf.String())
	}
}

func TestRenderSubsAllSourcesFailed(t *testing.T) {
	d := SubsJSON{
		Domain:       "example.com",
		Kind:         "subs",
		StartedAt:    fixedTime,
		SourceErrors: map[string]string{"crt.sh": "rate limited", "certspotter": "rate limited"},
	}
	var buf bytes.Buffer
	RenderSubs(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("every source errored")) {
		t.Errorf("text should call out the all-sources-down state:\n%s", buf.String())
	}
}

func TestRenderSubsTopLevelError(t *testing.T) {
	d := SubsJSON{Domain: "", Kind: "subs", StartedAt: fixedTime, Error: "empty domain"}
	var buf bytes.Buffer
	RenderSubs(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("enumeration failed")) {
		t.Errorf("text err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderSubsMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Enumeration failed")) {
		t.Errorf("md err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderSubsHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Enumeration failed")) {
		t.Errorf("html err path:\n%s", buf.String())
	}
}

// ─── Reverse ──────────────────────────────────────────────────────────────

func fixtureReverse() ReverseJSON {
	return ReverseJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "reverse",
		IP:              "1.1.1.1",
		StartedAt:       fixedTime,
		TookMS:          456,
		Hostnames: []HostnameJSON{
			{Name: "one.one.one.one", Sources: []string{"ptr"}},
			{Name: "shared.example.com", Sources: []string{"hackertarget", "shodan"}},
			{Name: "ht-only.example.com", Sources: []string{"hackertarget"}},
		},
	}
}

func TestRenderReverseText(t *testing.T) {
	var buf bytes.Buffer
	RenderReverse(&buf, fixtureReverse())
	assertGolden(t, "reverse.txt", buf.Bytes())
}

func TestRenderReverseMD(t *testing.T) {
	var buf bytes.Buffer
	RenderReverseMD(&buf, fixtureReverse())
	assertGolden(t, "reverse.md", buf.Bytes())
}

func TestRenderReverseHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderReverseHTML(&buf, fixtureReverse())
	assertGolden(t, "reverse.html", buf.Bytes())
}

func TestRenderReverseEmpty(t *testing.T) {
	d := ReverseJSON{IP: "1.2.3.4", Kind: "reverse", StartedAt: fixedTime, SourceDisabled: []string{"shodan"}}
	var buf bytes.Buffer
	RenderReverse(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("no hostnames found")) {
		t.Errorf("text empty path:\n%s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("Disabled (no API key): shodan")) {
		t.Errorf("text should mention disabled source:\n%s", buf.String())
	}
}

func TestRenderReverseErr(t *testing.T) {
	d := ReverseJSON{IP: "bad", Kind: "reverse", StartedAt: fixedTime, Error: "not an IP"}
	var buf bytes.Buffer
	RenderReverse(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("lookup failed")) {
		t.Errorf("text err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderReverseMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Lookup failed")) {
		t.Errorf("md err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderReverseHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Lookup failed")) {
		t.Errorf("html err path:\n%s", buf.String())
	}
}

// ─── Arch (Wayback) ───────────────────────────────────────────────────────

func fixtureArch() ArchJSON {
	first := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	last := time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)
	return ArchJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "arch",
		Domain:          "example.com",
		StartedAt:       fixedTime,
		TookMS:          2345,
		Total:           3,
		UniqueURLs:      3,
		First:           &first,
		Last:            &last,
		RecentSamples: []SnapshotJSON{
			{Timestamp: last, URL: "https://example.com/foo", Status: 404},
			{Timestamp: time.Date(2020, 5, 1, 0, 0, 0, 0, time.UTC), URL: "https://example.com/about", Status: 200},
			{Timestamp: first, URL: "https://example.com/", Status: 200},
		},
	}
}

func TestRenderArchText(t *testing.T) {
	var buf bytes.Buffer
	RenderArch(&buf, fixtureArch())
	assertGolden(t, "arch.txt", buf.Bytes())
}

func TestRenderArchMD(t *testing.T) {
	var buf bytes.Buffer
	RenderArchMD(&buf, fixtureArch())
	assertGolden(t, "arch.md", buf.Bytes())
}

func TestRenderArchHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderArchHTML(&buf, fixtureArch())
	assertGolden(t, "arch.html", buf.Bytes())
}

func TestRenderArchEmpty(t *testing.T) {
	d := ArchJSON{Domain: "empty.example", Kind: "arch", StartedAt: fixedTime}
	var buf bytes.Buffer
	RenderArch(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Total snapshots: 0")) {
		t.Errorf("text empty path:\n%s", buf.String())
	}
}

func TestRenderArchErr(t *testing.T) {
	d := ArchJSON{Domain: "bad", Kind: "arch", StartedAt: fixedTime, Error: "boom"}
	var buf bytes.Buffer
	RenderArch(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("lookup failed")) {
		t.Errorf("text err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderArchMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Lookup failed")) {
		t.Errorf("md err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderArchHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Lookup failed")) {
		t.Errorf("html err path:\n%s", buf.String())
	}
}

func fixtureWhois() WhoisJSON {
	return WhoisJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "whois",
		Domain:          "example.com",
		StartedAt:       fixedTime,
		TookMS:          412,
		Registrar:       "MarkMonitor Inc.",
		RegistrarIANAID: "292",
		RegistrarURL:    "https://www.markmonitor.com",
		Source:          "rdap",
	}
}

func TestRenderWhoisText(t *testing.T) {
	var buf bytes.Buffer
	RenderWhois(&buf, fixtureWhois())
	assertGolden(t, "whois.txt", buf.Bytes())
}

func TestRenderWhoisMD(t *testing.T) {
	var buf bytes.Buffer
	RenderWhoisMD(&buf, fixtureWhois())
	assertGolden(t, "whois.md", buf.Bytes())
}

func TestRenderWhoisHTML(t *testing.T) {
	var buf bytes.Buffer
	RenderWhoisHTML(&buf, fixtureWhois())
	assertGolden(t, "whois.html", buf.Bytes())
}

func TestRenderWhoisNotFound(t *testing.T) {
	d := WhoisJSON{Domain: "example.hu", Kind: "whois", StartedAt: fixedTime, NotFound: true}
	for _, render := range []func(*bytes.Buffer, WhoisJSON){
		func(b *bytes.Buffer, w WhoisJSON) { RenderWhois(b, w) },
		func(b *bytes.Buffer, w WhoisJSON) { RenderWhoisMD(b, w) },
		func(b *bytes.Buffer, w WhoisJSON) { RenderWhoisHTML(b, w) },
	} {
		var buf bytes.Buffer
		render(&buf, d)
		if !bytes.Contains(bytes.ToLower(buf.Bytes()), []byte("no registrar data")) {
			t.Errorf("not-found path missing message:\n%s", buf.String())
		}
	}
}

func TestWhoisNotFoundManualURL(t *testing.T) {
	hu := ToWhoisJSON("vipcomm.hu", nil, fixedTime, 0, nil)
	if !hu.NotFound {
		t.Fatal("nil registrar should yield NotFound")
	}
	if want := "https://info.domain.hu/webwhois/hu/domain/vipcomm.hu"; hu.ManualLookupURL != want {
		t.Errorf(".hu manual URL = %q, want %q", hu.ManualLookupURL, want)
	}
	// Non-.hu TLDs fall back to the authoritative IANA root-zone db entry.
	want := "https://www.iana.org/domains/root/db/com.html"
	if com := ToWhoisJSON("example.com", nil, fixedTime, 0, nil); com.ManualLookupURL != want {
		t.Errorf("non-.hu manual URL = %q, want %q", com.ManualLookupURL, want)
	}
}

func TestRenderWhoisErr(t *testing.T) {
	d := WhoisJSON{Domain: "bad", Kind: "whois", StartedAt: fixedTime, Error: "boom"}
	var buf bytes.Buffer
	RenderWhois(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("lookup failed")) {
		t.Errorf("text err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderWhoisMD(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Lookup failed")) {
		t.Errorf("md err path:\n%s", buf.String())
	}
	buf.Reset()
	RenderWhoisHTML(&buf, d)
	if !bytes.Contains(buf.Bytes(), []byte("Lookup failed")) {
		t.Errorf("html err path:\n%s", buf.String())
	}
}

// ─── JSON ─────────────────────────────────────────────────────────────────

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, ToFullJSON(fixtureReport())); err != nil {
		t.Fatal(err)
	}
	// JSON contains durations and floats — but with frozen inputs it's stable.
	assertGolden(t, "full.json", buf.Bytes())
}
