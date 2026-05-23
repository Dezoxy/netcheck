package secheaders

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// findingByName finds the first Finding matching name. Returns zero-value
// Finding if not present.
func findingByName(fs []Finding, name string) Finding {
	for _, f := range fs {
		if f.Name == name {
			return f
		}
	}
	return Finding{}
}

// =============================================================================
// grade() unit tests — feed http.Header values directly, no HTTP.
// =============================================================================

func TestGradeHSTS(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		https  bool
		want   Grade
		substr string // substring expected in Comment
	}{
		{"missing on https", "", true, GradeMissing, "Set"},
		{"missing on http", "", false, GradeMissing, "only honoured over HTTPS"},
		{"valid 1y + includeSubDomains + preload", "max-age=31536000; includeSubDomains; preload", true, GradePass, "preload directive"},
		{"valid 1y + includeSubDomains, no preload", "max-age=31536000; includeSubDomains", true, GradePass, "Add `preload`"},
		{"too short max-age", "max-age=3600; includeSubDomains", true, GradeWeak, "too short"},
		{"no includeSubDomains", "max-age=31536000", true, GradeWeak, "subdomains aren't protected"},
		{"unparseable max-age", "max-age=foo", true, GradeWeak, "no parseable max-age"},
		{"no max-age directive", "includeSubDomains", true, GradeWeak, "no parseable max-age"},
		{"min boundary just below", "max-age=15767999; includeSubDomains", true, GradeWeak, "too short"},
		{"min boundary exact", "max-age=15768000; includeSubDomains", true, GradePass, "Add `preload`"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := gradeHSTS(c.value, c.https)
			if got.Grade != c.want {
				t.Errorf("grade = %q, want %q (comment: %s)", got.Grade, c.want, got.Comment)
			}
			if !strings.Contains(got.Comment, c.substr) {
				t.Errorf("comment %q should contain %q", got.Comment, c.substr)
			}
		})
	}
}

func TestGradeCSP(t *testing.T) {
	cases := []struct {
		value string
		want  Grade
	}{
		{"", GradeMissing},
		{"default-src 'self'", GradePass},
		{"default-src 'self'; script-src 'unsafe-inline'", GradeWeak},
		{"default-src 'self'; script-src 'unsafe-eval'", GradeWeak},
		{"default-src 'self' 'unsafe-inline' 'unsafe-eval'", GradeWeak},
		{"default-src 'self'; script-src 'nonce-abc123'", GradePass},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			got := gradeCSP(c.value)
			if got.Grade != c.want {
				t.Errorf("CSP %q: grade = %q, want %q", c.value, got.Grade, c.want)
			}
		})
	}
}

func TestGradeXFO(t *testing.T) {
	cases := []struct {
		value string
		want  Grade
	}{
		{"", GradeMissing},
		{"DENY", GradePass},
		{"SAMEORIGIN", GradePass},
		{"sameorigin", GradePass},
		{"deny", GradePass},
		{"ALLOW-FROM https://example.com", GradeWeak},
		{"INVALID", GradeWeak},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			got := gradeXFO(c.value)
			if got.Grade != c.want {
				t.Errorf("XFO %q: grade = %q, want %q (comment: %s)", c.value, got.Grade, c.want, got.Comment)
			}
		})
	}
}

func TestGradeXCTO(t *testing.T) {
	cases := []struct {
		value string
		want  Grade
	}{
		{"", GradeMissing},
		{"nosniff", GradePass},
		{"NoSniff", GradePass},
		{"  nosniff  ", GradePass},
		{"sniff", GradeWeak},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			got := gradeXCTO(c.value)
			if got.Grade != c.want {
				t.Errorf("XCTO %q: grade = %q, want %q", c.value, got.Grade, c.want)
			}
		})
	}
}

func TestGradeReferrer(t *testing.T) {
	cases := []struct {
		value string
		want  Grade
	}{
		{"", GradeMissing},
		{"no-referrer", GradePass},
		{"same-origin", GradePass},
		{"strict-origin", GradePass},
		{"strict-origin-when-cross-origin", GradePass},
		{"origin", GradePass},
		{"unsafe-url", GradeWeak},
		{"no-referrer-when-downgrade", GradeWeak},
		// Multi-value chain — worst (most permissive) wins:
		{"no-referrer, unsafe-url", GradeWeak},
		{"made-up-policy", GradeWeak},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			got := gradeReferrer(c.value)
			if got.Grade != c.want {
				t.Errorf("Referrer %q: grade = %q, want %q (comment: %s)", c.value, got.Grade, c.want, got.Comment)
			}
		})
	}
}

func TestGradePermissions(t *testing.T) {
	if g := gradePermissions("").Grade; g != GradeMissing {
		t.Errorf("empty: got %q, want missing", g)
	}
	if g := gradePermissions("camera=(), geolocation=()").Grade; g != GradePass {
		t.Errorf("present: got %q, want pass", g)
	}
}

// =============================================================================
// hstsMaxAge / containsToken — parser helpers.
// =============================================================================

func TestHSTSMaxAge(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantOK  bool
		variant string
	}{
		{"max-age=31536000", 31536000, true, "bare"},
		{"max-age=31536000; includeSubDomains", 31536000, true, "with subdomains"},
		{"includeSubDomains; max-age=86400", 86400, true, "reverse order"},
		{`max-age="86400"`, 86400, true, "quoted value"},
		{"MAX-AGE=86400", 86400, true, "uppercase directive"},
		{"max-age=", 0, false, "empty value"},
		{"includeSubDomains", 0, false, "no max-age directive"},
		{"max-age=foo", 0, false, "non-numeric"},
	}
	for _, c := range cases {
		t.Run(c.variant, func(t *testing.T) {
			n, ok := hstsMaxAge(c.in)
			if ok != c.wantOK {
				t.Errorf("ok = %v, want %v", ok, c.wantOK)
			}
			if ok && n != c.want {
				t.Errorf("n = %d, want %d", n, c.want)
			}
		})
	}
}

func TestContainsToken(t *testing.T) {
	if !containsToken("max-age=86400; includeSubDomains; preload", "includeSubDomains") {
		t.Error("includeSubDomains should be present")
	}
	if !containsToken("max-age=86400; INCLUDESUBDOMAINS", "includeSubDomains") {
		t.Error("case-insensitive match expected")
	}
	if containsToken("max-age=86400", "preload") {
		t.Error("preload should not be present")
	}
}

// =============================================================================
// grade() against an http.Header (covers Server / X-Powered-By disclosure path)
// =============================================================================

func TestGradeIncludesServerAndPoweredBy(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=()")
	h.Set("Server", "nginx/1.25.3")
	h.Set("X-Powered-By", "PHP/8.1.0")

	u, _ := url.Parse("https://example.com/")
	out := grade(u, h)

	server := findingByName(out, "Server")
	if server.Grade != GradeInfo {
		t.Errorf("Server grade = %q, want info", server.Grade)
	}
	if server.Value != "nginx/1.25.3" {
		t.Errorf("Server value = %q, want nginx/1.25.3", server.Value)
	}

	powered := findingByName(out, "X-Powered-By")
	if powered.Grade != GradeWeak {
		t.Errorf("X-Powered-By grade = %q, want weak", powered.Grade)
	}
}

func TestGradeOmitsServerAndPoweredByWhenAbsent(t *testing.T) {
	u, _ := url.Parse("https://example.com/")
	out := grade(u, http.Header{})
	if (findingByName(out, "Server") != Finding{}) {
		t.Error("Server finding should not appear when header absent")
	}
	if (findingByName(out, "X-Powered-By") != Finding{}) {
		t.Error("X-Powered-By finding should not appear when header absent")
	}
}

// =============================================================================
// Audit() — full HTTP path against httptest.
// =============================================================================

func TestAuditFullPassingServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	out := Audit(context.Background(), srv.URL, true /* insecure: test cert */, 5*time.Second)
	if out.Err != nil {
		t.Fatalf("unexpected error: %v", out.Err)
	}
	if out.Status != 200 {
		t.Errorf("status = %d, want 200", out.Status)
	}
	pass, weak, missing, _ := out.Summary()
	if pass != 6 || weak != 0 || missing != 0 {
		t.Errorf("counts: pass=%d weak=%d missing=%d, want 6/0/0", pass, weak, missing)
	}
}

func TestAuditFullBareServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	out := Audit(context.Background(), srv.URL, false, 5*time.Second)
	if out.Err != nil {
		t.Fatalf("unexpected error: %v", out.Err)
	}
	// 6 graded headers, all missing on the bare server.
	_, _, missing, info := out.Summary()
	if missing != 6 {
		t.Errorf("missing = %d, want 6", missing)
	}
	if info != 1 {
		t.Errorf("info (Server) = %d, want 1", info)
	}
	// HSTS on a plain HTTP URL gets the "expected on plain HTTP" comment.
	hsts := findingByName(out.Findings, "Strict-Transport-Security")
	if !strings.Contains(hsts.Comment, "only honoured over HTTPS") {
		t.Errorf("HSTS comment on http URL: %q", hsts.Comment)
	}
}

func TestAuditBadURL(t *testing.T) {
	out := Audit(context.Background(), "", false, 1*time.Second)
	if out.Err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestAuditNormalizesSchemelessURL(t *testing.T) {
	// We can't actually connect to "example.com" in a unit test, but we can
	// verify normalizeURL fills in https://.
	got, err := normalizeURL("example.com/foo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("normalizeURL %q, want https:// prefix", got)
	}
}

func TestAuditSetUserAgent(t *testing.T) {
	// Stash and restore so we don't leak into other tests.
	prev := userAgent
	defer func() { userAgent = prev }()

	SetUserAgent("netcheck-test/1.0")
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	_ = Audit(context.Background(), srv.URL, false, 5*time.Second)
	if got != "netcheck-test/1.0" {
		t.Errorf("UA seen by server = %q, want netcheck-test/1.0", got)
	}
}

func TestSetUserAgentIgnoresEmpty(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	userAgent = "before"
	SetUserAgent("")
	if userAgent != "before" {
		t.Errorf("SetUserAgent(\"\") should be a no-op, got %q", userAgent)
	}
}
