package pathenum

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// normalizeBase / joinPath / categorize
// =============================================================================

func TestNormalizeBase(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"example.com", "https://example.com", false},
		{"https://example.com", "https://example.com", false},
		{"http://example.com:8080/", "http://example.com:8080/", false},
		{"https://example.com/foo?bar=1#x", "https://example.com/foo", false}, // query/fragment stripped
		{"", "", true},
		{"://broken", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := normalizeBase(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct {
		base, path, want string
	}{
		{"https://example.com", "robots.txt", "https://example.com/robots.txt"},
		{"https://example.com/", "robots.txt", "https://example.com/robots.txt"},
		{"https://example.com", "/robots.txt", "https://example.com/robots.txt"},
		{"https://example.com/", "/robots.txt", "https://example.com/robots.txt"},
		{"https://example.com", "", "https://example.com"},
		{"https://example.com/app", "login", "https://example.com/app/login"},
	}
	for _, c := range cases {
		t.Run(c.base+"+"+c.path, func(t *testing.T) {
			if got := joinPath(c.base, c.path); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCategorize(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{200, "found"},
		{201, ""},
		{301, "redirect"},
		{302, "redirect"},
		{307, "redirect"},
		{401, "auth-required"},
		{403, "blocked"},
		{404, ""}, // not categorized; handled separately as "miss"
		{500, "server-error"},
		{502, "server-error"},
		{418, ""}, // teapot — uninteresting
	}
	for _, c := range cases {
		if got := categorize(c.status); got != c.want {
			t.Errorf("categorize(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

// =============================================================================
// DefaultWordlist / LoadWordlist
// =============================================================================

func TestDefaultWordlistIsNonEmpty(t *testing.T) {
	w := DefaultWordlist()
	if len(w) < 30 {
		t.Errorf("default wordlist too small: %d entries", len(w))
	}
	// Sanity: contains canonical entries.
	want := []string{"robots.txt", ".git/HEAD", "admin", ".env", "phpmyadmin"}
	got := map[string]bool{}
	for _, p := range w {
		got[p] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("default wordlist missing %q", w)
		}
	}
}

func TestDefaultWordlistReturnsCopy(t *testing.T) {
	w := DefaultWordlist()
	w[0] = "MUTATED"
	if DefaultWordlist()[0] == "MUTATED" {
		t.Error("DefaultWordlist must return an independent copy")
	}
}

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.txt")
	content := `# comment
robots.txt
  admin

# another comment

.env
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"robots.txt", "admin", ".env"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadWordlistMissing(t *testing.T) {
	if _, err := LoadWordlist("/nonexistent/path/here"); err == nil {
		t.Error("expected error on missing file")
	}
}

// =============================================================================
// Enumerate against a controlled server
// =============================================================================

func TestEnumerateClassifiesResponses(t *testing.T) {
	mux := http.NewServeMux()
	// 200 OK on robots.txt
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("User-agent: *\nDisallow:\n"))
	})
	// 403 on /admin
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	// 401 on /api
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	// 301 on /old → /new
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/new")
		w.WriteHeader(301)
	})
	// 500 on /broken
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})
	// 204 on /quiet — categorize() returns "", so this shouldn't appear
	mux.HandleFunc("/quiet", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	// everything else → 404
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Enumerate(context.Background(), srv.URL, Options{
		Wordlist:        []string{"robots.txt", "admin", "api", "old", "broken", "quiet", "missing-path"},
		Concurrency:     4,
		PerPathTimeout:  3 * time.Second,
		FollowRedirects: false,
	}, 10*time.Second)

	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}

	gotByPath := map[string]Finding{}
	for _, f := range res.Findings {
		gotByPath[f.Path] = f
	}

	// Findings must include the 5 non-204/non-404 paths.
	for _, want := range []string{"robots.txt", "admin", "api", "old", "broken"} {
		if _, ok := gotByPath[want]; !ok {
			t.Errorf("expected finding for %q, got %v", want, gotByPath)
		}
	}

	// Category checks.
	if gotByPath["robots.txt"].Category != "found" {
		t.Errorf("robots.txt category = %q", gotByPath["robots.txt"].Category)
	}
	if gotByPath["admin"].Category != "blocked" {
		t.Errorf("admin category = %q", gotByPath["admin"].Category)
	}
	if gotByPath["api"].Category != "auth-required" {
		t.Errorf("api category = %q", gotByPath["api"].Category)
	}
	if gotByPath["old"].Category != "redirect" || gotByPath["old"].Redirect != "/new" {
		t.Errorf("old: cat=%q redirect=%q", gotByPath["old"].Category, gotByPath["old"].Redirect)
	}
	if gotByPath["broken"].Category != "server-error" {
		t.Errorf("broken category = %q", gotByPath["broken"].Category)
	}
	// /quiet (204) and /missing-path (404) must NOT appear.
	if _, ok := gotByPath["quiet"]; ok {
		t.Error("204 should not show up as a finding")
	}
	if _, ok := gotByPath["missing-path"]; ok {
		t.Error("404 should not show up as a finding")
	}

	if res.Stats.Total != 7 {
		t.Errorf("Total = %d, want 7", res.Stats.Total)
	}
	if res.Stats.Interesting != 5 {
		t.Errorf("Interesting = %d, want 5", res.Stats.Interesting)
	}
	if res.Stats.NotFound != 1 {
		t.Errorf("NotFound = %d, want 1", res.Stats.NotFound)
	}
}

func TestEnumerateUsesDefaultWordlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything 404 — we just want to confirm Total tracks the wordlist size.
		w.WriteHeader(404)
	}))
	defer srv.Close()
	res := Enumerate(context.Background(), srv.URL, Options{
		Concurrency: 20,
	}, 30*time.Second)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.Stats.Total != len(DefaultWordlist()) {
		t.Errorf("Total = %d, want default wordlist length %d", res.Stats.Total, len(DefaultWordlist()))
	}
}

func TestEnumerateBadURL(t *testing.T) {
	res := Enumerate(context.Background(), "", Options{}, time.Second)
	if res.Err == nil {
		t.Error("expected err on empty URL")
	}
}

func TestEnumerateTransportError(t *testing.T) {
	// Stub httpDo to always fail.
	prev := httpDo
	defer func() { httpDo = prev }()
	httpDo = func(client *http.Client, req *http.Request) (*http.Response, error) {
		return nil, http.ErrHandlerTimeout
	}
	res := Enumerate(context.Background(), "https://example.com", Options{
		Wordlist: []string{"a", "b", "c"},
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.Stats.Errors != 3 {
		t.Errorf("Errors = %d, want 3", res.Stats.Errors)
	}
}

func TestEnumerateFollowRedirectsDefault(t *testing.T) {
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "/new")
		w.WriteHeader(301)
	})
	mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// FollowRedirects=true: should arrive at /new and report status 200.
	res := Enumerate(context.Background(), srv.URL, Options{
		Wordlist:        []string{"old"},
		FollowRedirects: true,
		PerPathTimeout:  3 * time.Second,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding")
	}
	if res.Findings[0].Status != 200 {
		t.Errorf("FollowRedirects=true: got status %d, want 200", res.Findings[0].Status)
	}
}

func TestSetUserAgent(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	SetUserAgent("test-ua/1.0")
	if userAgent != "test-ua/1.0" {
		t.Errorf("got %q", userAgent)
	}
	SetUserAgent("")
	if userAgent != "test-ua/1.0" {
		t.Errorf("empty SetUserAgent should be no-op, got %q", userAgent)
	}
}

// Findings should be sorted by status, then path.
func TestFindingsSorted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zzz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/aaa", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/forbidden", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Enumerate(context.Background(), srv.URL, Options{
		Wordlist: []string{"zzz", "aaa", "forbidden"},
	}, 10*time.Second)
	if len(res.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(res.Findings))
	}
	// Order should be: 200 aaa, 200 zzz, 403 forbidden.
	if res.Findings[0].Path != "aaa" || res.Findings[1].Path != "zzz" || res.Findings[2].Path != "forbidden" {
		t.Errorf("unexpected order: %+v", []string{
			res.Findings[0].Path, res.Findings[1].Path, res.Findings[2].Path,
		})
	}
}

func TestSchemeDefaultsToHTTPS(t *testing.T) {
	got, err := normalizeBase("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("got %q, want https:// default", got)
	}
}
