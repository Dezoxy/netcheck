package reverseip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// normalizeIP / normalizeName
// =============================================================================

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"1.1.1.1", "1.1.1.1", false},
		{"  1.1.1.1  ", "1.1.1.1", false},
		{"1.1.1.1:443", "1.1.1.1", false},
		{"[::1]", "::1", false},
		{"[::1]:443", "::1", false},
		{"2606:4700:4700::1111", "2606:4700:4700::1111", false},
		{"", "", true},
		{"not-an-ip", "", true},
		{"example.com", "", true}, // hostnames are rejected
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := normalizeIP(c.in)
			if c.wantErr && err == nil {
				t.Errorf("want error, got %q", got)
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Foo.Example.COM.", "foo.example.com"},
		{"  one.example.com  ", "one.example.com"},
		{"foo@bar.com", ""}, // looks like email
		{"has space.com", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeName(c.in); got != c.want {
			t.Errorf("normalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// =============================================================================
// Hackertarget source
// =============================================================================

func TestHackertargetParse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("one.example.com\ntwo.example.com\n"))
	}))
	defer srv.Close()
	defer SetSourceURLsForTest(srv.URL, "")()

	names, err := (hackertargetSource{}).Fetch(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "one.example.com" || names[1] != "two.example.com" {
		t.Errorf("got %v, want [one.example.com two.example.com]", names)
	}
}

func TestHackertargetErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("error check your input"))
	}))
	defer srv.Close()
	defer SetSourceURLsForTest(srv.URL, "")()

	_, err := (hackertargetSource{}).Fetch(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error on Hackertarget error body")
	}
}

// =============================================================================
// Shodan source
// =============================================================================

func TestShodanParse(t *testing.T) {
	gotPath := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		_, _ = w.Write([]byte(`{"hostnames":["a.example.com","b.example.com"],"domains":["example.com"]}`))
	}))
	defer srv.Close()
	defer SetSourceURLsForTest("", srv.URL)()

	names, err := (shodanSource{apiKey: "test-key"}).Fetch(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("got %v, want 2 hostnames", names)
	}
	if !strings.Contains(gotPath, "/shodan/host/1.1.1.1") {
		t.Errorf("expected /shodan/host/<ip> path, got %s", gotPath)
	}
	if !strings.Contains(gotPath, "key=test-key") {
		t.Errorf("expected key=test-key in query, got %s", gotPath)
	}
}

// =============================================================================
// Enumerate — full integration
// =============================================================================

func TestEnumerateMergesSources(t *testing.T) {
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("shared.example.com\nht-only.example.com\n"))
	}))
	defer htSrv.Close()
	shSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hostnames":["shared.example.com","shodan-only.example.com"]}`))
	}))
	defer shSrv.Close()
	defer SetSourceURLsForTest(htSrv.URL, shSrv.URL)()

	res := Enumerate(context.Background(), "1.1.1.1", Options{ShodanAPIKey: "k"}, 5*time.Second)
	// PTR for 1.1.1.1 might or might not succeed at lookup-time in CI — accept
	// either: as long as the merge from HT + Shodan worked.
	names := map[string]Hostname{}
	for _, h := range res.Hostnames {
		names[h.Name] = h
	}
	for _, want := range []string{"shared.example.com", "ht-only.example.com", "shodan-only.example.com"} {
		if _, ok := names[want]; !ok {
			t.Errorf("missing %q; got %v", want, names)
		}
	}
	shared := names["shared.example.com"]
	if len(shared.Sources) < 2 {
		t.Errorf("shared.example.com should have 2 sources, got %v", shared.Sources)
	}
}

func TestEnumerateShodanSkippedWithoutKey(t *testing.T) {
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("only.example.com\n"))
	}))
	defer htSrv.Close()
	defer SetSourceURLsForTest(htSrv.URL, "")()

	res := Enumerate(context.Background(), "1.1.1.1", Options{}, 5*time.Second)
	found := false
	for _, d := range res.SourceDisabled {
		if d == "shodan" {
			found = true
		}
	}
	if !found {
		t.Errorf("shodan should be in SourceDisabled, got %v", res.SourceDisabled)
	}
	if _, ok := res.SourceErrors["shodan"]; ok {
		t.Error("shodan should be silently skipped, not reported as error")
	}
}

func TestEnumerateBadInput(t *testing.T) {
	res := Enumerate(context.Background(), "", Options{}, time.Second)
	if res.Err == nil {
		t.Error("expected top-level error")
	}
	res = Enumerate(context.Background(), "not-an-ip", Options{}, time.Second)
	if res.Err == nil {
		t.Error("expected error on non-IP input")
	}
}

// =============================================================================
// httpGet / SetUserAgent
// =============================================================================

func TestHTTPGetSendsUserAgent(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	SetUserAgent("netcheck-test/0.0")

	seen := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if _, err := httpGet(context.Background(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if seen != "netcheck-test/0.0" {
		t.Errorf("UA = %q", seen)
	}
}

func TestSetUserAgentEmptyNoop(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	userAgent = "before"
	SetUserAgent("")
	if userAgent != "before" {
		t.Errorf("got %q", userAgent)
	}
}

func TestHTTPGetErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"error":"bad key"}`))
	}))
	defer srv.Close()
	_, err := httpGet(context.Background(), srv.URL, nil)
	if err == nil || !strings.Contains(err.Error(), "bad key") {
		t.Errorf("want body snippet in err, got %v", err)
	}
}
