package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRDAPLookupHTTPRoundTrip verifies the RDAP lookup against a local
// httptest server returning canned JSON. Exercises:
//   - User-Agent header is set
//   - Accept header is set
//   - JSON decoded into the schema
//   - Entity walking picks the registrant org name
//   - Abuse email surfaces from a nested abuse entity
func TestRDAPLookupHTTPRoundTrip(t *testing.T) {
	var gotUA, gotAccept string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"name": "GOGL",
			"country": "US",
			"port43": "whois.arin.net",
			"entities": [
				{
					"roles": ["registrant"],
					"vcardArray": ["vcard", [
						["version", {}, "text", "4.0"],
						["fn", {}, "text", "Google LLC"],
						["org", {}, "text", "Google LLC"]
					]]
				},
				{
					"roles": ["abuse"],
					"vcardArray": ["vcard", [
						["email", {}, "text", "network-abuse@google.com"]
					]]
				}
			]
		}`))
	}))
	defer srv.Close()

	SetUserAgent("netcheck-test/1.0")

	// We can't easily redirect "rdap.org" to the test server without a
	// transport override, so we exercise the lower-level lookupRDAP directly
	// using the test client and a synthesized URL. The HTTP request happens
	// at the same code path the cache calls.
	client := &http.Client{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info := lookupRDAPAt(ctx, client, srv.URL, "8.8.8.8")
	if info == nil {
		t.Fatal("RDAP lookup returned nil")
	}
	if info.Name != "Google LLC" {
		t.Errorf("Name = %q, want Google LLC", info.Name)
	}
	if info.Registry != "arin" {
		t.Errorf("Registry = %q, want arin", info.Registry)
	}
	if info.AbuseEmail != "network-abuse@google.com" {
		t.Errorf("AbuseEmail = %q", info.AbuseEmail)
	}
	if gotUA != "netcheck-test/1.0" {
		t.Errorf("server saw User-Agent = %q, want netcheck-test/1.0", gotUA)
	}
	if !strings.Contains(gotAccept, "application/dns-message") && !strings.Contains(gotAccept, "application/rdap+json") {
		t.Errorf("server saw Accept = %q, expected RDAP variant", gotAccept)
	}
}

func TestRDAPLookupHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	info := lookupRDAPAt(context.Background(), client, srv.URL, "8.8.8.8")
	if info != nil {
		t.Errorf("expected nil on HTTP 500, got %+v", info)
	}
}
