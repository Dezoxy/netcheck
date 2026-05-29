package ipinfo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// rawVCard builds a jCard ["vcard", [props...]] payload as json.RawMessage.
func rawVCard(t *testing.T, props [][]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal([]any{"vcard", props})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// domainRDAPBody is a trimmed gTLD RDAP domain response carrying a
// registrar entity with the three fields we extract.
const domainRDAPBody = `{
	"objectClassName": "domain",
	"ldhName": "example.com",
	"entities": [
		{
			"roles": ["registrar"],
			"publicIds": [
				{ "type": "IANA Registrar ID", "identifier": "292" }
			],
			"vcardArray": ["vcard", [
				["version", {}, "text", "4.0"],
				["fn", {}, "text", "MarkMonitor Inc."]
			]],
			"links": [
				{ "rel": "about", "href": "https://www.markmonitor.com" }
			],
			"entities": [
				{
					"roles": ["abuse"],
					"vcardArray": ["vcard", [
						["email", {}, "text", "abuse@markmonitor.com"]
					]]
				}
			]
		},
		{
			"roles": ["registrant"],
			"vcardArray": ["vcard", [["fn", {}, "text", "Redacted"]]]
		}
	]
}`

func TestRDAPDomainLookupHTTPRoundTrip(t *testing.T) {
	var gotPath, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(domainRDAPBody))
	}))
	defer srv.Close()

	SetUserAgent("netcheck-test/1.0")
	client := &http.Client{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pass a full URL to also exercise normalizeDomain.
	r := lookupRDAPDomainAt(ctx, client, srv.URL, "https://Example.com/path")
	if r == nil {
		t.Fatal("registrar lookup returned nil")
	}
	if r.Name != "MarkMonitor Inc." {
		t.Errorf("Name = %q, want MarkMonitor Inc.", r.Name)
	}
	if r.IANAID != "292" {
		t.Errorf("IANAID = %q, want 292", r.IANAID)
	}
	if r.URL != "https://www.markmonitor.com" {
		t.Errorf("URL = %q", r.URL)
	}
	if gotPath != "/domain/example.com" {
		t.Errorf("server saw path %q, want /domain/example.com", gotPath)
	}
	if gotUA != "netcheck-test/1.0" {
		t.Errorf("server saw User-Agent %q", gotUA)
	}
}

func TestRDAPDomainLookupHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound) // ccTLD with no RDAP, or unknown domain
	}))
	defer srv.Close()

	r := lookupRDAPDomainAt(context.Background(), &http.Client{Timeout: 2 * time.Second}, srv.URL, "example.invalidtld")
	if r != nil {
		t.Errorf("expected nil on HTTP 404, got %+v", r)
	}
}

// TestRegistrarFromDomain covers the parser's fallbacks directly: vCard
// "url" when no "about" link, and nil when no registrar entity exists.
func TestRegistrarFromDomain(t *testing.T) {
	t.Run("vcard url fallback", func(t *testing.T) {
		resp := &rdapDomainResponse{Entities: []rdapEntity{{
			Roles:     []string{"registrar"},
			PublicIds: []rdapPublicID{{Type: "IANA Registrar ID", Identifier: "9999"}},
			VCardArray: rawVCard(t, [][]any{
				{"fn", map[string]any{}, "text", "Example Registrar"},
				{"url", map[string]any{}, "uri", "https://reg.example"},
			}),
		}}}
		r := registrarFromDomain(resp)
		if r == nil || r.URL != "https://reg.example" || r.Name != "Example Registrar" || r.IANAID != "9999" {
			t.Fatalf("got %+v", r)
		}
	})

	t.Run("no registrar entity", func(t *testing.T) {
		resp := &rdapDomainResponse{Entities: []rdapEntity{{Roles: []string{"registrant"}}}}
		if r := registrarFromDomain(resp); r != nil {
			t.Errorf("want nil, got %+v", r)
		}
	})
}
