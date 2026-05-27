package dnscompare

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestDoHRoundTrip stands up an httptest server that speaks the RFC 8484
// wire-format protocol: parse the request body as a DNS Msg, return a Msg
// carrying a canned A record. Verifies:
//   - Content-Type / Accept headers are set
//   - Wire-format encode/decode round-trip
//   - Result surfaces through Compare()
func TestDoHRoundTrip(t *testing.T) {
	var gotContentType, gotAccept string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// Build a response: SetReply copies the question, then we add the answer.
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 1.2.3.4")
			resp.Answer = append(resp.Answer, rr)
		}

		out, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	// Use Compare() directly to exercise the full path.
	resolvers := []Resolver{
		{Name: "test-doh", Address: srv.URL, Type: TypeDoH},
	}
	result := Compare(context.Background(), resolvers, "example.com", "A", 5*time.Second, CompareOpts{})
	if len(result.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(result.Results))
	}
	r := result.Results[0]
	if r.Err != nil {
		t.Fatalf("DoH query returned error: %v", r.Err)
	}
	if len(r.Records) != 1 || r.Records[0] != "1.2.3.4" {
		t.Errorf("records = %v, want [1.2.3.4]", r.Records)
	}

	if gotContentType != "application/dns-message" {
		t.Errorf("server saw Content-Type = %q, want application/dns-message", gotContentType)
	}
	if gotAccept != "application/dns-message" {
		t.Errorf("server saw Accept = %q, want application/dns-message", gotAccept)
	}
}

func TestDoHServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	resolvers := []Resolver{{Name: "broken", Address: srv.URL, Type: TypeDoH}}
	result := Compare(context.Background(), resolvers, "example.com", "A", 2*time.Second, CompareOpts{})
	if result.Results[0].Err == nil {
		t.Error("expected error on HTTP 503, got nil")
	}
}

// TestDNSSECOptSetsDOBit verifies CompareOpts.DNSSEC controls the DO
// (DNSSEC OK) flag on EDNS0. The DoH test server inspects the inbound
// Msg and reports back whether DO was set; we assert it tracks the opt.
func TestDNSSECOptSetsDOBit(t *testing.T) {
	cases := []struct {
		name   string
		opts   CompareOpts
		wantDO bool
	}{
		{"DNSSEC off", CompareOpts{}, false},
		{"DNSSEC on", CompareOpts{DNSSEC: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var observedDO bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				req := new(dns.Msg)
				if err := req.Unpack(body); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				if opt := req.IsEdns0(); opt != nil {
					observedDO = opt.Do()
				}
				resp := new(dns.Msg)
				resp.SetReply(req)
				out, _ := resp.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(out)
			}))
			defer srv.Close()

			resolvers := []Resolver{{Name: "do-bit", Address: srv.URL, Type: TypeDoH}}
			_ = Compare(context.Background(), resolvers, "example.com", "A", 2*time.Second, c.opts)
			if observedDO != c.wantDO {
				t.Errorf("DO bit observed=%v, want %v", observedDO, c.wantDO)
			}
		})
	}
}
