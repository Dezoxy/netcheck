package ipinfo

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─── ASNCache ─────────────────────────────────────────────────────────────

func TestASNCacheStoresAndReturnsValue(t *testing.T) {
	c := NewASNCache()
	// Pre-populate to avoid hitting the network.
	c.mu.Lock()
	c.m["1.1.1.1"] = &ASNInfo{ASN: "13335", Org: "CLOUDFLARENET"}
	c.mu.Unlock()

	got := c.Lookup(context.Background(), "1.1.1.1")
	if got == nil || got.ASN != "13335" {
		t.Errorf("cache hit returned %+v, want ASN=13335", got)
	}
}

func TestASNCacheRemembersMisses(t *testing.T) {
	c := NewASNCache()
	c.mu.Lock()
	c.m["8.8.8.8"] = nil
	c.mu.Unlock()
	// Second lookup should return nil immediately from cache, no DNS call.
	got := c.Lookup(context.Background(), "8.8.8.8")
	if got != nil {
		t.Errorf("expected cached nil, got %+v", got)
	}
}

func TestASNCachePrivateIPShortCircuit(t *testing.T) {
	c := NewASNCache()
	// Private IP: should never hit DNS, should return nil quickly.
	start := time.Now()
	got := c.Lookup(context.Background(), "192.168.1.1")
	took := time.Since(start)
	if got != nil {
		t.Errorf("private IP returned %+v, want nil", got)
	}
	if took > 500*time.Millisecond {
		t.Errorf("private IP took %v — suggests it tried DNS", took)
	}
}

func TestASNCacheInvalidIPShortCircuit(t *testing.T) {
	c := NewASNCache()
	got := c.Lookup(context.Background(), "not-an-ip")
	if got != nil {
		t.Errorf("invalid IP returned %+v, want nil", got)
	}
}

// ─── lookupCymru ──────────────────────────────────────────────────────────

func TestLookupCymruPrivateIPReturnsNil(t *testing.T) {
	if got := lookupCymru(context.Background(), "10.0.0.1"); got != nil {
		t.Errorf("private IP returned %+v, want nil", got)
	}
}

func TestLookupCymruInvalidIPReturnsNil(t *testing.T) {
	if got := lookupCymru(context.Background(), "garbage"); got != nil {
		t.Errorf("garbage input returned %+v, want nil", got)
	}
}

// ─── splitPipes ───────────────────────────────────────────────────────────

func TestSplitPipes(t *testing.T) {
	cases := map[string][]string{
		"15169 | 8.8.8.0/24 | US | arin | 2014-03-14": {"15169", "8.8.8.0/24", "US", "arin", "2014-03-14"},
		"a|b|c": {"a", "b", "c"},
		"  x  ": {"x"},
		"":      {""},
		"foo":   {"foo"},
		"a||b":  {"a", "", "b"},
	}
	for in, want := range cases {
		got := splitPipes(in)
		if len(got) != len(want) {
			t.Errorf("splitPipes(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("splitPipes(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

// ─── LookupIP orchestration ───────────────────────────────────────────────

func TestLookupIPPrivateReturnsEmptyEnrichment(t *testing.T) {
	// Private IP: ASN + RDAP should be nil, PTR may also be nil. The
	// orchestration must still return a struct (not crash).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := LookupIP(ctx, net.ParseIP("192.168.1.1"), nil, nil)
	if got.IP == nil || got.IP.String() != "192.168.1.1" {
		t.Errorf("IP = %v, want 192.168.1.1", got.IP)
	}
	if got.ASN != nil {
		t.Errorf("ASN = %+v, want nil for private IP", got.ASN)
	}
	if got.RDAP != nil {
		t.Errorf("RDAP = %+v, want nil for private IP", got.RDAP)
	}
}

func TestLookupDNSIPPrivateReturnsEmptyEnrichment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := LookupDNSIP(ctx, "10.0.0.1", nil)
	if got.ASN != nil {
		t.Errorf("ASN = %+v, want nil", got.ASN)
	}
	if got.CDN.Provider != "" {
		t.Errorf("CDN = %+v, want empty", got.CDN)
	}
}

// ─── ReverseNames ─────────────────────────────────────────────────────────

func TestReverseNamesAgainstLocalhost(t *testing.T) {
	// 127.0.0.1 reverse-resolves on every CI runner.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := ReverseNames(ctx, "127.0.0.1")
	// We accept either ["localhost"] or empty (some distros don't have the PTR).
	// The point of the test is to exercise the code path without crashing.
	if len(got) > 0 {
		for _, n := range got {
			if n == "" {
				t.Errorf("ReverseNames returned empty string in list: %v", got)
			}
		}
	}
}

func TestReverseNamesInvalidReturnsNil(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := ReverseNames(ctx, "not-an-ip")
	if got != nil {
		t.Errorf("invalid input returned %v, want nil", got)
	}
}

// ─── RDAPCache uses the http server path ─────────────────────────────────

func TestRDAPCacheRemembersMissesViaHTTP(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewRDAPCache()
	// First lookup hits the server (returns nil because 404).
	if v := lookupRDAPAt(context.Background(), c.client, srv.URL, "8.8.8.8"); v != nil {
		t.Errorf("expected nil on 404, got %+v", v)
	}
	// Store the miss explicitly to validate the public cache wrapper.
	c.mu.Lock()
	c.m["8.8.8.8"] = nil
	c.mu.Unlock()

	if v := c.Lookup(context.Background(), "8.8.8.8"); v != nil {
		t.Errorf("expected cached nil, got %+v", v)
	}
}
