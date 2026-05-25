package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netcheck/internal/reverseip"
	"netcheck/internal/subenum"
	"netcheck/internal/takeover"
	"netcheck/internal/wayback"
)

// ─── /api/check/headers ───────────────────────────────────────────────────

func TestHeadersCheckRejectsGet(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/check/headers", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHeadersCheckEmptyURL(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/headers", map[string]any{"url": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHeadersCheckHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	resp, data := appRequest(t, http.MethodPost, "/api/check/headers", map[string]any{"url": srv.URL})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	var out struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != "headers" {
		t.Errorf("kind = %q, want headers", out.Kind)
	}
}

// ─── /api/check/tech ──────────────────────────────────────────────────────

func TestTechCheckEmptyURL(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/tech", map[string]any{"url": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTechCheckHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	resp, data := appRequest(t, http.MethodPost, "/api/check/tech", map[string]any{"url": srv.URL})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
}

// ─── /api/check/subs ──────────────────────────────────────────────────────

func TestSubsCheckEmptyDomain(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/subs", map[string]any{"domain": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSubsCheckHappyPath(t *testing.T) {
	// Mock both CT log sources.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	restore := subenum.SetSourceURLsForTest(srv.URL, srv.URL)
	defer restore()

	resp, _ := appRequest(t, http.MethodPost, "/api/check/subs", map[string]any{"domain": "example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ─── /api/check/reverse ───────────────────────────────────────────────────

func TestReverseCheckEmptyIP(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/reverse", map[string]any{"ip": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestReverseCheckHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(""))
	}))
	defer srv.Close()
	restore := reverseip.SetSourceURLsForTest(srv.URL, "")
	defer restore()

	resp, _ := appRequest(t, http.MethodPost, "/api/check/reverse", map[string]any{"ip": "127.0.0.1"})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ─── /api/check/arch ──────────────────────────────────────────────────────

func TestArchCheckEmptyDomain(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/arch", map[string]any{"domain": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestArchCheckHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[["timestamp","original","statuscode"]]`))
	}))
	defer srv.Close()
	restore := wayback.SetSourceURLForTest(srv.URL)
	defer restore()

	resp, _ := appRequest(t, http.MethodPost, "/api/check/arch", map[string]any{"domain": "example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ─── /api/check/tls (active — auth gate) ──────────────────────────────────

func TestTLSCheckRefusesWithoutAuth(t *testing.T) {
	resp, data := appRequest(t, http.MethodPost, "/api/check/tls", map[string]any{
		"host":                 "cloudflare.com:443",
		"i_have_authorization": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", resp.StatusCode, data)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["authorized"] != false {
		t.Errorf("payload[authorized] = %v, want false", got["authorized"])
	}
	if !strings.Contains(got["error"].(string), "authorization required") {
		t.Errorf("error message should mention authorization: %v", got["error"])
	}
	if !strings.Contains(got["how_to_enable"].(string), "ETHICS") {
		t.Errorf("how_to_enable should point at ETHICS.md: %v", got["how_to_enable"])
	}
}

func TestTLSCheckEmptyHostAfterAuth(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/tls", map[string]any{
		"host":                 "",
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// ─── /api/check/takeover (active — auth gate) ─────────────────────────────

func TestTakeoverCheckRefusesWithoutAuth(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/takeover", map[string]any{
		"domain":               "foo.example.com",
		"i_have_authorization": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestTakeoverCheckHappyPath(t *testing.T) {
	// Use takeover package's seam to stub the resolver — see internal test
	// helper. We can't reach the unexported var, so we just verify the
	// happy path produces 200 with the gate set. The domain not having a
	// CNAME is fine — Result is returned with HasCNAME=false.
	resp, _ := appRequest(t, http.MethodPost, "/api/check/takeover", map[string]any{
		"domain":               "example.com",
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	_ = takeover.Providers() // silence unused-import if not used elsewhere
}

// ─── /api/check/ports (active — auth gate) ────────────────────────────────

func TestPortsCheckRefusesWithoutAuth(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/ports", map[string]any{
		"host":                 "127.0.0.1",
		"i_have_authorization": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestPortsCheckBadPortList(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/ports", map[string]any{
		"host":                 "127.0.0.1",
		"ports":                "abc",
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on bad port list", resp.StatusCode)
	}
}

func TestPortsCheckHappyPath(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/ports", map[string]any{
		"host":                 "127.0.0.1",
		"ports":                "1,2",
		"per_port_timeout_ms":  100,
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ─── /api/check/enum (active — auth gate) ─────────────────────────────────

func TestEnumCheckRefusesWithoutAuth(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/enum", map[string]any{
		"url":                  "https://example.com",
		"i_have_authorization": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestEnumCheckEmptyURLAfterAuth(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/enum", map[string]any{
		"url":                  "",
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestEnumCheckHappyPathWithCustomWordlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	resp, _ := appRequest(t, http.MethodPost, "/api/check/enum", map[string]any{
		"url":                  srv.URL,
		"wordlist":             []string{"robots.txt", "admin"},
		"per_path_timeout_ms":  500,
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ─── sniffTarget v1.4 kinds ───────────────────────────────────────────────

func TestSniffTargetV14Kinds(t *testing.T) {
	cases := []struct {
		kind, body, want string
	}{
		{"headers", `{"url":"https://example.com/foo"}`, "https://example.com/foo"},
		{"tech", `{"url":"https://x.com"}`, "https://x.com"},
		{"subs", `{"domain":"example.com"}`, "example.com"},
		{"reverse", `{"ip":"1.2.3.4"}`, "1.2.3.4"},
		{"arch", `{"domain":"example.com"}`, "example.com"},
		{"takeover", `{"domain":"foo.example.com"}`, "foo.example.com"},
		{"tls-audit", `{"host":"example.com","port":"443"}`, "example.com"},
		{"tls-audit", `{"host":"example.com","port":"8443"}`, "example.com:8443"},
		{"ports", `{"host":"127.0.0.1","port":""}`, "127.0.0.1"},
		{"enum", `{"base_url":"https://example.com"}`, "https://example.com"},
		{"audit", `{"target":"example.com"}`, "example.com"},
	}
	for _, c := range cases {
		t.Run(c.kind+":"+c.body, func(t *testing.T) {
			got := sniffTarget(json.RawMessage(c.body), c.kind)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
