package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtectLocalAPI(t *testing.T) {
	const jsonBody = `{"host":"example.com"}`
	tests := []struct {
		name         string
		method       string
		path         string
		host         string
		contentType  string
		headers      map[string]string
		allowedHosts []string
		wantStatus   int
	}{
		// Legitimate callers.
		{name: "workbench same-origin POST", method: "POST", path: "/api/check/dns", host: "127.0.0.1:8787", contentType: "application/json", headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8787"}, wantStatus: 200},
		{name: "curl POST without browser headers", method: "POST", path: "/api/check/dns", host: "127.0.0.1:8787", contentType: "application/json", wantStatus: 200},
		{name: "JSON with charset parameter", method: "POST", path: "/api/check/dns", host: "127.0.0.1:8787", contentType: "application/json; charset=utf-8", wantStatus: 200},
		{name: "vite dev proxy host", method: "POST", path: "/api/check/dns", host: "localhost:5173", contentType: "application/json", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, wantStatus: 200},
		{name: "IPv6 loopback host", method: "GET", path: "/api/healthz", host: "[::1]:8787", wantStatus: 200},
		{name: "LAN IP host (container published on the LAN)", method: "GET", path: "/api/healthz", host: "192.168.1.10:8787", wantStatus: 200},
		{name: "*.localhost host", method: "GET", path: "/api/healthz", host: "netcheck.localhost:8787", wantStatus: 200},
		{name: "allowlisted reverse-proxy name", method: "GET", path: "/api/healthz", host: "Netcheck.Home.Lan.", allowedHosts: []string{"netcheck.home.lan"}, wantStatus: 200},
		{name: "same-origin DELETE needs no body", method: "DELETE", path: "/api/reports/abc", host: "127.0.0.1:8787", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, wantStatus: 200},
		{name: "static UI is not an API route", method: "GET", path: "/", host: "127.0.0.1:8787", wantStatus: 200},

		// Cross-site requests from another page in the user's browser.
		{name: "cross-site POST (Sec-Fetch-Site)", method: "POST", path: "/api/check/ports", host: "127.0.0.1:8787", contentType: "application/json", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, wantStatus: 403},
		{name: "cross-site POST as text/plain simple request", method: "POST", path: "/api/check/ports", host: "127.0.0.1:8787", contentType: "text/plain", headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, wantStatus: 403},
		{name: "foreign Origin without Sec-Fetch-Site", method: "POST", path: "/api/check/ports", host: "127.0.0.1:8787", contentType: "application/json", headers: map[string]string{"Origin": "https://evil.example"}, wantStatus: 403},
		{name: "cross-site DELETE of a saved report", method: "DELETE", path: "/api/reports/abc", host: "127.0.0.1:8787", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, wantStatus: 403},

		// DNS rebinding: attacker's name resolved to loopback.
		{name: "rebinding GET of saved reports", method: "GET", path: "/api/reports", host: "evil.example:8787", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, wantStatus: 403},
		{name: "rebinding GET of the event stream", method: "GET", path: "/api/events/stream", host: "evil.example:8787", wantStatus: 403},
		{name: "name not on the allowlist", method: "GET", path: "/api/healthz", host: "other.home.lan", allowedHosts: []string{"netcheck.home.lan"}, wantStatus: 403},

		// Non-JSON bodies on JSON endpoints.
		{name: "same-origin text/plain POST", method: "POST", path: "/api/check/dns", host: "127.0.0.1:8787", contentType: "text/plain", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, wantStatus: 415},
		{name: "form POST without browser headers", method: "POST", path: "/api/reports", host: "127.0.0.1:8787", contentType: "application/x-www-form-urlencoded", wantStatus: 415},
		{name: "POST with no Content-Type", method: "POST", path: "/api/diff", host: "127.0.0.1:8787", wantStatus: 415},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			var body *strings.Reader
			if tt.method == "POST" {
				body = strings.NewReader(jsonBody)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Host = tt.host
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			protectLocalAPI(next, tt.allowedHosts).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if wantReach := tt.wantStatus == 200; reached != wantReach {
				t.Fatalf("handler reached = %v, want %v", reached, wantReach)
			}
			if tt.wantStatus != 200 && !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
				t.Errorf("refusal Content-Type = %q, want JSON like every other API error", rec.Header().Get("Content-Type"))
			}
		})
	}
}

// The wrapper in front of the real handler: a cross-site page cannot start an
// authorized port scan, and the workbench's own requests still work.
func TestProtectLocalAPIWithAppHandler(t *testing.T) {
	h := protectLocalAPI(newTestAppHandler(), nil)

	attack := httptest.NewRequest("POST", "/api/check/ports",
		strings.NewReader(`{"host":"victim.example","i_have_authorization":true}`))
	attack.Host = "127.0.0.1:8787"
	attack.Header.Set("Content-Type", "text/plain")
	attack.Header.Set("Origin", "https://evil.example")
	attack.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, attack)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site scan: status = %d, want 403", rec.Code)
	}

	own := httptest.NewRequest("GET", "/api/healthz", nil)
	own.Host = "127.0.0.1:8787"
	own.Header.Set("Sec-Fetch-Site", "same-origin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, own)
	if rec.Code != http.StatusOK {
		t.Fatalf("workbench health check: status = %d, want 200", rec.Code)
	}
}

func TestAPIConcurrencyIsClamped(t *testing.T) {
	opts, err := portsOptionsFromRequest(portsCheckRequest{Host: "example.com", Concurrency: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Concurrency != maxAPIPortsConcurrency {
		t.Errorf("ports concurrency = %d, want clamp to %d", opts.Concurrency, maxAPIPortsConcurrency)
	}

	for _, tt := range []struct{ in, max, want int }{
		{0, 20, 0},   // unset: the package applies its default
		{-5, 20, -5}, // invalid: the package applies its default
		{15, 20, 15},
		{20, 20, 20},
		{500, 20, 20},
	} {
		if got := clampConcurrency(tt.in, tt.max); got != tt.want {
			t.Errorf("clampConcurrency(%d, %d) = %d, want %d", tt.in, tt.max, got, tt.want)
		}
	}
}
