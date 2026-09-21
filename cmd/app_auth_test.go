package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthRequired(t *testing.T) {
	for _, tt := range []struct {
		listen  string
		allowed []string
		forced  bool
		want    bool
	}{
		{"127.0.0.1:8787", nil, false, false}, // laptop default: open
		{"localhost:8787", nil, false, false},
		{"[::1]:8787", nil, false, false},
		{"127.0.0.1:8787", nil, true, true},                               // --auth
		{"127.0.0.1:8787", []string{"netcheck.example.com"}, false, true}, // reverse proxy / tunnel
		{"0.0.0.0:8787", nil, false, true},                                // container image
		{":8787", nil, false, true},                                       // every interface
		{"[::]:8787", nil, false, true},
		{"192.168.1.10:8787", nil, false, true},
		{"myhost:8787", nil, false, true}, // a name we cannot prove is loopback
	} {
		if got := authRequired(tt.listen, tt.allowed, tt.forced); got != tt.want {
			t.Errorf("authRequired(%q, %v, %v) = %v, want %v", tt.listen, tt.allowed, tt.forced, got, tt.want)
		}
	}
}

func TestRequireToken(t *testing.T) {
	const tok = "correct-horse-battery-staple-01"
	tests := []struct {
		name       string
		path       string
		cookie     string
		authz      string
		wantStatus int
	}{
		{name: "API without credentials", path: "/api/reports", wantStatus: 401},
		{name: "API with valid cookie", path: "/api/reports", cookie: tok, wantStatus: 200},
		{name: "API with valid bearer", path: "/api/check/dns", authz: "Bearer " + tok, wantStatus: 200},
		{name: "API with wrong cookie", path: "/api/reports", cookie: "wrong-token-wrong-token", wantStatus: 401},
		{name: "API with wrong bearer", path: "/api/reports", authz: "Bearer nope", wantStatus: 401},
		{name: "API with basic auth scheme", path: "/api/reports", authz: "Basic " + tok, wantStatus: 401},
		{name: "API ignores a token query parameter", path: "/api/reports?token=" + tok, wantStatus: 401},
		{name: "health check stays open", path: "/api/healthz", wantStatus: 200},
		{name: "static workbench stays open", path: "/", wantStatus: 200},
		{name: "static asset stays open", path: "/assets/index.js", wantStatus: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: tokenCookieName, Value: tt.cookie})
			}
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}
			rec := httptest.NewRecorder()
			requireToken(next, tok).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if reached != (tt.wantStatus == 200) {
				t.Fatalf("handler reached = %v", reached)
			}
			if tt.wantStatus == 401 && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate")
			}
		})
	}
}

func TestSignInSetsCookieAndDropsTokenFromURL(t *testing.T) {
	const tok = "correct-horse-battery-staple-01"
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for _, tt := range []struct {
		name         string
		target       string
		forwardProto string
		wantLocation string
		wantSecure   bool
	}{
		{name: "plain http on a laptop or LAN", target: "/?token=" + tok, wantLocation: "/"},
		{name: "keeps other query parameters", target: "/?mode=dns&token=" + tok, wantLocation: "/?mode=dns"},
		{name: "behind a TLS proxy or Cloudflare Tunnel", target: "/?token=" + tok, forwardProto: "https", wantLocation: "/", wantSecure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.target, nil)
			if tt.forwardProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardProto)
			}
			rec := httptest.NewRecorder()
			requireToken(next, tok).ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("got %d cookies, want 1", len(cookies))
			}
			c := cookies[0]
			if c.Name != tokenCookieName || c.Value != tok || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Errorf("cookie = %+v, want HttpOnly SameSite=Strict Path=/ with the token", c)
			}
			if c.Secure != tt.wantSecure {
				t.Errorf("cookie Secure = %v, want %v", c.Secure, tt.wantSecure)
			}
		})
	}

	req := httptest.NewRequest("GET", "/?token=wrong-token-wrong-token", nil)
	rec := httptest.NewRecorder()
	requireToken(next, tok).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Errorf("wrong sign-in token: status %d, cookies %d; want 401 and no cookie", rec.Code, len(rec.Result().Cookies()))
	}
}

func TestAppToken(t *testing.T) {
	t.Setenv(appTokenEnvVar, "")
	a, err := appToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := appToken()
	if len(a) < 40 || a == b {
		t.Errorf("random tokens: %q, %q; want two different tokens of 256 bits", a, b)
	}

	t.Setenv(appTokenEnvVar, "  pinned-token-for-compose  ")
	if got, err := appToken(); err != nil || got != "pinned-token-for-compose" {
		t.Errorf("env token = %q, %v; want the trimmed value", got, err)
	}

	t.Setenv(appTokenEnvVar, "short")
	if _, err := appToken(); err == nil {
		t.Error("a token under 16 characters should be rejected")
	}
}

func TestSignInURL(t *testing.T) {
	for _, tt := range []struct{ listen, want string }{
		{"127.0.0.1:8787", "http://127.0.0.1:8787/?token=T"},
		{"0.0.0.0:8787", "http://localhost:8787/?token=T"},
		{":8787", "http://localhost:8787/?token=T"},
		{"[::]:8787", "http://localhost:8787/?token=T"},
		{"[::1]:9000", "http://[::1]:9000/?token=T"},
	} {
		if got := signInURL(tt.listen, "T"); got != tt.want {
			t.Errorf("signInURL(%q) = %q, want %q", tt.listen, got, tt.want)
		}
	}
}

// The full chain as RunApp builds it: host and cross-origin checks, then the
// token, then the real handler.
func TestTokenWithAppHandler(t *testing.T) {
	const tok = "correct-horse-battery-staple-01"
	h := protectLocalAPI(requireToken(newTestAppHandler(), tok), []string{"netcheck.example.com"})

	do := func(req *http.Request) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	proxied := func(path string) *http.Request {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "netcheck.example.com" // as forwarded by Caddy, Traefik, nginx or cloudflared
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-Forwarded-Proto", "https")
		return req
	}

	if code := do(proxied("/api/reports")); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated API through the proxy: %d, want 401", code)
	}
	withCookie := proxied("/api/reports")
	withCookie.AddCookie(&http.Cookie{Name: tokenCookieName, Value: tok})
	if code := do(withCookie); code != http.StatusOK {
		t.Errorf("API with cookie through the proxy: %d, want 200", code)
	}
	if code := do(proxied("/api/healthz")); code != http.StatusOK {
		t.Errorf("health check through the proxy: %d, want 200", code)
	}
	if code := do(proxied("/")); code != http.StatusOK {
		t.Errorf("workbench shell through the proxy: %d, want 200", code)
	}
}
