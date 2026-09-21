package cmd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
)

// Token authentication for `netcheck app` (RISK-003, decision 4).
//
// The API has no users, so "authentication" here means one random token per
// server. It is required whenever the server can be reached from somewhere
// other than this machine: a non-loopback bind (the container image binds
// 0.0.0.0) or any --allowed-host name, which implies a reverse proxy or
// tunnel in front. Plain `netcheck app` on a laptop stays open, so local
// scripts keep working; --auth turns the token on anyway.
//
// A browser authenticates once by opening the URL printed at start-up
// (/?token=...): the server answers with an HttpOnly, SameSite=Strict cookie
// that lasts 30 days, and redirects to the same page without the token. Scripts send
// `Authorization: Bearer <token>`. NETCHECK_APP_TOKEN fixes the token across
// restarts (docker-compose, homelab).
//
// Only /api/ is protected. The static workbench is the same bundle as in the
// public repository and holds no data; keeping it public lets the browser
// load it and fetch the PWA manifest, which is requested without cookies.
// /api/healthz stays open for container and uptime health checks.

const (
	authFlagName     = "auth"
	appTokenEnvVar   = "NETCHECK_APP_TOKEN"
	tokenCookieName  = "netcheck_token"
	tokenQueryParam  = "token"
	minAppTokenBytes = 16
	// tokenCookieMaxAge keeps a browser signed in across restarts. Behind an
	// identity-aware proxy (Cloudflare Access) the token is the second lock,
	// and re-entering it after every browser restart would only add friction.
	// Restarting netcheck without NETCHECK_APP_TOKEN rotates the token and
	// invalidates every cookie.
	tokenCookieMaxAge = 30 * 24 * 60 * 60
)

// authRequired decides whether the token is enforced for this server.
func authRequired(listen string, allowedHosts []string, forced bool) bool {
	return forced || len(allowedHosts) > 0 || !loopbackListen(listen)
}

// loopbackListen reports whether a --listen address only accepts connections
// from this machine. An empty host (":8787") means every interface.
func loopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	host = normalizeHost(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// appToken returns NETCHECK_APP_TOKEN if set, otherwise a fresh random token.
func appToken() (string, error) {
	if v := strings.TrimSpace(os.Getenv(appTokenEnvVar)); v != "" {
		if len(v) < minAppTokenBytes {
			return "", errShortAppToken
		}
		return v, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type appTokenError string

func (e appTokenError) Error() string { return string(e) }

const errShortAppToken = appTokenError(appTokenEnvVar + " must be at least 16 characters")

func requireToken(next http.Handler, token string) http.Handler {
	want := []byte(token)
	matches := func(got string) bool {
		return got != "" && subtle.ConstantTimeCompare([]byte(got), want) == 1
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sign-in: the start-up URL. Set the cookie and drop the token from
		// the address bar and history.
		if q := r.URL.Query(); q.Has(tokenQueryParam) && !strings.HasPrefix(r.URL.Path, "/api/") {
			if !matches(q.Get(tokenQueryParam)) {
				http.Error(w, "invalid token: open the URL netcheck app printed at start-up", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     tokenCookieName,
				Value:    token,
				Path:     "/",
				MaxAge:   tokenCookieMaxAge,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   requestIsHTTPS(r),
			})
			q.Del(tokenQueryParam)
			u := *r.URL
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.RequestURI(), http.StatusSeeOther)
			return
		}

		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(tokenCookieName); err == nil && matches(c.Value) {
			next.ServeHTTP(w, r)
			return
		}
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && matches(strings.TrimSpace(bearer)) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="netcheck"`)
		writeJSON(w, http.StatusUnauthorized, apiError{
			Error: "authentication required: open the URL netcheck app printed at start-up, or send Authorization: Bearer <token>",
		})
	})
}

// requestIsHTTPS is true for TLS served directly or by a proxy in front
// (Caddy, Traefik, nginx and cloudflared all set X-Forwarded-Proto).
func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// signInURL is the address to open, printed at start-up. A wildcard bind is
// shown as localhost; behind a proxy, use the public name with the same path.
func signInURL(listen, token string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = listen, ""
	}
	if ip := net.ParseIP(normalizeHost(host)); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "localhost"
	}
	addr := host
	if port != "" {
		addr = net.JoinHostPort(host, port)
	}
	return "http://" + addr + "/?" + tokenQueryParam + "=" + token
}
