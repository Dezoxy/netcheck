package cmd

import (
	"mime"
	"net"
	"net/http"
	"strings"
)

// Request filtering for `netcheck app`.
//
// The server has no authentication; its boundary is that it listens on the
// user's own machine. Two browser attacks cross that boundary anyway:
//
//   - Cross-site requests. Any page open in the user's browser can POST to
//     127.0.0.1:8787. With a text/plain body the request is a CORS "simple
//     request" that needs no preflight, so the page can start checks,
//     including active scans with i_have_authorization set.
//   - DNS rebinding. A page on attacker.example re-resolves that name to
//     127.0.0.1, which makes this server same-origin to it, so the page can
//     read API responses and saved reports.
//
// protectLocalAPI closes both: cross-origin non-safe requests are refused
// (http.CrossOriginProtection, Go 1.25), the Host header must name this
// machine rather than an arbitrary domain, and JSON endpoints only accept
// application/json bodies. Clients that send no browser headers at all
// (curl, scripts) are unaffected. See RISK-001 in docs/architecture.

// allowedHostFlagName is the `netcheck app` flag that adds a hostname to the
// Host allowlist, for a reverse proxy or a LAN name.
const allowedHostFlagName = "allowed-host"

func protectLocalAPI(next http.Handler, allowedHosts []string) http.Handler {
	allowed := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		if h = normalizeHost(h); h != "" {
			allowed[h] = true
		}
	}

	checked := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, ok := hostAllowed(r.Host, allowed); !ok {
			writeJSON(w, http.StatusForbidden, apiError{
				Error: "host " + host + " is not allowed; to serve this name, start netcheck app with --" + allowedHostFlagName + " " + host,
			})
			return
		}
		if requiresJSONBody(r) && !isJSONContentType(r.Header.Get("Content-Type")) {
			writeJSON(w, http.StatusUnsupportedMediaType, apiError{Error: "Content-Type must be application/json"})
			return
		}
		next.ServeHTTP(w, r)
	})

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "cross-origin request refused"})
	}))
	return cop.Handler(checked)
}

// hostAllowed reports whether a request's Host header may reach the API, and
// returns the normalised host name for the error message. DNS rebinding needs
// a DNS name the attacker controls, so IP literals are always safe, as are
// localhost and *.localhost, which resolve to loopback by definition
// (RFC 6761). Anything else must be allowlisted explicitly.
func hostAllowed(hostHeader string, allowed map[string]bool) (string, bool) {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = normalizeHost(host)
	switch {
	case host == "":
		// No Host header: not a browser (every browser sends one).
		return host, true
	case net.ParseIP(host) != nil:
		return host, true
	case host == "localhost" || strings.HasSuffix(host, ".localhost"):
		return host, true
	default:
		return host, allowed[host]
	}
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	return strings.TrimSuffix(h, ".")
}

// requiresJSONBody is true for the API's state-changing methods. GET, HEAD and
// DELETE carry no body here; the static UI is outside /api/.
func requiresJSONBody(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

func isJSONContentType(v string) bool {
	mt, _, err := mime.ParseMediaType(v)
	return err == nil && mt == "application/json"
}

// API callers may raise scan parallelism above the CLI defaults, but only this
// far: twice the default. It bounds what any single request can make this
// machine send, whoever sends it.
const (
	maxAPIPortsConcurrency = 100 // CLI and portscan default: 50
	maxAPIEnumConcurrency  = 20  // CLI and pathenum default: 10
)

// clampConcurrency caps a requested value. Zero or negative passes through so
// the scanning package applies its own default.
func clampConcurrency(n, max int) int {
	if n > max {
		return max
	}
	return n
}
