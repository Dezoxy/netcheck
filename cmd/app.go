package cmd

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Dezoxy/netcheck/internal/webui"
	"github.com/Dezoxy/netcheck/pkg/diff"
	"github.com/Dezoxy/netcheck/pkg/dnscompare"
	"github.com/Dezoxy/netcheck/pkg/pathenum"
	"github.com/Dezoxy/netcheck/pkg/portscan"
	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/route"
	"github.com/Dezoxy/netcheck/pkg/target"
)

type fullCheckRequest struct {
	Target   string `json:"target"`
	Insecure bool   `json:"insecure"`
}

type dnsCheckRequest struct {
	Host              string   `json:"host"`
	Types             []string `json:"types,omitempty"`     // default A,AAAA
	Resolvers         []string `json:"resolvers,omitempty"` // extra URL-style resolvers
	NoSystem          bool     `json:"no_system,omitempty"`
	NoDefaults        bool     `json:"no_defaults,omitempty"`
	NoConfigResolvers bool     `json:"no_config_resolvers,omitempty"`
}

type routeCheckRequest struct {
	Host      string `json:"host"`
	MaxHops   int    `json:"max_hops,omitempty"` // default 30
	Probes    int    `json:"probes,omitempty"`   // default 3
	WaitSec   int    `json:"wait_sec,omitempty"` // default 2
	NoResolve bool   `json:"no_resolve,omitempty"`
	NoASN     bool   `json:"no_asn,omitempty"`
}

type ipCheckRequest struct {
	Target string `json:"target"`
}

// ─── v1.4 passive recon — request types ───────────────────────────────────

type headersCheckRequest struct {
	URL      string `json:"url"`
	Insecure bool   `json:"insecure,omitempty"`
}

type techCheckRequest struct {
	URL      string `json:"url"`
	Insecure bool   `json:"insecure,omitempty"`
}

type subsCheckRequest struct {
	Domain string `json:"domain"`
}

type reverseCheckRequest struct {
	IP string `json:"ip"`
}

type archCheckRequest struct {
	Domain string `json:"domain"`
}

// ─── v1.4 active scanning — request types ─────────────────────────────────
//
// Active checks require the client to set `"i_have_authorization": true` in
// the request body. Same semantics as `--i-have-authorization` on the CLI:
// a deliberation boundary, not a security one. The frontend should surface
// this as an explicit checkbox + confirm dialog.

type tlsCheckRequest struct {
	Host        string `json:"host"`
	IAuthorized bool   `json:"i_have_authorization"`
}

type takeoverCheckRequest struct {
	Domain      string `json:"domain"`
	IAuthorized bool   `json:"i_have_authorization"`
}

type portsCheckRequest struct {
	Host        string `json:"host"`
	Ports       string `json:"ports,omitempty"` // explicit TCP list, e.g. "22,80,443,8000-8010"
	Top         int    `json:"top,omitempty"`   // default 100
	Concurrency int    `json:"concurrency,omitempty"`
	PerPortMS   int    `json:"per_port_timeout_ms,omitempty"`
	// Protocols selects which protocols to scan. nil/empty → ["tcp"] for
	// back-compat. Valid values: "tcp", "udp". Web UI sends one of:
	//   ["tcp"]          — default
	//   ["udp"]          — UDP only
	//   ["tcp", "udp"]   — both
	Protocols []string `json:"protocols,omitempty"`
	// UDPPorts is the explicit UDP port list. Optional — engine defaults
	// to a curated top-50 UDP list when "udp" is in Protocols.
	UDPPorts    string `json:"udp_ports,omitempty"`
	IAuthorized bool   `json:"i_have_authorization"`
}

type enumCheckRequest struct {
	URL             string   `json:"url"`
	Wordlist        []string `json:"wordlist,omitempty"` // explicit list; if empty, builtin is used
	Concurrency     int      `json:"concurrency,omitempty"`
	PerPathMS       int      `json:"per_path_timeout_ms,omitempty"`
	Insecure        bool     `json:"insecure,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
	IAuthorized     bool     `json:"i_have_authorization"`
}

// auditCheckRequest is the body for POST /api/check/audit. Active controls
// whether the active-scanning sub-checks (tls, takeover, ports, enum) run;
// when true, IAuthorized must also be true or the request is refused with
// the same 403 shape as the standalone active endpoints.
type auditCheckRequest struct {
	Target      string `json:"target"`
	Active      bool   `json:"active,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
	IAuthorized bool   `json:"i_have_authorization,omitempty"`
}

type apiError struct {
	Error string `json:"error"`
}

// RunApp starts the local Netcheck web application.
func RunApp(args []string) int {
	fs := flag.NewFlagSet("netcheck app", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8787", "HTTP listen address")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck app [flags]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           newAppHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "netcheck app listening on http://%s\n", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func newAppHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", handleAppHealth)
	mux.HandleFunc("/api/check/full", handleFullCheck)
	mux.HandleFunc("/api/check/dns", handleDNSCheck)
	mux.HandleFunc("/api/check/route", handleRouteCheck)
	mux.HandleFunc("/api/check/ip", handleIPCheck)
	// v1.4 passive recon
	mux.HandleFunc("/api/check/headers", handleHeadersCheck)
	mux.HandleFunc("/api/check/tech", handleTechCheck)
	mux.HandleFunc("/api/check/subs", handleSubsCheck)
	mux.HandleFunc("/api/check/reverse", handleReverseCheck)
	mux.HandleFunc("/api/check/arch", handleArchCheck)
	// v1.4 active scanning — auth gate enforced inside the handler
	mux.HandleFunc("/api/check/tls", handleTLSAuditCheck)
	mux.HandleFunc("/api/check/takeover", handleTakeoverCheck)
	mux.HandleFunc("/api/check/ports", handlePortsCheck)
	mux.HandleFunc("/api/check/ports/stream", handlePortsStream)
	mux.HandleFunc("/api/check/enum", handleEnumCheck)
	// v1.6 aggregate command
	mux.HandleFunc("/api/check/audit", handleAuditCheck)
	mux.HandleFunc("/api/reports", handleReportsCollection)
	mux.HandleFunc("/api/reports/", handleReportItem)
	mux.HandleFunc("/api/diff", handleDiff)
	mux.Handle("/", http.FileServer(http.FS(webui.Dist())))
	return mux
}

func handleAppHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Check endpoints ──────────────────────────────────────────────────────

func handleFullCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req fullCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := target.Parse(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	run := BuildFullReport(r.Context(), t, checkTimeout(), req.Insecure)
	writeJSON(w, http.StatusOK, report.ToFullJSON(run))
}

func handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req dnsCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	host, err := target.NormalizeHost(req.Host)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	types := req.Types
	if len(types) == 0 {
		types = []string{"A", "AAAA"}
	}
	parsedTypes, err := dnscompare.ParseTypes(strings.Join(types, ","))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	var resolvers []dnscompare.Resolver
	if !req.NoSystem {
		resolvers = append(resolvers, dnscompare.SystemResolvers()...)
	}
	if !req.NoDefaults {
		resolvers = append(resolvers, dnscompare.DefaultResolvers...)
	}
	if !req.NoConfigResolvers {
		for _, cr := range loadedConfig.Resolvers {
			if parsed, perr := configResolverToDNS(cr); perr == nil {
				resolvers = append(resolvers, parsed)
			}
		}
	}
	for _, extra := range req.Resolvers {
		parsed, perr := dnscompare.ParseResolver(extra)
		if perr != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: perr.Error()})
			return
		}
		resolvers = append(resolvers, parsed)
	}
	if len(resolvers) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no resolvers configured"})
		return
	}

	out := BuildDNSCompare(r.Context(), host, resolvers, parsedTypes, 5*time.Second)
	writeJSON(w, http.StatusOK, out)
}

func handleRouteCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req routeCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	host, err := target.NormalizeHost(req.Host)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	opts := route.Options{
		MaxHops:   defaultInt(req.MaxHops, 30),
		Probes:    defaultInt(req.Probes, 3),
		WaitSec:   defaultInt(req.WaitSec, 2),
		NoResolve: req.NoResolve,
	}
	out, err := BuildRoute(r.Context(), host, opts, 60*time.Second, req.NoASN)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func handleIPCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req ipCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	out, err := BuildIPInfo(r.Context(), req.Target, checkTimeout())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ─── v1.4 passive recon — handlers ────────────────────────────────────────

func handleHeadersCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req headersCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "url required"})
		return
	}
	out := BuildHeaders(r.Context(), req.URL, checkTimeout(), req.Insecure)
	writeJSON(w, http.StatusOK, out)
}

func handleTechCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req techCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "url required"})
		return
	}
	out := BuildTech(r.Context(), req.URL, checkTimeout(), req.Insecure)
	writeJSON(w, http.StatusOK, out)
}

func handleSubsCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req subsCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "domain required"})
		return
	}
	out := BuildSubs(r.Context(), req.Domain, subsDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

func handleReverseCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req reverseCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.IP) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "ip required"})
		return
	}
	out := BuildReverse(r.Context(), req.IP, reverseDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

func handleArchCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req archCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "domain required"})
		return
	}
	out := BuildArch(r.Context(), req.Domain, archDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

// ─── v1.4 active scanning — handlers ──────────────────────────────────────
//
// Each handler refuses to do anything until the request body sets
// `"i_have_authorization": true`. Refusal is HTTP 403 with a clear payload —
// the frontend uses this to drive the auth-gate UI.

// requireAuthHeader returns false (and writes the refusal response) when the
// request didn't include the i_have_authorization flag. Centralised so all
// four active handlers behave identically.
func requireAuthInBody(w http.ResponseWriter, cmdName string, authorized bool) bool {
	if authorized {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":         "authorization required for active scan",
		"command":       cmdName,
		"authorized":    false,
		"how_to_enable": "set \"i_have_authorization\": true in the JSON body. See docs/ETHICS.md.",
	})
	return false
}

func handleTLSAuditCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req tlsCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireAuthInBody(w, "tls", req.IAuthorized) {
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "host required"})
		return
	}
	out := BuildTLSAudit(r.Context(), req.Host, tlsDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

func handleTakeoverCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req takeoverCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireAuthInBody(w, "takeover", req.IAuthorized) {
		return
	}
	if strings.TrimSpace(req.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "domain required"})
		return
	}
	out := BuildTakeover(r.Context(), req.Domain, takeoverDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

func handlePortsCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req portsCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireAuthInBody(w, "ports", req.IAuthorized) {
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "host required"})
		return
	}
	opts, err := portsOptionsFromRequest(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	out := BuildPorts(r.Context(), req.Host, opts, portsDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

// portsOptionsFromRequest builds a portscan.Options from an HTTP request
// body. Centralised so both the POST and SSE endpoints validate input
// identically — including the protocol selector added in R-13.
func portsOptionsFromRequest(req portsCheckRequest) (portscan.Options, error) {
	opts := portscan.Options{
		Top:         req.Top,
		Concurrency: req.Concurrency,
	}
	if req.PerPortMS > 0 {
		opts.PerPortTimeout = time.Duration(req.PerPortMS) * time.Millisecond
	}
	if req.Ports != "" {
		ports, err := portscan.ParsePortList(req.Ports)
		if err != nil {
			return portscan.Options{}, err
		}
		opts.Ports = ports
	}
	if req.UDPPorts != "" {
		ports, err := portscan.ParsePortList(req.UDPPorts)
		if err != nil {
			return portscan.Options{}, err
		}
		opts.UDPPorts = ports
	}
	// Validate and normalise Protocols. nil/empty stays nil (engine
	// defaults to ["tcp"]); otherwise we accept "tcp" and "udp" only.
	if len(req.Protocols) > 0 {
		seen := map[string]bool{}
		for _, p := range req.Protocols {
			switch p {
			case "tcp", "udp":
			default:
				return portscan.Options{}, fmt.Errorf("invalid protocol %q (want tcp or udp)", p)
			}
			if !seen[p] {
				seen[p] = true
				opts.Protocols = append(opts.Protocols, p)
			}
		}
	}
	return opts, nil
}

// handlePortsStream is the SSE-flavoured variant of handlePortsCheck. Returns
// a `text/event-stream` body with three event types:
//
//	event: progress  → { port, state, service, index, total }
//	event: done      → the full PortScanJSON, same shape as the POST endpoint
//	event: error     → { error: "..." }
//
// Why a separate endpoint rather than `?stream=1` on the existing one: the
// response Content-Type and write pattern are completely different, and
// mixing them in one handler reads worse than a small bit of duplication.
//
// Auth and request shape match the POST endpoint exactly — the body is JSON-
// encoded `portsCheckRequest` with `i_have_authorization: true`. The client
// uses fetch + ReadableStream to consume the body; older EventSource (which
// only supports GET) would force us to put the auth token in the URL.
func handlePortsStream(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req portsCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireAuthInBody(w, "ports", req.IAuthorized) {
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "host required"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Should never happen on net/http — but reverse proxies or wrapped
		// writers (e.g. compression middleware) could in theory strip the
		// Flusher. Fall back to a single end-of-scan response, which is the
		// behaviour the POST endpoint already provides.
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "streaming not supported"})
		return
	}

	opts, err := portsOptionsFromRequest(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	// SSE headers. text/event-stream + Cache-Control: no-store is the
	// HTML5 spec recipe; X-Accel-Buffering disables nginx output buffering
	// in case someone fronts the app with one.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Funnel concurrent OnProgress callbacks into a buffered channel; a
	// single emitter goroutine writes SSE frames to the HTTP response. The
	// scan goroutines never touch the response writer directly — which
	// matters because http.ResponseWriter is NOT safe for concurrent use.
	progress := make(chan portscan.Progress, 256)
	opts.OnProgress = func(p portscan.Progress) {
		// Non-blocking send: if the consumer is slow, drop progress events
		// rather than stalling the scan. The final 'done' event still
		// carries the full result.
		select {
		case progress <- p:
		default:
		}
	}

	// Emitter goroutine — owns the writer. Closes the channel on scan
	// completion (signaled by scanDone).
	scanDone := make(chan struct{})
	emitterDone := make(chan struct{})
	go func() {
		defer close(emitterDone)
		enc := json.NewEncoder(w)
		// One frame per call. enc encodes to writer directly (its Encode
		// emits a trailing \n), and we wrap with the SSE framing:
		// `event: X\ndata: <json>\n\n`. The extra blank line is the SSE
		// frame terminator.
		emit := func(event string, payload any) {
			fmt.Fprintf(w, "event: %s\ndata: ", event)
			_ = enc.Encode(payload)
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
		for {
			select {
			case p, ok := <-progress:
				if !ok {
					return
				}
				emit("progress", map[string]any{
					"port":    p.Port,
					"proto":   p.Proto,
					"state":   p.State,
					"service": p.Service,
					"index":   p.Index,
					"total":   p.TotalPorts,
				})
			case <-scanDone:
				// Drain any remaining buffered events before exiting so the
				// client gets the full picture.
				for {
					select {
					case p := <-progress:
						emit("progress", map[string]any{
							"port":    p.Port,
							"state":   p.State,
							"service": p.Service,
							"index":   p.Index,
							"total":   p.TotalPorts,
						})
					default:
						return
					}
				}
			}
		}
	}()

	out := BuildPorts(r.Context(), req.Host, opts, portsDefaultTimeout(loadedConfig.Timeout))
	close(scanDone)
	<-emitterDone

	// Final frame: full report. Client uses this to populate the saved-
	// reports UI / diff / export — exactly the same shape as the POST.
	fmt.Fprint(w, "event: done\ndata: ")
	_ = json.NewEncoder(w).Encode(out)
	fmt.Fprint(w, "\n")
	flusher.Flush()
}

func handleEnumCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req enumCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireAuthInBody(w, "enum", req.IAuthorized) {
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "url required"})
		return
	}
	opts := pathenum.Options{
		Wordlist:        req.Wordlist,
		Concurrency:     req.Concurrency,
		Insecure:        req.Insecure,
		FollowRedirects: req.FollowRedirects,
	}
	if req.PerPathMS > 0 {
		opts.PerPathTimeout = time.Duration(req.PerPathMS) * time.Millisecond
	}
	out := BuildPathEnum(r.Context(), req.URL, opts, enumDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

// ─── v1.6 audit aggregate ─────────────────────────────────────────────────

func handleAuditCheck(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req auditCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "target required"})
		return
	}
	// Auth gate only required when `active` is requested. The passive
	// variant of audit composes only over passive sub-commands (none of
	// which need authorization themselves) — so refusing it would be a
	// stricter contract than the standalone calls.
	if req.Active {
		if !requireAuthInBody(w, "audit", req.IAuthorized) {
			return
		}
	}
	out := BuildAudit(r.Context(), req.Target, AuditOptions{
		Active:   req.Active,
		Insecure: req.Insecure,
	}, auditDefaultTimeout(loadedConfig.Timeout))
	writeJSON(w, http.StatusOK, out)
}

// ─── Saved reports ────────────────────────────────────────────────────────

// SavedReportMeta is what `GET /api/reports` returns: just metadata, no body.
type SavedReportMeta struct {
	ID      string    `json:"id"`
	SavedAt time.Time `json:"saved_at"`
	Kind    string    `json:"kind"`            // "full" / "dns" / "route" / "ip"
	Target  string    `json:"target"`          // host or url, for display
	Label   string    `json:"label,omitempty"` // optional user-supplied label
	OK      *bool     `json:"ok,omitempty"`    // for "full" only
}

// savedReportFile is the on-disk format of one saved report.
type savedReportFile struct {
	ID      string          `json:"id"`
	SavedAt time.Time       `json:"saved_at"`
	Kind    string          `json:"kind"`
	Target  string          `json:"target"`
	Label   string          `json:"label,omitempty"`
	OK      *bool           `json:"ok,omitempty"`
	Report  json.RawMessage `json:"report"` // the original FullJSON / DNSCompareJSON / etc.
}

type saveReportRequest struct {
	Report json.RawMessage `json:"report"`
	Label  string          `json:"label,omitempty"`
}

func handleReportsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleListReports(w, r)
	case http.MethodPost:
		handleSaveReport(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "GET or POST required"})
	}
}

func handleReportItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	id = strings.Trim(id, "/")
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusNotFound, apiError{Error: "report not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		serveReport(w, id)
	case http.MethodDelete:
		deleteReport(w, id)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "GET or DELETE required"})
	}
}

func handleListReports(w http.ResponseWriter, _ *http.Request) {
	dir, err := savedReportsDir()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	out := []SavedReportMeta{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var f savedReportFile
		if err := json.Unmarshal(data, &f); err != nil {
			continue
		}
		out = append(out, SavedReportMeta{
			ID:      f.ID,
			SavedAt: f.SavedAt,
			Kind:    f.Kind,
			Target:  f.Target,
			Label:   f.Label,
			OK:      f.OK,
		})
	}
	// Newest first.
	sort.Slice(out, func(i, j int) bool { return out[i].SavedAt.After(out[j].SavedAt) })
	writeJSON(w, http.StatusOK, out)
}

func handleSaveReport(w http.ResponseWriter, r *http.Request) {
	var req saveReportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Report) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "missing report"})
		return
	}

	// Sniff just the kind + ok first. Target lives under different fields per
	// kind, so we extract it separately below.
	var sniff struct {
		Kind string `json:"kind"`
		OK   *bool  `json:"ok,omitempty"`
	}
	_ = json.Unmarshal(req.Report, &sniff)

	target := sniffTarget(req.Report, sniff.Kind)
	if sniff.Kind == "" || target == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "report missing kind or target"})
		return
	}

	now := time.Now().UTC()
	id := newReportID(now, sniff.Kind, target)
	file := savedReportFile{
		ID:      id,
		SavedAt: now,
		Kind:    sniff.Kind,
		Target:  target,
		Label:   req.Label,
		OK:      sniff.OK,
		Report:  req.Report,
	}

	dir, err := savedReportsDir()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0600); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, SavedReportMeta{
		ID:      id,
		SavedAt: now,
		Kind:    sniff.Kind,
		Target:  target,
		Label:   req.Label,
		OK:      sniff.OK,
	})
}

func serveReport(w http.ResponseWriter, id string) {
	dir, err := savedReportsDir()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "report not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func deleteReport(w http.ResponseWriter, id string) {
	dir, err := savedReportsDir()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	path := filepath.Join(dir, id+".json")
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "report not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── helpers ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "app JSON response error: %v\n", err)
	}
}

func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "POST required"})
		return false
	}
	return true
}

// defaultMaxBodyBytes is the request-body size cap used by single-report
// endpoints. 1 MiB easily fits any single check result we emit today.
const defaultMaxBodyBytes = 1 << 20 // 1 MiB

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSONWithLimit(w, r, v, defaultMaxBodyBytes)
}

// decodeJSONWithLimit is the variant used by endpoints whose body carries
// more than a single report. /api/diff bundles two full reports (old + new)
// in one body, so it needs ~2× the single-report ceiling. Codex flagged on
// #69 that the default 1 MiB cap could 400 two valid saved reports.
func decodeJSONWithLimit(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON request"})
		return false
	}
	return true
}

func checkTimeout() time.Duration {
	if loadedConfig != nil && loadedConfig.Timeout > 0 {
		return loadedConfig.Timeout
	}
	return 10 * time.Second
}

func defaultInt(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// savedReportsDir returns ~/.config/netcheck/saved-reports (or
// $XDG_DATA_HOME/netcheck/saved-reports if set). Created on first save.
//
// Tests override this via SetSavedReportsDir to point at a temp dir.
func savedReportsDir() (string, error) {
	if dirOverride != "" {
		return dirOverride, nil
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "netcheck", "saved-reports"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "netcheck", "saved-reports"), nil
}

// dirOverride lets tests redirect savedReportsDir to a temp dir.
var dirOverride string

// SetSavedReportsDir overrides the savedReportsDir lookup. Pass "" to clear.
// Intended for tests only.
func SetSavedReportsDir(path string) { dirOverride = path }

// newReportID builds a filesystem-safe ID combining timestamp + kind + target.
func newReportID(now time.Time, kind, target string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			return r
		}
		return '-'
	}, target)
	return fmt.Sprintf("%s-%s-%s", now.Format("20060102-150405"), kind, safe)
}

// sniffTarget extracts the display-target for a saved report based on its
// kind, since different report shapes store it under different field names.
//   - full:        target.raw  (URL)
//   - dns, route:  host        (hostname string)
//   - ip:          target      (the string the user typed: IP or hostname)
func sniffTarget(raw json.RawMessage, kind string) string {
	switch kind {
	case "full":
		var s struct {
			Target struct {
				Raw string `json:"raw"`
			} `json:"target"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.Target.Raw
	case "dns", "route":
		var s struct {
			Host string `json:"host"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.Host
	case "ip":
		var s struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.Target
	case "headers", "tech":
		var s struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.URL
	case "subs", "arch", "takeover":
		var s struct {
			Domain string `json:"domain"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.Domain
	case "reverse":
		var s struct {
			IP string `json:"ip"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.IP
	case "tls-audit", "ports":
		var s struct {
			Host string `json:"host"`
			Port string `json:"port"`
		}
		_ = json.Unmarshal(raw, &s)
		if s.Port != "" && s.Port != "443" {
			return s.Host + ":" + s.Port
		}
		return s.Host
	case "enum":
		var s struct {
			BaseURL string `json:"base_url"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.BaseURL
	case "audit":
		var s struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(raw, &s)
		return s.Target
	}
	return ""
}

// ─── /api/diff ────────────────────────────────────────────────────────────

// diffRequest is the body of POST /api/diff. `Old` and `New` are the
// two reports to compare; either can be any of the kinds in
// `report.AnyReport` — diff.Diff dispatches per-kind internally.
type diffRequest struct {
	Old json.RawMessage `json:"old"`
	New json.RawMessage `json:"new"`
}

// handleDiff compares two saved/loaded JSON reports and returns the
// structured diff.Report (the same shape the `netcheck diff` CLI emits
// with --output json). The web UI calls this from the Reports route
// when the user picks two reports to compare.
//
// Body carries TWO reports — uses decodeJSONWithLimit with an 8 MiB
// ceiling instead of the 1 MiB default so paired large reports don't
// 400. 8 MiB is ~4× a worst-case single report (top-1000 ports scan
// with banners, audit aggregate) — generous headroom without being
// silly. Codex P2 on #69.
//
// Parse errors → 400. Diff errors (e.g. nil) → 422. Success → 200.
func handleDiff(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req diffRequest
	if !decodeJSONWithLimit(w, r, &req, 8<<20) {
		return
	}
	if len(req.Old) == 0 || len(req.New) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "both 'old' and 'new' required"})
		return
	}
	rep, err := diff.Diff(req.Old, req.New)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
