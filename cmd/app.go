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

	"netcheck/internal/dnscompare"
	"netcheck/internal/report"
	"netcheck/internal/route"
	"netcheck/internal/target"
	"netcheck/internal/webui"
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
	mux.HandleFunc("/api/reports", handleReportsCollection)
	mux.HandleFunc("/api/reports/", handleReportItem)
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

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
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
	}
	return ""
}
