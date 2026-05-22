package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"netcheck/internal/report"
	"netcheck/internal/target"
	"netcheck/internal/webui"
)

type fullCheckRequest struct {
	Target   string `json:"target"`
	Insecure bool   `json:"insecure"`
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
	mux.Handle("/", http.FileServer(http.FS(webui.Dist())))
	return mux
}

func handleAppHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleFullCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "POST required"})
		return
	}

	var req fullCheckRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid JSON request"})
		return
	}

	t, err := target.Parse(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	timeout := loadedConfig.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	run := BuildFullReport(r.Context(), t, timeout, req.Insecure)
	writeJSON(w, http.StatusOK, report.ToFullJSON(run))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "app JSON response error: %v\n", err)
	}
}
