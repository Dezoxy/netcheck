package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netcheck/internal/reverseip"
	"netcheck/internal/subenum"
	"netcheck/internal/wayback"
)

// pointAuditAt redirects the v1.4 external sub-sources to local httptest
// servers so /api/check/audit runs end-to-end without leaving the box.
func pointAuditAt(t *testing.T) func() {
	t.Helper()
	subsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	cdxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[["timestamp","original","statuscode"]]`))
	}))
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(""))
	}))
	restoreSubs := subenum.SetSourceURLsForTest(subsSrv.URL, subsSrv.URL)
	restoreCdx := wayback.SetSourceURLForTest(cdxSrv.URL)
	restoreReverse := reverseip.SetSourceURLsForTest(htSrv.URL, "")
	return func() {
		restoreReverse()
		restoreCdx()
		restoreSubs()
		subsSrv.Close()
		cdxSrv.Close()
		htSrv.Close()
	}
}

func TestAuditCheckRejectsGet(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/check/audit", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestAuditCheckEmptyTarget(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/audit", map[string]any{"target": ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuditCheckPassiveHappyPath(t *testing.T) {
	defer pointAuditAt(t)()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	resp, data := appRequest(t, http.MethodPost, "/api/check/audit", map[string]any{
		"target": srv.URL,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	var out struct {
		Kind   string `json:"kind"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != "audit" {
		t.Errorf("kind = %q, want audit", out.Kind)
	}
	if out.Active {
		t.Errorf("active = true, want false (no `active` in request)")
	}
}

func TestAuditCheckActiveRefusesWithoutAuth(t *testing.T) {
	resp, data := appRequest(t, http.MethodPost, "/api/check/audit", map[string]any{
		"target":               "example.com",
		"active":               true,
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
		t.Errorf("authorized = %v, want false", got["authorized"])
	}
	if !strings.Contains(got["error"].(string), "authorization required") {
		t.Errorf("error should mention authorization: %v", got["error"])
	}
}

func TestAuditCheckActivePassesWithAuth(t *testing.T) {
	defer pointAuditAt(t)()
	// We don't need the active sub-checks to actually succeed — they'll
	// fail against the invalid TLD. We're just verifying the gate accepts
	// the request and audit emits SOMETHING with active=true.
	resp, data := appRequest(t, http.MethodPost, "/api/check/audit", map[string]any{
		"target":               "test.invalid.netcheck-audit",
		"active":               true,
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	var out struct {
		Kind   string `json:"kind"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Active {
		t.Errorf("active = false, want true")
	}
}
