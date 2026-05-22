package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// helper: POST/GET/DELETE against the app handler and decode JSON.
func appRequest(t *testing.T, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reqBody = bytes.NewReader(data)
	}
	srv := httptest.NewServer(newAppHandler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(method, srv.URL+path, reqBody)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

// ─── /api/check/dns ───────────────────────────────────────────────────────

func TestDNSCheckRejectsGet(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/check/dns", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestDNSCheckMissingResolvers(t *testing.T) {
	// no_system + no_defaults + no_config_resolvers + no extra resolvers = error
	body := map[string]any{
		"host":                "google.com",
		"no_system":           true,
		"no_defaults":         true,
		"no_config_resolvers": true,
	}
	resp, data := appRequest(t, http.MethodPost, "/api/check/dns", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body %s)", resp.StatusCode, data)
	}
}

func TestDNSCheckBadHost(t *testing.T) {
	body := map[string]any{"host": ""}
	resp, _ := appRequest(t, http.MethodPost, "/api/check/dns", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDNSCheckSuccess(t *testing.T) {
	// Use a single resolver so the test doesn't hammer real DNS. Cloudflare
	// is usually reachable from CI; if not, the resolver will record an Err
	// and we still get a 200 back with the structured result.
	body := map[string]any{
		"host":                "cloudflare.com",
		"no_system":           true,
		"no_defaults":         true,
		"no_config_resolvers": true,
		"resolvers":           []string{"1.1.1.1"},
	}
	resp, data := appRequest(t, http.MethodPost, "/api/check/dns", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, data)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["kind"] != "dns" {
		t.Errorf("kind = %v, want dns", got["kind"])
	}
}

// ─── /api/check/ip ────────────────────────────────────────────────────────

func TestIPCheckRejectsGet(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/check/ip", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestIPCheckBadInput(t *testing.T) {
	body := map[string]any{"target": ""}
	resp, _ := appRequest(t, http.MethodPost, "/api/check/ip", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestIPCheckPrivateAddress(t *testing.T) {
	// Private IP exercises the orchestration without touching the network
	// for ASN/RDAP (they short-circuit on private IPs).
	body := map[string]any{"target": "192.168.1.1"}
	resp, data := appRequest(t, http.MethodPost, "/api/check/ip", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, data)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["kind"] != "ip" {
		t.Errorf("kind = %v, want ip", got["kind"])
	}
}

// ─── /api/check/route ─────────────────────────────────────────────────────

func TestRouteCheckRejectsGet(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/check/route", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestRouteCheckBadHost(t *testing.T) {
	body := map[string]any{"host": ""}
	resp, _ := appRequest(t, http.MethodPost, "/api/check/route", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// Note: we don't run a full route success test — it requires the system
// traceroute binary and takes 30+ seconds. The CLI-level RunRoute test in
// route_run_test.go already covers the end-to-end path via the fake binary.

// ─── /api/reports ─────────────────────────────────────────────────────────

func TestReportsListEmptyWhenNoDir(t *testing.T) {
	dir := t.TempDir()
	SetSavedReportsDir(filepath.Join(dir, "does-not-exist"))
	t.Cleanup(func() { SetSavedReportsDir("") })

	resp, data := appRequest(t, http.MethodGet, "/api/reports", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, data)
	}
	var got []SavedReportMeta
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %v", got)
	}
}

func TestSaveReportFullThenListThenDelete(t *testing.T) {
	dir := t.TempDir()
	SetSavedReportsDir(dir)
	t.Cleanup(func() { SetSavedReportsDir("") })

	// Save a synthetic "full" report.
	body := map[string]any{
		"report": map[string]any{
			"netcheck_version": "0.5.0",
			"kind":             "full",
			"started_at":       "2026-05-22T15:00:00Z",
			"target":           map[string]any{"raw": "https://example.com", "host": "example.com", "port": "443", "scheme": "https"},
			"dns":              map[string]any{"took_ms": 10, "a": []string{"1.2.3.4"}, "aaaa": []string{}},
			"http":             map[string]any{"status": 200, "final_url": "https://example.com/", "hops": []any{}, "timing": map[string]any{"dns_ms": 0, "connect_ms": 0, "ttfb_ms": 0, "total_ms": 0}},
			"ok":               true,
		},
		"label": "test save",
	}
	resp, data := appRequest(t, http.MethodPost, "/api/reports", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("save status = %d, body=%s", resp.StatusCode, data)
	}
	var meta SavedReportMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Kind != "full" || meta.Target != "https://example.com" || meta.Label != "test save" {
		t.Errorf("meta = %+v", meta)
	}
	if meta.OK == nil || !*meta.OK {
		t.Errorf("OK = %v, want true", meta.OK)
	}

	// File got written.
	if _, err := os.Stat(filepath.Join(dir, meta.ID+".json")); err != nil {
		t.Errorf("file not created: %v", err)
	}

	// List contains it.
	resp, data = appRequest(t, http.MethodGet, "/api/reports", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	var list []SavedReportMeta
	_ = json.Unmarshal(data, &list)
	if len(list) != 1 || list[0].ID != meta.ID {
		t.Errorf("list = %v, want 1 entry matching meta.ID=%s", list, meta.ID)
	}

	// GET the individual report — should round-trip the full body.
	resp, data = appRequest(t, http.MethodGet, "/api/reports/"+meta.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", resp.StatusCode)
	}
	// MarshalIndent puts whitespace between "kind": and the value — assert
	// against the parsed structure instead of the formatted string.
	var got struct {
		Report struct {
			Kind string `json:"kind"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Report.Kind != "full" {
		t.Errorf("report.kind = %q, want full", got.Report.Kind)
	}

	// DELETE.
	resp, _ = appRequest(t, http.MethodDelete, "/api/reports/"+meta.ID, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", resp.StatusCode)
	}

	// GET 404 after delete.
	resp, _ = appRequest(t, http.MethodGet, "/api/reports/"+meta.ID, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("after delete: status = %d, want 404", resp.StatusCode)
	}
}

func TestSaveReportMissingKind(t *testing.T) {
	dir := t.TempDir()
	SetSavedReportsDir(dir)
	t.Cleanup(func() { SetSavedReportsDir("") })

	body := map[string]any{"report": map[string]any{"foo": "bar"}}
	resp, _ := appRequest(t, http.MethodPost, "/api/reports", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestReportItemRejectsSlash(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/reports/abc/def", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (slashes in id rejected)", resp.StatusCode)
	}
}

func TestReportItemNotFound(t *testing.T) {
	dir := t.TempDir()
	SetSavedReportsDir(dir)
	t.Cleanup(func() { SetSavedReportsDir("") })

	resp, _ := appRequest(t, http.MethodGet, "/api/reports/nonexistent", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestReportItemBadMethod(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/reports/some-id", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// ─── sniffTarget ──────────────────────────────────────────────────────────

func TestSniffTarget(t *testing.T) {
	cases := []struct {
		kind, raw, want string
	}{
		{"full", `{"target":{"raw":"https://example.com"}}`, "https://example.com"},
		{"dns", `{"host":"example.com"}`, "example.com"},
		{"route", `{"host":"example.com"}`, "example.com"},
		{"ip", `{"target":"1.1.1.1"}`, "1.1.1.1"},
		{"unknown", `{"target":"x"}`, ""},
		{"full", `{}`, ""},
	}
	for _, c := range cases {
		got := sniffTarget([]byte(c.raw), c.kind)
		if got != c.want {
			t.Errorf("sniffTarget(%s, %q) = %q, want %q", c.kind, c.raw, got, c.want)
		}
	}
}

// ─── newReportID ──────────────────────────────────────────────────────────

func TestNewReportIDSanitizesTarget(t *testing.T) {
	id := newReportID(mustTime("2026-05-22T15:30:45Z"), "full", "https://example.com/path?q=1")
	// Should not contain ://, /, ?, =
	for _, bad := range []string{"://", "?", "="} {
		if strings.Contains(id, bad) {
			t.Errorf("id %q contains forbidden char %q", id, bad)
		}
	}
	if !strings.Contains(id, "20260522-153045") {
		t.Errorf("id %q missing timestamp", id)
	}
	if !strings.Contains(id, "full") {
		t.Errorf("id %q missing kind", id)
	}
}
