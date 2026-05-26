package cmd

import (
	"encoding/json"
	"net/http"
	"testing"
)

// /api/diff smoke. The handler delegates to pkg/diff which has its own
// per-kind tests; here we just verify the HTTP envelope works end to
// end and returns the same shape pkg/diff produces.

func TestDiffRejectsGet(t *testing.T) {
	resp, _ := appRequest(t, http.MethodGet, "/api/diff", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestDiffRejectsEmptyBodies(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/diff", map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDiffPortsHappyPath(t *testing.T) {
	older := map[string]any{
		"kind": "ports", "host": "example.com",
		"ports": []any{
			map[string]any{"port": 22, "service": "ssh"},
			map[string]any{"port": 80, "service": "http"},
		},
	}
	newer := map[string]any{
		"kind": "ports", "host": "example.com",
		"ports": []any{
			map[string]any{"port": 80, "service": "http"},
			map[string]any{"port": 443, "service": "https"},
		},
	}
	resp, body := appRequest(t, http.MethodPost, "/api/diff", map[string]any{
		"old": older,
		"new": newer,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var rep map[string]any
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	if rep["kind"] != "ports" {
		t.Errorf("kind = %v, want ports", rep["kind"])
	}
	if rep["changed"] != true {
		t.Errorf("changed = %v, want true", rep["changed"])
	}
	// Sections should contain the "Ports opened" / "Ports closed" entries.
	secs, _ := rep["sections"].([]any)
	if len(secs) == 0 {
		t.Errorf("expected non-empty sections in diff: %v", rep)
	}
}
