package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPortsStreamRejectsWithoutAuth checks the auth gate before any SSE
// framing happens — should fall through to writeJSON with the same 403 shape
// as the non-streaming endpoint.
func TestPortsStreamRejectsWithoutAuth(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/ports/stream", map[string]any{
		"host":                 "127.0.0.1",
		"i_have_authorization": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestPortsStreamRejectsEmptyHost(t *testing.T) {
	resp, _ := appRequest(t, http.MethodPost, "/api/check/ports/stream", map[string]any{
		"host":                 "",
		"i_have_authorization": true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestPortsStreamEmitsProgressAndDone verifies the happy-path stream shape:
//   - Content-Type is text/event-stream
//   - At least one `event: progress` frame
//   - Exactly one `event: done` frame at the end carrying the full report
func TestPortsStreamEmitsProgressAndDone(t *testing.T) {
	srv := httptest.NewServer(newTestAppHandler())
	t.Cleanup(srv.Close)

	// Scan a few low ports against localhost. Most will be filtered; that's
	// fine — what we care about is the progress event count, not the
	// open/closed mix.
	body, _ := json.Marshal(map[string]any{
		"host":                 "127.0.0.1",
		"ports":                "1,2,3",
		"per_port_timeout_ms":  200,
		"i_have_authorization": true,
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/check/ports/stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, all)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	events := parseSSE(t, resp.Body)
	progressCount := 0
	doneCount := 0
	var lastDone map[string]any
	for _, ev := range events {
		switch ev.event {
		case "progress":
			progressCount++
			// Each progress should at least have port + state + index/total.
			var p map[string]any
			if err := json.Unmarshal([]byte(ev.data), &p); err != nil {
				t.Errorf("progress data not JSON: %v (%s)", err, ev.data)
				continue
			}
			if _, ok := p["port"]; !ok {
				t.Errorf("progress missing port: %s", ev.data)
			}
			if _, ok := p["state"]; !ok {
				t.Errorf("progress missing state: %s", ev.data)
			}
		case "done":
			doneCount++
			if err := json.Unmarshal([]byte(ev.data), &lastDone); err != nil {
				t.Errorf("done data not JSON: %v", err)
			}
		}
	}
	if progressCount == 0 {
		t.Errorf("expected at least one progress event, got 0")
	}
	if doneCount != 1 {
		t.Errorf("expected exactly 1 done event, got %d", doneCount)
	}
	if lastDone == nil {
		t.Fatal("done payload missing")
	}
	// done payload should look like a PortScanJSON.
	if lastDone["kind"] != "ports" {
		t.Errorf("done.kind = %v, want ports", lastDone["kind"])
	}
}

// sseEvent is a parsed SSE frame.
type sseEvent struct {
	event string
	data  string
}

// parseSSE reads SSE frames until EOF. Each frame is separated by a blank
// line; lines beginning with `event:` and `data:` are joined into a single
// event. Good enough for tests — not a fully spec-compliant parser.
func parseSSE(t *testing.T, body io.Reader) []sseEvent {
	t.Helper()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []sseEvent
	var cur sseEvent
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if cur.event != "" || cur.data != "" {
				out = append(out, cur)
				cur = sseEvent{}
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
		}
	}
	// Flush a dangling frame in case the server didn't terminate with a
	// blank line (we do, but be defensive).
	if cur.event != "" || cur.data != "" {
		out = append(out, cur)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}
