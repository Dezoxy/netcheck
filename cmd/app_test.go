package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	res := httptest.NewRecorder()

	newAppHandler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if body := res.Body.String(); !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("body = %q, want health JSON", body)
	}
}

func TestFullCheckAPIRejectsUnsupportedMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/check/full", nil)
	res := httptest.NewRecorder()

	newAppHandler().ServeHTTP(res, req)

	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusMethodNotAllowed)
	}
	if allow := res.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("Allow = %q, want %q", allow, http.MethodPost)
	}
}

func TestFullCheckAPIRejectsInvalidTargetBeforeNetworkWork(t *testing.T) {
	body := bytes.NewBufferString(`{"target":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/check/full", body)
	res := httptest.NewRecorder()

	newAppHandler().ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if got := res.Body.String(); !strings.Contains(got, "empty target") {
		t.Fatalf("body = %q, want target parse error", got)
	}
}
