package cmd

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunAppRejectsUnexpectedArgs(t *testing.T) {
	var exit int
	_ = captureStderr(t, func() {
		exit = RunApp([]string{"extra"})
	})
	if exit != 2 {
		t.Fatalf("exit = %d, want 2", exit)
	}
}

func TestRunAppReturnsFailureWhenPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var exit int
	stderr := captureStderr(t, func() {
		exit = RunApp([]string{"--listen", ln.Addr().String()})
	})
	if exit != 1 {
		t.Fatalf("exit = %d, want 1", exit)
	}
	if !strings.Contains(stderr, "address already in use") {
		t.Fatalf("stderr = %q, want bind failure", stderr)
	}
}

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

func TestAppServesEmbeddedIndex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	newAppHandler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if contentType := res.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want HTML", contentType)
	}
	if body := res.Body.String(); !strings.Contains(body, `<div id="root"></div>`) {
		t.Fatalf("body = %q, want React root", body)
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

func TestFullCheckAPIRejectsInvalidJSON(t *testing.T) {
	for _, body := range []string{
		`{"target":`,
		`{"target":"example.com","unexpected":true}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/check/full", strings.NewReader(body))
		res := httptest.NewRecorder()

		newAppHandler().ServeHTTP(res, req)

		if res.Code != http.StatusBadRequest {
			t.Fatalf("body %q status = %d, want %d", body, res.Code, http.StatusBadRequest)
		}
		if got := res.Body.String(); !strings.Contains(got, "invalid JSON request") {
			t.Fatalf("body %q response = %q, want JSON parse error", body, got)
		}
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

func TestFullCheckAPIReturnsFullReport(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer targetServer.Close()

	body, err := json.Marshal(fullCheckRequest{Target: targetServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/check/full", bytes.NewReader(body))
	res := httptest.NewRecorder()

	newAppHandler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", res.Code, http.StatusOK, res.Body.String())
	}
	if contentType := res.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}

	var got struct {
		Kind   string `json:"kind"`
		Target struct {
			Raw string `json:"raw"`
		} `json:"target"`
		HTTP struct {
			Status int `json:"status"`
		} `json:"http"`
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != "full" {
		t.Fatalf("kind = %q, want full", got.Kind)
	}
	if got.Target.Raw != targetServer.URL {
		t.Fatalf("target raw = %q, want %q", got.Target.Raw, targetServer.URL)
	}
	if got.HTTP.Status != http.StatusNoContent {
		t.Fatalf("HTTP status = %d, want %d", got.HTTP.Status, http.StatusNoContent)
	}
	if !got.OK {
		t.Fatalf("ok = false, want true")
	}
}

func TestFullCheckAPIAllowsInsecureTLSCheck(t *testing.T) {
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer targetServer.Close()

	body, err := json.Marshal(fullCheckRequest{Target: targetServer.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/check/full", bytes.NewReader(body))
	res := httptest.NewRecorder()

	newAppHandler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", res.Code, http.StatusOK, res.Body.String())
	}

	var got struct {
		TLS *struct {
			Error string `json:"error"`
		} `json:"tls"`
		HTTP struct {
			Status int    `json:"status"`
			Error  string `json:"error"`
		} `json:"http"`
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.TLS == nil || got.TLS.Error != "" {
		t.Fatalf("TLS = %+v, want successful TLS result", got.TLS)
	}
	if got.HTTP.Error != "" || got.HTTP.Status != http.StatusAccepted {
		t.Fatalf("HTTP = %+v, want accepted response", got.HTTP)
	}
	if !got.OK {
		t.Fatalf("ok = false, want true")
	}
}
