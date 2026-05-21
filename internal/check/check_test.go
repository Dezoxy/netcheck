package check

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netcheck/internal/target"
)

// ─── LookupDNS ────────────────────────────────────────────────────────────

func TestLookupDNSLocalhost(t *testing.T) {
	// "localhost" resolves on every CI runner without external DNS.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := LookupDNS(ctx, "localhost")
	if r.Err != nil {
		t.Fatalf("LookupDNS(localhost) failed: %v", r.Err)
	}
	if len(r.A) == 0 && len(r.AAAA) == 0 {
		t.Errorf("got no A/AAAA records for localhost")
	}
}

func TestLookupDNSNonexistent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := LookupDNS(ctx, "this-host-should-never-exist.invalid")
	if r.Err == nil {
		t.Errorf("expected error for .invalid host, got A=%v AAAA=%v", r.A, r.AAAA)
	}
}

// ─── TCP ──────────────────────────────────────────────────────────────────

func TestTCPSuccess(t *testing.T) {
	// Stand up a listener on a free port and connect to it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept goroutine — we don't care what's sent, just that connect succeeds.
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	r := TCP(context.Background(), net.ParseIP("127.0.0.1"), portStr)
	if r.Err != nil {
		t.Fatalf("TCP connect failed: %v", r.Err)
	}
	if r.Addr != "127.0.0.1:"+portStr {
		t.Errorf("Addr = %q, want 127.0.0.1:%s", r.Addr, portStr)
	}
	if r.Took <= 0 {
		t.Errorf("Took = %v, want > 0", r.Took)
	}
}

func TestTCPRefused(t *testing.T) {
	// Bind and close immediately to grab a port we know is now unused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, portStr, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	r := TCP(ctx, net.ParseIP("127.0.0.1"), portStr)
	if r.Err == nil {
		t.Errorf("expected connection refused, got nil err on Addr=%s", r.Addr)
	}
}

// ─── TLS ──────────────────────────────────────────────────────────────────

func TestTLSHandshakeInsecure(t *testing.T) {
	// httptest.NewTLSServer issues a self-signed cert; we use insecure mode
	// to bypass verification but still exercise the full handshake parse.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := TLS(ctx, host, port, true)
	if r.Err != nil {
		t.Fatalf("TLS handshake failed: %v", r.Err)
	}
	if r.Version != tls.VersionTLS12 && r.Version != tls.VersionTLS13 {
		t.Errorf("Version = %d, want TLS 1.2 or 1.3", r.Version)
	}
	if len(r.Chain) == 0 {
		t.Errorf("Chain is empty")
	}
	if r.NotAfter.IsZero() {
		t.Errorf("NotAfter is zero")
	}
}

func TestTLSConnectFails(t *testing.T) {
	// Port 1 is reserved and typically closed; connect should fail fast.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	r := TLS(ctx, "127.0.0.1", "1", true)
	if r.Err == nil {
		t.Errorf("expected error connecting to 127.0.0.1:1, got nil")
	}
}

// ─── HTTP ─────────────────────────────────────────────────────────────────

func TestHTTPSuccessAndTiming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tgt, err := target.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := HTTP(context.Background(), tgt, false)
	if r.Err != nil {
		t.Fatalf("HTTP error: %v", r.Err)
	}
	if r.Status != 200 {
		t.Errorf("Status = %d, want 200", r.Status)
	}
	if r.Server != "test-server" {
		t.Errorf("Server = %q, want test-server", r.Server)
	}
	if r.Total <= 0 {
		t.Errorf("Total = %v, want > 0", r.Total)
	}
	if len(r.Hops) != 0 {
		t.Errorf("Hops = %v, want empty (no redirects)", r.Hops)
	}
}

func TestHTTPRedirectChain(t *testing.T) {
	var finalReached bool
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalReached = true
		w.WriteHeader(200)
	})
	// Two-step redirect: / → /step → /final
	mux.HandleFunc("/step", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/step", http.StatusMovedPermanently)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tgt, _ := target.Parse(srv.URL)
	r := HTTP(context.Background(), tgt, false)
	if r.Err != nil {
		t.Fatalf("HTTP error: %v", r.Err)
	}
	if r.Status != 200 {
		t.Errorf("Status = %d, want 200", r.Status)
	}
	if !strings.HasSuffix(r.FinalURL, "/final") {
		t.Errorf("FinalURL = %q, want suffix /final", r.FinalURL)
	}
	if len(r.Hops) != 2 {
		t.Errorf("Hops = %d, want 2", len(r.Hops))
	}
	if !finalReached {
		t.Errorf("server never saw the /final request")
	}
}

func TestHTTPRedirectLimit(t *testing.T) {
	// Loop redirect — every request bounces back to itself. The client should
	// stop after 10 hops.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	tgt, _ := target.Parse(srv.URL)
	r := HTTP(context.Background(), tgt, false)
	if r.Err == nil {
		t.Errorf("expected redirect-limit error, got Status=%d FinalURL=%s", r.Status, r.FinalURL)
	}
}

func TestHTTPConnectionRefused(t *testing.T) {
	// Bind+close to grab a guaranteed-unused port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	tgt, _ := target.Parse("http://" + addr)
	r := HTTP(context.Background(), tgt, false)
	if r.Err == nil {
		t.Errorf("expected error connecting to closed port, got Status=%d", r.Status)
	}
}

func TestSetUserAgent(t *testing.T) {
	// Capture the User-Agent the server sees.
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	prev := userAgent
	defer func() { userAgent = prev }()
	SetUserAgent("netcheck-check-test/1.0")

	tgt, _ := target.Parse(srv.URL)
	if r := HTTP(context.Background(), tgt, false); r.Err != nil {
		t.Fatal(r.Err)
	}
	if seen != "netcheck-check-test/1.0" {
		t.Errorf("server saw User-Agent = %q, want netcheck-check-test/1.0", seen)
	}
}

func TestSetUserAgentIgnoresEmpty(t *testing.T) {
	prev := userAgent
	defer func() { userAgent = prev }()
	userAgent = "before"
	SetUserAgent("")
	if userAgent != "before" {
		t.Errorf("empty SetUserAgent changed value to %q", userAgent)
	}
}
