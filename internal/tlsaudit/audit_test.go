package tlsaudit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// startTLSServer spins up an httptest TLS server with a constrained config
// and returns the listening host, port, and a teardown func.
func startTLSServer(t *testing.T, cfg *tls.Config) (string, string, func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	return host, port, srv.Close
}

// =============================================================================
// normalizeHostPort
// =============================================================================

func TestNormalizeHostPort(t *testing.T) {
	cases := []struct {
		in, host, port string
		wantErr        bool
	}{
		{"example.com", "example.com", "443", false},
		{"example.com:8443", "example.com", "8443", false},
		{"[::1]:443", "::1", "443", false},
		{"", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			h, p, err := normalizeHostPort(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h != c.host || p != c.port {
				t.Errorf("got (%q,%q), want (%q,%q)", h, p, c.host, c.port)
			}
		})
	}
}

// =============================================================================
// Audit against a modern (TLS 1.2/1.3) server
// =============================================================================

func TestAuditModernServer(t *testing.T) {
	host, port, stop := startTLSServer(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	defer stop()

	res := Audit(context.Background(), host+":"+port, 10*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}

	// TLS 1.0 / 1.1 should NOT be supported.
	for _, p := range res.Protocols {
		if p.Deprecated && p.Supported {
			t.Errorf("server should not support %s, but it did", p.Name)
		}
	}
	// TLS 1.2 or 1.3 (or both) should be supported.
	any12or13 := false
	for _, p := range res.Protocols {
		if !p.Deprecated && p.Supported {
			any12or13 = true
		}
	}
	if !any12or13 {
		t.Error("expected at least one of TLS 1.2 / TLS 1.3 to be supported")
	}

	// Cert info should be populated.
	if res.Cert == nil {
		t.Fatal("expected Cert to be populated")
	}
	if res.Cert.ChainLen == 0 {
		t.Error("expected non-zero chain length")
	}
	if res.Cert.Expired {
		t.Error("test cert should not be expired")
	}

	// Findings: should include either "no issues" or be all non-high.
	for _, f := range res.Findings {
		if f.Severity == "high" {
			t.Errorf("modern server shouldn't produce high-severity finding: %+v", f)
		}
	}
}

// =============================================================================
// Audit detects deprecated TLS 1.0 when allowed
// =============================================================================

func TestAuditDeprecatedProtocolDetected(t *testing.T) {
	// Server that ALLOWS TLS 1.0 (MinVersion: TLS 1.0).
	host, port, stop := startTLSServer(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12, // exclude 1.3 so we exercise cipher probing
	})
	defer stop()

	res := Audit(context.Background(), host+":"+port, 10*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}

	// TLS 1.0 should be detected as supported.
	gotTLS10 := false
	for _, p := range res.Protocols {
		if p.Name == "TLS 1.0" && p.Supported {
			gotTLS10 = true
		}
	}
	if !gotTLS10 {
		t.Error("expected TLS 1.0 to register as supported on a TLS 1.0+ server")
	}
	// And we should have flagged it as a high-severity finding.
	gotHighDeprecated := false
	for _, f := range res.Findings {
		if f.Severity == "high" && strings.Contains(f.Title, "TLS 1.0") {
			gotHighDeprecated = true
		}
	}
	if !gotHighDeprecated {
		t.Errorf("expected high-severity finding for TLS 1.0, got %+v", res.Findings)
	}
}

// =============================================================================
// Audit detects non-TLS port
// =============================================================================

func TestAuditNonTLSPort(t *testing.T) {
	// Plain TCP listener that accepts but speaks nothing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	res := Audit(context.Background(), host+":"+port, 2*time.Second)
	if res.Err == nil {
		t.Error("expected non-TLS port to return top-level error")
	}
}

// =============================================================================
// Audit on bad input
// =============================================================================

func TestAuditEmptyHost(t *testing.T) {
	res := Audit(context.Background(), "", 1*time.Second)
	if res.Err == nil {
		t.Error("expected error on empty host")
	}
}

func TestAuditDialFailure(t *testing.T) {
	// Port 1 — root-reserved, nothing listening.
	res := Audit(context.Background(), "127.0.0.1:1", 500*time.Millisecond)
	if res.Err == nil {
		t.Error("expected error when nothing is listening")
	}
}

// =============================================================================
// grade() — direct tests of the verdict logic
// =============================================================================

func TestGradeDeprecatedProtocol(t *testing.T) {
	r := Result{Protocols: []ProtocolResult{
		{Name: "TLS 1.0", Supported: true, Deprecated: true},
		{Name: "TLS 1.2", Supported: true},
	}}
	fs := grade(r)
	gotHigh := false
	for _, f := range fs {
		if f.Severity == "high" {
			gotHigh = true
		}
	}
	if !gotHigh {
		t.Errorf("deprecated protocol should yield high severity, got %+v", fs)
	}
}

func TestGradeWeakCiphers(t *testing.T) {
	r := Result{Ciphers: []CipherResult{
		{Name: "TLS_RSA_WITH_RC4_128_SHA", Supported: true, Insecure: true},
		{Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", Supported: true, Insecure: false},
	}}
	fs := grade(r)
	gotWeak := false
	for _, f := range fs {
		if f.Severity == "high" && strings.Contains(f.Title, "weak cipher") {
			gotWeak = true
		}
	}
	if !gotWeak {
		t.Errorf("weak cipher should yield high severity, got %+v", fs)
	}
}

func TestGradeExpiredCert(t *testing.T) {
	r := Result{Cert: &CertInfo{
		Expired:       true,
		NotAfter:      time.Now().Add(-24 * time.Hour),
		DaysRemaining: -1,
	}}
	fs := grade(r)
	gotExpired := false
	for _, f := range fs {
		if strings.Contains(strings.ToLower(f.Title), "expired") {
			gotExpired = true
		}
	}
	if !gotExpired {
		t.Errorf("expired cert should be flagged, got %+v", fs)
	}
}

func TestGradeExpiringSoon(t *testing.T) {
	r := Result{Cert: &CertInfo{DaysRemaining: 7, NotAfter: time.Now().Add(7 * 24 * time.Hour)}}
	fs := grade(r)
	gotExpiringSoon := false
	for _, f := range fs {
		if f.Severity == "high" && strings.Contains(f.Title, "expires soon") {
			gotExpiringSoon = true
		}
	}
	if !gotExpiringSoon {
		t.Errorf("expiry within 14 days should be high severity, got %+v", fs)
	}
}

func TestGradeExpiringWithin30Days(t *testing.T) {
	r := Result{Cert: &CertInfo{DaysRemaining: 21, NotAfter: time.Now().Add(21 * 24 * time.Hour)}}
	fs := grade(r)
	gotMedium := false
	for _, f := range fs {
		if f.Severity == "medium" && strings.Contains(f.Title, "30 days") {
			gotMedium = true
		}
	}
	if !gotMedium {
		t.Errorf("21 days to expiry should be medium severity, got %+v", fs)
	}
}

func TestGradeSelfSignedCert(t *testing.T) {
	r := Result{Cert: &CertInfo{
		SelfSigned:    true,
		DaysRemaining: 365,
		NotAfter:      time.Now().Add(365 * 24 * time.Hour),
	}}
	fs := grade(r)
	gotSelfSigned := false
	for _, f := range fs {
		if strings.Contains(strings.ToLower(f.Title), "self-signed") {
			gotSelfSigned = true
		}
	}
	if !gotSelfSigned {
		t.Errorf("self-signed cert should be flagged, got %+v", fs)
	}
}

func TestGradeNoIssues(t *testing.T) {
	r := Result{
		Protocols: []ProtocolResult{{Name: "TLS 1.3", Supported: true}},
		Cert: &CertInfo{
			DaysRemaining: 365,
			NotAfter:      time.Now().Add(365 * 24 * time.Hour),
		},
	}
	fs := grade(r)
	if len(fs) != 1 || fs[0].Severity != "info" {
		t.Errorf("expected single info finding, got %+v", fs)
	}
}

// =============================================================================
// Helper sanity tests
// =============================================================================

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0xdead, "0xdead"},
	}
	for _, c := range cases {
		if got := tlsVersionName(c.v); got != c.want {
			t.Errorf("tlsVersionName(0x%x) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestIsSelfSigned(t *testing.T) {
	c := &x509.Certificate{}
	// Trivially: empty Subject == empty Issuer (both are pkix.Name zero).
	if !isSelfSigned(c) {
		t.Error("empty-name cert should be classified self-signed")
	}
}

func TestPickCipherProbeVersion(t *testing.T) {
	// Only 1.3 supported → returns 0.
	prs := []ProtocolResult{{Version: tls.VersionTLS13, Supported: true}}
	if v := pickCipherProbeVersion(prs); v != 0 {
		t.Errorf("got %x, want 0 for 1.3-only", v)
	}
	// 1.2 + 1.3 → prefers 1.2.
	prs = []ProtocolResult{
		{Version: tls.VersionTLS12, Supported: true},
		{Version: tls.VersionTLS13, Supported: true},
	}
	if v := pickCipherProbeVersion(prs); v != tls.VersionTLS12 {
		t.Errorf("got %x, want TLS 1.2", v)
	}
	// 1.0 + 1.2 → prefers 1.2.
	prs = []ProtocolResult{
		{Version: tls.VersionTLS10, Supported: true},
		{Version: tls.VersionTLS12, Supported: true},
	}
	if v := pickCipherProbeVersion(prs); v != tls.VersionTLS12 {
		t.Errorf("got %x, want TLS 1.2 (highest pre-1.3 supported)", v)
	}
}

// Verify the dialer hook can be stubbed (covers the test seam).
func TestDialerStubbing(t *testing.T) {
	prev := dialer
	defer func() { dialer = prev }()
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("forced")
	}
	res := Audit(context.Background(), "example.com:443", 1*time.Second)
	if res.Err == nil {
		t.Error("expected top-level error when dialer is stubbed to fail")
	}
}
