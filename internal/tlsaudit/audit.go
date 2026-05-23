// Package tlsaudit probes a TLS endpoint with a matrix of protocol versions
// and cipher suites. Active — opens many TCP connections to the target.
// Gated behind the v1.5 authorization flag at the cmd layer.
package tlsaudit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Result is the full TLS audit.
type Result struct {
	Host      string
	Port      string
	Protocols []ProtocolResult
	Ciphers   []CipherResult
	Cert      *CertInfo
	Findings  []Finding
	StartedAt time.Time
	Took      time.Duration
	Err       error // top-level error (DNS / dial / non-TLS port)
}

// ProtocolResult is the outcome of one version-pinned handshake.
type ProtocolResult struct {
	Name        string // "TLS 1.0", "TLS 1.3"
	Version     uint16
	Supported   bool
	Cipher      string // negotiated cipher on success
	Error       string // when not supported
	Deprecated  bool   // TLS 1.0 / 1.1
}

// CipherResult is the outcome of probing one cipher suite. We only probe
// ciphers for TLS 1.0-1.2 — TLS 1.3 negotiates from a fixed in-spec set
// that Go doesn't let us enumerate per-handshake.
type CipherResult struct {
	Name      string
	ID        uint16
	Supported bool
	Insecure  bool   // Go labels this cipher as insecure
	Version   string // negotiated TLS version on success
}

// CertInfo is the leaf cert plus chain metadata.
type CertInfo struct {
	Subject       string
	Issuer        string
	DNSNames      []string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	ChainLen      int
	SelfSigned    bool
	Expired       bool
}

// Finding is a high-level audit verdict.
type Finding struct {
	Severity string // "high" | "medium" | "info"
	Title    string
	Detail   string
}

// dialer is overridable for tests that want to stub out network IO.
var dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// allTLSVersions is the matrix we probe in version order.
var allTLSVersions = []struct {
	name       string
	v          uint16
	deprecated bool
}{
	{"TLS 1.0", tls.VersionTLS10, true},
	{"TLS 1.1", tls.VersionTLS11, true},
	{"TLS 1.2", tls.VersionTLS12, false},
	{"TLS 1.3", tls.VersionTLS13, false},
}

// Audit probes hostport (e.g. "example.com" or "example.com:443") across
// every TLS version and every cipher suite Go can offer. Returns a Result
// with Err set on top-level failure (DNS, dial, non-TLS responder).
func Audit(ctx context.Context, hostport string, timeout time.Duration) Result {
	started := time.Now()
	out := Result{StartedAt: started}

	host, port, err := normalizeHostPort(hostport)
	if err != nil {
		out.Err = err
		out.Took = time.Since(started)
		return out
	}
	out.Host, out.Port = host, port

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Phase 1: probe every TLS version in parallel.
	out.Protocols = probeProtocols(c, host, port)

	// Bail early if nothing handshook — the port probably isn't TLS.
	anySupported := false
	for _, p := range out.Protocols {
		if p.Supported {
			anySupported = true
			break
		}
	}
	if !anySupported {
		out.Err = fmt.Errorf("no TLS version handshook successfully — not a TLS endpoint?")
		out.Took = time.Since(started)
		return out
	}

	// Phase 2: probe every cipher suite (secure + insecure) against the
	// best-supported pre-1.3 version we found. TLS 1.3 ciphers don't go
	// through this path.
	probeVersion := pickCipherProbeVersion(out.Protocols)
	if probeVersion != 0 {
		out.Ciphers = probeCiphers(c, host, port, probeVersion)
	}

	// Phase 3: certificate. Grab it on a vanilla handshake (best server-chosen
	// config) — gives us the chain the server actually serves to clients.
	out.Cert = grabCert(c, host, port)

	// Phase 4: findings.
	out.Findings = grade(out)
	out.Took = time.Since(started)
	return out
}

// normalizeHostPort accepts "host", "host:port", or "[ipv6]:port" and returns
// (host, port) with port defaulted to "443".
func normalizeHostPort(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("empty host")
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, nil
	}
	return s, "443", nil
}

// probeProtocols opens one TCP+TLS handshake per supported version and
// reports success / failure per version. Concurrent — one per version.
func probeProtocols(ctx context.Context, host, port string) []ProtocolResult {
	out := make([]ProtocolResult, len(allTLSVersions))
	var wg sync.WaitGroup
	for i, v := range allTLSVersions {
		i, v := i, v
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr := ProtocolResult{Name: v.name, Version: v.v, Deprecated: v.deprecated}
			cfg := &tls.Config{
				ServerName:         host,
				MinVersion:         v.v,
				MaxVersion:         v.v,
				InsecureSkipVerify: true, // we're auditing, not validating
			}
			conn, err := dialTLS(ctx, host, port, cfg)
			if err != nil {
				pr.Error = err.Error()
				out[i] = pr
				return
			}
			defer conn.Close()
			st := conn.ConnectionState()
			pr.Supported = true
			pr.Cipher = tls.CipherSuiteName(st.CipherSuite)
			out[i] = pr
		}()
	}
	wg.Wait()
	return out
}

// pickCipherProbeVersion picks the highest pre-1.3 version the server supports.
// Returns 0 if none — meaning we can't enumerate ciphers (TLS 1.3 only).
func pickCipherProbeVersion(prs []ProtocolResult) uint16 {
	for _, target := range []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
		for _, p := range prs {
			if p.Version == target && p.Supported {
				return target
			}
		}
	}
	return 0
}

// probeCiphers probes every cipher suite Go knows about, secure and insecure,
// against a single-cipher TLS config. Concurrent with a small worker pool.
func probeCiphers(ctx context.Context, host, port string, version uint16) []CipherResult {
	type suite struct {
		s        *tls.CipherSuite
		insecure bool
	}
	var suites []suite
	for _, c := range tls.CipherSuites() {
		suites = append(suites, suite{s: c, insecure: false})
	}
	for _, c := range tls.InsecureCipherSuites() {
		suites = append(suites, suite{s: c, insecure: true})
	}

	out := make([]CipherResult, len(suites))
	sem := make(chan struct{}, 10) // cap concurrency
	var wg sync.WaitGroup
	for i, s := range suites {
		i, s := i, s
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			cr := CipherResult{Name: s.s.Name, ID: s.s.ID, Insecure: s.insecure}
			// Only probe with this cipher if it's listed for our chosen version.
			versionOK := false
			for _, sv := range s.s.SupportedVersions {
				if sv == version {
					versionOK = true
					break
				}
			}
			if !versionOK {
				out[i] = cr
				return
			}
			cfg := &tls.Config{
				ServerName:         host,
				MinVersion:         version,
				MaxVersion:         version,
				CipherSuites:       []uint16{s.s.ID},
				InsecureSkipVerify: true,
			}
			conn, err := dialTLS(ctx, host, port, cfg)
			if err != nil {
				out[i] = cr
				return
			}
			defer conn.Close()
			st := conn.ConnectionState()
			if st.CipherSuite == s.s.ID {
				cr.Supported = true
				cr.Version = tlsVersionName(st.Version)
			}
			out[i] = cr
		}()
	}
	wg.Wait()
	return out
}

// grabCert handshakes with a permissive config and captures the leaf + chain.
// Returns nil if the handshake fails (every protocol probe also failed).
func grabCert(ctx context.Context, host, port string) *CertInfo {
	cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true}
	conn, err := dialTLS(ctx, host, port, cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	leaf := st.PeerCertificates[0]
	now := time.Now()
	expired := now.After(leaf.NotAfter)
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	selfSigned := isSelfSigned(leaf)
	return &CertInfo{
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		DNSNames:      append([]string{}, leaf.DNSNames...),
		NotBefore:     leaf.NotBefore,
		NotAfter:      leaf.NotAfter,
		DaysRemaining: days,
		ChainLen:      len(st.PeerCertificates),
		SelfSigned:    selfSigned,
		Expired:       expired,
	}
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Issuer.String() == c.Subject.String()
}

// dialTLS dials host:port over TCP and completes a TLS handshake with cfg.
// Returns the connected *tls.Conn or an error.
func dialTLS(ctx context.Context, host, port string, cfg *tls.Config) (*tls.Conn, error) {
	conn, err := dialer(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, cfg)
	// Per-handshake deadline derived from context.
	if dl, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(dl)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// tlsVersionName returns the human-readable TLS version. tls.VersionName was
// added in Go 1.21; we open-code it to avoid a build-tag dance.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// grade derives the high-level findings from a Result.
func grade(r Result) []Finding {
	var fs []Finding
	for _, p := range r.Protocols {
		if p.Supported && p.Deprecated {
			fs = append(fs, Finding{
				Severity: "high",
				Title:    p.Name + " supported",
				Detail:   "Deprecated protocol; modern browsers and most clients refuse to negotiate it.",
			})
		}
	}
	weakCount := 0
	for _, c := range r.Ciphers {
		if c.Supported && c.Insecure {
			weakCount++
		}
	}
	if weakCount > 0 {
		fs = append(fs, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("%d weak cipher suite(s) supported", weakCount),
			Detail:   "Server accepted handshakes with cipher suites Go classifies as insecure (e.g. RC4, 3DES, CBC-mode with known issues).",
		})
	}
	if r.Cert != nil {
		switch {
		case r.Cert.Expired:
			fs = append(fs, Finding{
				Severity: "high",
				Title:    "Certificate expired",
				Detail:   fmt.Sprintf("Certificate not_after is %s.", r.Cert.NotAfter.Format("2006-01-02")),
			})
		case r.Cert.DaysRemaining <= 14:
			fs = append(fs, Finding{
				Severity: "high",
				Title:    "Certificate expires soon",
				Detail:   fmt.Sprintf("%d day(s) until expiry.", r.Cert.DaysRemaining),
			})
		case r.Cert.DaysRemaining <= 30:
			fs = append(fs, Finding{
				Severity: "medium",
				Title:    "Certificate expires within 30 days",
				Detail:   fmt.Sprintf("%d day(s) until expiry — start the renewal now.", r.Cert.DaysRemaining),
			})
		}
		if r.Cert.SelfSigned {
			fs = append(fs, Finding{
				Severity: "medium",
				Title:    "Self-signed certificate",
				Detail:   "Browsers and standard clients will refuse to trust this without manual override.",
			})
		}
	}
	if len(fs) == 0 {
		fs = append(fs, Finding{
			Severity: "info",
			Title:    "No issues flagged",
			Detail:   "Modern protocols only, no weak ciphers accepted, certificate healthy.",
		})
	}
	return fs
}
