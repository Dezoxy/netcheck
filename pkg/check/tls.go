package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

// TLSResult holds the outcome of a TLS handshake to host:port, including the
// leaf certificate's key fields and the full presented chain.
type TLSResult struct {
	Version     uint16
	CipherSuite uint16
	Issuer      string
	Subject     string
	DNSNames    []string
	NotBefore   time.Time
	NotAfter    time.Time
	Chain       []*x509.Certificate
	Err         error
	Took        time.Duration
}

// TLS performs a TLS handshake using host as the SNI value. When insecure is
// true the handshake skips certificate verification (used for inspecting
// expired/self-signed/wrong-host certs without aborting).
func TLS(ctx context.Context, host, port string, insecure bool) TLSResult {
	start := time.Now()
	d := tls.Dialer{
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	took := time.Since(start)
	if err != nil {
		return TLSResult{Err: err, Took: took}
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return TLSResult{Err: errors.New("connection is not TLS"), Took: took}
	}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return TLSResult{Err: errors.New("no peer certificates"), Took: took}
	}
	leaf := state.PeerCertificates[0]
	return TLSResult{
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		Issuer:      leaf.Issuer.CommonName,
		Subject:     leaf.Subject.CommonName,
		DNSNames:    leaf.DNSNames,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Chain:       state.PeerCertificates,
		Took:        took,
	}
}
