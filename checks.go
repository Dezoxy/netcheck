package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

type Target struct {
	Raw    string
	URL    *url.URL
	Host   string
	Port   string
	Scheme string
}

func parseTarget(s string) (*Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty target")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("no hostname in %q", s)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return &Target{Raw: s, URL: u, Host: u.Hostname(), Port: port, Scheme: u.Scheme}, nil
}

type DNSResult struct {
	A      []net.IP
	AAAA   []net.IP
	IPInfo map[string]DNSIPInfo
	Err    error
	Took   time.Duration
}

func lookupDNS(ctx context.Context, host string) DNSResult {
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	res := DNSResult{Took: time.Since(start)}
	if err != nil {
		res.Err = err
		return res
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			res.A = append(res.A, v4)
		} else {
			res.AAAA = append(res.AAAA, a.IP)
		}
	}
	return res
}

type TCPResult struct {
	Addr string
	Err  error
	Took time.Duration
}

func checkTCP(ctx context.Context, ip net.IP, port string) TCPResult {
	addr := net.JoinHostPort(ip.String(), port)
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	took := time.Since(start)
	if err != nil {
		return TCPResult{Addr: addr, Err: err, Took: took}
	}
	conn.Close()
	return TCPResult{Addr: addr, Took: took}
}

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

func checkTLS(ctx context.Context, host, port string, insecure bool) TLSResult {
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

type HTTPHop struct {
	URL    string
	Status int
}

type HTTPResult struct {
	Status      int
	FinalURL    string
	Hops        []HTTPHop
	Server      string
	Proto       string
	DNSTime     time.Duration
	ConnectTime time.Duration
	TLSTime     time.Duration
	TTFB        time.Duration
	Total       time.Duration
	Err         error
}

func checkHTTP(ctx context.Context, target *Target, insecure bool) HTTPResult {
	var hops []HTTPHop
	var dnsTime, connectTime, tlsTime, ttfb time.Duration
	var dnsStart, connStart, tlsStart, gotConn time.Time

	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { dnsTime = time.Since(dnsStart) },
		ConnectStart:      func(string, string) { connStart = time.Now() },
		ConnectDone:       func(string, string, error) { connectTime = time.Since(connStart) },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { tlsTime = time.Since(tlsStart) },
		GotConn:           func(httptrace.GotConnInfo) { gotConn = time.Now() },
		GotFirstResponseByte: func() {
			if !gotConn.IsZero() {
				ttfb = time.Since(gotConn)
			}
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Response != nil && len(via) > 0 {
				prev := via[len(via)-1]
				hops = append(hops, HTTPHop{URL: prev.URL.String(), Status: req.Response.StatusCode})
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", target.Raw, nil)
	if err != nil {
		return HTTPResult{Err: err}
	}
	req.Header.Set("User-Agent", "netcheck/0.1")

	start := time.Now()
	resp, err := client.Do(req)
	total := time.Since(start)
	if err != nil {
		return HTTPResult{Err: err, Total: total, Hops: hops, DNSTime: dnsTime, ConnectTime: connectTime, TLSTime: tlsTime}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	return HTTPResult{
		Status:      resp.StatusCode,
		FinalURL:    resp.Request.URL.String(),
		Hops:        hops,
		Server:      resp.Header.Get("Server"),
		Proto:       resp.Proto,
		DNSTime:     dnsTime,
		ConnectTime: connectTime,
		TLSTime:     tlsTime,
		TTFB:        ttfb,
		Total:       total,
	}
}
