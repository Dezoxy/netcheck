package check

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	"netcheck/internal/target"
)

// HTTPHop is one step in a redirect chain.
type HTTPHop struct {
	URL    string
	Status int
}

// userAgent is the User-Agent header sent by the HTTP check.
// main.go wires the canonical "netcheck/<version>" (or the config override)
// via SetUserAgent at startup.
var userAgent = "netcheck"

// SetUserAgent sets the User-Agent string used by HTTP checks.
// Safe to call once at startup before any check runs.
func SetUserAgent(s string) {
	if s != "" {
		userAgent = s
	}
}

// HTTPResult captures status, redirect chain, server info, and detailed timing
// for an HTTP GET against the target.
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

// HTTP issues a GET to target.Raw, follows up to 10 redirects, and uses
// httptrace to break down where the time went.
func HTTP(ctx context.Context, t *target.Target, insecure bool) HTTPResult {
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

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", t.Raw, nil)
	if err != nil {
		return HTTPResult{Err: err}
	}
	req.Header.Set("User-Agent", userAgent)

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
