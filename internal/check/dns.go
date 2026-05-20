// Package check provides the four primitives behind the `full` URL check:
// DNS resolution, TCP connection, TLS handshake, and HTTP request.
package check

import (
	"context"
	"net"
	"time"

	"netcheck/internal/ipinfo"
)

// DNSResult holds the outcome of a single hostname lookup, optionally enriched
// with per-IP ASN/CDN/PTR info via the IPInfo map (populated by callers after
// the lookup completes — keeps this package free of HTTP dependencies).
type DNSResult struct {
	A      []net.IP
	AAAA   []net.IP
	IPInfo map[string]ipinfo.DNSIPInfo
	Err    error
	Took   time.Duration
}

// LookupDNS resolves the host via the system resolver and splits results by family.
func LookupDNS(ctx context.Context, host string) DNSResult {
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
