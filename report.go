package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

type Report struct {
	Target    *Target
	StartedAt time.Time
	DNS       DNSResult
	TCPv4     *TCPResult
	TCPv6     *TCPResult
	TLS       *TLSResult
	HTTP      HTTPResult
}

func (r *Report) OK() bool {
	if r.DNS.Err != nil {
		return false
	}
	tcpOK := (r.TCPv4 != nil && r.TCPv4.Err == nil) || (r.TCPv6 != nil && r.TCPv6.Err == nil)
	if !tcpOK {
		return false
	}
	if r.TLS != nil && r.TLS.Err != nil {
		return false
	}
	return r.HTTP.Err == nil && r.HTTP.Status > 0 && r.HTTP.Status < 400
}

func render(w io.Writer, r *Report) {
	fmt.Fprintln(w, "NETCHECK REPORT")
	fmt.Fprintf(w, "Target: %s\n", r.Target.Raw)
	fmt.Fprintf(w, "Time:   %s\n", r.StartedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w)

	renderDNS(w, &r.DNS)
	renderTCP(w, r.TCPv4, r.TCPv6)
	if r.TLS != nil {
		renderTLS(w, r.TLS)
	}
	renderHTTP(w, &r.HTTP)
	renderSummary(w, r)
}

func mark(ok bool) string {
	if ok {
		return "[OK]"
	}
	return "[FAIL]"
}

func ms(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func renderDNS(w io.Writer, d *DNSResult) {
	fmt.Fprintln(w, "DNS")
	if d.Err != nil {
		fmt.Fprintf(w, "  %s lookup failed: %v\n", mark(false), d.Err)
		fmt.Fprintf(w, "  lookup time: %s\n\n", ms(d.Took))
		return
	}
	if len(d.A) == 0 && len(d.AAAA) == 0 {
		fmt.Fprintf(w, "  %s no records returned\n", mark(false))
	}
	for _, ip := range d.A {
		fmt.Fprintf(w, "  %s A     %s%s\n", mark(true), ip, dnsInfoSuffixFor(d, ip))
	}
	if len(d.A) == 0 {
		fmt.Fprintln(w, "    -  A     (none)")
	}
	for _, ip := range d.AAAA {
		fmt.Fprintf(w, "  %s AAAA  %s%s\n", mark(true), ip, dnsInfoSuffixFor(d, ip))
	}
	if len(d.AAAA) == 0 {
		fmt.Fprintln(w, "    -  AAAA  (none)")
	}
	fmt.Fprintf(w, "  lookup time: %s\n\n", ms(d.Took))
}

func dnsInfoSuffixFor(d *DNSResult, ip net.IP) string {
	if d == nil || d.IPInfo == nil {
		return ""
	}
	info, ok := d.IPInfo[normalizeIP(ip).String()]
	if !ok {
		return ""
	}
	return dnsInfoSuffix(&info)
}

func renderTCP(w io.Writer, v4, v6 *TCPResult) {
	if v4 == nil && v6 == nil {
		return
	}
	fmt.Fprintln(w, "TCP")
	if v4 != nil {
		if v4.Err != nil {
			fmt.Fprintf(w, "  %s IPv4 %s -- %v\n", mark(false), v4.Addr, v4.Err)
		} else {
			fmt.Fprintf(w, "  %s IPv4 %s reachable (%s)\n", mark(true), v4.Addr, ms(v4.Took))
		}
	}
	if v6 != nil {
		if v6.Err != nil {
			fmt.Fprintf(w, "  %s IPv6 %s -- %v\n", mark(false), v6.Addr, v6.Err)
		} else {
			fmt.Fprintf(w, "  %s IPv6 %s reachable (%s)\n", mark(true), v6.Addr, ms(v6.Took))
		}
	}
	fmt.Fprintln(w)
}

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
	}
	return fmt.Sprintf("0x%04x", v)
}

func renderTLS(w io.Writer, t *TLSResult) {
	fmt.Fprintln(w, "TLS")
	if t.Err != nil {
		fmt.Fprintf(w, "  %s handshake failed: %v\n\n", mark(false), t.Err)
		return
	}
	days := int(time.Until(t.NotAfter).Hours() / 24)
	fmt.Fprintf(w, "  %s Certificate valid\n", mark(days > 0))
	fmt.Fprintf(w, "    Subject:   %s\n", t.Subject)
	fmt.Fprintf(w, "    Issuer:    %s\n", t.Issuer)
	fmt.Fprintf(w, "    Protocol:  %s (cipher %s)\n", tlsVersionName(t.Version), tls.CipherSuiteName(t.CipherSuite))
	fmt.Fprintf(w, "    Expires:   %s (%d days)\n", t.NotAfter.Format("2006-01-02"), days)
	fmt.Fprintf(w, "    Chain:     %d cert(s)\n", len(t.Chain))
	if len(t.DNSNames) > 0 {
		names := t.DNSNames
		more := 0
		if len(names) > 5 {
			more = len(names) - 5
			names = names[:5]
		}
		if more > 0 {
			fmt.Fprintf(w, "    SANs:      %v (+%d more)\n", names, more)
		} else {
			fmt.Fprintf(w, "    SANs:      %v\n", names)
		}
	}
	fmt.Fprintf(w, "  handshake time: %s\n\n", ms(t.Took))
}

func renderHTTP(w io.Writer, h *HTTPResult) {
	fmt.Fprintln(w, "HTTP")
	if h.Err != nil {
		fmt.Fprintf(w, "  %s request failed: %v\n\n", mark(false), h.Err)
		return
	}
	fmt.Fprintf(w, "  %s Status:    %d\n", mark(h.Status < 400), h.Status)
	fmt.Fprintf(w, "    Protocol:  %s\n", h.Proto)
	if h.Server != "" {
		fmt.Fprintf(w, "    Server:    %s\n", h.Server)
	}
	fmt.Fprintf(w, "    Final URL: %s\n", h.FinalURL)
	if len(h.Hops) > 0 {
		fmt.Fprintf(w, "    Redirects: %d\n", len(h.Hops))
		for i, hop := range h.Hops {
			fmt.Fprintf(w, "      %d. %d  %s\n", i+1, hop.Status, hop.URL)
		}
	} else {
		fmt.Fprintln(w, "    Redirects: 0")
	}
	fmt.Fprintln(w, "  Timing (first request):")
	fmt.Fprintf(w, "    DNS:     %s\n", ms(h.DNSTime))
	fmt.Fprintf(w, "    Connect: %s\n", ms(h.ConnectTime))
	if h.TLSTime > 0 {
		fmt.Fprintf(w, "    TLS:     %s\n", ms(h.TLSTime))
	}
	fmt.Fprintf(w, "    TTFB:    %s\n", ms(h.TTFB))
	fmt.Fprintf(w, "    Total:   %s\n\n", ms(h.Total))
}

func renderSummary(w io.Writer, r *Report) {
	fmt.Fprintln(w, "Summary")
	fmt.Fprintf(w, "  %s DNS\n", mark(r.DNS.Err == nil && (len(r.DNS.A) > 0 || len(r.DNS.AAAA) > 0)))
	tcpOK := (r.TCPv4 != nil && r.TCPv4.Err == nil) || (r.TCPv6 != nil && r.TCPv6.Err == nil)
	fmt.Fprintf(w, "  %s TCP\n", mark(tcpOK))
	if r.TLS != nil {
		fmt.Fprintf(w, "  %s TLS\n", mark(r.TLS.Err == nil))
	}
	fmt.Fprintf(w, "  %s HTTP\n", mark(r.HTTP.Err == nil && r.HTTP.Status > 0 && r.HTTP.Status < 400))
}
