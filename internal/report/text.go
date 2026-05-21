package report

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"text/tabwriter"
	"time"

	"netcheck/internal/check"
	"netcheck/internal/dnscompare"
	"netcheck/internal/ipinfo"
)

// Render writes the full text report to w.
func Render(w io.Writer, r *Report) {
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

func renderDNS(w io.Writer, d *check.DNSResult) {
	fmt.Fprintln(w, "DNS")
	if d.Err != nil {
		fmt.Fprintf(w, "  %s lookup failed: %v\n", Mark(false), d.Err)
		fmt.Fprintf(w, "  lookup time: %s\n\n", MS(d.Took))
		return
	}
	if len(d.A) == 0 && len(d.AAAA) == 0 {
		fmt.Fprintf(w, "  %s no records returned\n", Mark(false))
	}
	for _, ip := range d.A {
		fmt.Fprintf(w, "  %s A     %s%s\n", Mark(true), ip, dnsInfoSuffixFor(d, ip))
	}
	if len(d.A) == 0 {
		fmt.Fprintln(w, "    -  A     (none)")
	}
	for _, ip := range d.AAAA {
		fmt.Fprintf(w, "  %s AAAA  %s%s\n", Mark(true), ip, dnsInfoSuffixFor(d, ip))
	}
	if len(d.AAAA) == 0 {
		fmt.Fprintln(w, "    -  AAAA  (none)")
	}
	fmt.Fprintf(w, "  lookup time: %s\n\n", MS(d.Took))
}

func dnsInfoSuffixFor(d *check.DNSResult, ip net.IP) string {
	if d == nil || d.IPInfo == nil {
		return ""
	}
	info, ok := d.IPInfo[ipinfo.NormalizeIP(ip).String()]
	if !ok {
		return ""
	}
	return ipinfo.DNSInfoSuffix(&info)
}

func renderTCP(w io.Writer, v4, v6 *check.TCPResult) {
	if v4 == nil && v6 == nil {
		return
	}
	fmt.Fprintln(w, "TCP")
	if v4 != nil {
		if v4.Err != nil {
			fmt.Fprintf(w, "  %s IPv4 %s -- %v\n", Mark(false), v4.Addr, v4.Err)
		} else {
			fmt.Fprintf(w, "  %s IPv4 %s reachable (%s)\n", Mark(true), v4.Addr, MS(v4.Took))
		}
	}
	if v6 != nil {
		if v6.Err != nil {
			fmt.Fprintf(w, "  %s IPv6 %s -- %v\n", Mark(false), v6.Addr, v6.Err)
		} else {
			fmt.Fprintf(w, "  %s IPv6 %s reachable (%s)\n", Mark(true), v6.Addr, MS(v6.Took))
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

func renderTLS(w io.Writer, t *check.TLSResult) {
	fmt.Fprintln(w, "TLS")
	if t.Err != nil {
		fmt.Fprintf(w, "  %s handshake failed: %v\n\n", Mark(false), t.Err)
		return
	}
	days := int(time.Until(t.NotAfter).Hours() / 24)
	fmt.Fprintf(w, "  %s Certificate valid\n", Mark(days > 0))
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
	fmt.Fprintf(w, "  handshake time: %s\n\n", MS(t.Took))
}

func renderHTTP(w io.Writer, h *check.HTTPResult) {
	fmt.Fprintln(w, "HTTP")
	if h.Err != nil {
		fmt.Fprintf(w, "  %s request failed: %v\n\n", Mark(false), h.Err)
		return
	}
	fmt.Fprintf(w, "  %s Status:    %d\n", Mark(h.Status < 400), h.Status)
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
	fmt.Fprintf(w, "    DNS:     %s\n", MS(h.DNSTime))
	fmt.Fprintf(w, "    Connect: %s\n", MS(h.ConnectTime))
	if h.TLSTime > 0 {
		fmt.Fprintf(w, "    TLS:     %s\n", MS(h.TLSTime))
	}
	fmt.Fprintf(w, "    TTFB:    %s\n", MS(h.TTFB))
	fmt.Fprintf(w, "    Total:   %s\n\n", MS(h.Total))
}

func renderSummary(w io.Writer, r *Report) {
	fmt.Fprintln(w, "Summary")
	fmt.Fprintf(w, "  %s DNS\n", Mark(r.DNS.Err == nil && (len(r.DNS.A) > 0 || len(r.DNS.AAAA) > 0)))
	tcpOK := (r.TCPv4 != nil && r.TCPv4.Err == nil) || (r.TCPv6 != nil && r.TCPv6.Err == nil)
	fmt.Fprintf(w, "  %s TCP\n", Mark(tcpOK))
	if r.TLS != nil {
		fmt.Fprintf(w, "  %s TLS\n", Mark(r.TLS.Err == nil))
	}
	fmt.Fprintf(w, "  %s HTTP\n", Mark(r.HTTP.Err == nil && r.HTTP.Status > 0 && r.HTTP.Status < 400))
}

// RenderDNSCompare writes the multi-resolver DNS comparison table to w.
func RenderDNSCompare(w io.Writer, r *dnscompare.Result) {
	fmt.Fprintf(w, "%s records\n", r.QType)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  RESOLVER\tADDRESS\tTIME\tANSWER")
	for _, res := range r.Results {
		addr := res.Resolver.Address
		took := MS(res.Took)
		if res.Err != nil {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s %v\n", res.Resolver.Name, addr, took, Mark(false), res.Err)
			continue
		}
		if len(res.Records) == 0 {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t(no records)\n", res.Resolver.Name, addr, took)
			continue
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", res.Resolver.Name, addr, took, res.Records[0])
		for _, rec := range res.Records[1:] {
			fmt.Fprintf(tw, "  \t\t\t%s\n", rec)
		}
	}
	tw.Flush()

	v := r.Verdict()
	switch {
	case len(v.Groups) == 0:
		fmt.Fprintln(w, "  Verdict: all resolvers failed")
	case v.Agree:
		fmt.Fprintln(w, "  Verdict: all resolvers agree")
	default:
		fmt.Fprintf(w, "  Verdict: resolvers disagree (%d distinct answer sets)\n", len(v.Groups))
		for i, g := range v.Groups {
			fmt.Fprintf(w, "    Set %d (%s):\n", i+1, strings.Join(g.Resolvers, ", "))
			if len(g.Records) == 0 {
				fmt.Fprintln(w, "      (empty)")
			}
			for _, rec := range g.Records {
				fmt.Fprintf(w, "      %s\n", rec)
			}
		}
	}
	fmt.Fprintln(w)
}

// RenderIPInfo writes the IP-ownership block for one or more IPs. When the
// caller resolved a hostname, set fromHost=true and pass resolveTook for the
// "Resolved: N address(es) in <T>" header line.
func RenderIPInfo(w io.Writer, targetLabel string, details []ipinfo.IPDetails, fromHost bool, resolveTook time.Duration) {
	fmt.Fprintln(w, "IP INFO")
	fmt.Fprintf(w, "Target:   %s\n", targetLabel)
	fmt.Fprintf(w, "Time:     %s\n", nowFn().Format("2006-01-02 15:04:05"))
	if fromHost {
		fmt.Fprintf(w, "Resolved: %d address(es) in %s\n", len(details), MS(resolveTook))
	}

	for i, info := range details {
		if i > 0 || fromHost {
			fmt.Fprintln(w)
		}
		if !fromHost {
			renderIPFields(w, info)
			continue
		}
		renderIPBlock(w, "Address", info)
	}
}

func renderIPBlock(w io.Writer, label string, info ipinfo.IPDetails) {
	fmt.Fprintf(w, "%-9s %s\n", label+":", info.IP)
	renderIPFields(w, info)
}

func renderIPFields(w io.Writer, info ipinfo.IPDetails) {
	fmt.Fprintf(w, "Reverse:  %s\n", formatReverse(info.Reverse))
	fmt.Fprintf(w, "ASN:      %s\n", ipinfo.FormatASNDetails(info.ASN, info.RDAP))
	fmt.Fprintf(w, "Country:  %s\n", countryFor(info))
	fmt.Fprintf(w, "Prefix:   %s\n", prefixFor(info))
	fmt.Fprintf(w, "Registry: %s\n", registryFor(info))
	fmt.Fprintf(w, "CDN:      %s\n", formatCDN(info.CDN))
	fmt.Fprintf(w, "Abuse:    %s\n", abuseFor(info))
}

func formatReverse(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ", ")
}

func countryFor(info ipinfo.IPDetails) string {
	if info.ASN != nil && info.ASN.Country != "" {
		return info.ASN.Country
	}
	if info.RDAP != nil && info.RDAP.Country != "" {
		return info.RDAP.Country
	}
	return "-"
}

func prefixFor(info ipinfo.IPDetails) string {
	if info.ASN != nil && info.ASN.Prefix != "" {
		return info.ASN.Prefix
	}
	return "-"
}

func registryFor(info ipinfo.IPDetails) string {
	if info.RDAP != nil && info.RDAP.Registry != "" {
		return info.RDAP.Registry
	}
	if info.ASN != nil && info.ASN.Registry != "" {
		return info.ASN.Registry
	}
	return "-"
}

func abuseFor(info ipinfo.IPDetails) string {
	if info.RDAP != nil && info.RDAP.AbuseEmail != "" {
		return info.RDAP.AbuseEmail
	}
	return "-"
}

func formatCDN(match ipinfo.CDNMatch) string {
	if match.Provider == "" {
		return "-"
	}
	if match.Confidence == "" || match.Reason == "" {
		return match.Provider
	}
	return fmt.Sprintf("%s (%s confidence - %s)", match.Provider, match.Confidence, match.Reason)
}
