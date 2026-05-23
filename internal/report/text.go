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
	days := daysRemaining(t.NotAfter)
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

// RenderHeaders writes the security-header audit as text.
func RenderHeaders(w io.Writer, d HeadersJSON) {
	fmt.Fprintln(w, "SECURITY HEADERS")
	fmt.Fprintf(w, "URL:      %s\n", d.URL)
	if d.FinalURL != "" && d.FinalURL != d.URL {
		fmt.Fprintf(w, "Final:    %s\n", d.FinalURL)
	}
	if d.Status != 0 {
		fmt.Fprintf(w, "Status:   %d\n", d.Status)
	}
	fmt.Fprintf(w, "Time:     %s (%dms)\n", d.StartedAt.Format("2006-01-02 15:04:05"), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "  %s audit failed: %s\n", Mark(false), d.Error)
		return
	}
	fmt.Fprintln(w)

	for _, f := range d.Findings {
		fmt.Fprintf(w, "  %s %s\n", gradeText(f.Grade), f.Name)
		if f.Value != "" {
			fmt.Fprintf(w, "      value: %s\n", f.Value)
		}
		if f.Comment != "" {
			fmt.Fprintf(w, "      note:  %s\n", f.Comment)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %d pass · %d weak · %d missing · %d info\n",
		d.Summary.Pass, d.Summary.Weak, d.Summary.Missing, d.Summary.Info)
}

// RenderTLSAudit writes the TLS audit result as text.
func RenderTLSAudit(w io.Writer, d TLSAuditJSON) {
	fmt.Fprintln(w, "TLS AUDIT")
	fmt.Fprintf(w, "Host:     %s:%s\n", d.Host, d.Port)
	fmt.Fprintf(w, "Time:     %s (%dms)\n", d.StartedAt.Format("2006-01-02 15:04:05"), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "  %s audit failed: %s\n", Mark(false), d.Error)
		return
	}
	fmt.Fprintln(w)

	// Protocol matrix.
	fmt.Fprintln(w, "Protocols")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range d.Protocols {
		mark := "[ -- ]"
		extra := ""
		if p.Supported {
			mark = "[ OK ]"
			extra = "  cipher=" + p.Cipher
		}
		if p.Deprecated {
			mark = mark + "  DEPRECATED"
		}
		fmt.Fprintf(tw, "  %s\t%s%s\n", mark, p.Name, extra)
	}
	tw.Flush()
	fmt.Fprintln(w)

	// Supported ciphers (already filtered to supported only).
	if len(d.Ciphers) > 0 {
		fmt.Fprintf(w, "Supported cipher suites (%d):\n", len(d.Ciphers))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, c := range d.Ciphers {
			tag := ""
			if c.Insecure {
				tag = "  WEAK"
			}
			fmt.Fprintf(tw, "  %s\t%s%s\n", c.Version, c.Name, tag)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	// Certificate.
	if d.Cert != nil {
		fmt.Fprintln(w, "Certificate")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  Subject\t%s\n", d.Cert.Subject)
		fmt.Fprintf(tw, "  Issuer\t%s\n", d.Cert.Issuer)
		if len(d.Cert.DNSNames) > 0 {
			fmt.Fprintf(tw, "  Names\t%s\n", strings.Join(d.Cert.DNSNames, ", "))
		}
		fmt.Fprintf(tw, "  Not before\t%s\n", d.Cert.NotBefore.Format("2006-01-02"))
		fmt.Fprintf(tw, "  Not after\t%s (%d days)\n", d.Cert.NotAfter.Format("2006-01-02"), d.Cert.DaysRemaining)
		fmt.Fprintf(tw, "  Chain length\t%d\n", d.Cert.ChainLen)
		if d.Cert.SelfSigned {
			fmt.Fprintln(tw, "  Self-signed\ttrue")
		}
		if d.Cert.Expired {
			fmt.Fprintln(tw, "  Expired\ttrue")
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	// Findings.
	fmt.Fprintln(w, "Findings")
	for _, f := range d.Findings {
		fmt.Fprintf(w, "  [%s] %s\n", severityTag(f.Severity), f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, "         %s\n", f.Detail)
		}
	}
}

// severityTag formats a severity as a 6-char tag for the text report.
func severityTag(s string) string {
	switch s {
	case "high":
		return "HIGH  "
	case "medium":
		return "MEDIUM"
	case "info":
		return "INFO  "
	default:
		return "      "
	}
}

// RenderReverse writes the reverse-IP result as text.
func RenderReverse(w io.Writer, d ReverseJSON) {
	fmt.Fprintln(w, "REVERSE IP LOOKUP")
	fmt.Fprintf(w, "IP:       %s\n", d.IP)
	fmt.Fprintf(w, "Time:     %s (%dms)\n", d.StartedAt.Format("2006-01-02 15:04:05"), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "  %s lookup failed: %s\n", Mark(false), d.Error)
		return
	}
	fmt.Fprintln(w)

	if len(d.Hostnames) == 0 {
		fmt.Fprintln(w, "  (no hostnames found)")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  HOSTNAME\tSOURCES")
		for _, h := range d.Hostnames {
			fmt.Fprintf(tw, "  %s\t%s\n", h.Name, strings.Join(h.Sources, ", "))
		}
		tw.Flush()
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Total: %d hostname(s)\n", len(d.Hostnames))
	}

	if len(d.SourceDisabled) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Disabled (no API key): %s\n", strings.Join(d.SourceDisabled, ", "))
	}
	if len(d.SourceErrors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Source errors:")
		for name, err := range d.SourceErrors {
			fmt.Fprintf(w, "  %s: %s\n", name, err)
		}
	}
}

// RenderArch writes the Wayback / archive.org result as text.
func RenderArch(w io.Writer, d ArchJSON) {
	fmt.Fprintln(w, "WAYBACK ARCHIVE")
	fmt.Fprintf(w, "Domain:   %s\n", d.Domain)
	fmt.Fprintf(w, "Time:     %s (%dms)\n", d.StartedAt.Format("2006-01-02 15:04:05"), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "  %s lookup failed: %s\n", Mark(false), d.Error)
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total snapshots: %d\n", d.Total)
	fmt.Fprintf(w, "Unique URLs:     %d\n", d.UniqueURLs)
	if d.First != nil {
		fmt.Fprintf(w, "First seen:      %s\n", d.First.Format("2006-01-02"))
	}
	if d.Last != nil {
		fmt.Fprintf(w, "Last seen:       %s\n", d.Last.Format("2006-01-02"))
	}

	if len(d.RecentSamples) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Recent snapshots (showing %d, newest first):\n", len(d.RecentSamples))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  DATE\tSTATUS\tURL")
	for _, s := range d.RecentSamples {
		status := "-"
		if s.Status > 0 {
			status = fmt.Sprintf("%d", s.Status)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", s.Timestamp.Format("2006-01-02"), status, s.URL)
	}
	tw.Flush()
}

// RenderSubs writes the subdomain enumeration result as text.
func RenderSubs(w io.Writer, d SubsJSON) {
	fmt.Fprintln(w, "SUBDOMAIN ENUMERATION")
	fmt.Fprintf(w, "Domain:   %s\n", d.Domain)
	fmt.Fprintf(w, "Time:     %s (%dms)\n", d.StartedAt.Format("2006-01-02 15:04:05"), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "  %s enumeration failed: %s\n", Mark(false), d.Error)
		return
	}
	fmt.Fprintln(w)

	if len(d.Subdomains) == 0 && len(d.SourceErrors) == len(allSubsSources()) {
		fmt.Fprintln(w, "  (no subdomains found — every source errored)")
	} else if len(d.Subdomains) == 0 {
		fmt.Fprintln(w, "  (no subdomains found in CT logs)")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAME\tSOURCES")
		for _, s := range d.Subdomains {
			fmt.Fprintf(tw, "  %s\t%s\n", s.Name, strings.Join(s.Sources, ", "))
		}
		tw.Flush()
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Total: %d subdomain(s)\n", len(d.Subdomains))
	}

	if len(d.SourceErrors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Source errors:")
		for name, err := range d.SourceErrors {
			fmt.Fprintf(w, "  %s: %s\n", name, err)
		}
	}
}

// allSubsSources returns the names of every CT source we query — used by the
// text renderer to decide whether "no results" means "no findings" vs
// "everything was down". The strings here have to match the Name()
// returned by each subenum.Source implementation.
func allSubsSources() []string { return []string{"crt.sh", "certspotter"} }

// RenderTech writes the tech-detection result as text.
func RenderTech(w io.Writer, d TechJSON) {
	fmt.Fprintln(w, "TECH FINGERPRINT")
	fmt.Fprintf(w, "URL:      %s\n", d.URL)
	if d.FinalURL != "" && d.FinalURL != d.URL {
		fmt.Fprintf(w, "Final:    %s\n", d.FinalURL)
	}
	if d.Status != 0 {
		fmt.Fprintf(w, "Status:   %d\n", d.Status)
	}
	fmt.Fprintf(w, "Time:     %s (%dms)\n", d.StartedAt.Format("2006-01-02 15:04:05"), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "  %s detect failed: %s\n", Mark(false), d.Error)
		return
	}
	fmt.Fprintln(w)

	if len(d.Matches) == 0 {
		fmt.Fprintln(w, "  (no known technologies fingerprinted)")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tCATEGORY\tVERSION\tCONFIDENCE\tEVIDENCE")
	for _, m := range d.Matches {
		ver := m.Version
		if ver == "" {
			ver = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", m.Name, m.Category, ver, m.Confidence, m.Evidence)
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total: %d match(es)\n", len(d.Matches))
}

// gradeText renders the grade as a fixed-width tag for the text report.
func gradeText(g string) string {
	switch g {
	case "pass":
		return "[PASS   ]"
	case "weak":
		return "[WEAK   ]"
	case "missing":
		return "[MISSING]"
	case "info":
		return "[INFO   ]"
	default:
		return "[       ]"
	}
}
