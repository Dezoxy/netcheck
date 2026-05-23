package report

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// RenderFullMD writes a Markdown rendering of the full check Report.
func RenderFullMD(w io.Writer, r *Report) {
	d := ToFullJSON(r)
	fmt.Fprintf(w, "# netcheck report\n\n")
	fmt.Fprintf(w, "- **Target:** `%s`\n", d.Target.Raw)
	fmt.Fprintf(w, "- **Time:** %s\n", d.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "- **Status:** %s\n\n", okLabel(d.OK))

	// DNS
	fmt.Fprintln(w, "## DNS")
	if d.DNS.Error != "" {
		fmt.Fprintf(w, "Lookup failed: `%s`\n\n", d.DNS.Error)
	} else {
		fmt.Fprintln(w, "| Type | IP | ASN | CDN | Reverse |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, ip := range d.DNS.A {
			info := d.DNS.IPInfo[ip]
			fmt.Fprintf(w, "| A | `%s` | %s | %s | %s |\n",
				ip, mdASN(info.ASN), mdCDN(info.CDN), mdList(info.Reverse))
		}
		for _, ip := range d.DNS.AAAA {
			info := d.DNS.IPInfo[ip]
			fmt.Fprintf(w, "| AAAA | `%s` | %s | %s | %s |\n",
				ip, mdASN(info.ASN), mdCDN(info.CDN), mdList(info.Reverse))
		}
		fmt.Fprintf(w, "\n_lookup time: %dms_\n\n", d.DNS.TookMS)
	}

	// TCP
	if d.TCPv4 != nil || d.TCPv6 != nil {
		fmt.Fprintln(w, "## TCP")
		fmt.Fprintln(w, "| Family | Address | Status | Time |")
		fmt.Fprintln(w, "|---|---|---|---|")
		if d.TCPv4 != nil {
			fmt.Fprintf(w, "| IPv4 | `%s` | %s | %dms |\n", d.TCPv4.Addr, mdTCPStatus(d.TCPv4), d.TCPv4.TookMS)
		}
		if d.TCPv6 != nil {
			fmt.Fprintf(w, "| IPv6 | `%s` | %s | %dms |\n", d.TCPv6.Addr, mdTCPStatus(d.TCPv6), d.TCPv6.TookMS)
		}
		fmt.Fprintln(w)
	}

	// TLS
	if d.TLS != nil {
		fmt.Fprintln(w, "## TLS")
		if d.TLS.Error != "" {
			fmt.Fprintf(w, "Handshake failed: `%s`\n\n", d.TLS.Error)
		} else {
			fmt.Fprintf(w, "- **Subject:** %s\n", d.TLS.Subject)
			fmt.Fprintf(w, "- **Issuer:** %s\n", d.TLS.Issuer)
			fmt.Fprintf(w, "- **Protocol:** %s (cipher `%s`)\n", d.TLS.Version, d.TLS.CipherSuite)
			fmt.Fprintf(w, "- **Expires:** %s (%d days)\n", d.TLS.NotAfter.Format("2006-01-02"), d.TLS.DaysRemaining)
			fmt.Fprintf(w, "- **Chain:** %d cert(s)\n", d.TLS.ChainCount)
			fmt.Fprintf(w, "- **Handshake time:** %dms\n\n", d.TLS.TookMS)
		}
	}

	// HTTP
	fmt.Fprintln(w, "## HTTP")
	if d.HTTP.Error != "" {
		fmt.Fprintf(w, "Request failed: `%s`\n\n", d.HTTP.Error)
	} else {
		fmt.Fprintf(w, "- **Status:** %d\n", d.HTTP.Status)
		fmt.Fprintf(w, "- **Protocol:** %s\n", d.HTTP.Proto)
		if d.HTTP.Server != "" {
			fmt.Fprintf(w, "- **Server:** %s\n", d.HTTP.Server)
		}
		fmt.Fprintf(w, "- **Final URL:** `%s`\n", d.HTTP.FinalURL)
		if len(d.HTTP.Hops) > 0 {
			fmt.Fprintf(w, "- **Redirects:** %d\n", len(d.HTTP.Hops))
			for i, h := range d.HTTP.Hops {
				fmt.Fprintf(w, "  %d. `%d` → `%s`\n", i+1, h.Status, h.URL)
			}
		}
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "**Timing (ms):**")
		fmt.Fprintln(w, "| DNS | Connect | TLS | TTFB | Total |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		fmt.Fprintf(w, "| %d | %d | %d | %d | %d |\n\n",
			d.HTTP.Timing.DNSMS, d.HTTP.Timing.ConnectMS, d.HTTP.Timing.TLSMS, d.HTTP.Timing.TTFBMS, d.HTTP.Timing.TotalMS)
	}
}

// RenderDNSCompareMD writes a Markdown rendering of a multi-query DNS compare run.
func RenderDNSCompareMD(w io.Writer, d DNSCompareJSON) {
	fmt.Fprintf(w, "# netcheck dns compare — `%s`\n\n", d.Host)
	fmt.Fprintf(w, "_%s_\n\n", d.StartedAt.Format(time.RFC3339))

	for _, q := range d.Queries {
		fmt.Fprintf(w, "## %s records\n\n", q.QType)
		fmt.Fprintln(w, "| Resolver | Address | Time | Answer |")
		fmt.Fprintln(w, "|---|---|---|---|")
		for _, r := range q.Results {
			if r.Error != "" {
				fmt.Fprintf(w, "| %s | `%s` | %dms | _error: %s_ |\n", r.Name, r.Address, r.TookMS, r.Error)
				continue
			}
			ans := "_(no records)_"
			if len(r.Records) > 0 {
				ans = "`" + strings.Join(r.Records, "` `") + "`"
			}
			fmt.Fprintf(w, "| %s | `%s` | %dms | %s |\n", r.Name, r.Address, r.TookMS, ans)
		}
		fmt.Fprintln(w)
		if q.Verdict.Agree {
			fmt.Fprintln(w, "**Verdict:** all resolvers agree.")
		} else if len(q.Verdict.Groups) == 0 {
			fmt.Fprintln(w, "**Verdict:** all resolvers failed.")
		} else {
			fmt.Fprintf(w, "**Verdict:** resolvers disagree (%d distinct answer sets).\n", len(q.Verdict.Groups))
			for i, g := range q.Verdict.Groups {
				fmt.Fprintf(w, "- Set %d (%s): `%s`\n", i+1, strings.Join(g.Resolvers, ", "), strings.Join(g.Records, "`, `"))
			}
		}
		fmt.Fprintln(w)
	}
}

// RenderRouteMD writes a Markdown rendering of a route run.
func RenderRouteMD(w io.Writer, d RouteJSON) {
	fmt.Fprintf(w, "# netcheck route — `%s`", d.Host)
	if d.DestIP != "" {
		fmt.Fprintf(w, " (`%s`)", d.DestIP)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "\n_%s · %s %s_\n\n", d.StartedAt.Format(time.RFC3339), d.Tool, strings.Join(d.ToolArgs, " "))

	fmt.Fprintln(w, "| Hop | Address | RTT (ms) | ASN |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, h := range d.Hops {
		addr := "`*`"
		rtt := "`*`"
		asn := ""
		if !h.Timeout {
			addr = mdHopAddr(h)
			rtt = mdHopRTT(h)
			if h.ASN != nil {
				asn = "`AS" + h.ASN.ASN + "` " + h.ASN.Org
			}
		}
		fmt.Fprintf(w, "| %d | %s | %s | %s |\n", h.N, addr, rtt, asn)
	}
	fmt.Fprintln(w)
	if d.Reached {
		fmt.Fprintf(w, "**Reached `%s` in %d hops.**\n", d.DestIP, len(d.Hops))
	} else if len(d.Hops) > 0 {
		fmt.Fprintf(w, "**Stopped after %d hops (destination not confirmed).**\n", len(d.Hops))
	}
	if d.Timeouts > 0 {
		fmt.Fprintf(w, "\n_%d hop(s) timed out — routers commonly drop or rate-limit probes; missing hops do not always mean a broken route._\n", d.Timeouts)
	}
}

// RenderIPInfoMD writes a Markdown rendering of an IP info run.
func RenderIPInfoMD(w io.Writer, d IPInfoJSON) {
	fmt.Fprintf(w, "# netcheck ip — `%s`\n\n", d.Target)
	fmt.Fprintf(w, "_%s", d.StartedAt.Format(time.RFC3339))
	if d.FromHost {
		fmt.Fprintf(w, " · resolved %d address(es) in %dms", len(d.Details), d.ResolveTookMS)
	}
	fmt.Fprintln(w, "_")
	fmt.Fprintln(w)

	for i, det := range d.Details {
		if d.FromHost {
			fmt.Fprintf(w, "## `%s`\n\n", det.IP)
		}
		fmt.Fprintf(w, "- **Reverse:** %s\n", mdList(det.Reverse))
		fmt.Fprintf(w, "- **ASN:** %s\n", mdASN(det.ASN))
		fmt.Fprintf(w, "- **Country:** %s\n", mdField(asnCountry(det.ASN), rdapCountry(det.RDAP)))
		fmt.Fprintf(w, "- **Prefix:** %s\n", mdField(asnPrefix(det.ASN)))
		fmt.Fprintf(w, "- **Registry:** %s\n", mdField(rdapRegistry(det.RDAP), asnRegistry(det.ASN)))
		fmt.Fprintf(w, "- **CDN:** %s\n", mdCDN(det.CDN))
		fmt.Fprintf(w, "- **Abuse:** %s\n", mdField(rdapAbuse(det.RDAP)))
		if i < len(d.Details)-1 {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w)
}

// --- markdown helpers ---

func okLabel(ok bool) string {
	if ok {
		return "OK"
	}
	return "FAIL"
}

func mdASN(a *ASNJSON) string {
	if a == nil {
		return "—"
	}
	s := "`AS" + a.ASN + "`"
	if a.Org != "" {
		s += " " + a.Org
	}
	return s
}

func mdCDN(c *CDNJSON) string {
	if c == nil {
		return "—"
	}
	if c.Confidence != "" && c.Reason != "" {
		return fmt.Sprintf("%s _(%s — %s)_", c.Provider, c.Confidence, c.Reason)
	}
	return c.Provider
}

func mdList(ss []string) string {
	if len(ss) == 0 {
		return "—"
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, "`"+s+"`")
	}
	return strings.Join(out, ", ")
}

func mdField(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return "—"
}

func mdTCPStatus(r *TCPJSON) string {
	if r.Error != "" {
		return "FAIL: " + r.Error
	}
	return "OK"
}

func mdHopAddr(h HopJSON) string {
	if len(h.IPs) == 0 {
		return "_(no addresses)_"
	}
	out := make([]string, 0, len(h.IPs))
	for _, ip := range h.IPs {
		out = append(out, "`"+ip+"`")
	}
	return strings.Join(out, " / ")
}

func mdHopRTT(h HopJSON) string {
	if len(h.Probes) == 0 {
		return "`*`"
	}
	parts := make([]string, 0, len(h.Probes))
	for _, p := range h.Probes {
		parts = append(parts, fmt.Sprintf("%.2f", p.RTTMS))
	}
	return "`" + strings.Join(parts, " / ") + "`"
}

// Selectors used by mdField that aren't worth inlining everywhere.
func asnCountry(a *ASNJSON) string {
	if a == nil {
		return ""
	}
	return a.Country
}
func asnPrefix(a *ASNJSON) string {
	if a == nil {
		return ""
	}
	return a.Prefix
}
func asnRegistry(a *ASNJSON) string {
	if a == nil {
		return ""
	}
	return a.Registry
}
func rdapCountry(r *RDAPJSON) string {
	if r == nil {
		return ""
	}
	return r.Country
}
func rdapRegistry(r *RDAPJSON) string {
	if r == nil {
		return ""
	}
	return r.Registry
}
func rdapAbuse(r *RDAPJSON) string {
	if r == nil {
		return ""
	}
	return r.AbuseEmail
}

// RenderHeadersMD writes the security-header audit as Markdown.
func RenderHeadersMD(w io.Writer, d HeadersJSON) {
	fmt.Fprintf(w, "# netcheck headers — `%s`\n\n", d.URL)
	fmt.Fprintf(w, "_%s · %dms_\n\n", d.StartedAt.Format(time.RFC3339), d.TookMS)
	if d.FinalURL != "" && d.FinalURL != d.URL {
		fmt.Fprintf(w, "- **Final URL:** `%s`\n", d.FinalURL)
	}
	if d.Status != 0 {
		fmt.Fprintf(w, "- **Status:** %d\n", d.Status)
	}
	if d.Error != "" {
		fmt.Fprintf(w, "\n> **Audit failed:** %s\n", d.Error)
		return
	}
	fmt.Fprintf(w, "- **Summary:** %d pass · %d weak · %d missing · %d info\n\n",
		d.Summary.Pass, d.Summary.Weak, d.Summary.Missing, d.Summary.Info)

	fmt.Fprintln(w, "| Header | Grade | Value | Note |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range d.Findings {
		val := f.Value
		if val == "" {
			val = "—"
		} else {
			val = "`" + val + "`"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", f.Name, gradeMD(f.Grade), val, mdEscapePipes(f.Comment))
	}
	fmt.Fprintln(w)
}

func gradeMD(g string) string {
	switch g {
	case "pass":
		return "**PASS**"
	case "weak":
		return "_weak_"
	case "missing":
		return "_missing_"
	case "info":
		return "_info_"
	default:
		return g
	}
}

// mdEscapePipes escapes "|" so it doesn't break a markdown table row.
func mdEscapePipes(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// RenderReverseMD writes the reverse-IP result as Markdown.
func RenderReverseMD(w io.Writer, d ReverseJSON) {
	fmt.Fprintf(w, "# netcheck reverse — `%s`\n\n", d.IP)
	fmt.Fprintf(w, "_%s · %dms_\n\n", d.StartedAt.Format(time.RFC3339), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "> **Lookup failed:** %s\n", d.Error)
		return
	}
	fmt.Fprintf(w, "- **Hostnames:** %d\n\n", len(d.Hostnames))

	if len(d.Hostnames) == 0 {
		fmt.Fprintln(w, "_(no hostnames found)_")
	} else {
		fmt.Fprintln(w, "| Hostname | Sources |")
		fmt.Fprintln(w, "|---|---|")
		for _, h := range d.Hostnames {
			fmt.Fprintf(w, "| `%s` | %s |\n", h.Name, strings.Join(h.Sources, ", "))
		}
		fmt.Fprintln(w)
	}

	if len(d.SourceDisabled) > 0 {
		fmt.Fprintf(w, "_Disabled (no API key): %s_\n\n", strings.Join(d.SourceDisabled, ", "))
	}
	if len(d.SourceErrors) > 0 {
		fmt.Fprintln(w, "## Source errors")
		fmt.Fprintln(w)
		for name, err := range d.SourceErrors {
			fmt.Fprintf(w, "- **%s:** %s\n", name, mdEscapePipes(err))
		}
		fmt.Fprintln(w)
	}
}

// RenderArchMD writes the Wayback result as Markdown.
func RenderArchMD(w io.Writer, d ArchJSON) {
	fmt.Fprintf(w, "# netcheck arch — `%s`\n\n", d.Domain)
	fmt.Fprintf(w, "_%s · %dms_\n\n", d.StartedAt.Format(time.RFC3339), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "> **Lookup failed:** %s\n", d.Error)
		return
	}
	fmt.Fprintf(w, "- **Total snapshots:** %d\n", d.Total)
	fmt.Fprintf(w, "- **Unique URLs:** %d\n", d.UniqueURLs)
	if d.First != nil {
		fmt.Fprintf(w, "- **First seen:** %s\n", d.First.Format("2006-01-02"))
	}
	if d.Last != nil {
		fmt.Fprintf(w, "- **Last seen:** %s\n", d.Last.Format("2006-01-02"))
	}
	fmt.Fprintln(w)

	if len(d.RecentSamples) == 0 {
		return
	}
	fmt.Fprintf(w, "## Recent snapshots (%d, newest first)\n\n", len(d.RecentSamples))
	fmt.Fprintln(w, "| Date | Status | URL |")
	fmt.Fprintln(w, "|---|---|---|")
	for _, s := range d.RecentSamples {
		status := "—"
		if s.Status > 0 {
			status = fmt.Sprintf("%d", s.Status)
		}
		fmt.Fprintf(w, "| %s | %s | `%s` |\n", s.Timestamp.Format("2006-01-02"), status, s.URL)
	}
	fmt.Fprintln(w)
}

// RenderSubsMD writes the subdomain enumeration result as Markdown.
func RenderSubsMD(w io.Writer, d SubsJSON) {
	fmt.Fprintf(w, "# netcheck subs — `%s`\n\n", d.Domain)
	fmt.Fprintf(w, "_%s · %dms_\n\n", d.StartedAt.Format(time.RFC3339), d.TookMS)
	if d.Error != "" {
		fmt.Fprintf(w, "> **Enumeration failed:** %s\n", d.Error)
		return
	}
	fmt.Fprintf(w, "- **Subdomains:** %d\n\n", len(d.Subdomains))

	if len(d.Subdomains) == 0 {
		fmt.Fprintln(w, "_(no subdomains found in CT logs)_")
	} else {
		fmt.Fprintln(w, "| Name | Sources |")
		fmt.Fprintln(w, "|---|---|")
		for _, s := range d.Subdomains {
			fmt.Fprintf(w, "| `%s` | %s |\n", s.Name, strings.Join(s.Sources, ", "))
		}
		fmt.Fprintln(w)
	}

	if len(d.SourceErrors) > 0 {
		fmt.Fprintln(w, "## Source errors")
		fmt.Fprintln(w)
		for name, err := range d.SourceErrors {
			fmt.Fprintf(w, "- **%s:** %s\n", name, mdEscapePipes(err))
		}
		fmt.Fprintln(w)
	}
}

// RenderTechMD writes the tech-detection result as Markdown.
func RenderTechMD(w io.Writer, d TechJSON) {
	fmt.Fprintf(w, "# netcheck tech — `%s`\n\n", d.URL)
	fmt.Fprintf(w, "_%s · %dms_\n\n", d.StartedAt.Format(time.RFC3339), d.TookMS)
	if d.FinalURL != "" && d.FinalURL != d.URL {
		fmt.Fprintf(w, "- **Final URL:** `%s`\n", d.FinalURL)
	}
	if d.Status != 0 {
		fmt.Fprintf(w, "- **Status:** %d\n", d.Status)
	}
	if d.Error != "" {
		fmt.Fprintf(w, "\n> **Detect failed:** %s\n", d.Error)
		return
	}
	fmt.Fprintf(w, "- **Matches:** %d\n\n", len(d.Matches))

	if len(d.Matches) == 0 {
		fmt.Fprintln(w, "_(no known technologies fingerprinted)_")
		return
	}

	fmt.Fprintln(w, "| Technology | Category | Version | Confidence | Evidence |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, m := range d.Matches {
		ver := m.Version
		if ver == "" {
			ver = "—"
		}
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s |\n",
			m.Name, m.Category, ver, m.Confidence, mdEscapePipes(m.Evidence))
	}
	fmt.Fprintln(w)
}
