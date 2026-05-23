package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"
)

// htmlCSS is the inline stylesheet used by every HTML report. Self-contained,
// no external requests — keeps the report file copyable and openable offline.
const htmlCSS = `body { font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1.5em; color: #1d1d1f; }
h1 { font-size: 1.6em; margin: 0 0 0.2em; }
h2 { font-size: 1.15em; margin-top: 1.6em; border-bottom: 1px solid #e0e0e6; padding-bottom: 0.2em; }
p.meta { color: #6a6a72; margin-top: 0; }
table { border-collapse: collapse; width: 100%; margin: 0.6em 0 1.2em; }
th, td { border: 1px solid #e0e0e6; padding: 6px 10px; text-align: left; vertical-align: top; }
th { background: #f7f7fa; font-weight: 600; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
code { background: #f4f4f8; padding: 1px 5px; border-radius: 3px; }
.ok { color: #0a7d28; font-weight: 600; }
.fail { color: #b00020; font-weight: 600; }
.weak { color: #b86200; font-weight: 600; }
.muted { color: #8a8a92; }
.info { color: #555560; font-weight: 600; }
ul.kv { list-style: none; padding: 0; margin: 0.4em 0 1em; }
ul.kv li { margin: 0.15em 0; }
ul.kv li b { display: inline-block; min-width: 130px; color: #4a4a52; font-weight: 500; }
.warn { background: #fff8e1; border-left: 3px solid #f4b400; padding: 0.5em 0.8em; margin: 0.8em 0; font-size: 0.95em; }
`

func htmlHead(w io.Writer, title string) {
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, "<html lang=\"en\"><head>")
	fmt.Fprintln(w, "<meta charset=\"utf-8\">")
	fmt.Fprintf(w, "<title>%s</title>\n", html.EscapeString(title))
	fmt.Fprintln(w, "<style>"+htmlCSS+"</style>")
	fmt.Fprintln(w, "</head><body>")
}

func htmlTail(w io.Writer) {
	fmt.Fprintln(w, "</body></html>")
}

// RenderFullHTML writes a single-file HTML rendering of the full check Report.
func RenderFullHTML(w io.Writer, r *Report) {
	d := ToFullJSON(r)
	htmlHead(w, "netcheck — "+d.Target.Raw)
	fmt.Fprintf(w, "<h1>netcheck report</h1>\n")
	fmt.Fprintf(w, "<p class=\"meta\">Target: <code>%s</code> · %s · <span class=\"%s\">%s</span></p>\n",
		html.EscapeString(d.Target.Raw), html.EscapeString(d.StartedAt.Format(time.RFC3339)),
		okClass(d.OK), okLabel(d.OK))

	// DNS
	fmt.Fprintln(w, "<h2>DNS</h2>")
	if d.DNS.Error != "" {
		fmt.Fprintf(w, "<p class=\"fail\">Lookup failed: <code>%s</code></p>\n", html.EscapeString(d.DNS.Error))
	} else {
		fmt.Fprintln(w, "<table><thead><tr><th>Type</th><th>IP</th><th>ASN</th><th>CDN</th><th>Reverse</th></tr></thead><tbody>")
		for _, ip := range d.DNS.A {
			info := d.DNS.IPInfo[ip]
			fmt.Fprintf(w, "<tr><td>A</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(ip), htmlASN(info.ASN), htmlCDN(info.CDN), htmlList(info.Reverse))
		}
		for _, ip := range d.DNS.AAAA {
			info := d.DNS.IPInfo[ip]
			fmt.Fprintf(w, "<tr><td>AAAA</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(ip), htmlASN(info.ASN), htmlCDN(info.CDN), htmlList(info.Reverse))
		}
		fmt.Fprintln(w, "</tbody></table>")
		fmt.Fprintf(w, "<p class=\"muted\">lookup time: %dms</p>\n", d.DNS.TookMS)
	}

	// TCP
	if d.TCPv4 != nil || d.TCPv6 != nil {
		fmt.Fprintln(w, "<h2>TCP</h2>")
		fmt.Fprintln(w, "<table><thead><tr><th>Family</th><th>Address</th><th>Status</th><th>Time</th></tr></thead><tbody>")
		if d.TCPv4 != nil {
			fmt.Fprintf(w, "<tr><td>IPv4</td><td><code>%s</code></td><td>%s</td><td>%dms</td></tr>\n",
				html.EscapeString(d.TCPv4.Addr), htmlTCPStatus(d.TCPv4), d.TCPv4.TookMS)
		}
		if d.TCPv6 != nil {
			fmt.Fprintf(w, "<tr><td>IPv6</td><td><code>%s</code></td><td>%s</td><td>%dms</td></tr>\n",
				html.EscapeString(d.TCPv6.Addr), htmlTCPStatus(d.TCPv6), d.TCPv6.TookMS)
		}
		fmt.Fprintln(w, "</tbody></table>")
	}

	// TLS
	if d.TLS != nil {
		fmt.Fprintln(w, "<h2>TLS</h2>")
		if d.TLS.Error != "" {
			fmt.Fprintf(w, "<p class=\"fail\">Handshake failed: <code>%s</code></p>\n", html.EscapeString(d.TLS.Error))
		} else {
			fmt.Fprintln(w, "<ul class=\"kv\">")
			fmt.Fprintf(w, "<li><b>Subject:</b> %s</li>\n", html.EscapeString(d.TLS.Subject))
			fmt.Fprintf(w, "<li><b>Issuer:</b> %s</li>\n", html.EscapeString(d.TLS.Issuer))
			fmt.Fprintf(w, "<li><b>Protocol:</b> %s (cipher <code>%s</code>)</li>\n",
				html.EscapeString(d.TLS.Version), html.EscapeString(d.TLS.CipherSuite))
			expiresCls := "ok"
			if d.TLS.DaysRemaining <= 30 {
				expiresCls = "fail"
			}
			fmt.Fprintf(w, "<li><b>Expires:</b> <span class=\"%s\">%s (%d days)</span></li>\n",
				expiresCls, html.EscapeString(d.TLS.NotAfter.Format("2006-01-02")), d.TLS.DaysRemaining)
			fmt.Fprintf(w, "<li><b>Chain:</b> %d cert(s)</li>\n", d.TLS.ChainCount)
			fmt.Fprintf(w, "<li><b>Handshake:</b> %dms</li>\n", d.TLS.TookMS)
			fmt.Fprintln(w, "</ul>")
		}
	}

	// HTTP
	fmt.Fprintln(w, "<h2>HTTP</h2>")
	if d.HTTP.Error != "" {
		fmt.Fprintf(w, "<p class=\"fail\">Request failed: <code>%s</code></p>\n", html.EscapeString(d.HTTP.Error))
	} else {
		fmt.Fprintln(w, "<ul class=\"kv\">")
		statusCls := "ok"
		if d.HTTP.Status >= 400 {
			statusCls = "fail"
		}
		fmt.Fprintf(w, "<li><b>Status:</b> <span class=\"%s\">%d</span></li>\n", statusCls, d.HTTP.Status)
		fmt.Fprintf(w, "<li><b>Protocol:</b> %s</li>\n", html.EscapeString(d.HTTP.Proto))
		if d.HTTP.Server != "" {
			fmt.Fprintf(w, "<li><b>Server:</b> %s</li>\n", html.EscapeString(d.HTTP.Server))
		}
		fmt.Fprintf(w, "<li><b>Final URL:</b> <code>%s</code></li>\n", html.EscapeString(d.HTTP.FinalURL))
		fmt.Fprintf(w, "<li><b>Redirects:</b> %d</li>\n", len(d.HTTP.Hops))
		fmt.Fprintln(w, "</ul>")
		if len(d.HTTP.Hops) > 0 {
			fmt.Fprintln(w, "<ol>")
			for _, h := range d.HTTP.Hops {
				fmt.Fprintf(w, "<li><code>%d</code> → <code>%s</code></li>\n", h.Status, html.EscapeString(h.URL))
			}
			fmt.Fprintln(w, "</ol>")
		}
		fmt.Fprintln(w, "<h3>Timing</h3>")
		fmt.Fprintln(w, "<table><thead><tr><th>DNS</th><th>Connect</th><th>TLS</th><th>TTFB</th><th>Total</th></tr></thead><tbody>")
		fmt.Fprintf(w, "<tr><td>%dms</td><td>%dms</td><td>%dms</td><td>%dms</td><td>%dms</td></tr>\n",
			d.HTTP.Timing.DNSMS, d.HTTP.Timing.ConnectMS, d.HTTP.Timing.TLSMS, d.HTTP.Timing.TTFBMS, d.HTTP.Timing.TotalMS)
		fmt.Fprintln(w, "</tbody></table>")
	}

	htmlTail(w)
}

// RenderDNSCompareHTML writes a single-file HTML rendering of a DNS compare run.
func RenderDNSCompareHTML(w io.Writer, d DNSCompareJSON) {
	htmlHead(w, "netcheck dns — "+d.Host)
	fmt.Fprintf(w, "<h1>netcheck dns compare</h1>\n")
	fmt.Fprintf(w, "<p class=\"meta\">Host: <code>%s</code> · %s</p>\n",
		html.EscapeString(d.Host), html.EscapeString(d.StartedAt.Format(time.RFC3339)))

	for _, q := range d.Queries {
		fmt.Fprintf(w, "<h2>%s records</h2>\n", html.EscapeString(q.QType))
		fmt.Fprintln(w, "<table><thead><tr><th>Resolver</th><th>Address</th><th>Time</th><th>Answer</th></tr></thead><tbody>")
		for _, r := range q.Results {
			if r.Error != "" {
				fmt.Fprintf(w, "<tr><td>%s</td><td><code>%s</code></td><td>%dms</td><td class=\"fail\">error: %s</td></tr>\n",
					html.EscapeString(r.Name), html.EscapeString(r.Address), r.TookMS, html.EscapeString(r.Error))
				continue
			}
			ans := "<span class=\"muted\">(no records)</span>"
			if len(r.Records) > 0 {
				ans = htmlList(r.Records)
			}
			fmt.Fprintf(w, "<tr><td>%s</td><td><code>%s</code></td><td>%dms</td><td>%s</td></tr>\n",
				html.EscapeString(r.Name), html.EscapeString(r.Address), r.TookMS, ans)
		}
		fmt.Fprintln(w, "</tbody></table>")

		switch {
		case q.Verdict.Agree:
			fmt.Fprintln(w, "<p><b>Verdict:</b> <span class=\"ok\">all resolvers agree</span></p>")
		case len(q.Verdict.Groups) == 0:
			fmt.Fprintln(w, "<p><b>Verdict:</b> <span class=\"fail\">all resolvers failed</span></p>")
		default:
			fmt.Fprintf(w, "<p><b>Verdict:</b> resolvers disagree (%d distinct answer sets)</p>\n", len(q.Verdict.Groups))
			fmt.Fprintln(w, "<ul>")
			for i, g := range q.Verdict.Groups {
				fmt.Fprintf(w, "<li>Set %d (%s): %s</li>\n", i+1,
					html.EscapeString(strings.Join(g.Resolvers, ", ")), htmlList(g.Records))
			}
			fmt.Fprintln(w, "</ul>")
		}
	}
	htmlTail(w)
}

// RenderRouteHTML writes a single-file HTML rendering of a route run.
func RenderRouteHTML(w io.Writer, d RouteJSON) {
	htmlHead(w, "netcheck route — "+d.Host)
	fmt.Fprintf(w, "<h1>netcheck route</h1>\n")
	fmt.Fprintf(w, "<p class=\"meta\">Host: <code>%s</code>", html.EscapeString(d.Host))
	if d.DestIP != "" {
		fmt.Fprintf(w, " (<code>%s</code>)", html.EscapeString(d.DestIP))
	}
	fmt.Fprintf(w, " · %s · <code>%s %s</code></p>\n",
		html.EscapeString(d.StartedAt.Format(time.RFC3339)),
		html.EscapeString(d.Tool), html.EscapeString(strings.Join(d.ToolArgs, " ")))

	fmt.Fprintln(w, "<table><thead><tr><th>Hop</th><th>Address</th><th>RTT (ms)</th><th>ASN</th></tr></thead><tbody>")
	for _, h := range d.Hops {
		addr := "<span class=\"muted\">*</span>"
		rtt := "<span class=\"muted\">*</span>"
		asn := ""
		if !h.Timeout {
			addr = htmlHopAddr(h)
			rtt = htmlHopRTT(h)
			if h.ASN != nil {
				asn = "<code>AS" + html.EscapeString(h.ASN.ASN) + "</code> " + html.EscapeString(h.ASN.Org)
			}
		}
		fmt.Fprintf(w, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", h.N, addr, rtt, asn)
	}
	fmt.Fprintln(w, "</tbody></table>")

	if d.Reached {
		fmt.Fprintf(w, "<p class=\"ok\">Reached %s in %d hops.</p>\n", html.EscapeString(d.DestIP), len(d.Hops))
	} else if len(d.Hops) > 0 {
		fmt.Fprintf(w, "<p>Stopped after %d hops (destination not confirmed).</p>\n", len(d.Hops))
	}
	if d.Timeouts > 0 {
		fmt.Fprintf(w, "<div class=\"warn\">%d hop(s) timed out — routers commonly drop or rate-limit probes; missing hops do not always mean a broken route.</div>\n", d.Timeouts)
	}
	htmlTail(w)
}

// RenderIPInfoHTML writes a single-file HTML rendering of an IP info run.
func RenderIPInfoHTML(w io.Writer, d IPInfoJSON) {
	htmlHead(w, "netcheck ip — "+d.Target)
	fmt.Fprintf(w, "<h1>netcheck ip</h1>\n")
	fmt.Fprintf(w, "<p class=\"meta\">Target: <code>%s</code> · %s", html.EscapeString(d.Target), html.EscapeString(d.StartedAt.Format(time.RFC3339)))
	if d.FromHost {
		fmt.Fprintf(w, " · resolved %d address(es) in %dms", len(d.Details), d.ResolveTookMS)
	}
	fmt.Fprintln(w, "</p>")

	for _, det := range d.Details {
		if d.FromHost {
			fmt.Fprintf(w, "<h2><code>%s</code></h2>\n", html.EscapeString(det.IP))
		}
		fmt.Fprintln(w, "<ul class=\"kv\">")
		fmt.Fprintf(w, "<li><b>Reverse:</b> %s</li>\n", htmlList(det.Reverse))
		fmt.Fprintf(w, "<li><b>ASN:</b> %s</li>\n", htmlASN(det.ASN))
		fmt.Fprintf(w, "<li><b>Country:</b> %s</li>\n", htmlField(asnCountry(det.ASN), rdapCountry(det.RDAP)))
		fmt.Fprintf(w, "<li><b>Prefix:</b> %s</li>\n", htmlField(asnPrefix(det.ASN)))
		fmt.Fprintf(w, "<li><b>Registry:</b> %s</li>\n", htmlField(rdapRegistry(det.RDAP), asnRegistry(det.ASN)))
		fmt.Fprintf(w, "<li><b>CDN:</b> %s</li>\n", htmlCDN(det.CDN))
		fmt.Fprintf(w, "<li><b>Abuse:</b> %s</li>\n", htmlField(rdapAbuse(det.RDAP)))
		fmt.Fprintln(w, "</ul>")
	}
	htmlTail(w)
}

// --- html helpers ---

func okClass(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func htmlASN(a *ASNJSON) string {
	if a == nil {
		return "<span class=\"muted\">—</span>"
	}
	s := "<code>AS" + html.EscapeString(a.ASN) + "</code>"
	if a.Org != "" {
		s += " " + html.EscapeString(a.Org)
	}
	return s
}

func htmlCDN(c *CDNJSON) string {
	if c == nil {
		return "<span class=\"muted\">—</span>"
	}
	if c.Confidence != "" && c.Reason != "" {
		return fmt.Sprintf("%s <span class=\"muted\">(%s — %s)</span>",
			html.EscapeString(c.Provider), html.EscapeString(c.Confidence), html.EscapeString(c.Reason))
	}
	return html.EscapeString(c.Provider)
}

func htmlList(ss []string) string {
	if len(ss) == 0 {
		return "<span class=\"muted\">—</span>"
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, "<code>"+html.EscapeString(s)+"</code>")
	}
	return strings.Join(out, " ")
}

func htmlField(values ...string) string {
	for _, v := range values {
		if v != "" {
			return html.EscapeString(v)
		}
	}
	return "<span class=\"muted\">—</span>"
}

func htmlTCPStatus(r *TCPJSON) string {
	if r.Error != "" {
		return "<span class=\"fail\">FAIL: " + html.EscapeString(r.Error) + "</span>"
	}
	return "<span class=\"ok\">OK</span>"
}

func htmlHopAddr(h HopJSON) string {
	if len(h.IPs) == 0 {
		return "<span class=\"muted\">(no addresses)</span>"
	}
	out := make([]string, 0, len(h.IPs))
	for _, ip := range h.IPs {
		out = append(out, "<code>"+html.EscapeString(ip)+"</code>")
	}
	return strings.Join(out, " / ")
}

func htmlHopRTT(h HopJSON) string {
	if len(h.Probes) == 0 {
		return "<span class=\"muted\">*</span>"
	}
	parts := make([]string, 0, len(h.Probes))
	for _, p := range h.Probes {
		parts = append(parts, fmt.Sprintf("%.2f", p.RTTMS))
	}
	return "<code>" + html.EscapeString(strings.Join(parts, " / ")) + "</code>"
}

// RenderHeadersHTML writes a single-file HTML rendering of the headers audit.
func RenderHeadersHTML(w io.Writer, d HeadersJSON) {
	htmlHead(w, "netcheck headers — "+d.URL)
	fmt.Fprintf(w, "<h1>netcheck headers</h1>\n")
	fmt.Fprintf(w, "<p class=\"meta\">URL: <code>%s</code> · %s · %dms",
		html.EscapeString(d.URL), html.EscapeString(d.StartedAt.Format(time.RFC3339)), d.TookMS)
	if d.FinalURL != "" && d.FinalURL != d.URL {
		fmt.Fprintf(w, " · final <code>%s</code>", html.EscapeString(d.FinalURL))
	}
	if d.Status != 0 {
		fmt.Fprintf(w, " · status %d", d.Status)
	}
	fmt.Fprintln(w, "</p>")

	if d.Error != "" {
		fmt.Fprintf(w, "<div class=\"warn\"><b>Audit failed:</b> %s</div>\n", html.EscapeString(d.Error))
		htmlTail(w)
		return
	}

	fmt.Fprintf(w, "<p><b>Summary:</b> "+
		"<span class=\"ok\">%d pass</span> · "+
		"<span class=\"weak\">%d weak</span> · "+
		"<span class=\"fail\">%d missing</span> · "+
		"<span class=\"info\">%d info</span></p>\n",
		d.Summary.Pass, d.Summary.Weak, d.Summary.Missing, d.Summary.Info)

	fmt.Fprintln(w, "<table>")
	fmt.Fprintln(w, "<thead><tr><th>Header</th><th>Grade</th><th>Value</th><th>Note</th></tr></thead>")
	fmt.Fprintln(w, "<tbody>")
	for _, f := range d.Findings {
		val := html.EscapeString(f.Value)
		if val == "" {
			val = "<span class=\"muted\">—</span>"
		} else {
			val = "<code>" + val + "</code>"
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(f.Name), gradeHTML(f.Grade), val, html.EscapeString(f.Comment))
	}
	fmt.Fprintln(w, "</tbody></table>")
	htmlTail(w)
}

// RenderTechHTML writes a single-file HTML rendering of the tech detection.
func RenderTechHTML(w io.Writer, d TechJSON) {
	htmlHead(w, "netcheck tech — "+d.URL)
	fmt.Fprintf(w, "<h1>netcheck tech</h1>\n")
	fmt.Fprintf(w, "<p class=\"meta\">URL: <code>%s</code> · %s · %dms",
		html.EscapeString(d.URL), html.EscapeString(d.StartedAt.Format(time.RFC3339)), d.TookMS)
	if d.FinalURL != "" && d.FinalURL != d.URL {
		fmt.Fprintf(w, " · final <code>%s</code>", html.EscapeString(d.FinalURL))
	}
	if d.Status != 0 {
		fmt.Fprintf(w, " · status %d", d.Status)
	}
	fmt.Fprintln(w, "</p>")

	if d.Error != "" {
		fmt.Fprintf(w, "<div class=\"warn\"><b>Detect failed:</b> %s</div>\n", html.EscapeString(d.Error))
		htmlTail(w)
		return
	}

	fmt.Fprintf(w, "<p><b>%d match(es)</b></p>\n", len(d.Matches))

	if len(d.Matches) == 0 {
		fmt.Fprintln(w, "<p class=\"muted\">(no known technologies fingerprinted)</p>")
		htmlTail(w)
		return
	}

	fmt.Fprintln(w, "<table>")
	fmt.Fprintln(w, "<thead><tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr></thead>")
	fmt.Fprintln(w, "<tbody>")
	for _, m := range d.Matches {
		ver := html.EscapeString(m.Version)
		if ver == "" {
			ver = "<span class=\"muted\">—</span>"
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(m.Name),
			html.EscapeString(m.Category),
			ver,
			confidenceHTML(m.Confidence),
			html.EscapeString(m.Evidence))
	}
	fmt.Fprintln(w, "</tbody></table>")
	htmlTail(w)
}

func confidenceHTML(c string) string {
	switch c {
	case "high":
		return `<span class="ok">high</span>`
	case "medium":
		return `<span class="weak">medium</span>`
	case "low":
		return `<span class="muted">low</span>`
	default:
		return html.EscapeString(c)
	}
}

func gradeHTML(g string) string {
	switch g {
	case "pass":
		return `<span class="ok">PASS</span>`
	case "weak":
		return `<span class="weak">WEAK</span>`
	case "missing":
		return `<span class="fail">MISSING</span>`
	case "info":
		return `<span class="info">INFO</span>`
	default:
		return html.EscapeString(g)
	}
}
