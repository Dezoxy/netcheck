package ipinfo

// WHOIS (port 43) fallback for the registrar lookup. RDAP is the primary
// path (rdap_domain.go); many ccTLDs (.hu and other WHOIS-only registries)
// expose no RDAP registrar entity, so when RDAP comes up empty we query the
// TLD's classic WHOIS server and parse the registrar out of its free-text
// response.
//
// Resolution mirrors a real WHOIS client: ask IANA's WHOIS server which
// server is authoritative for the TLD (the "whois:" referral line), then
// query that server for the domain. Only the registrar *name* is available
// this way — IANA ID and URL are structured RDAP-only fields.

import (
	"context"
	"io"
	"net"
	"strings"
	"time"
)

// ianaWhoisServer is the root WHOIS server. Querying it with a bare TLD
// returns that TLD's authoritative WHOIS server in a "whois:" line.
const ianaWhoisServer = "whois.iana.org:43"

// whoisDialTimeout bounds a single port-43 round-trip when the caller's
// context carries no deadline of its own.
const whoisDialTimeout = 8 * time.Second

// whoisRegistrarLabels are the field names (case-insensitive, exact key
// match) under which registries publish the sponsoring registrar. The list
// is ordered by preference — the first matching line wins.
var whoisRegistrarLabels = []string{
	"registrar",
	"sponsoring registrar",
	"registrar name",
}

// lookupWhois43 resolves the sponsoring registrar for a domain over WHOIS
// (port 43). Returns the registrar name, or "" when the TLD has no WHOIS
// referral or the response carries no recognisable registrar line. Best
// effort and tolerant of failure — it is only ever a fallback.
func lookupWhois43(ctx context.Context, domain string) string {
	domain = normalizeDomain(domain)
	dot := strings.LastIndexByte(domain, '.')
	if dot < 0 {
		return ""
	}
	tld := domain[dot+1:]
	if tld == "" {
		return ""
	}

	server := whoisServerForTLD(ctx, tld)
	if server == "" {
		return ""
	}
	return parseRegistrar(whoisQuery(ctx, server, domain))
}

// whoisServerForTLD asks IANA which WHOIS server is authoritative for a TLD
// and returns it as a "host:43" address, or "" if there is no referral.
func whoisServerForTLD(ctx context.Context, tld string) string {
	for _, line := range strings.Split(whoisQuery(ctx, ianaWhoisServer, tld), "\n") {
		if v, ok := cutWhoisField(strings.TrimSpace(line), "whois"); ok && v != "" {
			return net.JoinHostPort(v, "43")
		}
	}
	return ""
}

// whoisQuery opens a port-43 connection, writes the query, and returns the
// raw response. Any transport error yields "" — callers degrade gracefully.
func whoisQuery(ctx context.Context, server, query string) string {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return ""
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(whoisDialTimeout))
	}

	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(conn, 1<<20)) // cap at 1 MiB
	return string(b)
}

// parseRegistrar scans a free-text WHOIS response for the first line whose
// field name matches one of whoisRegistrarLabels and returns its value.
func parseRegistrar(resp string) string {
	if resp == "" {
		return ""
	}
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		for _, label := range whoisRegistrarLabels {
			if v, ok := cutWhoisField(line, label); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// cutWhoisField splits a "key: value" WHOIS line and returns the trimmed
// value iff the key matches label exactly (case-insensitive). The exact
// match is deliberate — it stops "Registrar URL:" or "Registrar IANA ID:"
// from being mistaken for the "Registrar:" line.
func cutWhoisField(line, label string) (string, bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(line[:i]), label) {
		return "", false
	}
	return strings.TrimSpace(line[i+1:]), true
}
