// Package dnscompare runs the same DNS query against multiple resolvers in
// parallel and reports whether they agree.
package dnscompare

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

// ResolverType selects the wire protocol for a Resolver.
type ResolverType string

const (
	TypeUDP ResolverType = "udp" // classic DNS over UDP (default)
	TypeTCP ResolverType = "tcp" // DNS over TCP
	TypeDoT ResolverType = "dot" // DNS over TLS (port 853)
	TypeDoH ResolverType = "doh" // DNS over HTTPS (URL)
)

// Resolver describes a DNS server we'll query.
//
// For UDP, TCP, and DoT, Address is "host:port" (default port 53 for UDP/TCP,
// 853 for DoT). For DoH, Address is the full HTTPS URL of the dns-query endpoint
// (e.g. "https://cloudflare-dns.com/dns-query").
type Resolver struct {
	Name    string
	Address string
	Type    ResolverType // empty == TypeUDP
}

// DefaultResolvers are the well-known public resolvers we query by default.
var DefaultResolvers = []Resolver{
	{Name: "Cloudflare", Address: "1.1.1.1:53", Type: TypeUDP},
	{Name: "Google", Address: "8.8.8.8:53", Type: TypeUDP},
	{Name: "Quad9", Address: "9.9.9.9:53", Type: TypeUDP},
}

// SystemResolvers returns the first resolver listed in /etc/resolv.conf, or nil
// if the file is missing or empty. macOS often lists multiple loopback
// resolvers — we use just one to keep the comparison table readable.
func SystemResolvers() []Resolver {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil
	}
	port := cfg.Port
	if port == "" {
		port = "53"
	}
	return []Resolver{{Name: "System", Address: net.JoinHostPort(cfg.Servers[0], port), Type: TypeUDP}}
}

// EnsurePort accepts "host" or "host:port" or a bracketed IPv6 literal and
// returns a "host:port" form, defaulting to the given port if missing.
func EnsurePort(addr string, defaultPort string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Count(addr, ":") >= 2 {
		return "[" + addr + "]:" + defaultPort
	}
	return addr + ":" + defaultPort
}

// ParseResolver parses a user-supplied resolver string into a Resolver value.
//
// Accepted forms:
//   - "host" / "host:port" / "1.2.3.4" / "[::1]:53"  → UDP (port 53 default)
//   - "udp://host[:port]"                            → UDP
//   - "tcp://host[:port]"                            → TCP
//   - "tls://host[:port]" or "dot://host[:port]"     → DoT (port 853 default)
//   - "https://host/path" or "doh://host/path"       → DoH (URL as given)
//
// The returned Resolver.Name is the input string (callers can override).
func ParseResolver(raw string) (Resolver, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Resolver{}, errors.New("empty resolver")
	}

	// No scheme → assume UDP.
	if !strings.Contains(s, "://") {
		return Resolver{Name: s, Address: EnsurePort(s, "53"), Type: TypeUDP}, nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return Resolver{}, fmt.Errorf("invalid resolver %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "udp":
		return Resolver{Name: s, Address: EnsurePort(u.Host, "53"), Type: TypeUDP}, nil
	case "tcp":
		return Resolver{Name: s, Address: EnsurePort(u.Host, "53"), Type: TypeTCP}, nil
	case "tls", "dot":
		return Resolver{Name: s, Address: EnsurePort(u.Host, "853"), Type: TypeDoT}, nil
	case "https":
		return Resolver{Name: s, Address: s, Type: TypeDoH}, nil
	case "doh":
		// Rewrite doh://host/path → https://host/path
		u.Scheme = "https"
		return Resolver{Name: s, Address: u.String(), Type: TypeDoH}, nil
	default:
		return Resolver{}, fmt.Errorf("unsupported resolver scheme %q in %s", scheme, raw)
	}
}

var qtypeByName = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"MX":    dns.TypeMX,
	"TXT":   dns.TypeTXT,
	"NS":    dns.TypeNS,
	"SOA":   dns.TypeSOA,
}

// ParseTypes parses a comma-separated list of record-type names into the
// internal canonical form, rejecting unknown types and deduping while
// preserving order.
func ParseTypes(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	var out []string
	seen := map[string]bool{}
	for _, p := range parts {
		t := strings.ToUpper(strings.TrimSpace(p))
		if t == "" {
			continue
		}
		if _, ok := qtypeByName[t]; !ok {
			return nil, fmt.Errorf("unsupported record type: %s", t)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no record types specified")
	}
	return out, nil
}
