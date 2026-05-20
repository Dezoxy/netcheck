// Package dnscompare runs the same DNS query against multiple resolvers in
// parallel and reports whether they agree.
package dnscompare

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Resolver names a DNS server reachable at Address (host:port).
type Resolver struct {
	Name    string
	Address string // host:port
}

// DefaultResolvers are the well-known public resolvers we query by default.
var DefaultResolvers = []Resolver{
	{Name: "Cloudflare", Address: "1.1.1.1:53"},
	{Name: "Google", Address: "8.8.8.8:53"},
	{Name: "Quad9", Address: "9.9.9.9:53"},
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
	return []Resolver{{Name: "System", Address: net.JoinHostPort(cfg.Servers[0], port)}}
}

// EnsurePort accepts "host" or "host:port" or a bracketed IPv6 literal and
// returns a "host:port" form, defaulting port 53.
func EnsurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Count(addr, ":") >= 2 {
		return "[" + addr + "]:53"
	}
	return addr + ":53"
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
