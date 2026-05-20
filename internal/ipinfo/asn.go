package ipinfo

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ASNInfo is the parsed answer from Team Cymru's origin.asn.cymru.com service.
// See https://www.team-cymru.com/ip-asn-mapping for the data format.
type ASNInfo struct {
	ASN      string // e.g. "15169"
	Prefix   string // e.g. "8.8.8.0/24"
	Country  string // e.g. "US"
	Registry string // e.g. "arin"
	Org      string // e.g. "GOOGLE, US" (best-effort second lookup)
}

// ASNCache is a process-local cache of Cymru lookups (including misses).
type ASNCache struct {
	mu sync.Mutex
	m  map[string]*ASNInfo // key: IP string; nil value = "lookup failed, don't retry"
}

// NewASNCache returns an empty cache.
func NewASNCache() *ASNCache {
	return &ASNCache{m: map[string]*ASNInfo{}}
}

// DefaultASNCache is the process-wide cache used by the CLI.
var DefaultASNCache = NewASNCache()

// Lookup returns ASN info for an IP, caching results (including misses).
// Private and link-local IPs return nil with no error.
func (c *ASNCache) Lookup(ctx context.Context, ipStr string) *ASNInfo {
	c.mu.Lock()
	if v, ok := c.m[ipStr]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	info := lookupCymru(ctx, ipStr)

	c.mu.Lock()
	c.m[ipStr] = info
	c.mu.Unlock()
	return info
}

// lookupCymru does the actual DNS work. Returns nil on private IP or failure.
func lookupCymru(ctx context.Context, ipStr string) *ASNInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil || IsPrivateOrSpecial(ip) {
		return nil
	}

	qname := cymruQueryName(ip)
	if qname == "" {
		return nil
	}

	r := &net.Resolver{}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	txts, err := r.LookupTXT(c, qname)
	if err != nil || len(txts) == 0 {
		return nil
	}
	// Format: "ASN | Prefix | Country | Registry | Allocated"
	parts := splitPipes(txts[0])
	if len(parts) < 4 {
		return nil
	}
	info := &ASNInfo{
		ASN:      parts[0],
		Prefix:   parts[1],
		Country:  parts[2],
		Registry: strings.ToLower(parts[3]),
	}

	// Best-effort org lookup. AS<N>.asn.cymru.com -> "ASN | CC | Registry | Allocated | Org"
	orgTxts, err := r.LookupTXT(c, "AS"+info.ASN+".asn.cymru.com")
	if err == nil && len(orgTxts) > 0 {
		op := splitPipes(orgTxts[0])
		if len(op) >= 5 {
			info.Org = op[4]
		}
	}
	return info
}

func splitPipes(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// cymruQueryName builds the reverse-DNS-style query name used by Cymru.
// IPv4: 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
// IPv6: uses nibble form under origin6.asn.cymru.com
func cymruQueryName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	var nibbles []string
	for i := len(v6) - 1; i >= 0; i-- {
		b := v6[i]
		nibbles = append(nibbles, fmt.Sprintf("%x", b&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", b>>4))
	}
	return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
}

// IsPrivateOrSpecial reports whether the IP is private, loopback, link-local,
// or otherwise non-routable on the public internet — these never have a useful
// ASN, so skipping them keeps the route output clean.
func IsPrivateOrSpecial(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	return false
}
