// Package ipinfo enriches IP addresses with ASN (Team Cymru), RDAP, reverse
// DNS, and CDN classification. All lookups are cached per process.
package ipinfo

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSIPInfo is the per-IP enrichment attached to a DNS lookup result.
type DNSIPInfo struct {
	ASN     *ASNInfo
	Reverse []string
	CDN     CDNMatch
}

// IPDetails is the full enrichment for a single IP, used by `netcheck ip`.
type IPDetails struct {
	IP      net.IP
	Reverse []string
	ASN     *ASNInfo
	RDAP    *RDAPInfo
	CDN     CDNMatch
}

// LookupDNSIP runs the three enrichment lookups in parallel for one IP.
// Used by callers that have already resolved DNS and want lightweight per-IP
// annotation (no RDAP — see LookupIP for the heavyweight version).
func LookupDNSIP(ctx context.Context, ipStr string, asnC *ASNCache) DNSIPInfo {
	if asnC == nil {
		asnC = DefaultASNCache
	}
	var (
		asn  *ASNInfo
		ptrs []string
		wg   sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		asn = asnC.Lookup(ctx, ipStr)
	}()
	go func() {
		defer wg.Done()
		ptrs = ReverseNames(ctx, ipStr)
	}()
	wg.Wait()
	return DNSIPInfo{
		ASN:     asn,
		Reverse: ptrs,
		CDN:     ClassifyCDN(asn, ptrs),
	}
}

// LookupIP gathers ASN, RDAP, reverse DNS, and CDN signals for a single IP.
func LookupIP(ctx context.Context, ip net.IP, asnC *ASNCache, rdapC *RDAPCache) IPDetails {
	if asnC == nil {
		asnC = DefaultASNCache
	}
	if rdapC == nil {
		rdapC = DefaultRDAPCache
	}

	ip = NormalizeIP(ip)
	ipStr := ip.String()

	var (
		asn  *ASNInfo
		rdap *RDAPInfo
		ptrs []string
	)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		asn = asnC.Lookup(ctx, ipStr)
	}()
	go func() {
		defer wg.Done()
		rdap = rdapC.Lookup(ctx, ipStr)
	}()
	go func() {
		defer wg.Done()
		ptrs = ReverseNames(ctx, ipStr)
	}()
	wg.Wait()

	return IPDetails{
		IP:      ip,
		Reverse: ptrs,
		ASN:     asn,
		RDAP:    rdap,
		CDN:     ClassifyCDN(asn, ptrs),
	}
}

// ReverseNames returns PTR records for the given IP, with trailing dots trimmed.
// Errors are swallowed — a nil/empty slice just means "no reverse DNS available".
func ReverseNames(ctx context.Context, ipStr string) []string {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(c, ipStr)
	if err != nil {
		return nil
	}
	for i := range names {
		names[i] = strings.TrimSuffix(strings.TrimSpace(names[i]), ".")
	}
	return names
}

// UniqueIPs returns the input slice with duplicates removed (in original order).
// Each IP is canonicalized via NormalizeIP first.
func UniqueIPs(ips []net.IP) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	for _, ip := range ips {
		ip = NormalizeIP(ip)
		if ip == nil {
			continue
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
	}
	return out
}

// NormalizeIP converts the input to canonical 4-byte (v4) or 16-byte (v6) form.
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// DNSInfoSuffix formats DNSIPInfo as a short trailing string for inline display
// (e.g. "  AS15169 GOOGLE (CDN: Google)"). Returns "" when there's nothing useful.
func DNSInfoSuffix(info *DNSIPInfo) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.ASN != nil && info.ASN.ASN != "" {
		asn := "AS" + NormalizeASN(info.ASN.ASN)
		if org := CleanASNOrg(info.ASN.Org); org != "" {
			asn += " " + org
		}
		parts = append(parts, asn)
	}
	if info.CDN.Provider != "" {
		parts = append(parts, fmt.Sprintf("(CDN: %s)", info.CDN.Provider))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, " ")
}

// FormatASNDetails formats Cymru ASN info and optional RDAP org into a single
// line for the `netcheck ip` ASN row.
func FormatASNDetails(asn *ASNInfo, rdap *RDAPInfo) string {
	if asn == nil || asn.ASN == "" {
		return "-"
	}
	out := "AS" + NormalizeASN(asn.ASN)
	if org := CleanASNOrg(asn.Org); org != "" {
		out += " " + org
	}
	if rdap != nil && rdap.Name != "" && !sameOrgName(CleanASNOrg(asn.Org), rdap.Name) {
		out += " (" + rdap.Name + ")"
	}
	return out
}

// CleanASNOrg trims trailing country codes and tail-with-dash patterns from
// Cymru org strings (e.g. "GOOGLE, US" → "GOOGLE", "CLOUDFLARENET - Cloudflare, Inc., US" → "CLOUDFLARENET").
func CleanASNOrg(org string) string {
	org = strings.TrimSpace(org)
	if org == "" {
		return ""
	}
	if idx := strings.LastIndex(org, ","); idx > 0 {
		tail := strings.TrimSpace(org[idx+1:])
		if len(tail) == 2 {
			org = strings.TrimSpace(org[:idx])
		}
	}
	if idx := strings.Index(org, " - "); idx > 0 {
		org = strings.TrimSpace(org[:idx])
	}
	return org
}

func sameOrgName(a, b string) bool {
	a = normalizeOrgName(a)
	b = normalizeOrgName(b)
	return a != "" && b != "" && a == b
}

func normalizeOrgName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, ".", "")
	return strings.TrimSpace(s)
}
