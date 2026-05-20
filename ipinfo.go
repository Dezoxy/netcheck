package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	defaultASNCache  = newASNCache()
	defaultRDAPCache = newRDAPCache()
)

type DNSIPInfo struct {
	ASN     *ASNInfo
	Reverse []string
	CDN     CDNMatch
}

type IPDetails struct {
	IP      net.IP
	Reverse []string
	ASN     *ASNInfo
	RDAP    *RDAPInfo
	CDN     CDNMatch
}

func annotateDNS(ctx context.Context, d *DNSResult, asnC *asnCache) {
	if d.Err != nil {
		return
	}
	if asnC == nil {
		asnC = defaultASNCache
	}
	ips := uniqueIPs(append(append([]net.IP{}, d.A...), d.AAAA...))
	if len(ips) == 0 {
		return
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	info := make(map[string]DNSIPInfo, len(ips))
	for _, ip := range ips {
		ip := normalizeIP(ip)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipStr := ip.String()
			asn := asnC.Lookup(ctx, ipStr)
			ptrs := reverseNames(ctx, ipStr)
			mu.Lock()
			info[ipStr] = DNSIPInfo{
				ASN:     asn,
				Reverse: ptrs,
				CDN:     classifyCDN(asn, ptrs),
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	d.IPInfo = info
}

func lookupIPDetails(ctx context.Context, ip net.IP, asnC *asnCache, rdapC *rdapCache) IPDetails {
	if asnC == nil {
		asnC = defaultASNCache
	}
	if rdapC == nil {
		rdapC = defaultRDAPCache
	}

	ip = normalizeIP(ip)
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
		ptrs = reverseNames(ctx, ipStr)
	}()
	wg.Wait()

	return IPDetails{
		IP:      ip,
		Reverse: ptrs,
		ASN:     asn,
		RDAP:    rdap,
		CDN:     classifyCDN(asn, ptrs),
	}
}

func reverseNames(ctx context.Context, ipStr string) []string {
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

func uniqueIPs(ips []net.IP) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	for _, ip := range ips {
		ip = normalizeIP(ip)
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

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func dnsInfoSuffix(info *DNSIPInfo) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.ASN != nil && info.ASN.ASN != "" {
		asn := "AS" + normalizeASN(info.ASN.ASN)
		if org := cleanASNOrg(info.ASN.Org); org != "" {
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

func formatASNDetails(asn *ASNInfo, rdap *RDAPInfo) string {
	if asn == nil || asn.ASN == "" {
		return "-"
	}
	out := "AS" + normalizeASN(asn.ASN)
	if org := cleanASNOrg(asn.Org); org != "" {
		out += " " + org
	}
	if rdap != nil && rdap.Name != "" && !sameOrgName(cleanASNOrg(asn.Org), rdap.Name) {
		out += " (" + rdap.Name + ")"
	}
	return out
}

func cleanASNOrg(org string) string {
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
