package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	Name    string
	Address string // host:port
}

var defaultResolvers = []Resolver{
	{Name: "Cloudflare", Address: "1.1.1.1:53"},
	{Name: "Google", Address: "8.8.8.8:53"},
	{Name: "Quad9", Address: "9.9.9.9:53"},
}

func systemResolvers() []Resolver {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil
	}
	port := cfg.Port
	if port == "" {
		port = "53"
	}
	// macOS often lists multiple internal loopback resolvers that return the
	// same answers; use the first one to keep the table readable.
	return []Resolver{{Name: "System", Address: net.JoinHostPort(cfg.Servers[0], port)}}
}

func ensurePort(addr string) string {
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

var qtypeOrder = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"}

func parseTypes(s string) ([]string, error) {
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

type ResolverResult struct {
	Resolver Resolver
	Records  []string
	Err      error
	Took     time.Duration
}

func queryResolver(ctx context.Context, r Resolver, host string, qtypeName string, timeout time.Duration) ResolverResult {
	qtype := qtypeByName[qtypeName]
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	start := time.Now()
	c := &dns.Client{Timeout: timeout}
	in, _, err := c.ExchangeContext(ctx, m, r.Address)
	if err == nil && in != nil && in.Truncated {
		// Response didn't fit in UDP — retry over TCP.
		cTCP := &dns.Client{Timeout: timeout, Net: "tcp"}
		in, _, err = cTCP.ExchangeContext(ctx, m, r.Address)
	}
	took := time.Since(start)

	res := ResolverResult{Resolver: r, Took: took}
	if err != nil {
		res.Err = err
		return res
	}
	if in.Rcode != dns.RcodeSuccess {
		res.Err = fmt.Errorf("rcode %s", dns.RcodeToString[in.Rcode])
		return res
	}
	for _, ans := range in.Answer {
		// Some answers include CNAMEs in the chain even for A/AAAA queries.
		// Show all answers; the value extraction handles the type.
		res.Records = append(res.Records, recordValue(ans))
	}
	sort.Strings(res.Records)
	return res
}

func recordValue(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial)
	}
	return rr.String()
}

type DNSCompareResult struct {
	Host    string
	QType   string
	Results []ResolverResult
}

func compareResolvers(ctx context.Context, resolvers []Resolver, host, qtype string, timeout time.Duration) DNSCompareResult {
	results := make([]ResolverResult, len(resolvers))
	var wg sync.WaitGroup
	for i, r := range resolvers {
		wg.Add(1)
		go func(i int, r Resolver) {
			defer wg.Done()
			results[i] = queryResolver(ctx, r, host, qtype, timeout)
		}(i, r)
	}
	wg.Wait()
	return DNSCompareResult{Host: host, QType: qtype, Results: results}
}

// Verdict reports whether successful resolvers returned identical answer sets,
// and groups them by distinct answer set. Failed resolvers are ignored for the verdict.
type Verdict struct {
	Agree  bool
	Groups []VerdictGroup
}

type VerdictGroup struct {
	Records   []string
	Resolvers []string
}

func (d *DNSCompareResult) Verdict() Verdict {
	groups := map[string]*VerdictGroup{}
	var order []string
	for _, r := range d.Results {
		if r.Err != nil {
			continue
		}
		key := strings.Join(r.Records, "|")
		g, ok := groups[key]
		if !ok {
			g = &VerdictGroup{Records: r.Records}
			groups[key] = g
			order = append(order, key)
		}
		g.Resolvers = append(g.Resolvers, r.Resolver.Name)
	}
	out := Verdict{Agree: len(order) <= 1}
	for _, k := range order {
		out.Groups = append(out.Groups, *groups[k])
	}
	return out
}
