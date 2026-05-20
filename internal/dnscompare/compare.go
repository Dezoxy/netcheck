package dnscompare

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResolverResult is one resolver's answer to a query.
type ResolverResult struct {
	Resolver Resolver
	Records  []string
	Err      error
	Took     time.Duration
}

// Result groups the answers from a Compare call.
type Result struct {
	Host    string
	QType   string
	Results []ResolverResult
}

// Compare queries every resolver in parallel for host/qtype and returns the
// per-resolver results. Failures are captured in ResolverResult.Err — Compare
// itself does not return an error.
func Compare(ctx context.Context, resolvers []Resolver, host, qtype string, timeout time.Duration) Result {
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
	return Result{Host: host, QType: qtype, Results: results}
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

// Verdict reports whether successful resolvers returned identical answer sets,
// and groups them by distinct answer set. Failed resolvers are ignored.
type Verdict struct {
	Agree  bool
	Groups []VerdictGroup
}

// VerdictGroup is one distinct answer set and the resolvers that returned it.
type VerdictGroup struct {
	Records   []string
	Resolvers []string
}

// Verdict produces the agree/disagree breakdown for a Result.
func (d *Result) Verdict() Verdict {
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
