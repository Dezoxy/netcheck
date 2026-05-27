package dnscompare

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
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
	var (
		in  *dns.Msg
		err error
	)
	switch r.Type {
	case TypeDoH:
		in, err = queryDoH(ctx, r.Address, m, timeout)
	case TypeDoT:
		c := &dns.Client{Timeout: timeout, Net: "tcp-tls"}
		in, _, err = c.ExchangeContext(ctx, m, r.Address)
	case TypeTCP:
		c := &dns.Client{Timeout: timeout, Net: "tcp"}
		in, _, err = c.ExchangeContext(ctx, m, r.Address)
	default: // UDP
		c := &dns.Client{Timeout: timeout}
		in, _, err = c.ExchangeContext(ctx, m, r.Address)
		if err == nil && in != nil && in.Truncated {
			// Response didn't fit in UDP — retry over TCP.
			cTCP := &dns.Client{Timeout: timeout, Net: "tcp"}
			in, _, err = cTCP.ExchangeContext(ctx, m, r.Address)
		}
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

// queryDoH performs a DNS-over-HTTPS query using the wire-format POST method
// from RFC 8484. Address is the full URL of the dns-query endpoint.
func queryDoH(ctx context.Context, urlStr string, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS query: %w", err)
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(c, "POST", urlStr, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, urlStr)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	in := new(dns.Msg)
	if err := in.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking DoH response: %w", err)
	}
	return in, nil
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
	case *dns.CAA:
		// flags tag "value" — quoting the value keeps tooling-friendly parsing.
		return fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	case *dns.HTTPS:
		// HTTPS embeds dns.SVCB; reuse the SVCB renderer below.
		return svcbValue(&v.SVCB)
	case *dns.SVCB:
		return svcbValue(v)
	case *dns.DS:
		return fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *dns.DNSKEY:
		// Algorithm and key tag are the cheap bits to surface; full key blob
		// is huge and lives in rr.String() if a user really wants it.
		return fmt.Sprintf("%d %d %d %s", v.Flags, v.Protocol, v.Algorithm, v.PublicKey)
	}
	// Fallback for types we accept in qtypeByName but don't pretty-format
	// (NAPTR, HINFO, SPF, RRSIG, NSEC, NSEC3, CDS, CDNSKEY, …). dns.RR.String()
	// is "header rdata" with header = "name TTL class type", and the TTL is
	// the live cache-remaining value — so two resolvers serving identical
	// RDATA will look different to Verdict() purely because of TTL drift.
	// Strip the header so only the RDATA participates in the diff.
	return rdataOnly(rr)
}

// rdataOnly returns the zone-file RDATA portion of an RR, dropping the
// header (name TTL class type) that dns.RR.String() prepends. The header
// is the only part of String() that varies between otherwise-equivalent
// answers from different resolvers (TTL drift), so removing it is what
// lets Verdict() report agreement on unhandled record types.
func rdataOnly(rr dns.RR) string {
	hdr := rr.Header().String()
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), hdr))
}

// svcbValue renders an SVCB / HTTPS record's priority, target, and key=value
// param list in zone-file order. Used by both *dns.SVCB and *dns.HTTPS.
func svcbValue(v *dns.SVCB) string {
	target := strings.TrimSuffix(v.Target, ".")
	if target == "" {
		target = "."
	}
	parts := make([]string, 0, len(v.Value)+2)
	parts = append(parts, fmt.Sprintf("%d", v.Priority), target)
	for _, kv := range v.Value {
		parts = append(parts, fmt.Sprintf("%s=%q", kv.Key(), kv.String()))
	}
	return strings.Join(parts, " ")
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
