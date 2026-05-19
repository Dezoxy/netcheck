package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func runDNS(args []string) {
	fs := flag.NewFlagSet("netcheck dns", flag.ExitOnError)
	typesFlag := fs.String("type", "A,AAAA", "comma-separated record types (A,AAAA,CNAME,MX,TXT,NS,SOA)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-query timeout")
	var extra stringSlice
	fs.Var(&extra, "resolver", "additional resolver host[:port] (repeatable)")
	skipSystem := fs.Bool("no-system", false, "skip the system resolver")
	skipDefaults := fs.Bool("no-defaults", false, "skip built-in resolvers (Cloudflare/Google/Quad9)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck dns [flags] <host>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	host := fs.Arg(0)

	types, err := parseTypes(*typesFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	var resolvers []Resolver
	if !*skipSystem {
		resolvers = append(resolvers, systemResolvers()...)
	}
	if !*skipDefaults {
		resolvers = append(resolvers, defaultResolvers...)
	}
	for _, r := range extra {
		addr := ensurePort(r)
		resolvers = append(resolvers, Resolver{Name: addr, Address: addr})
	}
	if len(resolvers) == 0 {
		fmt.Fprintln(os.Stderr, "error: no resolvers configured")
		os.Exit(2)
	}

	fmt.Printf("DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, time.Now().Format("2006-01-02 15:04:05"))

	anyError := false
	for _, qt := range types {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
		result := compareResolvers(ctx, resolvers, host, qt, *timeout)
		cancel()
		renderDNSCompare(os.Stdout, &result)
		// Disagreement is expected for CDN-fronted hosts (GeoDNS), so only
		// hard-fail on transport/rcode errors. The verdict still surfaces splits.
		for _, r := range result.Results {
			if r.Err != nil {
				anyError = true
			}
		}
	}

	if anyError {
		os.Exit(1)
	}
}

func renderDNSCompare(w io.Writer, r *DNSCompareResult) {
	fmt.Fprintf(w, "%s records\n", r.QType)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  RESOLVER\tADDRESS\tTIME\tANSWER")
	for _, res := range r.Results {
		addr := res.Resolver.Address
		took := ms(res.Took)
		if res.Err != nil {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s %v\n", res.Resolver.Name, addr, took, mark(false), res.Err)
			continue
		}
		if len(res.Records) == 0 {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t(no records)\n", res.Resolver.Name, addr, took)
			continue
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", res.Resolver.Name, addr, took, res.Records[0])
		for _, rec := range res.Records[1:] {
			fmt.Fprintf(tw, "  \t\t\t%s\n", rec)
		}
	}
	tw.Flush()

	v := r.Verdict()
	switch {
	case len(v.Groups) == 0:
		fmt.Fprintln(w, "  Verdict: all resolvers failed")
	case v.Agree:
		fmt.Fprintln(w, "  Verdict: all resolvers agree")
	default:
		fmt.Fprintf(w, "  Verdict: resolvers disagree (%d distinct answer sets)\n", len(v.Groups))
		for i, g := range v.Groups {
			fmt.Fprintf(w, "    Set %d (%s):\n", i+1, strings.Join(g.Resolvers, ", "))
			if len(g.Records) == 0 {
				fmt.Fprintln(w, "      (empty)")
			}
			for _, rec := range g.Records {
				fmt.Fprintf(w, "      %s\n", rec)
			}
		}
	}
	fmt.Fprintln(w)
}
