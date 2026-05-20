package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"netcheck/internal/dnscompare"
	"netcheck/internal/report"
)

// stringSlice is a flag.Value for repeatable string flags like --resolver.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// RunDNS executes the `netcheck dns <host>` resolver-comparison command.
func RunDNS(args []string) {
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

	types, err := dnscompare.ParseTypes(*typesFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	var resolvers []dnscompare.Resolver
	if !*skipSystem {
		resolvers = append(resolvers, dnscompare.SystemResolvers()...)
	}
	if !*skipDefaults {
		resolvers = append(resolvers, dnscompare.DefaultResolvers...)
	}
	for _, r := range extra {
		addr := dnscompare.EnsurePort(r)
		resolvers = append(resolvers, dnscompare.Resolver{Name: addr, Address: addr})
	}
	if len(resolvers) == 0 {
		fmt.Fprintln(os.Stderr, "error: no resolvers configured")
		os.Exit(2)
	}

	fmt.Printf("DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, time.Now().Format("2006-01-02 15:04:05"))

	anyError := false
	for _, qt := range types {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
		result := dnscompare.Compare(ctx, resolvers, host, qt, *timeout)
		cancel()
		report.RenderDNSCompare(os.Stdout, &result)
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
