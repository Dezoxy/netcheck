package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"netcheck/internal/config"
	"netcheck/internal/dnscompare"
	"netcheck/internal/report"
)

// configResolverToDNS projects a config-file resolver entry into the
// dnscompare.Resolver shape. It accepts an explicit Type or falls back to
// parsing the Address as a URL (the same path --resolver takes).
func configResolverToDNS(r config.ResolverEntry) (dnscompare.Resolver, error) {
	if r.Address == "" {
		return dnscompare.Resolver{}, fmt.Errorf("missing address")
	}
	name := r.Name
	if name == "" {
		name = r.Address
	}
	t := strings.ToLower(strings.TrimSpace(r.Type))
	switch t {
	case "", "udp":
		return dnscompare.Resolver{Name: name, Address: dnscompare.EnsurePort(r.Address, "53"), Type: dnscompare.TypeUDP}, nil
	case "tcp":
		return dnscompare.Resolver{Name: name, Address: dnscompare.EnsurePort(r.Address, "53"), Type: dnscompare.TypeTCP}, nil
	case "dot", "tls":
		return dnscompare.Resolver{Name: name, Address: dnscompare.EnsurePort(r.Address, "853"), Type: dnscompare.TypeDoT}, nil
	case "doh", "https":
		// If the address has no scheme, accept either a full URL or a bare host
		// and assume https:// + /dns-query path.
		addr := r.Address
		if !strings.Contains(addr, "://") {
			addr = "https://" + strings.TrimSuffix(addr, "/") + "/dns-query"
		}
		return dnscompare.Resolver{Name: name, Address: addr, Type: dnscompare.TypeDoH}, nil
	default:
		// Unknown type — try the URL parser as a fallback.
		parsed, err := dnscompare.ParseResolver(r.Address)
		if err != nil {
			return dnscompare.Resolver{}, fmt.Errorf("unsupported type %q", r.Type)
		}
		parsed.Name = name
		return parsed, nil
	}
}

// stringSlice is a flag.Value for repeatable string flags like --resolver.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// RunDNS executes the `netcheck dns <host>` resolver-comparison command.
func RunDNS(args []string) {
	fs := flag.NewFlagSet("netcheck dns", flag.ExitOnError)
	configPath := addConfigFlag(fs)
	typesFlag := fs.String("type", "A,AAAA", "comma-separated record types (A,AAAA,CNAME,MX,TXT,NS,SOA)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-query timeout")
	var extra stringSlice
	fs.Var(&extra, "resolver", "additional resolver (host, host:port, or udp://, tcp://, tls://, dot://, https://, doh:// URL) (repeatable)")
	skipSystem := fs.Bool("no-system", false, "skip the system resolver")
	skipDefaults := fs.Bool("no-defaults", false, "skip built-in resolvers (Cloudflare/Google/Quad9)")
	skipConfig := fs.Bool("no-config-resolvers", false, "skip resolvers defined in the config file")
	outputFlag := addOutputFlag(fs)

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
	applyConfigOverride(*configPath)
	host := fs.Arg(0)

	format, err := ParseFormat(*outputFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

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
	if !*skipConfig {
		for _, r := range loadedConfig.Resolvers {
			parsed, err := configResolverToDNS(r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping config resolver %q: %v\n", r.Name, err)
				continue
			}
			resolvers = append(resolvers, parsed)
		}
	}
	for _, r := range extra {
		parsed, err := dnscompare.ParseResolver(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		resolvers = append(resolvers, parsed)
	}
	if len(resolvers) == 0 {
		fmt.Fprintln(os.Stderr, "error: no resolvers configured")
		os.Exit(2)
	}

	startedAt := time.Now()

	anyError := false
	collected := make([]dnscompare.Result, 0, len(types))
	for _, qt := range types {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
		result := dnscompare.Compare(ctx, resolvers, host, qt, *timeout)
		cancel()
		collected = append(collected, result)
		// Disagreement is expected for CDN-fronted hosts (GeoDNS), so only
		// hard-fail on transport/rcode errors. The verdict still surfaces splits.
		for _, r := range result.Results {
			if r.Err != nil {
				anyError = true
			}
		}
	}

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(os.Stdout, report.ToDNSCompareJSON(host, startedAt, collected)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case FormatMarkdown:
		report.RenderDNSCompareMD(os.Stdout, report.ToDNSCompareJSON(host, startedAt, collected))
	case FormatHTML:
		report.RenderDNSCompareHTML(os.Stdout, report.ToDNSCompareJSON(host, startedAt, collected))
	default:
		fmt.Printf("DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, startedAt.Format("2006-01-02 15:04:05"))
		for i := range collected {
			report.RenderDNSCompare(os.Stdout, &collected[i])
		}
	}

	if anyError {
		os.Exit(1)
	}
}
