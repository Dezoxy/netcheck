package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Dezoxy/netcheck/internal/config"
	"github.com/Dezoxy/netcheck/pkg/dnscompare"
	"github.com/Dezoxy/netcheck/pkg/report"
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
// Returns a process exit code (0 success, 1 at least one resolver errored, 2 bad invocation).
func RunDNS(args []string) int {
	fs := flag.NewFlagSet("netcheck dns", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	typesFlag := fs.String("type", "A,AAAA", "comma-separated record types (A,AAAA,CNAME,MX,TXT,NS,SOA)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-query timeout")
	var extra stringSlice
	fs.Var(&extra, "resolver", "additional resolver (host, host:port, or udp://, tcp://, tls://, dot://, https://, doh:// URL) (repeatable)")
	skipSystem := fs.Bool("no-system", false, "skip the system resolver")
	skipDefaults := fs.Bool("no-defaults", false, "skip built-in resolvers (Cloudflare/Google/Quad9)")
	skipConfig := fs.Bool("no-config-resolvers", false, "skip resolvers defined in the config file")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck dns [flags] <host>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	applyConfigOverride(*configPath)
	host := fs.Arg(0)

	format, err := ParseFormat(*outputFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	types, err := dnscompare.ParseTypes(*typesFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
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
			return 2
		}
		resolvers = append(resolvers, parsed)
	}
	if len(resolvers) == 0 {
		fmt.Fprintln(os.Stderr, "error: no resolvers configured")
		return 2
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

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, report.ToDNSCompareJSON(host, startedAt, collected)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderDNSCompareMD(w, report.ToDNSCompareJSON(host, startedAt, collected))
	case FormatHTML:
		report.RenderDNSCompareHTML(w, report.ToDNSCompareJSON(host, startedAt, collected))
	default:
		fmt.Fprintf(w, "DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, startedAt.Format("2006-01-02 15:04:05"))
		for i := range collected {
			report.RenderDNSCompare(w, &collected[i])
		}
	}

	if anyError {
		return 1
	}
	return 0
}

// BuildDNSCompare runs the same resolver-comparison pipeline as RunDNS for
// the given host and record types, against the given resolvers, and returns
// the JSON-ready DNSCompareJSON. CLI and app surfaces share this path.
//
// The caller chooses the resolver set (typically: SystemResolvers +
// DefaultResolvers + config-defined). Pass `nil` or empty `types` to default
// to A,AAAA. Errors from individual resolvers are recorded inside the result
// (per-resolver Err); BuildDNSCompare itself never returns an error.
func BuildDNSCompare(ctx context.Context, host string, resolvers []dnscompare.Resolver, types []string, timeout time.Duration) report.DNSCompareJSON {
	if len(types) == 0 {
		types = []string{"A", "AAAA"}
	}
	startedAt := time.Now()
	collected := make([]dnscompare.Result, 0, len(types))
	for _, qt := range types {
		qctx, cancel := context.WithTimeout(ctx, timeout*2)
		collected = append(collected, dnscompare.Compare(qctx, resolvers, host, qt, timeout))
		cancel()
	}
	return report.ToDNSCompareJSON(host, startedAt, collected)
}
