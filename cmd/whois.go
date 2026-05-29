package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Dezoxy/netcheck/pkg/ipinfo"
	"github.com/Dezoxy/netcheck/pkg/report"
)

// RunWhois executes the `netcheck whois <domain>` command.
// Returns a process exit code (0 success, 1 transport error, 2 bad input).
func RunWhois(args []string) int {
	fs := flag.NewFlagSet("netcheck whois", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", whoisDefaultTimeout(loadedConfig.Timeout), "RDAP query timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck whois [flags] <domain>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Looks up the sponsoring registrar for <domain>. Tries RDAP first (the")
		fmt.Fprintln(os.Stderr, "modern, structured WHOIS replacement) for the registrar name, IANA ID,")
		fmt.Fprintln(os.Stderr, "and URL; if the TLD exposes no RDAP registrar it falls back to a classic")
		fmt.Fprintln(os.Stderr, "WHOIS (port 43) query for the name. Passive — never touches the target.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Some registries (.hu and other GDPR-stripped ccTLDs) publish no registrar")
		fmt.Fprintln(os.Stderr, "over either protocol — those report \"not found\".")
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

	format, err := ParseFormat(*outputFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	return runWhoisFormat(w, fs.Arg(0), *timeout, format)
}

// whoisDefaultTimeout floors the timeout at 15s — RDAP is a single HTTPS
// round-trip (often through the rdap.org redirector), so it's quick.
func whoisDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 15*time.Second {
		return 15 * time.Second
	}
	return cfg
}

func runWhoisFormat(w io.Writer, domain string, timeout time.Duration, format Format) int {
	j := BuildWhois(context.Background(), domain, timeout)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderWhoisMD(w, j)
	case FormatHTML:
		report.RenderWhoisHTML(w, j)
	default:
		report.RenderWhois(w, j)
	}

	if j.Error != "" {
		return 1
	}
	return 0
}

// BuildWhois runs the RDAP registrar lookup and projects it into the JSON
// schema. Shared by the CLI and the HTTP-API surface. A TLD with no RDAP
// registrar data is a successful "not found", not an error.
func BuildWhois(ctx context.Context, domain string, timeout time.Duration) report.WhoisJSON {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	r := ipinfo.DefaultRDAPDomainCache.Lookup(c, domain)
	took := time.Since(started)
	return report.ToWhoisJSON(domain, r, started, took, nil)
}
