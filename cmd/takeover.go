package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netcheck/internal/report"
	"netcheck/internal/takeover"
)

// RunTakeover executes the `netcheck takeover <domain>` command. Active —
// requires authorization (the DNS lookup itself is benign, but the output
// produces exploitation-ready intel).
func RunTakeover(args []string) int {
	fs := flag.NewFlagSet("netcheck takeover", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", takeoverDefaultTimeout(loadedConfig.Timeout), "check timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	authzCheck := requireAuthorization(fs, "takeover")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck takeover [flags] <domain>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Checks whether <domain>'s CNAME points at a third-party service (GitHub")
		fmt.Fprintln(os.Stderr, "Pages, S3, Heroku, Azure, Shopify, ...) that is unclaimed and therefore")
		fmt.Fprintln(os.Stderr, "vulnerable to subdomain takeover.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "ACTIVE — DNS lookup is passive, but the verification probe sends one")
		fmt.Fprintln(os.Stderr, "HTTP GET to the CNAME target, and the output identifies a vulnerability.")
		fmt.Fprintln(os.Stderr, "Requires --i-have-authorization or NETCHECK_AUTHORIZED=1. See docs/ETHICS.md.")
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
	if err := authzCheck(os.Stderr); err != nil {
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

	return runTakeoverFormat(w, fs.Arg(0), *timeout, format)
}

func takeoverDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 15*time.Second {
		return 15 * time.Second
	}
	return cfg
}

func runTakeoverFormat(w io.Writer, domain string, timeout time.Duration, format Format) int {
	res := takeover.Check(context.Background(), domain, timeout)
	j := report.ToTakeoverJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderTakeoverMD(w, j)
	case FormatHTML:
		report.RenderTakeoverHTML(w, j)
	default:
		report.RenderTakeover(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildTakeover runs the check and projects it into the JSON schema. Shared
// by CLI and future HTTP-API surfaces.
func BuildTakeover(ctx context.Context, domain string, timeout time.Duration) report.TakeoverJSON {
	res := takeover.Check(ctx, domain, timeout)
	return report.ToTakeoverJSON(res)
}
