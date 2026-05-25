package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/wayback"
)

// RunArch executes the `netcheck arch <domain>` command.
// Returns a process exit code (0 success, 1 transport error, 2 bad input).
func RunArch(args []string) int {
	fs := flag.NewFlagSet("netcheck arch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", archDefaultTimeout(loadedConfig.Timeout), "CDX query timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck arch [flags] <domain>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Queries archive.org's CDX API for historical snapshots of <domain> and")
		fmt.Fprintln(os.Stderr, "its subdomains. Reports total snapshots, unique URLs, first/last seen,")
		fmt.Fprintln(os.Stderr, "and a sample of the most-recent captures. Passive — only talks to")
		fmt.Fprintln(os.Stderr, "archive.org, never to the target.")
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

	return runArchFormat(w, fs.Arg(0), *timeout, format)
}

// archDefaultTimeout floors the timeout at 60s — CDX queries on popular
// domains routinely take 20-40 seconds.
func archDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 60*time.Second {
		return 60 * time.Second
	}
	return cfg
}

func runArchFormat(w io.Writer, domain string, timeout time.Duration, format Format) int {
	res := wayback.Lookup(context.Background(), domain, timeout)
	j := report.ToArchJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderArchMD(w, j)
	case FormatHTML:
		report.RenderArchHTML(w, j)
	default:
		report.RenderArch(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildArch runs the lookup and projects it into the JSON schema.
// Shared by CLI and future HTTP-API surfaces.
func BuildArch(ctx context.Context, domain string, timeout time.Duration) report.ArchJSON {
	res := wayback.Lookup(ctx, domain, timeout)
	return report.ToArchJSON(res)
}
