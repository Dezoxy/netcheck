package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netcheck/internal/report"
	"netcheck/internal/secheaders"
)

// RunHeaders executes the `netcheck headers <url>` command.
// Returns a process exit code (0 success, 1 audit transport error, 2 bad invocation).
func RunHeaders(args []string) int {
	fs := flag.NewFlagSet("netcheck headers", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", loadedConfig.Timeout, "audit timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck headers [flags] <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Audits security-relevant response headers (HSTS, CSP, X-Frame-Options,")
		fmt.Fprintln(os.Stderr, "X-Content-Type-Options, Referrer-Policy, Permissions-Policy) plus")
		fmt.Fprintln(os.Stderr, "information-disclosure headers (Server, X-Powered-By). One HTTP GET,")
		fmt.Fprintln(os.Stderr, "no active probing.")
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

	return runHeadersFormat(w, fs.Arg(0), *timeout, *insecure, format)
}

// runHeadersFormat runs the audit and writes it in the requested format.
// Returns the exit code so RunHeaders + future callers can share the logic.
func runHeadersFormat(w io.Writer, rawURL string, timeout time.Duration, insecure bool, format Format) int {
	res := secheaders.Audit(context.Background(), rawURL, insecure, timeout)
	j := report.ToHeadersJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderHeadersMD(w, j)
	case FormatHTML:
		report.RenderHeadersHTML(w, j)
	default:
		report.RenderHeaders(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildHeaders runs the audit and projects it into the JSON schema. Shared by
// CLI and future HTTP-API surfaces.
func BuildHeaders(ctx context.Context, rawURL string, timeout time.Duration, insecure bool) report.HeadersJSON {
	res := secheaders.Audit(ctx, rawURL, insecure, timeout)
	return report.ToHeadersJSON(res)
}
