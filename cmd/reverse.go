package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/reverseip"
)

// RunReverse executes the `netcheck reverse <ip>` command.
// Returns a process exit code (0 success, 1 every source failed, 2 bad input).
func RunReverse(args []string) int {
	fs := flag.NewFlagSet("netcheck reverse", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", reverseDefaultTimeout(loadedConfig.Timeout), "lookup timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck reverse [flags] <ip>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Lists other hostnames pointing at <ip> by querying system reverse DNS")
		fmt.Fprintln(os.Stderr, "(PTR) and Hackertarget's public reverse-IP API, plus Shodan when the")
		fmt.Fprintln(os.Stderr, "config file's `apis.shodan_api_key` is set. Passive — netcheck never")
		fmt.Fprintln(os.Stderr, "talks to the target host itself.")
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

	return runReverseFormat(w, fs.Arg(0), *timeout, format)
}

// reverseDefaultTimeout floors the timeout at 30s — Hackertarget can take
// ~10s on a cold cache, and we want both sources to complete.
func reverseDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 30*time.Second {
		return 30 * time.Second
	}
	return cfg
}

func runReverseFormat(w io.Writer, ip string, timeout time.Duration, format Format) int {
	opts := reverseip.Options{ShodanAPIKey: loadedConfig.APIs.ShodanAPIKey}
	res := reverseip.Enumerate(context.Background(), ip, opts, timeout)
	j := report.ToReverseJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderReverseMD(w, j)
	case FormatHTML:
		report.RenderReverseHTML(w, j)
	default:
		report.RenderReverse(w, j)
	}

	if res.Err != nil {
		return 1
	}
	// Every active source errored → no usable result.
	if len(res.Hostnames) == 0 && len(res.SourceErrors) > 0 {
		// Compare against the count of ACTIVE sources (not disabled-by-config).
		activeSources := 2 // ptr + hackertarget
		if opts.ShodanAPIKey != "" {
			activeSources++
		}
		if len(res.SourceErrors) >= activeSources {
			return 1
		}
	}
	return 0
}

// BuildReverse runs the lookup and projects it into the JSON schema.
// Shared by CLI and future HTTP-API surfaces.
func BuildReverse(ctx context.Context, ip string, timeout time.Duration) report.ReverseJSON {
	opts := reverseip.Options{ShodanAPIKey: loadedConfig.APIs.ShodanAPIKey}
	res := reverseip.Enumerate(ctx, ip, opts, timeout)
	return report.ToReverseJSON(res)
}
