package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/subenum"
)

// RunSubs executes the `netcheck subs <domain>` command.
// Returns a process exit code (0 success, 1 transport error, 2 bad invocation).
//
// Per-source errors don't fail the run as long as at least one source
// returned. Only a top-level input error (empty/invalid domain) or every
// source erroring produces a non-zero exit.
func RunSubs(args []string) int {
	fs := flag.NewFlagSet("netcheck subs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	// subs goes out to two external APIs in parallel; allow more time than
	// the default per-check timeout.
	timeout := fs.Duration("timeout", subsDefaultTimeout(loadedConfig.Timeout), "enumeration timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck subs [flags] <domain>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Enumerates subdomains by querying public Certificate Transparency log")
		fmt.Fprintln(os.Stderr, "aggregators (crt.sh and CertSpotter) in parallel. Passive — no DNS lookups,")
		fmt.Fprintln(os.Stderr, "no port probes, no traffic to the target.")
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

	return runSubsFormat(w, fs.Arg(0), *timeout, format)
}

// subsDefaultTimeout returns a sensible default — at least 30s — even if the
// global config timeout is shorter. crt.sh in particular can take 10+ seconds
// for a large domain.
func subsDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 30*time.Second {
		return 30 * time.Second
	}
	return cfg
}

// runSubsFormat runs the enumeration and writes it in the requested format.
// Returns the exit code so RunSubs + future callers can share the logic.
func runSubsFormat(w io.Writer, domain string, timeout time.Duration, format Format) int {
	res := subenum.Enumerate(context.Background(), domain, timeout)
	j := report.ToSubsJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderSubsMD(w, j)
	case FormatHTML:
		report.RenderSubsHTML(w, j)
	default:
		report.RenderSubs(w, j)
	}

	// Failure cases:
	//   - top-level err (bad input)
	//   - every source errored (no usable data at all)
	if res.Err != nil {
		return 1
	}
	if len(res.Subdomains) == 0 && len(res.SourceErrors) > 0 && len(res.SourceErrors) >= 2 {
		return 1
	}
	return 0
}

// BuildSubs runs the enumeration and projects it into the JSON schema.
// Shared by CLI and future HTTP-API surfaces.
func BuildSubs(ctx context.Context, domain string, timeout time.Duration) report.SubsJSON {
	res := subenum.Enumerate(ctx, domain, timeout)
	return report.ToSubsJSON(res)
}
