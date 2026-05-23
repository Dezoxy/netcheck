package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netcheck/internal/report"
	"netcheck/internal/techdetect"
)

// RunTech executes the `netcheck tech <url>` command.
// Returns a process exit code (0 success, 1 transport error, 2 bad invocation).
func RunTech(args []string) int {
	fs := flag.NewFlagSet("netcheck tech", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", loadedConfig.Timeout, "detect timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck tech [flags] <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Identifies the web technologies (CMS, JS framework, server, CDN, language)")
		fmt.Fprintln(os.Stderr, "from response headers, cookies, and HTML body. One HTTP GET, body read")
		fmt.Fprintln(os.Stderr, "capped at 1 MiB, no active probing.")
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

	return runTechFormat(w, fs.Arg(0), *timeout, *insecure, format)
}

// runTechFormat runs the detection and writes it in the requested format.
// Returns the exit code so RunTech + future callers can share the logic.
func runTechFormat(w io.Writer, rawURL string, timeout time.Duration, insecure bool, format Format) int {
	res := techdetect.Detect(context.Background(), rawURL, insecure, timeout)
	j := report.ToTechJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderTechMD(w, j)
	case FormatHTML:
		report.RenderTechHTML(w, j)
	default:
		report.RenderTech(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildTech runs the detection and projects it into the JSON schema. Shared
// by CLI and future HTTP-API surfaces.
func BuildTech(ctx context.Context, rawURL string, timeout time.Duration, insecure bool) report.TechJSON {
	res := techdetect.Detect(ctx, rawURL, insecure, timeout)
	return report.ToTechJSON(res)
}
