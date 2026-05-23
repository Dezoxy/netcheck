package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netcheck/internal/portscan"
	"netcheck/internal/report"
)

// RunPorts executes the `netcheck ports <host>` command. Active —
// requires authorization.
func RunPorts(args []string) int {
	fs := flag.NewFlagSet("netcheck ports", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", portsDefaultTimeout(loadedConfig.Timeout), "overall scan timeout")
	portsFlag := fs.String("ports", "", "explicit port list (e.g. \"22,80,443,8000-8010\"). Overrides --top.")
	topFlag := fs.Int("top", 100, "scan the top-N most-likely-open ports (nmap default ordering). Ignored if --ports is set.")
	concurrency := fs.Int("concurrency", 50, "parallel dials")
	perPort := fs.Duration("per-port-timeout", 2*time.Second, "per-port connect timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	authzCheck := requireAuthorization(fs, "ports")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck ports [flags] <host>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "TCP connect scan against <host>. Default: top-100 most-likely-open ports.")
		fmt.Fprintln(os.Stderr, "Pass --ports to scan an explicit list; --top to change the top-N count.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "ACTIVE — opens parallel TCP handshakes to the target. Requires")
		fmt.Fprintln(os.Stderr, "--i-have-authorization or NETCHECK_AUTHORIZED=1. See docs/ETHICS.md.")
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

	opts := portscan.Options{
		Top:            *topFlag,
		Concurrency:    *concurrency,
		PerPortTimeout: *perPort,
	}
	if *portsFlag != "" {
		ports, err := portscan.ParsePortList(*portsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		opts.Ports = ports
	}

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	return runPortsFormat(w, fs.Arg(0), opts, *timeout, format)
}

func portsDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 60*time.Second {
		return 60 * time.Second
	}
	return cfg
}

func runPortsFormat(w io.Writer, host string, opts portscan.Options, timeout time.Duration, format Format) int {
	res := portscan.Scan(context.Background(), host, opts, timeout)
	j := report.ToPortScanJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderPortScanMD(w, j)
	case FormatHTML:
		report.RenderPortScanHTML(w, j)
	default:
		report.RenderPortScan(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildPorts runs the scan and projects it into the JSON schema. Shared
// by CLI and future HTTP-API surfaces.
func BuildPorts(ctx context.Context, host string, opts portscan.Options, timeout time.Duration) report.PortScanJSON {
	res := portscan.Scan(ctx, host, opts, timeout)
	return report.ToPortScanJSON(res)
}
