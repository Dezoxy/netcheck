package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"netcheck/internal/check"
	"netcheck/internal/report"
	"netcheck/internal/target"
)

// RunFull executes the `netcheck <target>` end-to-end check.
// Returns a process exit code (0 success, 1 check failed, 2 bad invocation).
func RunFull(args []string) int {
	fs := flag.NewFlagSet("netcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", loadedConfig.Timeout, "per-check timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck [flags] <target>")
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

	t, err := target.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	r := report.Report{Target: t, StartedAt: time.Now()}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	r.DNS = check.LookupDNS(ctx, t.Host)
	cancel()

	if r.DNS.Err == nil {
		c, cf := context.WithTimeout(context.Background(), *timeout)
		annotateDNS(c, &r.DNS, nil)
		cf()

		if len(r.DNS.A) > 0 {
			c, cf := context.WithTimeout(context.Background(), *timeout)
			res := check.TCP(c, r.DNS.A[0], t.Port)
			r.TCPv4 = &res
			cf()
		}
		if len(r.DNS.AAAA) > 0 {
			c, cf := context.WithTimeout(context.Background(), *timeout)
			res := check.TCP(c, r.DNS.AAAA[0], t.Port)
			r.TCPv6 = &res
			cf()
		}
	}

	if t.Scheme == "https" {
		c, cf := context.WithTimeout(context.Background(), *timeout)
		res := check.TLS(c, t.Host, t.Port, *insecure)
		r.TLS = &res
		cf()
	}

	c, cf := context.WithTimeout(context.Background(), *timeout*3)
	r.HTTP = check.HTTP(c, t, *insecure)
	cf()

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, report.ToFullJSON(&r)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderFullMD(w, &r)
	case FormatHTML:
		report.RenderFullHTML(w, &r)
	default:
		report.Render(w, &r)
	}

	if !r.OK() {
		return 1
	}
	return 0
}
