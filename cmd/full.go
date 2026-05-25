package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Dezoxy/netcheck/pkg/check"
	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/target"
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

	r := BuildFullReport(context.Background(), t, *timeout, *insecure)

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, report.ToFullJSON(r)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderFullMD(w, r)
	case FormatHTML:
		report.RenderFullHTML(w, r)
	default:
		report.Render(w, r)
	}

	if !r.OK() {
		return 1
	}
	return 0
}

// BuildFullReport executes the full DNS/TCP/TLS/HTTP pipeline for one parsed
// target without rendering it. CLI and app surfaces share this path.
func BuildFullReport(ctx context.Context, t *target.Target, timeout time.Duration, insecure bool) *report.Report {
	r := &report.Report{Target: t, StartedAt: time.Now()}

	dnsCtx, dnsCancel := context.WithTimeout(ctx, timeout)
	r.DNS = check.LookupDNS(dnsCtx, t.Host)
	dnsCancel()

	if r.DNS.Err == nil {
		annotateCtx, annotateCancel := context.WithTimeout(ctx, timeout)
		annotateDNS(annotateCtx, &r.DNS, nil)
		annotateCancel()

		if len(r.DNS.A) > 0 {
			tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
			res := check.TCP(tcpCtx, r.DNS.A[0], t.Port)
			r.TCPv4 = &res
			tcpCancel()
		}
		if len(r.DNS.AAAA) > 0 {
			tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
			res := check.TCP(tcpCtx, r.DNS.AAAA[0], t.Port)
			r.TCPv6 = &res
			tcpCancel()
		}
	}

	if t.Scheme == "https" {
		tlsCtx, tlsCancel := context.WithTimeout(ctx, timeout)
		res := check.TLS(tlsCtx, t.Host, t.Port, insecure)
		r.TLS = &res
		tlsCancel()
	}

	httpCtx, httpCancel := context.WithTimeout(ctx, timeout*3)
	r.HTTP = check.HTTP(httpCtx, t, insecure)
	httpCancel()

	return r
}
