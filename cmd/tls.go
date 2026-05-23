package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netcheck/internal/report"
	"netcheck/internal/tlsaudit"
)

// RunTLSAudit executes the `netcheck tls <host[:port]>` command. Active —
// requires authorization.
func RunTLSAudit(args []string) int {
	fs := flag.NewFlagSet("netcheck tls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", tlsDefaultTimeout(loadedConfig.Timeout), "audit timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	authzCheck := requireAuthorization(fs, "tls")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck tls [flags] <host[:port]>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Probes the target with every TLS version (1.0-1.3) and every cipher suite")
		fmt.Fprintln(os.Stderr, "Go knows about, captures the certificate chain, and reports findings —")
		fmt.Fprintln(os.Stderr, "deprecated protocols, weak ciphers, expired or expiring certs.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "ACTIVE — opens many TCP+TLS handshakes to the target. Requires")
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

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	return runTLSAuditFormat(w, fs.Arg(0), *timeout, format)
}

// tlsDefaultTimeout floors at 45s — Phase 2 (cipher probing) opens ~30
// handshakes, each with a 1-2s budget; default 10s is too tight.
func tlsDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 45*time.Second {
		return 45 * time.Second
	}
	return cfg
}

func runTLSAuditFormat(w io.Writer, host string, timeout time.Duration, format Format) int {
	res := tlsaudit.Audit(context.Background(), host, timeout)
	j := report.ToTLSAuditJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderTLSAuditMD(w, j)
	case FormatHTML:
		report.RenderTLSAuditHTML(w, j)
	default:
		report.RenderTLSAudit(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildTLSAudit runs the audit and projects it into the JSON schema. Shared
// by CLI and future HTTP-API surfaces.
func BuildTLSAudit(ctx context.Context, host string, timeout time.Duration) report.TLSAuditJSON {
	res := tlsaudit.Audit(ctx, host, timeout)
	return report.ToTLSAuditJSON(res)
}
