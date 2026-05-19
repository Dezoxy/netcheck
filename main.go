package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	timeout := flag.Duration("timeout", 10*time.Second, "per-check timeout")
	insecure := flag.Bool("insecure", false, "skip TLS verification")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck [flags] <target>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "examples:")
		fmt.Fprintln(os.Stderr, "  netcheck google.com")
		fmt.Fprintln(os.Stderr, "  netcheck https://example.com")
		fmt.Fprintln(os.Stderr, "  netcheck --insecure https://self-signed.badssl.com")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	target, err := parseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	report := Report{Target: target, StartedAt: time.Now()}

	dnsCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	report.DNS = lookupDNS(dnsCtx, target.Host)
	cancel()

	if report.DNS.Err == nil {
		if len(report.DNS.A) > 0 {
			ctx, c := context.WithTimeout(context.Background(), *timeout)
			r := checkTCP(ctx, report.DNS.A[0], target.Port)
			report.TCPv4 = &r
			c()
		}
		if len(report.DNS.AAAA) > 0 {
			ctx, c := context.WithTimeout(context.Background(), *timeout)
			r := checkTCP(ctx, report.DNS.AAAA[0], target.Port)
			report.TCPv6 = &r
			c()
		}
	}

	if target.Scheme == "https" {
		ctx, c := context.WithTimeout(context.Background(), *timeout)
		r := checkTLS(ctx, target.Host, target.Port, *insecure)
		report.TLS = &r
		c()
	}

	ctx, c := context.WithTimeout(context.Background(), *timeout*3)
	report.HTTP = checkHTTP(ctx, target, *insecure)
	c()

	render(os.Stdout, &report)

	if !report.OK() {
		os.Exit(1)
	}
}
