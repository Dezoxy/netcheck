package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "dns":
		runDNS(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Printf("netcheck %s\n", version)
	default:
		runFull(os.Args[1:])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "netcheck %s\n\n", version)
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  netcheck <target>              full check (DNS, TCP, TLS, HTTP)")
	fmt.Fprintln(os.Stderr, "  netcheck dns <host>            compare DNS resolvers")
	fmt.Fprintln(os.Stderr, "  netcheck help                  show this message")
	fmt.Fprintln(os.Stderr, "  netcheck version               show version")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "examples:")
	fmt.Fprintln(os.Stderr, "  netcheck google.com")
	fmt.Fprintln(os.Stderr, "  netcheck --insecure https://expired.badssl.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns google.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns --type MX,TXT cloudflare.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns --resolver 1.0.0.1 --resolver 8.8.4.4 google.com")
}

func runFull(args []string) {
	fs := flag.NewFlagSet("netcheck", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "per-check timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck [flags] <target>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	target, err := parseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	report := Report{Target: target, StartedAt: time.Now()}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	report.DNS = lookupDNS(ctx, target.Host)
	cancel()

	if report.DNS.Err == nil {
		if len(report.DNS.A) > 0 {
			c, cf := context.WithTimeout(context.Background(), *timeout)
			r := checkTCP(c, report.DNS.A[0], target.Port)
			report.TCPv4 = &r
			cf()
		}
		if len(report.DNS.AAAA) > 0 {
			c, cf := context.WithTimeout(context.Background(), *timeout)
			r := checkTCP(c, report.DNS.AAAA[0], target.Port)
			report.TCPv6 = &r
			cf()
		}
	}

	if target.Scheme == "https" {
		c, cf := context.WithTimeout(context.Background(), *timeout)
		r := checkTLS(c, target.Host, target.Port, *insecure)
		report.TLS = &r
		cf()
	}

	c, cf := context.WithTimeout(context.Background(), *timeout*3)
	report.HTTP = checkHTTP(c, target, *insecure)
	cf()

	render(os.Stdout, &report)

	if !report.OK() {
		os.Exit(1)
	}
}
