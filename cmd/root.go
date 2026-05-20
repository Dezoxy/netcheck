// Package cmd hosts the netcheck CLI surface. main calls Run.
package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"netcheck/internal/check"
	"netcheck/internal/ipinfo"
)

// Version is the canonical netcheck version string, surfaced via `--version`
// and wired into the RDAP User-Agent at startup.
const Version = "0.4.2"

// Run dispatches an os.Args invocation. Bare `netcheck` on an interactive
// terminal drops into the menu; otherwise the first positional is treated as
// a subcommand or full-check target.
func Run() {
	if len(os.Args) < 2 {
		if stdinIsTTY() {
			RunMenu(nil)
			return
		}
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "menu":
		RunMenu(os.Args[2:])
	case "dns":
		RunDNS(os.Args[2:])
	case "route":
		RunRoute(os.Args[2:])
	case "ip":
		RunIP(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Printf("netcheck %s\n", Version)
	default:
		RunFull(os.Args[1:])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "netcheck %s\n\n", Version)
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  netcheck                       interactive menu (when run on a terminal)")
	fmt.Fprintln(os.Stderr, "  netcheck menu                  interactive menu (explicit)")
	fmt.Fprintln(os.Stderr, "  netcheck <target>              full check (DNS, TCP, TLS, HTTP)")
	fmt.Fprintln(os.Stderr, "  netcheck dns <host>            compare DNS resolvers")
	fmt.Fprintln(os.Stderr, "  netcheck route <host>          trace the network path with per-hop ASN")
	fmt.Fprintln(os.Stderr, "  netcheck ip <ip|host>          show IP ownership, RDAP, reverse DNS, and CDN hints")
	fmt.Fprintln(os.Stderr, "  netcheck help                  show this message")
	fmt.Fprintln(os.Stderr, "  netcheck version               show version")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "examples:")
	fmt.Fprintln(os.Stderr, "  netcheck google.com")
	fmt.Fprintln(os.Stderr, "  netcheck --insecure https://expired.badssl.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns google.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns --type MX,TXT cloudflare.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns --resolver 1.0.0.1 --resolver 8.8.4.4 google.com")
	fmt.Fprintln(os.Stderr, "  netcheck route google.com")
	fmt.Fprintln(os.Stderr, "  netcheck route --no-asn --max-hops 20 1.1.1.1")
	fmt.Fprintln(os.Stderr, "  netcheck ip cloudflare.com")
	fmt.Fprintln(os.Stderr, "  netcheck ip 8.8.8.8")
}

// annotateDNS enriches a check.DNSResult with per-IP ASN/PTR/CDN info.
// Lives in cmd (not check or ipinfo) because it orchestrates across both
// packages — keeping it here avoids any cycle between them.
func annotateDNS(ctx context.Context, d *check.DNSResult, asnC *ipinfo.ASNCache) {
	if d.Err != nil {
		return
	}
	if asnC == nil {
		asnC = ipinfo.DefaultASNCache
	}
	all := append([]net.IP{}, d.A...)
	all = append(all, d.AAAA...)
	ips := ipinfo.UniqueIPs(all)
	if len(ips) == 0 {
		return
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	info := make(map[string]ipinfo.DNSIPInfo, len(ips))
	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipStr := ip.String()
			res := ipinfo.LookupDNSIP(ctx, ipStr, asnC)
			mu.Lock()
			info[ipStr] = res
			mu.Unlock()
		}()
	}
	wg.Wait()
	d.IPInfo = info
}
