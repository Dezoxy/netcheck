package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"netcheck/internal/check"
	"netcheck/internal/ipinfo"
	"netcheck/internal/report"
	"netcheck/internal/target"
)

// RunIP executes the `netcheck ip <ip|host>` command.
func RunIP(args []string) {
	fs := flag.NewFlagSet("netcheck ip", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "overall IP info timeout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck ip [flags] <ip|host>")
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

	if err := RunIPInfo(os.Stdout, fs.Arg(0), *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// RunIPInfo is the menu/CLI entry point that resolves input → IPs → enrichment → render.
func RunIPInfo(w io.Writer, raw string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	label, ips, fromHost, err := ResolveIPInput(ctx, raw)
	if err != nil {
		return err
	}
	resolveTook := time.Since(start)

	details := make([]ipinfo.IPDetails, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		i, ip := i, ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			details[i] = ipinfo.LookupIP(ctx, ip, nil, nil)
		}()
	}
	wg.Wait()

	report.RenderIPInfo(w, label, details, fromHost, resolveTook)
	return nil
}

// ResolveIPInput normalizes `raw` to one of: a literal IP, a bracketed IPv6
// literal (possibly with :port), or a hostname (resolved to A/AAAA records).
// Returns the display label, the IPs to enrich, fromHost (true when we
// resolved DNS), and an error.
func ResolveIPInput(ctx context.Context, raw string) (string, []net.IP, bool, error) {
	s := strings.Trim(strings.TrimSpace(raw), `"'`)
	if s == "" {
		return "", nil, false, fmt.Errorf("empty input")
	}
	if strings.HasPrefix(s, "[") && strings.Contains(s, "]") {
		s = strings.TrimPrefix(s[:strings.Index(s, "]")], "[")
	}
	if ip := net.ParseIP(s); ip != nil {
		ip = ipinfo.NormalizeIP(ip)
		return ip.String(), []net.IP{ip}, false, nil
	}

	host, err := target.NormalizeHost(raw)
	if err != nil {
		return "", nil, false, err
	}
	if ip := net.ParseIP(host); ip != nil {
		ip = ipinfo.NormalizeIP(ip)
		return ip.String(), []net.IP{ip}, false, nil
	}

	dns := check.LookupDNS(ctx, host)
	if dns.Err != nil {
		return "", nil, true, dns.Err
	}
	all := append([]net.IP{}, dns.A...)
	all = append(all, dns.AAAA...)
	ips := ipinfo.UniqueIPs(all)
	if len(ips) == 0 {
		return "", nil, true, fmt.Errorf("no A or AAAA records returned for %s", host)
	}
	return host, ips, true, nil
}
