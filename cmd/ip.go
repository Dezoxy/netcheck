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

	"github.com/Dezoxy/netcheck/pkg/check"
	"github.com/Dezoxy/netcheck/pkg/ipinfo"
	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/target"
)

// RunIP executes the `netcheck ip <ip|host>` command.
// Returns a process exit code.
func RunIP(args []string) int {
	fs := flag.NewFlagSet("netcheck ip", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", loadedConfig.Timeout, "overall IP info timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck ip [flags] <ip|host>")
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

	if err := RunIPInfoFormat(w, fs.Arg(0), *timeout, format); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// RunIPInfo is the legacy text-only entry point kept for callers (notably the
// menu) that haven't been threaded through with a format yet.
func RunIPInfo(w io.Writer, raw string, timeout time.Duration) error {
	return RunIPInfoFormat(w, raw, timeout, FormatText)
}

// RunIPInfoFormat resolves input → IPs → enrichment → render in the requested format.
func RunIPInfoFormat(w io.Writer, raw string, timeout time.Duration, format Format) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	startedAt := time.Now()
	label, ips, fromHost, err := ResolveIPInput(ctx, raw)
	if err != nil {
		return err
	}
	resolveTook := time.Since(startedAt)

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

	switch format {
	case FormatJSON:
		return report.WriteJSON(w, report.ToIPInfoJSON(label, startedAt, fromHost, resolveTook, details))
	case FormatMarkdown:
		report.RenderIPInfoMD(w, report.ToIPInfoJSON(label, startedAt, fromHost, resolveTook, details))
	case FormatHTML:
		report.RenderIPInfoHTML(w, report.ToIPInfoJSON(label, startedAt, fromHost, resolveTook, details))
	default:
		report.RenderIPInfo(w, label, details, fromHost, resolveTook)
	}
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

// BuildIPInfo resolves raw (literal IP or hostname) and enriches every
// resulting IP with ASN, RDAP, reverse DNS, and CDN classification. CLI
// and app surfaces share this path.
func BuildIPInfo(ctx context.Context, raw string, timeout time.Duration) (report.IPInfoJSON, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startedAt := time.Now()
	label, ips, fromHost, err := ResolveIPInput(c, raw)
	if err != nil {
		return report.IPInfoJSON{}, err
	}
	resolveTook := time.Since(startedAt)

	details := make([]ipinfo.IPDetails, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		i, ip := i, ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			details[i] = ipinfo.LookupIP(c, ip, nil, nil)
		}()
	}
	wg.Wait()

	return report.ToIPInfoJSON(label, startedAt, fromHost, resolveTook, details), nil
}
