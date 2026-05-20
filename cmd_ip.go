package main

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
)

func runIP(args []string) {
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

	if err := runIPInfo(os.Stdout, fs.Arg(0), *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runIPInfo(w io.Writer, raw string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	target, ips, fromHost, err := resolveIPInput(ctx, raw)
	if err != nil {
		return err
	}
	resolveTook := time.Since(start)

	asnC := defaultASNCache
	rdapC := defaultRDAPCache
	details := make([]IPDetails, len(ips))

	var wg sync.WaitGroup
	for i, ip := range ips {
		i, ip := i, ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			details[i] = lookupIPDetails(ctx, ip, asnC, rdapC)
		}()
	}
	wg.Wait()

	renderIPInfo(w, target, details, fromHost, resolveTook)
	return nil
}

func resolveIPInput(ctx context.Context, raw string) (string, []net.IP, bool, error) {
	s := strings.Trim(strings.TrimSpace(raw), `"'`)
	if s == "" {
		return "", nil, false, fmt.Errorf("empty input")
	}
	if strings.HasPrefix(s, "[") && strings.Contains(s, "]") {
		s = strings.TrimPrefix(s[:strings.Index(s, "]")], "[")
	}
	if ip := net.ParseIP(s); ip != nil {
		ip = normalizeIP(ip)
		return ip.String(), []net.IP{ip}, false, nil
	}

	host, err := normalizeHost(raw)
	if err != nil {
		return "", nil, false, err
	}
	if ip := net.ParseIP(host); ip != nil {
		ip = normalizeIP(ip)
		return ip.String(), []net.IP{ip}, false, nil
	}

	dns := lookupDNS(ctx, host)
	if dns.Err != nil {
		return "", nil, true, dns.Err
	}
	ips := uniqueIPs(append(append([]net.IP{}, dns.A...), dns.AAAA...))
	if len(ips) == 0 {
		return "", nil, true, fmt.Errorf("no A or AAAA records returned for %s", host)
	}
	return host, ips, true, nil
}

func renderIPInfo(w io.Writer, target string, details []IPDetails, fromHost bool, resolveTook time.Duration) {
	fmt.Fprintln(w, "IP INFO")
	fmt.Fprintf(w, "Target:   %s\n", target)
	fmt.Fprintf(w, "Time:     %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if fromHost {
		fmt.Fprintf(w, "Resolved: %d address(es) in %s\n", len(details), ms(resolveTook))
	}

	for i, info := range details {
		if i > 0 || fromHost {
			fmt.Fprintln(w)
		}
		if !fromHost {
			renderIPFields(w, info)
			continue
		}
		renderIPBlock(w, "Address", info)
	}
}

func renderIPBlock(w io.Writer, label string, info IPDetails) {
	fmt.Fprintf(w, "%-9s %s\n", label+":", info.IP)
	renderIPFields(w, info)
}

func renderIPFields(w io.Writer, info IPDetails) {
	fmt.Fprintf(w, "Reverse:  %s\n", formatReverse(info.Reverse))
	fmt.Fprintf(w, "ASN:      %s\n", formatASNDetails(info.ASN, info.RDAP))
	fmt.Fprintf(w, "Country:  %s\n", countryFor(info))
	fmt.Fprintf(w, "Prefix:   %s\n", prefixFor(info))
	fmt.Fprintf(w, "Registry: %s\n", registryFor(info))
	fmt.Fprintf(w, "CDN:      %s\n", formatCDN(info.CDN))
	fmt.Fprintf(w, "Abuse:    %s\n", abuseFor(info))
}

func formatReverse(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ", ")
}

func countryFor(info IPDetails) string {
	if info.ASN != nil && info.ASN.Country != "" {
		return info.ASN.Country
	}
	if info.RDAP != nil && info.RDAP.Country != "" {
		return info.RDAP.Country
	}
	return "-"
}

func prefixFor(info IPDetails) string {
	if info.ASN != nil && info.ASN.Prefix != "" {
		return info.ASN.Prefix
	}
	return "-"
}

func registryFor(info IPDetails) string {
	if info.RDAP != nil && info.RDAP.Registry != "" {
		return info.RDAP.Registry
	}
	if info.ASN != nil && info.ASN.Registry != "" {
		return info.ASN.Registry
	}
	return "-"
}

func abuseFor(info IPDetails) string {
	if info.RDAP != nil && info.RDAP.AbuseEmail != "" {
		return info.RDAP.AbuseEmail
	}
	return "-"
}

func formatCDN(match CDNMatch) string {
	if match.Provider == "" {
		return "-"
	}
	if match.Confidence == "" || match.Reason == "" {
		return match.Provider
	}
	return fmt.Sprintf("%s (%s confidence - %s)", match.Provider, match.Confidence, match.Reason)
}
