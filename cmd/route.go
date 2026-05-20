package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"netcheck/internal/ipinfo"
	"netcheck/internal/report"
	"netcheck/internal/route"
)

// RunRoute executes the `netcheck route <host>` traceroute-with-ASN command.
func RunRoute(args []string) {
	fs := flag.NewFlagSet("netcheck route", flag.ExitOnError)
	configPath := addConfigFlag(fs)
	maxHops := fs.Int("max-hops", 30, "maximum number of hops")
	probes := fs.Int("probes", 3, "probes per hop")
	wait := fs.Int("wait", 2, "per-probe wait in seconds")
	noResolve := fs.Bool("no-resolve", false, "skip reverse DNS for each hop")
	noASN := fs.Bool("no-asn", false, "skip Team Cymru ASN lookup per hop")
	timeout := fs.Duration("timeout", 60*time.Second, "overall traceroute timeout")
	outputFlag := addOutputFlag(fs)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck route [flags] <host>")
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
	applyConfigOverride(*configPath)
	host := fs.Arg(0)

	format, err := ParseFormat(*outputFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	bin, err := route.Find()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, route.InstallHint())
		os.Exit(2)
	}

	opts := route.Options{
		MaxHops:   *maxHops,
		Probes:    *probes,
		WaitSec:   *wait,
		NoResolve: *noResolve,
	}
	cmdArgs := route.BuildArgs(opts, host)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Best-effort target IP for the header (independent of traceroute's own resolution).
	resCtx, resCancel := context.WithTimeout(ctx, 3*time.Second)
	destIP := route.ResolveTarget(resCtx, host)
	resCancel()

	startedAt := time.Now()
	toolArgs := cmdArgs[:len(cmdArgs)-1] // drop the host

	// In text mode we print the header immediately so the user gets feedback
	// while traceroute is still running. Structured formats buffer everything
	// and emit at the end.
	if format == FormatText {
		fmt.Printf("ROUTE\nHost:  %s", host)
		if destIP != "" {
			fmt.Printf("  (%s)", destIP)
		}
		fmt.Printf("\nTime:  %s\n", startedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Tool:  %s %v\n\n", bin, toolArgs)
	}

	hopsCh, errCh := route.Stream(ctx, bin, cmdArgs)

	asnC := ipinfo.NewASNCache()
	// Buffer hops so we can render them in order, but kick off ASN lookups in
	// parallel as hops arrive — by the time we print, lookups are usually done.
	var (
		collected []*route.Hop
		asnWG     sync.WaitGroup
	)
	for hop := range hopsCh {
		collected = append(collected, hop)
		if *noASN {
			continue
		}
		for _, ip := range hop.IPs() {
			ip := ip
			asnWG.Add(1)
			go func() {
				defer asnWG.Done()
				asnC.Lookup(ctx, ip)
			}()
		}
	}
	if err := <-errCh; err != nil {
		fmt.Fprintf(os.Stderr, "traceroute error: %v\n", err)
	}
	asnWG.Wait()

	// The ASN cache is what powers route JSON/MD/HTML output. When --no-asn is
	// set, hand a nil cache through so the renderers omit the column.
	var renderASN *ipinfo.ASNCache
	if !*noASN {
		renderASN = asnC
	}

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(os.Stdout, report.ToRouteJSON(host, destIP, bin, toolArgs, startedAt, collected, renderASN)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case FormatMarkdown:
		report.RenderRouteMD(os.Stdout, report.ToRouteJSON(host, destIP, bin, toolArgs, startedAt, collected, renderASN))
	case FormatHTML:
		report.RenderRouteHTML(os.Stdout, report.ToRouteJSON(host, destIP, bin, toolArgs, startedAt, collected, renderASN))
	default:
		renderRouteText(os.Stdout, collected, asnC, destIP, *probes, *noASN)
	}
}

// renderRouteText draws the tab-aligned hop table for the text format. Stays
// in cmd/ because it needs the live ASNCache for per-hop lookups (the report
// package only sees the projected ASNJSON).
func renderRouteText(w *os.File, hops []*route.Hop, asnC *ipinfo.ASNCache, destIP string, probes int, noASN bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	headerCols := []string{"  HOP", "ADDRESS", "RTT"}
	if !noASN {
		headerCols = append(headerCols, "ASN")
	}
	fmt.Fprintln(tw, joinTabs(headerCols))

	timeouts := 0
	reached := false
	for _, h := range hops {
		row := []string{fmt.Sprintf("  %d", h.N), route.HopSummary(h), route.RTTSummary(h, probes)}
		if !noASN {
			row = append(row, asnLabel(h, asnC))
		}
		fmt.Fprintln(tw, joinTabs(row))
		if h.Timeout {
			timeouts++
		}
		if !h.Timeout && destIP != "" {
			for _, ip := range h.IPs() {
				if ip == destIP {
					reached = true
				}
			}
		}
	}
	tw.Flush()

	fmt.Fprintln(w)
	switch {
	case reached:
		fmt.Fprintf(w, "  Reached %s in %d hops\n", destIP, len(hops))
	case len(hops) > 0:
		fmt.Fprintf(w, "  Stopped after %d hops (destination not confirmed)\n", len(hops))
	default:
		fmt.Fprintln(w, "  No hops returned")
	}
	if timeouts > 0 {
		fmt.Fprintf(w, "  %d hop(s) timed out — routers commonly drop or rate-limit probes; missing hops do not always mean a broken route.\n", timeouts)
	}
}

func asnLabel(h *route.Hop, c *ipinfo.ASNCache) string {
	if h.Timeout {
		return ""
	}
	// Use first IP only for the label; rare to have multiple distinct ASNs in one hop.
	ips := h.IPs()
	if len(ips) == 0 {
		return ""
	}
	info := c.Lookup(context.Background(), ips[0])
	if info == nil {
		return "—"
	}
	if info.Org != "" {
		return fmt.Sprintf("AS%s %s", info.ASN, info.Org)
	}
	return "AS" + info.ASN
}

func joinTabs(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += "\t"
		}
		out += c
	}
	return out
}
