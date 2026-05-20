package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"text/tabwriter"
	"time"
)

func runRoute(args []string) {
	fs := flag.NewFlagSet("netcheck route", flag.ExitOnError)
	maxHops := fs.Int("max-hops", 30, "maximum number of hops")
	probes := fs.Int("probes", 3, "probes per hop")
	wait := fs.Int("wait", 2, "per-probe wait in seconds")
	noResolve := fs.Bool("no-resolve", false, "skip reverse DNS for each hop")
	noASN := fs.Bool("no-asn", false, "skip Team Cymru ASN lookup per hop")
	timeout := fs.Duration("timeout", 60*time.Second, "overall traceroute timeout")

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
	host := fs.Arg(0)

	bin, err := findTraceroute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, installHint())
		os.Exit(2)
	}

	opts := RouteOptions{
		MaxHops:   *maxHops,
		Probes:    *probes,
		WaitSec:   *wait,
		NoResolve: *noResolve,
	}
	cmdArgs := buildArgs(opts, host)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Best-effort target IP for the header (independent of traceroute's own resolution).
	resCtx, resCancel := context.WithTimeout(ctx, 3*time.Second)
	destIP := resolveTarget(resCtx, host)
	resCancel()

	fmt.Printf("ROUTE\nHost:  %s", host)
	if destIP != "" {
		fmt.Printf("  (%s)", destIP)
	}
	fmt.Printf("\nTime:  %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Tool:  %s %v\n\n", bin, cmdArgs[:len(cmdArgs)-1])

	hopsCh, errCh := streamTraceroute(ctx, bin, cmdArgs)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	headerCols := []string{"  HOP", "ADDRESS", "RTT"}
	if !*noASN {
		headerCols = append(headerCols, "ASN")
	}
	fmt.Fprintln(tw, joinTabs(headerCols))

	asnC := newASNCache()
	// Buffer hops so we can render them in order, but kick off ASN lookups in
	// parallel as hops arrive — by the time we print, lookups are usually done.
	var (
		collected []*Hop
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

	// Render the table now that everything is in.
	timeouts := 0
	reached := false
	for _, h := range collected {
		row := []string{fmt.Sprintf("  %d", h.N), hopSummary(h), rttSummary(h, *probes)}
		if !*noASN {
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

	fmt.Println()
	if reached {
		fmt.Printf("  Reached %s in %d hops\n", destIP, len(collected))
	} else if len(collected) > 0 {
		fmt.Printf("  Stopped after %d hops (destination not confirmed)\n", len(collected))
	} else {
		fmt.Println("  No hops returned")
	}
	if timeouts > 0 {
		fmt.Printf("  %d hop(s) timed out — routers commonly drop or rate-limit probes; missing hops do not always mean a broken route.\n", timeouts)
	}
}

func asnLabel(h *Hop, c *asnCache) string {
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
