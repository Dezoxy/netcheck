package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/Dezoxy/netcheck/pkg/ipinfo"
	"github.com/Dezoxy/netcheck/pkg/report"
	"github.com/Dezoxy/netcheck/pkg/route"
)

// RunRoute executes the `netcheck route <host>` traceroute-with-ASN command.
// Returns a process exit code.
func RunRoute(args []string) int {
	fs := flag.NewFlagSet("netcheck route", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	maxHops := fs.Int("max-hops", 30, "maximum number of hops")
	probes := fs.Int("probes", 3, "probes per hop")
	wait := fs.Int("wait", 2, "per-probe wait in seconds")
	noResolve := fs.Bool("no-resolve", false, "skip reverse DNS for each hop")
	noASN := fs.Bool("no-asn", false, "skip Team Cymru ASN lookup per hop")
	timeout := fs.Duration("timeout", 60*time.Second, "overall traceroute timeout")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck route [flags] <host>")
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
	host := fs.Arg(0)

	format, err := ParseFormat(*outputFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	opts := route.Options{
		MaxHops:   *maxHops,
		Probes:    *probes,
		WaitSec:   *wait,
		NoResolve: *noResolve,
	}

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	// In text mode we print the header before traceroute runs so the user gets
	// feedback while it's still working. Skipped when writing to a file via
	// --out (the file gets a complete render at the end).
	if format == FormatText && *outFlag == "" {
		if bin, herr := route.Find(); herr == nil {
			startedAt := time.Now()
			cmdArgs := route.BuildArgs(opts, host)
			toolArgs := cmdArgs[:len(cmdArgs)-1]
			resCtx, resCancel := context.WithTimeout(context.Background(), 3*time.Second)
			destIP := route.ResolveTarget(resCtx, host)
			resCancel()

			renderRouteHeader(w, &RouteData{
				Host:      host,
				DestIP:    destIP,
				Bin:       bin,
				ToolArgs:  toolArgs,
				StartedAt: startedAt,
			})
		}
	}

	data, err := collectRoute(host, opts, *timeout, *noASN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// When writing to a file in text mode, the header wasn't printed yet
	// (we skipped it above to keep the file self-contained). Emit it now.
	if format == FormatText && *outFlag != "" {
		renderRouteHeader(w, data)
	}

	if err := writeRoute(w, data, format); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Exit 1 when the run produced nothing useful — no hops collected at all
	// means traceroute failed to start or was killed before its first probe.
	if len(data.Hops) == 0 {
		return 1
	}
	return 0
}

// writeRoute renders RouteData to w in the requested format.
func writeRoute(w io.Writer, d *RouteData, format Format) error {
	var renderASN *ipinfo.ASNCache
	if !d.NoASN {
		renderASN = d.ASNCache
	}

	switch format {
	case FormatJSON:
		return report.WriteJSON(w, report.ToRouteJSON(d.Host, d.DestIP, d.Bin, d.ToolArgs, d.StartedAt, d.Hops, renderASN))
	case FormatMarkdown:
		report.RenderRouteMD(w, report.ToRouteJSON(d.Host, d.DestIP, d.Bin, d.ToolArgs, d.StartedAt, d.Hops, renderASN))
	case FormatHTML:
		report.RenderRouteHTML(w, report.ToRouteJSON(d.Host, d.DestIP, d.Bin, d.ToolArgs, d.StartedAt, d.Hops, renderASN))
	default:
		// When invoked from RunRoute, the header was already printed before
		// streaming. When invoked from a save context, we want it included.
		// The caller is responsible for picking — we just emit the table.
		renderRouteText(w, d.Hops, d.ASNCache, d.DestIP, d.Probes, d.NoASN)
	}
	return nil
}

// RouteData captures everything one traceroute run produces, in a form the
// menu can re-render in any format. RunRoute and menuRoute both build it.
type RouteData struct {
	Host      string
	DestIP    string
	Bin       string
	ToolArgs  []string
	StartedAt time.Time
	Hops      []*route.Hop
	ASNCache  *ipinfo.ASNCache // nil when no-asn was requested
	Probes    int
	NoASN     bool
}

// collectRoute runs traceroute and gathers parsed hops + ASN lookups. It does
// not write to stdout — callers render the data however they like.
func collectRoute(host string, opts route.Options, timeout time.Duration, noASN bool) (*RouteData, error) {
	bin, err := route.Find()
	if err != nil {
		return nil, fmt.Errorf("%v\n%s", err, route.InstallHint())
	}

	cmdArgs := route.BuildArgs(opts, host)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resCtx, resCancel := context.WithTimeout(ctx, 3*time.Second)
	destIP := route.ResolveTarget(resCtx, host)
	resCancel()

	startedAt := time.Now()
	toolArgs := cmdArgs[:len(cmdArgs)-1] // drop the host

	hopsCh, errCh := route.Stream(ctx, bin, cmdArgs)
	asnC := ipinfo.NewASNCache()

	var (
		collected []*route.Hop
		asnWG     sync.WaitGroup
	)
	for hop := range hopsCh {
		collected = append(collected, hop)
		if noASN {
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
		// Non-fatal: traceroute often exits non-zero when it doesn't reach the
		// destination. The collected hops are still meaningful.
		fmt.Fprintf(os.Stderr, "traceroute error: %v\n", err)
	}
	asnWG.Wait()

	return &RouteData{
		Host:      host,
		DestIP:    destIP,
		Bin:       bin,
		ToolArgs:  toolArgs,
		StartedAt: startedAt,
		Hops:      collected,
		ASNCache:  asnC,
		Probes:    opts.Probes,
		NoASN:     noASN,
	}, nil
}

// renderRouteHeader writes the "ROUTE / Host / Time / Tool" header. Extracted
// so RunRoute and menu re-render paths can share it.
func renderRouteHeader(w io.Writer, d *RouteData) {
	fmt.Fprintf(w, "ROUTE\nHost:  %s", d.Host)
	if d.DestIP != "" {
		fmt.Fprintf(w, "  (%s)", d.DestIP)
	}
	fmt.Fprintf(w, "\nTime:  %s\n", d.StartedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Tool:  %s %v\n\n", d.Bin, d.ToolArgs)
}

// renderRouteText draws the tab-aligned hop table for the text format. Stays
// in cmd/ because it needs the live ASNCache for per-hop lookups (the report
// package only sees the projected ASNJSON).
func renderRouteText(w io.Writer, hops []*route.Hop, asnC *ipinfo.ASNCache, destIP string, probes int, noASN bool) {
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

// BuildRoute runs traceroute against host with the given options and returns
// the JSON-ready RouteJSON, including per-hop ASN annotations unless noASN
// is set. CLI and app surfaces share this path.
//
// Returns an error only when the traceroute binary itself can't be located
// or started; per-hop timeouts and partial output are reported inside the
// RouteJSON (Timeouts count + per-hop Timeout flag).
func BuildRoute(ctx context.Context, host string, opts route.Options, timeout time.Duration, noASN bool) (report.RouteJSON, error) {
	data, err := collectRoute(host, opts, timeout, noASN)
	if err != nil {
		return report.RouteJSON{}, err
	}
	var asnC *ipinfo.ASNCache
	if !data.NoASN {
		asnC = data.ASNCache
	}
	return report.ToRouteJSON(data.Host, data.DestIP, data.Bin, data.ToolArgs, data.StartedAt, data.Hops, asnC), nil
}
