package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"netcheck/internal/check"
	"netcheck/internal/dnscompare"
	"netcheck/internal/ipinfo"
	"netcheck/internal/report"
	"netcheck/internal/route"
	"netcheck/internal/target"
)

// RunMenu drops into an interactive loop where the user picks an action and
// types a target. It keeps running until the user quits, and after each
// successful action offers to save the result as text/json/markdown/html.
func RunMenu(args []string) {
	// Args are accepted but ignored — menu is interactive only.
	_ = args

	in := bufio.NewReader(os.Stdin)
	out := os.Stdout

	fmt.Fprintf(out, "netcheck %s — interactive menu\n", Version)

	for {
		printMenu(out)
		choice, err := readLine(in, "Choose: ")
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(out)
				return
			}
			fmt.Fprintf(out, "  error: %v\n\n", err)
			continue
		}
		choice = strings.TrimSpace(strings.ToLower(choice))

		var s *savable
		switch choice {
		case "q", "quit", "exit", "":
			if choice == "" {
				continue // empty input → re-show menu, not quit
			}
			fmt.Fprintln(out, "Bye.")
			return
		case "1":
			res, err := menuFull(in, out)
			if err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
			s = res
		case "2":
			res, err := menuDNS(in, out)
			if err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
			s = res
		case "3":
			res, err := menuRoute(in, out)
			if err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
			s = res
		case "4":
			res, err := menuIP(in, out)
			if err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
			s = res
		case "5":
			res, err := menuHeaders(in, out)
			if err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
			s = res
		case "6":
			res, err := menuTech(in, out)
			if err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
			s = res
		default:
			fmt.Fprintf(out, "  unknown choice: %q\n", choice)
			continue
		}

		fmt.Fprintln(out)
		offerSave(in, out, s)
		fmt.Fprintln(out)
		_, _ = readLine(in, "Press Enter to return to menu... ")
		fmt.Fprintln(out)
	}
}

func printMenu(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  1) Full check (DNS, TCP, TLS, HTTP)")
	fmt.Fprintln(w, "  2) DNS compare across resolvers")
	fmt.Fprintln(w, "  3) Route (traceroute + per-hop ASN)")
	fmt.Fprintln(w, "  4) IP / ASN info")
	fmt.Fprintln(w, "  5) Security headers audit")
	fmt.Fprintln(w, "  6) Tech fingerprint (CMS / framework / server / CDN)")
	fmt.Fprintln(w, "  q) Quit")
	fmt.Fprintln(w)
}

func readLine(r *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// menuFull prompts for a target, runs the full check, prints text to out, and
// returns a savable that can re-render the same Report in any format.
func menuFull(in *bufio.Reader, out io.Writer) (*savable, error) {
	raw, err := readLine(in, "Target URL: ")
	if err != nil {
		return nil, err
	}
	t, err := target.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("could not parse target: %w", err)
	}
	if t.Raw != strings.TrimSpace(raw) {
		fmt.Fprintf(out, "  → normalized to: %s\n", t.Raw)
	}
	fmt.Fprintln(out)

	const timeout = 10 * time.Second
	r := report.Report{Target: t, StartedAt: time.Now()}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	r.DNS = check.LookupDNS(ctx, t.Host)
	cancel()

	if r.DNS.Err == nil {
		c, cf := context.WithTimeout(context.Background(), timeout)
		annotateDNS(c, &r.DNS, nil)
		cf()

		if len(r.DNS.A) > 0 {
			c, cf := context.WithTimeout(context.Background(), timeout)
			res := check.TCP(c, r.DNS.A[0], t.Port)
			r.TCPv4 = &res
			cf()
		}
		if len(r.DNS.AAAA) > 0 {
			c, cf := context.WithTimeout(context.Background(), timeout)
			res := check.TCP(c, r.DNS.AAAA[0], t.Port)
			r.TCPv6 = &res
			cf()
		}
	}
	if t.Scheme == "https" {
		c, cf := context.WithTimeout(context.Background(), timeout)
		res := check.TLS(c, t.Host, t.Port, false)
		r.TLS = &res
		cf()
	}
	c, cf := context.WithTimeout(context.Background(), timeout*3)
	r.HTTP = check.HTTP(c, t, false)
	cf()

	report.Render(out, &r)

	return &savable{
		Kind: "full",
		Host: t.Host,
		Render: func(w io.Writer, f Format) error {
			switch f {
			case FormatJSON:
				return report.WriteJSON(w, report.ToFullJSON(&r))
			case FormatMarkdown:
				report.RenderFullMD(w, &r)
			case FormatHTML:
				report.RenderFullHTML(w, &r)
			default:
				report.Render(w, &r)
			}
			return nil
		},
	}, nil
}

// menuDNS prompts for a host and runs the DNS comparison with defaults.
func menuDNS(in *bufio.Reader, out io.Writer) (*savable, error) {
	raw, err := readLine(in, "Host: ")
	if err != nil {
		return nil, err
	}
	host, err := target.NormalizeHost(raw)
	if err != nil {
		return nil, err
	}
	if host != strings.TrimSpace(raw) {
		fmt.Fprintf(out, "  → normalized to: %s\n", host)
	}
	fmt.Fprintln(out)

	var resolvers []dnscompare.Resolver
	resolvers = append(resolvers, dnscompare.SystemResolvers()...)
	resolvers = append(resolvers, dnscompare.DefaultResolvers...)
	for _, r := range loadedConfig.Resolvers {
		if parsed, perr := configResolverToDNS(r); perr == nil {
			resolvers = append(resolvers, parsed)
		}
	}

	startedAt := time.Now()
	fmt.Fprintf(out, "DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, startedAt.Format("2006-01-02 15:04:05"))

	const timeout = 5 * time.Second
	var collected []dnscompare.Result
	for _, qt := range []string{"A", "AAAA"} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
		result := dnscompare.Compare(ctx, resolvers, host, qt, timeout)
		cancel()
		collected = append(collected, result)
		report.RenderDNSCompare(out, &result)
	}

	return &savable{
		Kind: "dns",
		Host: host,
		Render: func(w io.Writer, f Format) error {
			switch f {
			case FormatJSON:
				return report.WriteJSON(w, report.ToDNSCompareJSON(host, startedAt, collected))
			case FormatMarkdown:
				report.RenderDNSCompareMD(w, report.ToDNSCompareJSON(host, startedAt, collected))
			case FormatHTML:
				report.RenderDNSCompareHTML(w, report.ToDNSCompareJSON(host, startedAt, collected))
			default:
				fmt.Fprintf(w, "DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, startedAt.Format("2006-01-02 15:04:05"))
				for i := range collected {
					report.RenderDNSCompare(w, &collected[i])
				}
			}
			return nil
		},
	}, nil
}

// menuRoute prompts for a host, runs traceroute, prints the text result, and
// returns a savable for re-render in any format.
func menuRoute(in *bufio.Reader, out io.Writer) (*savable, error) {
	raw, err := readLine(in, "Host: ")
	if err != nil {
		return nil, err
	}
	host, err := target.NormalizeHost(raw)
	if err != nil {
		return nil, err
	}
	if host != strings.TrimSpace(raw) {
		fmt.Fprintf(out, "  → normalized to: %s\n", host)
	}
	fmt.Fprintln(out)

	opts := route.Options{MaxHops: 30, Probes: 3, WaitSec: 2}
	const timeout = 60 * time.Second

	// Print the header before traceroute starts so the user has feedback.
	if bin, ferr := route.Find(); ferr == nil {
		cmdArgs := route.BuildArgs(opts, host)
		toolArgs := cmdArgs[:len(cmdArgs)-1]
		resCtx, resCancel := context.WithTimeout(context.Background(), 3*time.Second)
		destIP := route.ResolveTarget(resCtx, host)
		resCancel()
		renderRouteHeader(os.Stdout, &RouteData{
			Host: host, DestIP: destIP, Bin: bin, ToolArgs: toolArgs, StartedAt: time.Now(),
		})
	}

	data, err := collectRoute(host, opts, timeout, false)
	if err != nil {
		return nil, err
	}
	renderRouteText(os.Stdout, data.Hops, data.ASNCache, data.DestIP, data.Probes, data.NoASN)

	return &savable{
		Kind: "route",
		Host: host,
		Render: func(w io.Writer, f Format) error {
			if f == FormatText {
				renderRouteHeader(w, data)
			}
			return writeRoute(w, data, f)
		},
	}, nil
}

// menuIP prompts for an IP or host and shows ownership/RDAP/CDN details.
func menuIP(in *bufio.Reader, out io.Writer) (*savable, error) {
	raw, err := readLine(in, "IP or host: ")
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	startedAt := time.Now()
	label, ips, fromHost, err := ResolveIPInput(ctx, raw)
	if err != nil {
		return nil, err
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

	report.RenderIPInfo(out, label, details, fromHost, resolveTook)

	return &savable{
		Kind: "ip",
		Host: label,
		Render: func(w io.Writer, f Format) error {
			switch f {
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
		},
	}, nil
}

// menuHeaders prompts for a URL and runs the security-header audit.
func menuHeaders(in *bufio.Reader, out io.Writer) (*savable, error) {
	raw, err := readLine(in, "URL: ")
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(out)

	timeout := loadedConfig.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
	defer cancel()

	j := BuildHeaders(ctx, strings.TrimSpace(raw), timeout, false)
	report.RenderHeaders(out, j)

	return &savable{
		Kind: "headers",
		Host: j.URL,
		Render: func(w io.Writer, f Format) error {
			switch f {
			case FormatJSON:
				return report.WriteJSON(w, j)
			case FormatMarkdown:
				report.RenderHeadersMD(w, j)
			case FormatHTML:
				report.RenderHeadersHTML(w, j)
			default:
				report.RenderHeaders(w, j)
			}
			return nil
		},
	}, nil
}

// menuTech prompts for a URL and runs the tech-fingerprint detection.
func menuTech(in *bufio.Reader, out io.Writer) (*savable, error) {
	raw, err := readLine(in, "URL: ")
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(out)

	timeout := loadedConfig.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
	defer cancel()

	j := BuildTech(ctx, strings.TrimSpace(raw), timeout, false)
	report.RenderTech(out, j)

	return &savable{
		Kind: "tech",
		Host: j.URL,
		Render: func(w io.Writer, f Format) error {
			switch f {
			case FormatJSON:
				return report.WriteJSON(w, j)
			case FormatMarkdown:
				report.RenderTechMD(w, j)
			case FormatHTML:
				report.RenderTechHTML(w, j)
			default:
				report.RenderTech(w, j)
			}
			return nil
		},
	}, nil
}

// stdinIsTTY reports whether stdin is connected to a terminal. We use this to
// decide whether bare `netcheck` should drop into the menu (interactive) or
// print usage and exit (scripted/piped).
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
