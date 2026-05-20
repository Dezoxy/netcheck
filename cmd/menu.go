package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"netcheck/internal/check"
	"netcheck/internal/dnscompare"
	"netcheck/internal/report"
	"netcheck/internal/target"
)

// RunMenu drops into an interactive loop where the user picks an action and
// types a target. It keeps running until the user quits.
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

		switch choice {
		case "q", "quit", "exit", "":
			if choice == "" {
				// Treat empty input as a gentle nudge, not a quit.
				continue
			}
			fmt.Fprintln(out, "Bye.")
			return
		case "1":
			if err := menuFull(in, out); err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
		case "2":
			if err := menuDNS(in, out); err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
		case "3":
			if err := menuRoute(in, out); err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
		case "4":
			if err := menuIP(in, out); err != nil {
				fmt.Fprintf(out, "  %v\n", err)
			}
		default:
			fmt.Fprintf(out, "  unknown choice: %q\n", choice)
			continue
		}

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

// menuFull prompts for a target, normalizes it as a URL, and runs the full check.
func menuFull(in *bufio.Reader, out io.Writer) error {
	raw, err := readLine(in, "Target URL: ")
	if err != nil {
		return err
	}
	t, err := target.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("could not parse target: %w", err)
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
	return nil
}

// menuDNS prompts for a host and runs the DNS comparison with defaults.
func menuDNS(in *bufio.Reader, out io.Writer) error {
	raw, err := readLine(in, "Host: ")
	if err != nil {
		return err
	}
	host, err := target.NormalizeHost(raw)
	if err != nil {
		return err
	}
	if host != strings.TrimSpace(raw) {
		fmt.Fprintf(out, "  → normalized to: %s\n", host)
	}
	fmt.Fprintln(out)

	var resolvers []dnscompare.Resolver
	resolvers = append(resolvers, dnscompare.SystemResolvers()...)
	resolvers = append(resolvers, dnscompare.DefaultResolvers...)

	fmt.Fprintf(out, "DNS COMPARE\nHost:  %s\nTime:  %s\n\n", host, time.Now().Format("2006-01-02 15:04:05"))

	const timeout = 5 * time.Second
	for _, qt := range []string{"A", "AAAA"} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
		result := dnscompare.Compare(ctx, resolvers, host, qt, timeout)
		cancel()
		report.RenderDNSCompare(out, &result)
	}
	return nil
}

// menuRoute prompts for a host and runs traceroute with defaults + ASN annotation.
func menuRoute(in *bufio.Reader, out io.Writer) error {
	raw, err := readLine(in, "Host: ")
	if err != nil {
		return err
	}
	host, err := target.NormalizeHost(raw)
	if err != nil {
		return err
	}
	if host != strings.TrimSpace(raw) {
		fmt.Fprintf(out, "  → normalized to: %s\n", host)
	}
	fmt.Fprintln(out)

	// Delegate to the existing route command runner. It reads its own flags
	// from the slice we pass — defaults match what the CLI gives.
	RunRoute([]string{host})
	return nil
}

// menuIP prompts for an IP or host and shows ownership/RDAP/CDN details.
func menuIP(in *bufio.Reader, out io.Writer) error {
	raw, err := readLine(in, "IP or host: ")
	if err != nil {
		return err
	}
	fmt.Fprintln(out)
	return RunIPInfo(out, raw, 10*time.Second)
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
