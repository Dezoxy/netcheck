package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	nurl "net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Dezoxy/netcheck/pkg/pathenum"
	"github.com/Dezoxy/netcheck/pkg/portscan"
	"github.com/Dezoxy/netcheck/pkg/report"
)

// RunAudit executes the `netcheck audit <target>` command — one entry point
// that fans out to the relevant v1.4 commands in parallel and emits a
// consolidated report.
func RunAudit(args []string) int {
	fs := flag.NewFlagSet("netcheck audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", auditDefaultTimeout(loadedConfig.Timeout), "overall audit timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification on headers/tech/enum probes")
	active := fs.Bool("active", false, "also run the active-scanning suite (tls, takeover, ports, enum)")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	authzCheck := requireAuthorization(fs, "audit")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck audit [flags] <target>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Runs the passive recon suite in parallel against <target> and emits one")
		fmt.Fprintln(os.Stderr, "consolidated report. By default: ip + headers + tech + subs + arch.")
		fmt.Fprintln(os.Stderr, "IP targets fall back to ip + reverse only.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "With --active, ALSO runs tls + takeover + ports + enum. This is the")
		fmt.Fprintln(os.Stderr, "active-scanning tier and requires --i-have-authorization (or")
		fmt.Fprintln(os.Stderr, "NETCHECK_AUTHORIZED=1) per docs/ETHICS.md.")
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
	// Auth gate only required when --active is set. Without --active, the
	// audit is purely passive (same wire shape as the underlying v1.4
	// passive commands which don't need authorization).
	if *active {
		if err := authzCheck(os.Stderr); err != nil {
			return 2
		}
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

	opts := AuditOptions{Active: *active, Insecure: *insecure}
	return runAuditFormat(w, fs.Arg(0), opts, *timeout, format)
}

// auditDefaultTimeout floors at 90s — the audit's longest sub-command is
// the active TLS probe (~45s on a slow link), and we add headroom for
// network jitter when several probes happen in parallel.
func auditDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 90*time.Second {
		return 90 * time.Second
	}
	return cfg
}

func runAuditFormat(w io.Writer, target string, opts AuditOptions, timeout time.Duration, format Format) int {
	res := BuildAudit(context.Background(), target, opts, timeout)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderAuditMD(w, res)
	case FormatHTML:
		report.RenderAuditHTML(w, res)
	default:
		report.RenderAudit(w, res)
	}

	if res.Error != "" {
		return 1
	}
	return 0
}

// AuditOptions tunes BuildAudit.
type AuditOptions struct {
	Active   bool
	Insecure bool
}

// BuildAudit runs every applicable sub-check in parallel and assembles the
// AuditJSON envelope. Per-sub-command errors land in Errors; only top-level
// failures (bad target, empty input) set Error.
func BuildAudit(ctx context.Context, target string, opts AuditOptions, timeout time.Duration) report.AuditJSON {
	started := time.Now()
	out := report.AuditJSON{
		NetcheckVersion: report.SchemaVersion,
		Kind:            "audit",
		Target:          target,
		StartedAt:       started,
		Active:          opts.Active,
		Errors:          map[string]string{},
	}

	host, tlsTarget, url, isIP, err := classifyAuditTarget(target)
	if err != nil {
		out.Error = err.Error()
		out.TookMS = time.Since(started).Milliseconds()
		return out
	}
	out.Host = host

	// URL-based checks (headers, tech, enum) run whenever we have a URL
	// form. That includes URL targets pointing at an IP (e.g.
	// http://127.0.0.1:8080/) — the probes work fine, you're just hitting
	// an IP-addressed server.
	runURLChecks := url != ""
	// Domain-based checks (subs CT logs, arch Wayback, takeover CNAME) need
	// an actual hostname; they're nonsense for IPs.
	runDomainChecks := !isIP

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup

	// run wraps the per-section work in panic-recovery + locked writes back
	// to `out`. The closure captures `name` so panics still get attributed.
	run := func(name string, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					out.Errors[name] = fmt.Sprintf("panic: %v", r)
					mu.Unlock()
				}
			}()
			f()
		}()
	}

	// ─── IP info: always applicable (works for both hostnames and IPs) ───
	run("ip", func() {
		ipRes, err := BuildIPInfo(c, host, ipDefaultTimeout(timeout))
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			out.Errors["ip"] = err.Error()
			return
		}
		out.IP = &ipRes
	})

	if isIP {
		// IP target: reverse is the natural pair for `ip`.
		run("reverse", func() {
			r := BuildReverse(c, host, reverseDefaultTimeout(timeout))
			mu.Lock()
			out.Reverse = &r
			mu.Unlock()
		})
	}

	// URL-based checks. Apply equally to bare hostnames (URL synthesised
	// as https://host) and URL-shaped targets including IP-addressed ones.
	if runURLChecks {
		run("headers", func() {
			r := BuildHeaders(c, url, checkTimeout(), opts.Insecure)
			mu.Lock()
			out.Headers = &r
			mu.Unlock()
		})
		run("tech", func() {
			r := BuildTech(c, url, checkTimeout(), opts.Insecure)
			mu.Lock()
			out.Tech = &r
			mu.Unlock()
		})
	}

	// Domain-based checks — meaningless for IP-only targets.
	if runDomainChecks {
		run("subs", func() {
			r := BuildSubs(c, host, subsDefaultTimeout(timeout))
			mu.Lock()
			out.Subs = &r
			mu.Unlock()
		})
		run("arch", func() {
			r := BuildArch(c, host, archDefaultTimeout(timeout))
			mu.Lock()
			out.Arch = &r
			mu.Unlock()
		})
	}

	// Active add-ons.
	if opts.Active {
		// TLS + ports work for any host (IP or hostname).
		// TLS uses tlsTarget (host:port form) so an explicit non-443 port
		// in the input — e.g. `https://host:8443` — gets audited on the
		// right endpoint instead of falling back to :443.
		run("tls", func() {
			r := BuildTLSAudit(c, tlsTarget, tlsDefaultTimeout(timeout))
			mu.Lock()
			out.TLS = &r
			mu.Unlock()
		})
		run("ports", func() {
			r := BuildPorts(c, host, defaultAuditPortOptions(), portsDefaultTimeout(timeout))
			mu.Lock()
			out.Ports = &r
			mu.Unlock()
		})
		// Takeover is CNAME-based — hostnames only.
		if runDomainChecks {
			run("takeover", func() {
				r := BuildTakeover(c, host, takeoverDefaultTimeout(timeout))
				mu.Lock()
				out.Takeover = &r
				mu.Unlock()
			})
		}
		// Enum is URL-based.
		if runURLChecks {
			run("enum", func() {
				r := BuildPathEnum(c, url, defaultAuditEnumOptions(opts.Insecure), enumDefaultTimeout(timeout))
				mu.Lock()
				out.Enum = &r
				mu.Unlock()
			})
		}
	}

	wg.Wait()
	if len(out.Errors) == 0 {
		out.Errors = nil // drop empty map so JSON output stays clean
	}
	out.TookMS = time.Since(started).Milliseconds()
	return out
}

// classifyAuditTarget normalises the user-supplied target into four
// downstream forms:
//
//   - host       — bare hostname or IP (no port, no brackets). Used for
//     domain-shaped checks (subs, arch, takeover) and ports.
//   - tlsTarget  — host:port form preserved from the input when the user
//     specified a port; otherwise equals host. Used for the
//     TLS sub-check so `audit https://target:8443` audits
//     :8443 instead of defaulting to :443.
//   - url        — URL form for headers/tech/enum. Empty for bare IP
//     targets (URL-shaped checks don't run). IPv6 literals
//     are properly bracketed: `[::1]` not `::1`.
//   - isIP       — true when host is an IP literal. Drives the
//     domain-vs-IP routing in BuildAudit.
//
// Order of fixes worth surfacing (both flagged by Codex on the original
// review): bracketed-IPv6 + IP detection after SplitHostPort fall-through.
func classifyAuditTarget(raw string) (host, tlsTarget, url string, isIP bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", "", false, errors.New("empty target")
	}
	if strings.Contains(s, "://") {
		u, perr := nurl.Parse(s)
		if perr != nil {
			return "", "", "", false, perr
		}
		if u.Host == "" {
			return "", "", "", false, fmt.Errorf("no host in %q", raw)
		}
		host = u.Hostname() // strips brackets + port
		isIP = net.ParseIP(host) != nil
		// u.Host preserves "[::1]:8443" / "host:8443" — perfect for the
		// TLS target. Falls back to plain host when no port was set.
		tlsTarget = u.Host
		return host, tlsTarget, s, isIP, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), ip.String(), "", true, nil
	}
	// Bare host (possibly with :port). SplitHostPort handles both
	// "host:8080" and "[::1]:8080" — important: don't assume the
	// extracted host is a name; it could still be an IP literal.
	host = s
	port := ""
	if h, p, splitErr := net.SplitHostPort(s); splitErr == nil {
		host = h
		port = p
		if ip := net.ParseIP(h); ip != nil {
			isIP = true
		}
	}
	tlsTarget = host
	if port != "" {
		tlsTarget = net.JoinHostPort(host, port)
	}
	if isIP {
		// Bare IP with optional port — URL-shaped checks don't run.
		return host, tlsTarget, "", true, nil
	}
	// Hostname. Synthesise https://host (IPv6 wouldn't reach this branch
	// since the SplitHostPort path above flagged isIP, but be defensive
	// in case the input was `[::1]` without a port — that path goes via
	// net.ParseIP further up).
	url = "https://" + hostInURL(host)
	return host, tlsTarget, url, false, nil
}

// hostInURL brackets an IPv6 literal so it's URL-safe. Plain hostnames /
// IPv4 pass through unchanged.
func hostInURL(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

// defaultAuditPortOptions returns the port-scan options used inside `audit`.
// Opinionated for "default scan" semantics — top-100 + 50-way concurrency +
// 1.5s per port keeps the audit under ~10s even on a slow link.
func defaultAuditPortOptions() portscan.Options {
	return portscan.Options{Top: 100, Concurrency: 50, PerPortTimeout: 1500 * time.Millisecond}
}

// defaultAuditEnumOptions returns the path-enum options used inside `audit`.
// Uses the builtin ~70-entry wordlist; an explicit --wordlist file goes
// through the direct `netcheck enum` command.
func defaultAuditEnumOptions(insecure bool) pathenum.Options {
	return pathenum.Options{
		Concurrency:    10,
		PerPathTimeout: 3 * time.Second,
		Insecure:       insecure,
	}
}

// ipDefaultTimeout — kept here (rather than ip.go) because it's an audit
// concern. The CLI `netcheck ip` uses the global config timeout directly.
func ipDefaultTimeout(overall time.Duration) time.Duration {
	if overall > 30*time.Second {
		return 30 * time.Second
	}
	return overall
}
