package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Hop struct {
	N       int
	Probes  []HopProbe
	Timeout bool // all probes timed out
	Raw     string
}

type HopProbe struct {
	Host string
	IP   string
	RTT  time.Duration
}

// IPs returns the distinct IPs seen in this hop's probes.
func (h *Hop) IPs() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range h.Probes {
		if p.IP == "" || seen[p.IP] {
			continue
		}
		seen[p.IP] = true
		out = append(out, p.IP)
	}
	return out
}

type RouteOptions struct {
	MaxHops   int
	Probes    int
	WaitSec   int  // per-probe wait (seconds)
	NoResolve bool // pass -n / -d
}

// findTraceroute locates the binary appropriate for the current OS, returning
// (binary path, args prefix, error). The args prefix excludes max-hops/probes/wait
// flags — those are applied by buildArgs.
func findTraceroute() (string, error) {
	candidates := []string{"traceroute"}
	if runtime.GOOS == "windows" {
		candidates = []string{"tracert"}
	}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("traceroute binary not found on PATH")
}

func buildArgs(opts RouteOptions, host string) []string {
	if runtime.GOOS == "windows" {
		// tracert: -d no-resolve, -h max-hops, -w timeout(ms)
		args := []string{}
		if opts.NoResolve {
			args = append(args, "-d")
		}
		if opts.MaxHops > 0 {
			args = append(args, "-h", strconv.Itoa(opts.MaxHops))
		}
		if opts.WaitSec > 0 {
			args = append(args, "-w", strconv.Itoa(opts.WaitSec*1000))
		}
		args = append(args, host)
		return args
	}
	// macOS / Linux traceroute: -n no-resolve, -m max-hops, -q probes, -w wait
	args := []string{}
	if opts.NoResolve {
		args = append(args, "-n")
	}
	if opts.MaxHops > 0 {
		args = append(args, "-m", strconv.Itoa(opts.MaxHops))
	}
	if opts.Probes > 0 {
		args = append(args, "-q", strconv.Itoa(opts.Probes))
	}
	if opts.WaitSec > 0 {
		args = append(args, "-w", strconv.Itoa(opts.WaitSec))
	}
	args = append(args, host)
	return args
}

// installHint returns a platform-appropriate hint when traceroute is missing.
func installHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS normally ships /usr/sbin/traceroute. Check $PATH or run /usr/sbin/traceroute directly."
	case "linux":
		return "Install with: sudo apt install traceroute  (Debian/Ubuntu)  or  sudo dnf install traceroute  (Fedora)."
	case "windows":
		return "tracert ships with Windows. Ensure System32 is on PATH."
	}
	return "Install the system traceroute utility."
}

// hopLineRe matches a line that starts with a hop number. We then parse the rest manually.
var hopLineRe = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
var rttRe = regexp.MustCompile(`([0-9]+\.?[0-9]*)\s*ms`)
var ipRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)`)

// parseHopLine parses one line of traceroute output into a Hop.
// Returns nil if the line is not a hop line (header, blank, etc).
func parseHopLine(line string) *Hop {
	m := hopLineRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	n, _ := strconv.Atoi(m[1])
	rest := strings.TrimSpace(m[2])
	hop := &Hop{N: n, Raw: line}

	// Quick check: if the rest is just stars and whitespace, it's a full timeout.
	if onlyStars(rest) {
		hop.Timeout = true
		return hop
	}

	// Find RTTs and IPs independently. macOS/Linux traceroute interleaves
	// "host (ip)  rtt ms  rtt ms  rtt ms" but may switch hosts mid-line on
	// asymmetric paths. We pair each RTT with the most-recent IP seen to its left.
	rtts := rttRe.FindAllStringSubmatchIndex(rest, -1)
	ips := ipRe.FindAllStringIndex(rest, -1)

	// Filter out IPs that are actually part of an RTT (e.g. "1.234" inside "1.234 ms")
	ips = filterIPsInsideRTTs(rest, ips, rtts)

	if len(rtts) == 0 {
		// No RTTs parsed — treat as timeout-ish but keep raw line.
		hop.Timeout = true
		return hop
	}

	for _, rttIdx := range rtts {
		val, _ := strconv.ParseFloat(rest[rttIdx[2]:rttIdx[3]], 64)
		probe := HopProbe{RTT: time.Duration(val * float64(time.Millisecond))}

		// Pick the IP whose start index is the largest one still <= this RTT's start.
		var chosenIP string
		for _, ipIdx := range ips {
			if ipIdx[0] < rttIdx[0] {
				chosenIP = rest[ipIdx[0]:ipIdx[1]]
			} else {
				break
			}
		}
		// Also try to grab a hostname token directly before the IP / RTT.
		probe.IP = chosenIP
		probe.Host = hostBefore(rest, chosenIP)
		hop.Probes = append(hop.Probes, probe)
	}
	return hop
}

func onlyStars(s string) bool {
	stripped := strings.ReplaceAll(s, "*", "")
	return strings.TrimSpace(stripped) == ""
}

func filterIPsInsideRTTs(s string, ips, rtts [][]int) [][]int {
	var out [][]int
	for _, ip := range ips {
		inside := false
		for _, rtt := range rtts {
			if ip[0] >= rtt[0] && ip[1] <= rtt[1] {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, ip)
		}
	}
	return out
}

// hostBefore returns a likely hostname token preceding the IP in the line.
// Returns "" if the token before is the IP itself or numeric.
func hostBefore(line, ip string) string {
	if ip == "" {
		return ""
	}
	idx := strings.Index(line, ip)
	if idx <= 0 {
		return ""
	}
	left := strings.TrimRight(line[:idx], " \t(")
	// Take the last whitespace-separated token.
	fields := strings.Fields(left)
	if len(fields) == 0 {
		return ""
	}
	tok := fields[len(fields)-1]
	// If the token looks like an IP itself (a previous probe's IP), discard it.
	if net.ParseIP(tok) != nil {
		return ""
	}
	// Strip trailing characters that aren't part of a hostname.
	tok = strings.TrimRight(tok, ":,")
	if tok == "" || tok == ip {
		return ""
	}
	return tok
}

// streamTraceroute runs the traceroute binary and emits parsed hops on the
// channel as they appear. The channel is closed when the command exits.
func streamTraceroute(ctx context.Context, bin string, args []string) (<-chan *Hop, <-chan error) {
	hops := make(chan *Hop)
	errCh := make(chan error, 1)

	go func() {
		defer close(hops)

		cmd := exec.CommandContext(ctx, bin, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			errCh <- err
			return
		}
		cmd.Stderr = io.Discard

		if err := cmd.Start(); err != nil {
			errCh <- err
			return
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 256*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if hop := parseHopLine(line); hop != nil {
				hops <- hop
			}
		}
		// Wait for the process so we don't leak it. Ignore exit status —
		// traceroute exits non-zero on macOS when it doesn't reach the dest,
		// which isn't a failure we want to surface.
		_ = cmd.Wait()
		errCh <- nil
	}()

	return hops, errCh
}

// resolveTarget resolves host to a single IP for display. Best-effort; returns
// empty string on failure.
func resolveTarget(ctx context.Context, host string) string {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ips[0].IP.String()
}

// hopSummary returns a one-line description of a hop's IPs for display.
func hopSummary(h *Hop) string {
	if h.Timeout {
		return "* * *"
	}
	ips := h.IPs()
	if len(ips) == 0 {
		return "(no addresses)"
	}
	// Prefer hostname if we have one; show IP in parens.
	var parts []string
	for i, ip := range ips {
		host := ""
		for _, p := range h.Probes {
			if p.IP == ip && p.Host != "" {
				host = p.Host
				break
			}
		}
		if host != "" && host != ip {
			parts = append(parts, fmt.Sprintf("%s (%s)", host, ip))
		} else {
			parts = append(parts, ip)
		}
		if i >= 1 {
			break // keep it tight; rare to have >2 anyway
		}
	}
	return strings.Join(parts, " / ")
}

// rttSummary returns "1.23ms / 1.45ms / 1.67ms" or "*" placeholders.
func rttSummary(h *Hop, probeCount int) string {
	if h.Timeout {
		return strings.TrimRight(strings.Repeat("*   ", probeCount), " ")
	}
	parts := make([]string, 0, probeCount)
	for i := 0; i < probeCount; i++ {
		if i < len(h.Probes) {
			parts = append(parts, fmtMS(h.Probes[i].RTT))
		} else {
			parts = append(parts, "*")
		}
	}
	return strings.Join(parts, "  ")
}

func fmtMS(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	v := float64(d) / float64(time.Millisecond)
	if v < 10 {
		return fmt.Sprintf("%.2fms", v)
	}
	return fmt.Sprintf("%.1fms", v)
}
