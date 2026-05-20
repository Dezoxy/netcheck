// Package route wraps the system traceroute (or tracert on Windows), streams
// hops as they arrive, and parses them into structured form.
package route

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Options controls the per-invocation traceroute flags.
type Options struct {
	MaxHops   int
	Probes    int
	WaitSec   int  // per-probe wait (seconds)
	NoResolve bool // pass -n / -d
}

// Find locates the traceroute binary appropriate for the current OS.
func Find() (string, error) {
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

// BuildArgs maps Options to the platform-appropriate flag set.
func BuildArgs(opts Options, host string) []string {
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

// InstallHint returns a platform-appropriate hint when traceroute is missing.
func InstallHint() string {
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

// Stream runs the traceroute binary and emits parsed hops on the channel as
// they appear. The hop channel is closed when the command exits; an error
// value (nil on clean exit) is then sent on the error channel.
func Stream(ctx context.Context, bin string, args []string) (<-chan *Hop, <-chan error) {
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
			if hop := ParseHopLine(line); hop != nil {
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

// ResolveTarget resolves host to a single IP for display in the route header.
// Best-effort — returns empty string on failure.
func ResolveTarget(ctx context.Context, host string) string {
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

// HopSummary returns a one-line description of a hop's IPs for display.
func HopSummary(h *Hop) string {
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

// RTTSummary returns the per-probe RTTs joined with two spaces, with `*`
// placeholders for missing probes.
func RTTSummary(h *Hop, probeCount int) string {
	if h.Timeout {
		return strings.TrimRight(strings.Repeat("*   ", probeCount), " ")
	}
	parts := make([]string, 0, probeCount)
	for i := 0; i < probeCount; i++ {
		if i < len(h.Probes) {
			parts = append(parts, FmtMS(h.Probes[i].RTT))
		} else {
			parts = append(parts, "*")
		}
	}
	return strings.Join(parts, "  ")
}

// FmtMS formats a duration as a millisecond value with appropriate precision.
func FmtMS(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	v := float64(d) / float64(time.Millisecond)
	if v < 10 {
		return fmt.Sprintf("%.2fms", v)
	}
	return fmt.Sprintf("%.1fms", v)
}
