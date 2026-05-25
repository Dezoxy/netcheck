package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Dezoxy/netcheck/pkg/diff"
)

// RunWatch implements `netcheck watch [flags] -- <subcommand> <args...>`. It
// re-runs the sub-command on an interval, diffs each result against the
// previous, and prints the diff (or "no changes").
//
// Implementation: we shell out to ourselves with `--output json --out -`
// injected. The alternative — wiring each Build* function through a generic
// invoker — would require parsing every subcommand's flags here, which
// duplicates root.go's switch. The subprocess overhead per iteration is in
// the milliseconds and not the bottleneck.
//
// The `--` separator is recommended but optional. Without it the first
// non-flag positional becomes the subcommand, which is convenient for
// `netcheck watch ports example.com`.
func RunWatch(args []string) int {
	fs := flag.NewFlagSet("netcheck watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	interval := fs.Duration("interval", 60*time.Second, "how often to re-run the sub-command")
	outDir := fs.String("out-dir", "", "save each snapshot to this directory (filename: <ts>-<kind>.json)")
	maxRuns := fs.Int("max-runs", 0, "stop after N runs (0 = forever)")
	quiet := fs.Bool("quiet", false, "suppress 'no changes' messages between runs")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck watch [flags] -- <subcommand> <args...>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Re-runs the given netcheck sub-command on an interval and prints")
		fmt.Fprintln(os.Stderr, "what changed since the previous iteration.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "examples:")
		fmt.Fprintln(os.Stderr, "  netcheck watch --interval 30s -- ports --i-have-authorization example.com")
		fmt.Fprintln(os.Stderr, "  netcheck watch --interval 5m  --out-dir ./snaps -- subs example.com")
		fmt.Fprintln(os.Stderr, "  netcheck watch ports example.com   # convenience: no -- needed")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	// Catch Ctrl-C so we can exit cleanly between iterations rather than
	// killing the child mid-scan.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	binary := selfBinary()
	var prevBytes []byte
	runCount := 0

	for {
		runCount++
		ts := time.Now()
		fmt.Fprintf(os.Stderr, "▶ run #%d %s — %s %v\n", runCount, ts.Format(time.RFC3339), binary, rest)

		currBytes, err := runOnce(ctx, binary, rest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: run #%d failed: %v\n", runCount, err)
		} else {
			if *outDir != "" {
				path := snapshotPath(*outDir, ts, currBytes)
				if err := os.WriteFile(path, currBytes, 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "warn: snapshot write failed: %v\n", err)
				}
			}
			if prevBytes != nil {
				rep, dErr := diff.Diff(prevBytes, currBytes)
				if dErr != nil {
					fmt.Fprintf(os.Stderr, "warn: diff failed: %v\n", dErr)
				} else if rep.Changed {
					diff.RenderText(os.Stdout, rep)
					fmt.Fprintln(os.Stdout)
				} else if !*quiet {
					fmt.Fprintln(os.Stderr, "  (no changes)")
				}
			}
			prevBytes = currBytes
		}

		if *maxRuns > 0 && runCount >= *maxRuns {
			return 0
		}

		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\nwatch: stopped")
			return 0
		case <-time.After(*interval):
		}
	}
}

// runOnce shells out to the netcheck binary with `--output json --out -`
// injected. Returns the captured JSON bytes.
//
// We insert the flags right after the subcommand name (`netcheck <cmd>
// --output json --out - <rest>`) because Go's `flag` package stops parsing
// at the first positional argument. Appending them at the end means they'd
// be silently ignored when the user has already supplied a host/url.
func runOnce(ctx context.Context, binary string, args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no subcommand")
	}
	full := []string{args[0], "--output", "json", "--out", "-"}
	full = append(full, args[1:]...)
	cmd := exec.CommandContext(ctx, binary, full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// exec error vs non-zero exit — non-zero exit is fine for some
		// subcommands (e.g. `ports` returns 1 when no ports open). Surface
		// the error but still return what we captured.
		if _, ok := err.(*exec.ExitError); ok && out.Len() > 0 {
			return out.Bytes(), nil
		}
		return nil, err
	}
	return out.Bytes(), nil
}

// selfBinary returns the path to the running netcheck binary, falling back
// to os.Args[0] for the rare case where /proc/self/exe is unavailable.
func selfBinary() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return os.Args[0]
}

// snapshotPath produces a filename like `2026-05-25T12-34-56Z-ports.json`.
// Reading `kind` out of the JSON lets us name files informatively without
// trusting the user's --out-dir hygiene.
func snapshotPath(dir string, ts time.Time, body []byte) string {
	kind := "report"
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		if k, ok := m["kind"].(string); ok && k != "" {
			kind = k
		}
	}
	// Replace colons in the timestamp — Windows doesn't allow them in
	// filenames and they're awkward to shell-quote elsewhere.
	stamp := ts.UTC().Format("2006-01-02T15-04-05Z")
	return filepath.Join(dir, fmt.Sprintf("%s-%s.json", stamp, kind))
}
