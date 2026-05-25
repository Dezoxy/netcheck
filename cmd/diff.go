package cmd

import (
	"flag"
	"fmt"
	"os"

	"netcheck/internal/diff"
)

// RunDiff implements `netcheck diff <old.json> <new.json>`. Returns:
//
//	0 — no changes detected
//	1 — changes detected (let scripts gate on the exit code)
//	2 — usage error / unparseable input
//
// The "1 means changes" convention mirrors `git diff` and `diff(1)`. It lets
// cron jobs do `netcheck diff a.json b.json && echo unchanged || alert`.
func RunDiff(args []string) int {
	fs := flag.NewFlagSet("netcheck diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	quiet := fs.Bool("quiet", false, "suppress output; exit code carries the answer")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck diff [flags] <old.json> <new.json>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Compares two saved netcheck JSON reports of the same kind and prints")
		fmt.Fprintln(os.Stderr, "what changed. Designed for `git-diff`-style usage:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  exit 0  — no changes")
		fmt.Fprintln(os.Stderr, "  exit 1  — changes detected")
		fmt.Fprintln(os.Stderr, "  exit 2  — usage or parse error")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}

	oldBytes, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	newBytes, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	rep, err := diff.Diff(oldBytes, newBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if !*quiet {
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

		switch format {
		case FormatJSON:
			if err := diff.RenderJSON(w, rep); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		case FormatMarkdown, FormatHTML:
			// Markdown and HTML reuse the text renderer for diffs — the
			// human view is line-oriented enough that fancy formatting
			// doesn't earn its keep. We can specialize later if needed.
			diff.RenderText(w, rep)
		default:
			diff.RenderText(w, rep)
		}
	}

	if rep.Changed {
		return 1
	}
	return 0
}
