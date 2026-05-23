package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"netcheck/internal/pathenum"
	"netcheck/internal/report"
)

// RunPathEnum executes the `netcheck enum <url>` command. Active — requires
// authorization.
func RunPathEnum(args []string) int {
	fs := flag.NewFlagSet("netcheck enum", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	timeout := fs.Duration("timeout", enumDefaultTimeout(loadedConfig.Timeout), "overall enumeration timeout")
	wordlistPath := fs.String("wordlist", "", "path to a custom wordlist file (one path per line; # comments allowed). Default: builtin ~70-entry list.")
	concurrency := fs.Int("concurrency", 10, "parallel requests")
	perPath := fs.Duration("per-path-timeout", 5*time.Second, "per-request timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	followRedirects := fs.Bool("follow-redirects", false, "follow 3xx responses instead of reporting them")
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)
	authzCheck := requireAuthorization(fs, "enum")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck enum [flags] <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Requests every path in a wordlist under <url> and reports the responses")
		fmt.Fprintln(os.Stderr, "that are not 404 / 410. Categorizes by status: found (200), redirect")
		fmt.Fprintln(os.Stderr, "(3xx), blocked (403), auth-required (401), server-error (5xx).")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "ACTIVE — sends one HTTP GET per wordlist entry. Requires")
		fmt.Fprintln(os.Stderr, "--i-have-authorization or NETCHECK_AUTHORIZED=1. See docs/ETHICS.md.")
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
	if err := authzCheck(os.Stderr); err != nil {
		return 2
	}
	applyConfigOverride(*configPath)

	format, err := ParseFormat(*outputFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	opts := pathenum.Options{
		Concurrency:     *concurrency,
		PerPathTimeout:  *perPath,
		Insecure:        *insecure,
		FollowRedirects: *followRedirects,
	}
	if *wordlistPath != "" {
		words, err := pathenum.LoadWordlist(*wordlistPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		if len(words) == 0 {
			fmt.Fprintln(os.Stderr, "error: wordlist is empty")
			return 2
		}
		opts.Wordlist = words
	}

	w, closer, err := openOut(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer closer()

	return runPathEnumFormat(w, fs.Arg(0), opts, *timeout, format)
}

func enumDefaultTimeout(cfg time.Duration) time.Duration {
	if cfg < 60*time.Second {
		return 60 * time.Second
	}
	return cfg
}

func runPathEnumFormat(w io.Writer, baseURL string, opts pathenum.Options, timeout time.Duration, format Format) int {
	res := pathenum.Enumerate(context.Background(), baseURL, opts, timeout)
	j := report.ToPathEnumJSON(res)

	switch format {
	case FormatJSON:
		if err := report.WriteJSON(w, j); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case FormatMarkdown:
		report.RenderPathEnumMD(w, j)
	case FormatHTML:
		report.RenderPathEnumHTML(w, j)
	default:
		report.RenderPathEnum(w, j)
	}

	if res.Err != nil {
		return 1
	}
	return 0
}

// BuildPathEnum runs the enumeration and projects it into the JSON schema.
// Shared by CLI and future HTTP-API surfaces.
func BuildPathEnum(ctx context.Context, baseURL string, opts pathenum.Options, timeout time.Duration) report.PathEnumJSON {
	res := pathenum.Enumerate(ctx, baseURL, opts, timeout)
	return report.ToPathEnumJSON(res)
}
