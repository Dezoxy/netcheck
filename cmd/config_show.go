package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Dezoxy/netcheck/internal/config"
)

// RunConfigShow prints the active config: where it was loaded from, the
// resolved values, and the list of configured resolvers. Supports --output
// json|markdown|html|text. Returns a process exit code.
func RunConfigShow(args []string) int {
	fs := flag.NewFlagSet("netcheck config show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := addConfigFlag(fs)
	outputFlag := addOutputFlag(fs)
	outFlag := addOutFlag(fs)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netcheck config show [flags]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
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

	switch format {
	case FormatJSON:
		if err := writeConfigJSON(w); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	default:
		writeConfigText(w)
	}
	return 0
}

type configShowJSON struct {
	NetcheckVersion string                 `json:"netcheck_version"`
	Kind            string                 `json:"kind"`             // "config"
	Source          string                 `json:"source,omitempty"` // empty = defaults only
	Timeout         string                 `json:"timeout"`
	UserAgent       string                 `json:"user_agent"`
	FollowRedirects bool                   `json:"follow_redirects"`
	MaxRedirects    int                    `json:"max_redirects"`
	PreferIPv6      bool                   `json:"prefer_ipv6"`
	Resolvers       []config.ResolverEntry `json:"resolvers,omitempty"`
	APIs            configShowAPIs         `json:"apis"`
}

// configShowAPIs reports which API keys are configured WITHOUT leaking the
// actual key. "set" / "" — never the value itself.
type configShowAPIs struct {
	Shodan string `json:"shodan_api_key"` // "set" | ""
}

func writeConfigJSON(w io.Writer) error {
	c := loadedConfig
	out := configShowJSON{
		NetcheckVersion: "0.5.0", // JSON schema version
		Kind:            "config",
		Source:          c.Source,
		Timeout:         c.Timeout.String(),
		UserAgent:       UserAgent(),
		FollowRedirects: c.FollowRedirects,
		MaxRedirects:    c.MaxRedirects,
		PreferIPv6:      c.PreferIPv6,
		Resolvers:       c.Resolvers,
		APIs: configShowAPIs{
			Shodan: maskedAPIKey(c.APIs.ShodanAPIKey),
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

func writeConfigText(w io.Writer) {
	c := loadedConfig
	fmt.Fprintln(w, "CONFIG")
	fmt.Fprintf(w, "Time:   %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if c.Source != "" {
		fmt.Fprintf(w, "Source: %s\n", c.Source)
	} else {
		fmt.Fprintln(w, "Source: (defaults — no config file loaded)")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Settings")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Timeout\t%s\n", c.Timeout)
	fmt.Fprintf(tw, "  User-Agent\t%s\n", UserAgent())
	fmt.Fprintf(tw, "  Follow redirects\t%t\n", c.FollowRedirects)
	fmt.Fprintf(tw, "  Max redirects\t%d\n", c.MaxRedirects)
	fmt.Fprintf(tw, "  Prefer IPv6\t%t\n", c.PreferIPv6)
	tw.Flush()
	fmt.Fprintln(w)

	if len(c.Resolvers) == 0 {
		fmt.Fprintln(w, "Resolvers (from config): none")
		fmt.Fprintln(w, "  Built-in resolvers (Cloudflare/Google/Quad9) and system /etc/resolv.conf are always available.")
	} else {
		fmt.Fprintf(w, "Resolvers (from config — %d):\n", len(c.Resolvers))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAME\tADDRESS\tTYPE")
		for _, r := range c.Resolvers {
			t := r.Type
			if t == "" {
				t = "udp"
			}
			name := r.Name
			if name == "" {
				name = "(unnamed)"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", name, r.Address, t)
		}
		tw.Flush()
	}

	// API keys — show set/unset only, never the value itself.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "API keys")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Shodan\t%s\n", apiKeyStatus(c.APIs.ShodanAPIKey))
	tw.Flush()
}

// maskedAPIKey returns "set" when v is non-empty, "" otherwise. We never
// surface the actual key value — `config show` output gets pasted into chat
// and tickets.
func maskedAPIKey(v string) string {
	if v != "" {
		return "set"
	}
	return ""
}

// apiKeyStatus is the human-text variant used by writeConfigText.
func apiKeyStatus(v string) string {
	if v != "" {
		return "set"
	}
	return "(not set)"
}
