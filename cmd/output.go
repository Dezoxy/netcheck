package cmd

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
)

// Format selects the output renderer for a command.
type Format int

const (
	FormatText Format = iota
	FormatJSON
	FormatMarkdown
	FormatHTML
)

// ParseFormat accepts "text", "json", "markdown" (or "md"), or "html" (case-
// and whitespace-insensitive) and returns the matching Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text", "txt":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	case "html", "htm":
		return FormatHTML, nil
	default:
		return FormatText, fmt.Errorf("unknown output format %q (want one of: text, json, markdown, html)", s)
	}
}

// addOutputFlag registers `--output` and the `-j` shortcut on the given
// flagset, returning the pointer the caller passes to ParseFormat after
// fs.Parse returns.
//
// Both flags write to the same underlying string; last-write-wins under flag
// ordering, matching how any other CLI would behave with two settings of the
// same logical option. `-j` is a bool-style flag (no `=true` needed) that
// sets the format to "json". `--output=text -j` → json. `-j --output=text`
// → text.
func addOutputFlag(fs *flag.FlagSet) *string {
	target := new(string)
	*target = "text"
	fs.Var(&outputFormatFlag{target: target}, "output", "output format: text, json, markdown, html")
	fs.Var(&jsonShortFlag{target: target}, "j", "shortcut for --output json")
	return target
}

// outputFormatFlag is the flag.Value implementation backing --output. Reading
// the underlying *string later in ParseFormat is unchanged.
type outputFormatFlag struct{ target *string }

func (o *outputFormatFlag) String() string {
	if o.target == nil {
		return "text"
	}
	return *o.target
}

func (o *outputFormatFlag) Set(v string) error {
	*o.target = v
	return nil
}

// jsonShortFlag is the boolean `-j` shortcut. IsBoolFlag() makes the flag
// package treat `-j` (alone) as `-j=true`; setting it writes "json" into the
// same target *string as --output.
type jsonShortFlag struct{ target *string }

func (j *jsonShortFlag) String() string { return "false" }

func (j *jsonShortFlag) IsBoolFlag() bool { return true }

func (j *jsonShortFlag) Set(v string) error {
	// Validate the value the same way the stdlib `flag` package validates
	// its own bool flags — via strconv.ParseBool. Returning an error here
	// makes `fs.Parse` reject typos like `-j=foo` or `-j=t` instead of
	// silently accepting them and running with the wrong output format.
	//
	// Codex flagged this on #57: the original implementation returned nil
	// for any non-truthy value, so `-j=foo` succeeded as a no-op and the
	// command produced text output, divergent from standard bool-flag
	// behaviour where invalid values fail fast.
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	// Truthy → switch the format to JSON. Falsy is a no-op so that
	// `-j=false` (explicitly disabled) doesn't clobber a value set by an
	// earlier `--output` flag in the same invocation.
	if b {
		*j.target = "json"
	}
	return nil
}
