package cmd

import (
	"flag"
	"fmt"
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

// addOutputFlag registers `--output` on the given flagset, returning the
// pointer the caller passes to ParseFormat after fs.Parse returns.
func addOutputFlag(fs *flag.FlagSet) *string {
	return fs.String("output", "text", "output format: text, json, markdown, html")
}
