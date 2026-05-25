package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// RenderText writes the diff report as plain text — the human-readable
// default for `netcheck diff` and `netcheck watch`.
func RenderText(w io.Writer, r Report) {
	fmt.Fprintf(w, "DIFF: %s", r.Kind)
	if r.Target != "" {
		fmt.Fprintf(w, " — %s", r.Target)
	}
	fmt.Fprintln(w)
	if !r.OldStarted.IsZero() && !r.NewStarted.IsZero() {
		fmt.Fprintf(w, "  old: %s\n", r.OldStarted.Format(time.RFC3339))
		fmt.Fprintf(w, "  new: %s\n", r.NewStarted.Format(time.RFC3339))
	}

	if !r.Changed {
		fmt.Fprintln(w, "  (no changes)")
		return
	}

	for _, s := range r.Sections {
		if len(s.Changes) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", s.Title)
		for _, c := range s.Changes {
			fmt.Fprintf(w, "  %s %s\n", icon(c.Severity), c.Message)
		}
	}
}

// RenderJSON writes the diff as JSON. Useful for piping into other tools or
// for `netcheck watch --out-dir` style snapshotting.
func RenderJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func icon(s Severity) string {
	switch s {
	case SevOK:
		return "[+]"
	case SevWarn:
		return "[!]"
	case SevErr:
		return "[-]"
	}
	return "[·]"
}
