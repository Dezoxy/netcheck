package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// savable is what a menu action returns when its result is worth offering to
// save. Render writes the captured data to w in the requested format.
type savable struct {
	Kind   string // "full", "dns", "route", "ip"
	Host   string // used to build the default filename
	Render func(w io.Writer, format Format) error
}

// offerSave asks the user whether they want to keep the result and, if yes,
// what format to use. Working-dir invocations save silently into the binary's
// directory; installed invocations prompt for a path with ~/Documents as the
// suggestion.
func offerSave(in *bufio.Reader, out io.Writer, s *savable) {
	if s == nil {
		return
	}
	choice, err := readLine(in, "Save this result? [y/N]: ")
	if err != nil || strings.ToLower(strings.TrimSpace(choice)) != "y" {
		return
	}

	format, ok := promptFormat(in, out)
	if !ok {
		return
	}

	dir, isWorkingDir := defaultSaveDir()
	if !isWorkingDir {
		fmt.Fprintf(out, "Save directory [%s]: ", dir)
		raw, err := readLine(in, "")
		if err == nil {
			if trimmed := strings.TrimSpace(raw); trimmed != "" {
				dir = expandPath(trimmed)
			}
		}
	}

	// Make sure the directory exists. mkdir -p is fine even for the working-dir
	// case where bin/ already exists.
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(out, "  could not create %s: %v\n", dir, err)
		return
	}

	name := defaultFilename(s.Kind, s.Host, format)
	full := filepath.Join(dir, name)

	f, err := os.Create(full)
	if err != nil {
		fmt.Fprintf(out, "  could not write %s: %v\n", full, err)
		return
	}
	if err := s.Render(f, format); err != nil {
		f.Close()
		fmt.Fprintf(out, "  render error: %v\n", err)
		return
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(out, "  close error: %v\n", err)
		return
	}
	fmt.Fprintf(out, "  Saved to %s\n", full)
}

// promptFormat asks for one of the four output formats. Returns false when the
// user declines (empty input is treated as "I changed my mind").
func promptFormat(in *bufio.Reader, out io.Writer) (Format, bool) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  1) Text")
	fmt.Fprintln(out, "  2) JSON")
	fmt.Fprintln(out, "  3) Markdown")
	fmt.Fprintln(out, "  4) HTML")
	raw, err := readLine(in, "Format [2]: ")
	if err != nil {
		return FormatText, false
	}
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", "2", "json":
		return FormatJSON, true
	case "1", "text", "txt":
		return FormatText, true
	case "3", "md", "markdown":
		return FormatMarkdown, true
	case "4", "html":
		return FormatHTML, true
	default:
		fmt.Fprintf(out, "  unknown format %q — cancelled\n", raw)
		return FormatText, false
	}
}

// defaultSaveDir returns the suggested save directory and reports whether the
// binary appears to be running from its source working directory.
//
// Detection heuristic: if the executable's parent directory's parent contains
// a go.mod (or Makefile) — i.e. <repo>/bin/netcheck — we're in the working
// dir and save into the bin/ folder. Otherwise the binary is "installed"
// (go install, brew, /usr/local/bin, etc.) and we suggest ~/Documents.
func defaultSaveDir() (dir string, isWorkingDir bool) {
	exe, err := os.Executable()
	if err == nil {
		// Resolve symlinks so `go install` aliases don't fool the check.
		if resolved, lerr := filepath.EvalSymlinks(exe); lerr == nil {
			exe = resolved
		}
		binDir := filepath.Dir(exe)
		repoDir := filepath.Dir(binDir)
		if filepath.Base(binDir) == "bin" && hasFile(repoDir, "go.mod") {
			return binDir, true
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "Documents"), false
	}
	return ".", false
}

func hasFile(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// expandPath expands a leading ~/ to the user's home directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// defaultFilename builds "netcheck-<kind>-<sanitized-host>-<timestamp>.<ext>".
func defaultFilename(kind, host string, format Format) string {
	ext := "txt"
	switch format {
	case FormatJSON:
		ext = "json"
	case FormatMarkdown:
		ext = "md"
	case FormatHTML:
		ext = "html"
	}
	stamp := time.Now().Format("20060102-150405")
	return fmt.Sprintf("netcheck-%s-%s-%s.%s", kind, sanitizeForFilename(host), stamp, ext)
}

// sanitizeForFilename strips characters that aren't safe on common filesystems
// (Windows is the strictest — we use its blocklist for portability).
func sanitizeForFilename(s string) string {
	r := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"?", "-",
		"*", "-",
		"<", "-",
		">", "-",
		"|", "-",
		"\"", "-",
		" ", "-",
	)
	out := r.Replace(strings.TrimSpace(s))
	if out == "" || out == "." || out == ".." {
		return "result"
	}
	return out
}
