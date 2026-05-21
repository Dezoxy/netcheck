package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// addOutFlag registers `--out` on the given flagset. Empty value means
// "write to stdout" (the existing behavior). A non-empty path is created
// (parent dirs included) and used as the destination.
func addOutFlag(fs *flag.FlagSet) *string {
	return fs.String("out", "", "write the result to this file instead of stdout (parent dirs created if needed)")
}

// openOut returns a writer for the requested output path, plus a closer the
// caller must defer. When path is empty, the writer is os.Stdout and the
// closer is a no-op. When set, the file is created (mkdir -p on the parent
// directory) and the closer flushes/closes it.
//
// On non-empty path, openOut also prints "Saved to <path>" to stderr after
// the closer runs successfully — so users who use --out get confirmation
// without polluting the file content.
func openOut(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", path, err)
	}
	abs, _ := filepath.Abs(path)
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", path, cerr)
			return
		}
		fmt.Fprintf(os.Stderr, "Saved to %s\n", abs)
	}, nil
}
