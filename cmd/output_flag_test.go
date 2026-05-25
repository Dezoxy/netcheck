package cmd

import (
	"flag"
	"io"
	"testing"
)

// TestOutputFlagJsonShortcut exercises the -j shortcut against the canonical
// --output flag. Last-write-wins applies: whichever appears later on the
// command line is the winner.
//
// strconv.ParseBool's accept-list (1, t, T, TRUE, true, True, 0, f, F, FALSE,
// false, False) is the contract — values outside that set are parse errors,
// matching standard Go bool-flag behaviour.
func TestOutputFlagJsonShortcut(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default unset", []string{}, "text"},
		{"explicit --output text", []string{"--output", "text"}, "text"},
		{"-j alone", []string{"-j"}, "json"},
		{"-j=true", []string{"-j=true"}, "json"},
		{"-j=1", []string{"-j=1"}, "json"},
		{"-j=t", []string{"-j=t"}, "json"},
		{"-j=TRUE", []string{"-j=TRUE"}, "json"},
		{"-j=false has no effect", []string{"-j=false"}, "text"},
		{"-j=0 has no effect", []string{"-j=0"}, "text"},
		{"--output=json", []string{"--output=json"}, "json"},
		{"-j wins when last", []string{"--output=text", "-j"}, "json"},
		{"--output wins when last", []string{"-j", "--output=text"}, "text"},
		{"-j then markdown", []string{"-j", "--output=markdown"}, "markdown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			out := addOutputFlag(fs)
			if err := fs.Parse(c.args); err != nil {
				t.Fatalf("parse %v: %v", c.args, err)
			}
			if *out != c.want {
				t.Errorf("args=%v: got %q, want %q", c.args, *out, c.want)
			}
		})
	}
}

// TestOutputFlagJsonShortcutRejectsInvalid is the regression guard for Codex's
// P2 on #57: invalid values to -j must fail parsing, not silently no-op into
// text output. We delegate to strconv.ParseBool so anything outside its
// accept-list ("yes", "no", "on", "off", "foo", "2", …) errors at fs.Parse.
func TestOutputFlagJsonShortcutRejectsInvalid(t *testing.T) {
	invalid := [][]string{
		{"-j=foo"},
		{"-j=yes"},
		{"-j=no"},
		{"-j=2"},
		{"-j=on"},
		{"-j=off"},
	}
	for _, args := range invalid {
		t.Run(args[0], func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			_ = addOutputFlag(fs)
			if err := fs.Parse(args); err == nil {
				t.Errorf("fs.Parse(%v) = nil, want error", args)
			}
		})
	}
}

// TestOutFlagShortcut verifies that -o and --out write to the same target.
// Last-write-wins is the documented contract.
func TestOutFlagShortcut(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default unset", []string{}, ""},
		{"--out path", []string{"--out", "/tmp/foo.json"}, "/tmp/foo.json"},
		{"-o path", []string{"-o", "/tmp/bar.json"}, "/tmp/bar.json"},
		{"--out then -o wins (later)", []string{"--out", "/tmp/a", "-o", "/tmp/b"}, "/tmp/b"},
		{"-o then --out wins (later)", []string{"-o", "/tmp/a", "--out", "/tmp/b"}, "/tmp/b"},
		{"-o -", []string{"-o", "-"}, "-"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			out := addOutFlag(fs)
			if err := fs.Parse(c.args); err != nil {
				t.Fatalf("parse %v: %v", c.args, err)
			}
			if *out != c.want {
				t.Errorf("args=%v: got %q, want %q", c.args, *out, c.want)
			}
		})
	}
}

// TestOutputFlagParseFormatIntegration is a paranoid end-to-end check: the
// value `-j` writes into the target round-trips through ParseFormat to
// FormatJSON, matching what the call sites actually do after fs.Parse.
func TestOutputFlagParseFormatIntegration(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := addOutputFlag(fs)
	if err := fs.Parse([]string{"-j"}); err != nil {
		t.Fatal(err)
	}
	format, err := ParseFormat(*out)
	if err != nil {
		t.Fatalf("ParseFormat(%q): %v", *out, err)
	}
	if format != FormatJSON {
		t.Errorf("ParseFormat(%q) = %v, want FormatJSON", *out, format)
	}
}
