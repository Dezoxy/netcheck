package cmd

import (
	"strings"
	"testing"
)

func TestRunCompletionMissingShellExits2(t *testing.T) {
	if code := RunCompletion(nil); code != 2 {
		t.Fatalf("expected exit 2 for missing shell, got %d", code)
	}
}

func TestRunCompletionUnknownShellExits2(t *testing.T) {
	if code := RunCompletion([]string{"tcsh"}); code != 2 {
		t.Fatalf("expected exit 2 for unknown shell, got %d", code)
	}
}

func TestRunCompletionHelpExits0(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		if code := RunCompletion([]string{arg}); code != 0 {
			t.Fatalf("%s: expected exit 0, got %d", arg, code)
		}
	}
}

func TestRunCompletionBashScript(t *testing.T) {
	out := captureStdout(t, func() {
		if code := RunCompletion([]string{"bash"}); code != 0 {
			t.Fatalf("expected exit 0, got %d", code)
		}
	})
	// Spot-check the script's structural pieces — function name, complete
	// registration, and a handful of subcommand names that should be in the
	// completion list. Catches both "wrong script returned" and "subcommand
	// dropped from the list."
	for _, want := range []string{
		"_netcheck()",
		"complete -F _netcheck netcheck",
		"audit",
		"completion",
		"ports",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("bash script missing %q\n--- script ---\n%s", want, out)
		}
	}
}

func TestRunCompletionZshScript(t *testing.T) {
	out := captureStdout(t, func() {
		if code := RunCompletion([]string{"zsh"}); code != 0 {
			t.Fatalf("expected exit 0, got %d", code)
		}
	})
	for _, want := range []string{
		"#compdef netcheck",
		"compdef _netcheck netcheck",
		"_describe",
		"audit:aggregate report",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("zsh script missing %q", want)
		}
	}
}

func TestRunCompletionFishScript(t *testing.T) {
	out := captureStdout(t, func() {
		if code := RunCompletion([]string{"fish"}); code != 0 {
			t.Fatalf("expected exit 0, got %d", code)
		}
	})
	for _, want := range []string{
		"complete -c netcheck",
		"__fish_use_subcommand",
		"-a audit",
		"--output",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fish script missing %q", want)
		}
	}
}

func TestRunCompletionPowerShellScript(t *testing.T) {
	// Both `powershell` and `pwsh` should produce the same script.
	for _, name := range []string{"powershell", "pwsh"} {
		out := captureStdout(t, func() {
			if code := RunCompletion([]string{name}); code != 0 {
				t.Fatalf("%s: expected exit 0, got %d", name, code)
			}
		})
		for _, want := range []string{
			"Register-ArgumentCompleter",
			"-CommandName netcheck",
			"CompletionResult",
			"'audit'",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s script missing %q", name, want)
			}
		}
	}
}

// All four scripts should mention every public subcommand. Cheap guard against
// a future drift where someone adds `netcheck foo` to root.go but forgets to
// update completion.go.
func TestRunCompletionScriptsMentionAllSubcommands(t *testing.T) {
	shells := []string{"bash", "zsh", "fish", "powershell"}
	for _, shell := range shells {
		out := captureStdout(t, func() { RunCompletion([]string{shell}) })
		for _, sc := range completionSubcommands {
			if !strings.Contains(out, sc.name) {
				t.Errorf("%s script missing subcommand %q", shell, sc.name)
			}
		}
	}
}
