package cmd

import (
	"testing"
	"time"
)

func TestWhoisDefaultTimeout(t *testing.T) {
	if got := whoisDefaultTimeout(5 * time.Second); got != 15*time.Second {
		t.Errorf("got %v, want 15s floor", got)
	}
	if got := whoisDefaultTimeout(30 * time.Second); got != 30*time.Second {
		t.Errorf("got %v, want passthrough", got)
	}
}

func TestRunWhoisTopLevelBadInput(t *testing.T) {
	if code := RunWhois([]string{}); code != 2 {
		t.Errorf("exit code = %d, want 2 on missing domain", code)
	}
	if code := RunWhois([]string{"--output", "yaml", "example.com"}); code != 2 {
		t.Errorf("exit code = %d, want 2 on bad format", code)
	}
}
