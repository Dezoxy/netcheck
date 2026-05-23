package cmd

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestRequireAuthorizationFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	check := requireAuthorization(fs, "ports")
	if err := fs.Parse([]string{"--" + AuthzFlagName}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := check(&buf); err != nil {
		t.Errorf("flag should authorize, got err=%v output=%q", err, buf.String())
	}
}

func TestRequireAuthorizationDenied(t *testing.T) {
	t.Setenv(AuthzEnvVar, "")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	check := requireAuthorization(fs, "ports")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := check(&buf)
	if err == nil {
		t.Fatal("expected refusal error")
	}
	out := buf.String()
	for _, want := range []string{"ports", "--" + AuthzFlagName, AuthzEnvVar, "ETHICS.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal message should mention %q:\n%s", want, out)
		}
	}
}

func TestEnvAuthorized(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"True", true},
		{"YES", true},
		{"Yes", true},
		{"yes", true},
		{"0", false},
		{"", false},
		{"maybe", false},
	}
	for _, c := range cases {
		t.Run(c.val, func(t *testing.T) {
			t.Setenv(AuthzEnvVar, c.val)
			if got := envAuthorized(); got != c.want {
				t.Errorf("env %q: got %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestRequireAuthorizationViaEnv(t *testing.T) {
	t.Setenv(AuthzEnvVar, "1")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	check := requireAuthorization(fs, "tls")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := check(&buf); err != nil {
		t.Errorf("env should authorize, got err=%v", err)
	}
}
