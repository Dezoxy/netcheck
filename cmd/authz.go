package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

// AuthzEnvVar is the environment variable name users can set to authorize
// every active-scanning command without passing the flag each invocation.
// Documented in docs/ETHICS.md.
const AuthzEnvVar = "NETCHECK_AUTHORIZED"

// AuthzFlagName is the flag name attached to every v1.5 active-scanning
// command.
const AuthzFlagName = "i-have-authorization"

// requireAuthorization registers the --i-have-authorization flag on fs and
// returns a check function. The check returns nil if the user provided the
// flag, set NETCHECK_AUTHORIZED to a truthy value, or both. Otherwise it
// writes a refusal message to errOut and returns a non-nil error.
//
// Every v1.5 command wires this in. v1.4 commands don't — those are passive.
func requireAuthorization(fs *flag.FlagSet, cmdName string) (check func(errOut io.Writer) error) {
	authorized := fs.Bool(AuthzFlagName, false,
		"confirm you are authorized to actively probe the target (or set "+AuthzEnvVar+"=1)")
	return func(errOut io.Writer) error {
		if *authorized || envAuthorized() {
			return nil
		}
		fmt.Fprintln(errOut, refusalMessage(cmdName))
		return errAuthRequired
	}
}

// envAuthorized reports whether NETCHECK_AUTHORIZED is set to a truthy value
// (1, true, yes — case-insensitive). Anything else, or unset, returns false.
func envAuthorized() bool {
	v := os.Getenv(AuthzEnvVar)
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	// Tolerate "yes" / "Yes" / "YES" beyond what strconv accepts.
	switch v {
	case "yes", "Yes", "YES":
		return true
	}
	return false
}

// errAuthRequired is a sentinel returned by the check function so callers can
// translate it directly to exit code 2 (bad invocation) without printing a
// duplicate error — the refusal message has already been written.
var errAuthRequired = fmt.Errorf("authorization required")

// refusalMessage returns the human-readable refusal banner. Same text for
// every active-scanning command, parameterized on the command name.
func refusalMessage(cmdName string) string {
	return fmt.Sprintf(`error: `+"`netcheck %s`"+` is an active network probe.

You must confirm you are authorized to test the target. Pass
--%s, or set %s=1, to proceed.

See docs/ETHICS.md (or https://github.com/Dezoxy/netcheck/blob/main/docs/ETHICS.md)
for what "authorized" means in this project's context.`,
		cmdName, AuthzFlagName, AuthzEnvVar)
}
