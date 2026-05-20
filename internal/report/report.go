// Package report renders check results as text (v0.5 will add json/markdown/html siblings).
package report

import (
	"fmt"
	"time"

	"netcheck/internal/check"
	"netcheck/internal/target"
)

// Report aggregates a full `netcheck <target>` run.
type Report struct {
	Target    *target.Target
	StartedAt time.Time
	DNS       check.DNSResult
	TCPv4     *check.TCPResult
	TCPv6     *check.TCPResult
	TLS       *check.TLSResult
	HTTP      check.HTTPResult
}

// OK reports whether every check in the report succeeded — used by the CLI to
// pick its exit code.
func (r *Report) OK() bool {
	if r.DNS.Err != nil {
		return false
	}
	tcpOK := (r.TCPv4 != nil && r.TCPv4.Err == nil) || (r.TCPv6 != nil && r.TCPv6.Err == nil)
	if !tcpOK {
		return false
	}
	if r.TLS != nil && r.TLS.Err != nil {
		return false
	}
	return r.HTTP.Err == nil && r.HTTP.Status > 0 && r.HTTP.Status < 400
}

// Mark renders a per-check status indicator.
func Mark(ok bool) string {
	if ok {
		return "[OK]"
	}
	return "[FAIL]"
}

// MS renders a duration as a "<N>ms" string, or "-" when the value is zero or negative.
func MS(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
