package route

import (
	"testing"
	"time"
)

func TestParseHopLineIgnoresNonHops(t *testing.T) {
	for _, line := range []string{
		"",
		"   ",
		"traceroute to google.com (142.250.184.206), 64 hops max",
		"some garbage no hop number",
		"\tindented but no number",
	} {
		if got := ParseHopLine(line); got != nil {
			t.Errorf("ParseHopLine(%q) = %+v, want nil", line, got)
		}
	}
}

func TestParseHopLineFullTimeout(t *testing.T) {
	got := ParseHopLine(" 2  * * *")
	if got == nil {
		t.Fatal("ParseHopLine returned nil")
	}
	if got.N != 2 {
		t.Errorf("N = %d, want 2", got.N)
	}
	if !got.Timeout {
		t.Errorf("Timeout = false, want true")
	}
	if len(got.Probes) != 0 {
		t.Errorf("Probes = %v, want empty", got.Probes)
	}
}

func TestParseHopLineIPv4NumericOnly(t *testing.T) {
	// macOS traceroute with -n (no DNS resolution).
	got := ParseHopLine(" 1  192.168.1.1  1.234 ms  1.123 ms  1.045 ms")
	if got == nil {
		t.Fatal("ParseHopLine returned nil")
	}
	if got.N != 1 || got.Timeout {
		t.Fatalf("N=%d Timeout=%v", got.N, got.Timeout)
	}
	if len(got.Probes) != 3 {
		t.Fatalf("Probes len = %d, want 3", len(got.Probes))
	}
	for i, p := range got.Probes {
		if p.IP != "192.168.1.1" {
			t.Errorf("Probes[%d].IP = %q, want 192.168.1.1", i, p.IP)
		}
		if p.Host != "" {
			t.Errorf("Probes[%d].Host = %q, want empty", i, p.Host)
		}
	}
	if got.Probes[0].RTT != time.Duration(1.234*float64(time.Millisecond)) {
		t.Errorf("Probes[0].RTT = %v, want ~1.234ms", got.Probes[0].RTT)
	}
}

func TestParseHopLineHostnameAndIP(t *testing.T) {
	got := ParseHopLine(" 3  some.host.example.com (1.2.3.4)  10.5 ms  9.8 ms  10.1 ms")
	if got == nil {
		t.Fatal("nil")
	}
	if len(got.Probes) != 3 {
		t.Fatalf("Probes len = %d", len(got.Probes))
	}
	if got.Probes[0].IP != "1.2.3.4" {
		t.Errorf("Probes[0].IP = %q, want 1.2.3.4", got.Probes[0].IP)
	}
	if got.Probes[0].Host != "some.host.example.com" {
		t.Errorf("Probes[0].Host = %q, want some.host.example.com", got.Probes[0].Host)
	}
	ips := got.IPs()
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("IPs() = %v, want [1.2.3.4]", ips)
	}
}

func TestParseHopLinePartialTimeout(t *testing.T) {
	// Some probes succeed, others time out — macOS prints "*" for the missing ones.
	got := ParseHopLine(" 4  10.0.0.1  2.5 ms  *  *")
	if got == nil {
		t.Fatal("nil")
	}
	if got.Timeout {
		t.Errorf("Timeout = true, want false (one probe succeeded)")
	}
	// One RTT parsed → one probe; the timeouts are not represented as probes.
	if len(got.Probes) != 1 {
		t.Fatalf("Probes len = %d, want 1", len(got.Probes))
	}
}

func TestParseHopLineMultipleIPsInSameHop(t *testing.T) {
	// On asymmetric paths different probes hit different routers in the same hop.
	got := ParseHopLine(" 5  host1 (1.1.1.1)  10.0 ms  host2 (2.2.2.2)  11.0 ms  12.0 ms")
	if got == nil {
		t.Fatal("nil")
	}
	if len(got.Probes) != 3 {
		t.Fatalf("Probes len = %d, want 3", len(got.Probes))
	}
	if got.Probes[0].IP != "1.1.1.1" {
		t.Errorf("Probes[0].IP = %q", got.Probes[0].IP)
	}
	if got.Probes[1].IP != "2.2.2.2" {
		t.Errorf("Probes[1].IP = %q", got.Probes[1].IP)
	}
	// Probes[2] should pair with the most-recent IP — still 2.2.2.2.
	if got.Probes[2].IP != "2.2.2.2" {
		t.Errorf("Probes[2].IP = %q, want 2.2.2.2", got.Probes[2].IP)
	}
	// IPs() dedupes.
	ips := got.IPs()
	if len(ips) != 2 {
		t.Errorf("IPs() = %v, want 2 distinct", ips)
	}
}

func TestParseHopLineIPv6(t *testing.T) {
	got := ParseHopLine(" 7  2606:4700::6810:84e5  18.5 ms  18.2 ms  18.7 ms")
	if got == nil {
		t.Fatal("nil")
	}
	if len(got.Probes) != 3 {
		t.Fatalf("Probes len = %d", len(got.Probes))
	}
	if got.Probes[0].IP != "2606:4700::6810:84e5" {
		t.Errorf("Probes[0].IP = %q, want 2606:4700::6810:84e5", got.Probes[0].IP)
	}
}

func TestParseHopLineRTTValueNotMistakenForIP(t *testing.T) {
	// "1.234" inside "1.234 ms" must not be parsed as an IP.
	got := ParseHopLine(" 1  10.0.0.1  1.234 ms")
	if got == nil {
		t.Fatal("nil")
	}
	if len(got.Probes) != 1 {
		t.Fatalf("Probes len = %d, want 1", len(got.Probes))
	}
	if got.Probes[0].IP != "10.0.0.1" {
		t.Errorf("Probes[0].IP = %q, want 10.0.0.1", got.Probes[0].IP)
	}
}
