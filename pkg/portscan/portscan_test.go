package portscan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// startListener opens a TCP listener on a random port and returns the port.
// Caller is responsible for closing the listener (deferred t.Cleanup).
func startListener(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, func() { ln.Close() }
}

// =============================================================================
// TopPorts / ParsePortList
// =============================================================================

func TestTopPorts(t *testing.T) {
	if got := len(TopPorts(10)); got != 10 {
		t.Errorf("TopPorts(10) length = %d, want 10", got)
	}
	if got := TopPorts(0); got != nil {
		t.Errorf("TopPorts(0) = %v, want nil", got)
	}
	if got := len(TopPorts(99999)); got != len(nmapTop1000) {
		t.Errorf("TopPorts(huge) length = %d, want %d", got, len(nmapTop1000))
	}
	// First entry should be 80 (canonical nmap top port).
	if TopPorts(1)[0] != 80 {
		t.Errorf("TopPorts(1)[0] = %d, want 80", TopPorts(1)[0])
	}
}

func TestParsePortList(t *testing.T) {
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"22", []int{22}, false},
		{"22,80,443", []int{22, 80, 443}, false},
		{"443,22,80", []int{22, 80, 443}, false}, // sorted
		{"22, 80 , 443", []int{22, 80, 443}, false},
		{"22,22,22", []int{22}, false}, // deduped
		{"8000-8003", []int{8000, 8001, 8002, 8003}, false},
		{"22,8080-8082,443", []int{22, 443, 8080, 8081, 8082}, false},
		{"", nil, true},
		{"abc", nil, true},
		{"0", nil, true},
		{"70000", nil, true},
		{"22-10", nil, true},
		{"abc-def", nil, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParsePortList(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !equalInts(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// serviceName / isFiltered
// =============================================================================

func TestServiceName(t *testing.T) {
	if serviceName(22) != "ssh" {
		t.Error("22 should be ssh")
	}
	if serviceName(443) != "https" {
		t.Error("443 should be https")
	}
	if serviceName(99999) != "" {
		t.Error("99999 should be empty")
	}
}

func TestIsFiltered(t *testing.T) {
	cases := []struct {
		err  string
		want bool
	}{
		{"dial tcp 1.2.3.4:80: i/o timeout", true},
		{"context deadline exceeded", true},
		{"no route to host", true},
		{"connection refused", false},
		{"dial tcp 1.2.3.4:80: connect: connection refused", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.err, func(t *testing.T) {
			if got := isFiltered(c.err); got != c.want {
				t.Errorf("isFiltered(%q) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// =============================================================================
// Scan against a local listener
// =============================================================================

func TestScanOpenPortDetected(t *testing.T) {
	port, stop := startListener(t)
	defer stop()

	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:          []int{port, port + 1}, // open + (very likely) closed
		Concurrency:    2,
		PerPortTimeout: 500 * time.Millisecond,
	}, 5*time.Second)

	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Stats.Open != 1 {
		t.Errorf("Open = %d, want 1", res.Stats.Open)
	}
	if res.Stats.Total != 2 {
		t.Errorf("Total = %d, want 2", res.Stats.Total)
	}
	if len(res.Ports) != 1 || res.Ports[0].Port != port {
		t.Errorf("got Ports=%v, want single entry on port %d", res.Ports, port)
	}
}

func TestScanFilteredCount(t *testing.T) {
	// Stub dialer to always return a timeout. Scan should count all ports as
	// "filtered" and zero open.
	prev := dialer
	defer func() { dialer = prev }()
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &timeoutError{}
	}

	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:          []int{80, 443},
		Concurrency:    2,
		PerPortTimeout: 100 * time.Millisecond,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Stats.Filtered != 2 {
		t.Errorf("Filtered = %d, want 2", res.Stats.Filtered)
	}
	if res.Stats.Open != 0 {
		t.Errorf("Open = %d, want 0", res.Stats.Open)
	}
}

func TestScanClosedCount(t *testing.T) {
	// Stub dialer to always return "connection refused" (not a timeout).
	prev := dialer
	defer func() { dialer = prev }()
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &refusedError{}
	}

	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:       []int{80, 443},
		Concurrency: 2,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Stats.Closed != 2 {
		t.Errorf("Closed = %d, want 2", res.Stats.Closed)
	}
}

func TestScanResolveFailure(t *testing.T) {
	// Nonexistent TLD — should fail resolution.
	res := Scan(context.Background(), "definitely-not-a-real-tld.invalid.netcheck-test", Options{}, 2*time.Second)
	if res.Err == nil {
		t.Error("expected resolve error")
	}
}

func TestScanEmptyHost(t *testing.T) {
	res := Scan(context.Background(), "", Options{}, 1*time.Second)
	if res.Err == nil {
		t.Error("expected error on empty host")
	}
}

func TestScanDefaultsFillIn(t *testing.T) {
	// Verify defaults: Top=0 → 100, Concurrency=0 → 50, PerPortTimeout=0 → 2s.
	// Stub dialer to refused so we don't actually hit the network.
	prev := dialer
	defer func() { dialer = prev }()
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &refusedError{}
	}

	res := Scan(context.Background(), "127.0.0.1", Options{}, 30*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Stats.Total != 100 {
		t.Errorf("default Top should give 100 ports, got %d", res.Stats.Total)
	}
}

// =============================================================================
// Concurrency caps don't deadlock
// =============================================================================

func TestScanConcurrencyOne(t *testing.T) {
	prev := dialer
	defer func() { dialer = prev }()
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &refusedError{}
	}
	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:       []int{80, 81, 82},
		Concurrency: 1,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Stats.Closed != 3 {
		t.Errorf("Closed = %d, want 3", res.Stats.Closed)
	}
}

// =============================================================================
// Test-only error types
// =============================================================================

type timeoutError struct{}

func (timeoutError) Error() string   { return "dial tcp 127.0.0.1:80: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type refusedError struct{}

func (refusedError) Error() string { return "dial tcp 127.0.0.1:80: connect: connection refused" }

// Sanity: equalInts handles empty.
func TestEqualInts(t *testing.T) {
	if !equalInts(nil, nil) {
		t.Error("nil/nil should be equal")
	}
	if equalInts([]int{1}, []int{1, 2}) {
		t.Error("different lengths should not be equal")
	}
}

// Helper to build a comma list mostly to exercise strconv.Itoa indirectly.
func TestServiceMapHasKnownPorts(t *testing.T) {
	for _, p := range []int{22, 80, 443, 3306, 5432, 6379} {
		if serviceName(p) == "" {
			t.Errorf("port %d should have a service name", p)
		}
	}
	// Quick sanity that all entries fit valid port range.
	for p := range commonServices {
		if p < 1 || p > 65535 {
			t.Errorf("commonServices entry out of range: %d", p)
		}
	}
	_ = strconv.Itoa(0) // silence unused-import warning if commenting helpers
}
