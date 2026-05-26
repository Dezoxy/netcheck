package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// udpProbeFor / udpProbes registry
// =============================================================================

func TestUDPProbeForKnownPorts(t *testing.T) {
	// Spot-check the service-aware probes: each one should be non-empty
	// and well-formed enough that an attacker fingerprinting the source
	// would recognise the protocol.
	cases := []struct {
		port    int
		prefix  []byte // first few bytes that uniquely identify the probe
		minSize int
	}{
		{53, []byte{0xab, 0xcd, 0x01, 0x00}, 17},               // DNS header
		{123, []byte{0x1b}, 48},                                // NTPv4 client
		{161, []byte{0x30}, 30},                                // SNMP SEQUENCE
		{137, []byte{0xab, 0xcd}, 50},                          // NetBIOS-NS
		{500, []byte{0x00, 0x11, 0x22, 0x33}, 28},              // ISAKMP
		{443, []byte{0xc0, 0x00, 0x00, 0x00, 0x01}, 9},         // QUIC Initial
		{5353, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 30}, // mDNS
	}
	for _, c := range cases {
		p := udpProbeFor(c.port)
		if len(p) < c.minSize {
			t.Errorf("port %d: probe size %d < min %d", c.port, len(p), c.minSize)
		}
		if !startsWith(p, c.prefix) {
			t.Errorf("port %d: probe prefix %x != want %x", c.port, p[:min(len(p), len(c.prefix))], c.prefix)
		}
	}
}

func TestUDPProbeForSSDPContainsMSearch(t *testing.T) {
	p := udpProbeFor(1900)
	if !strings.Contains(string(p), "M-SEARCH") || !strings.Contains(string(p), "ssdp:discover") {
		t.Errorf("SSDP probe missing M-SEARCH marker: %q", p)
	}
}

func TestUDPProbeForUnknownFallsBackToZeroByte(t *testing.T) {
	// 7777 is not in udpProbes — the fallback should be a single zero byte.
	p := udpProbeFor(7777)
	if len(p) != 1 || p[0] != 0 {
		t.Errorf("fallback probe = %x, want [0x00]", p)
	}
}

// =============================================================================
// isUDPRefused error classification
// =============================================================================

func TestIsUDPRefusedMatchesECONNREFUSED(t *testing.T) {
	// Common platform forms of the error string. isUDPRefused is the one
	// signal we can read on a connected UDP socket without raw access.
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("read udp 127.0.0.1:53: connection refused"), true},
		{errors.New("ECONNREFUSED"), true},
		{errors.New("read udp: i/o timeout"), false},
		{errors.New(""), false},
	}
	for _, c := range cases {
		if got := isUDPRefused(c.err); got != c.want {
			t.Errorf("isUDPRefused(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// =============================================================================
// containsAny helper
// =============================================================================

func TestContainsAny(t *testing.T) {
	if !containsAny("read udp 1.2.3.4:53: connection refused", "connection refused", "ECONNREFUSED") {
		t.Errorf("containsAny should match 'connection refused'")
	}
	if containsAny("i/o timeout", "connection refused", "ECONNREFUSED") {
		t.Errorf("containsAny should NOT match unrelated text")
	}
	if containsAny("short", "this-is-far-longer-than-the-haystack") {
		t.Errorf("containsAny should NOT match needle longer than haystack")
	}
	if containsAny("anything", "") {
		t.Errorf("containsAny should NOT match empty needle")
	}
}

// =============================================================================
// TopUDPPorts dedup + cap
// =============================================================================

func TestTopUDPPortsDeduplicates(t *testing.T) {
	// The source list has intentional repeats — TopUDPPorts must yield a
	// deduped slice and still honour the requested length.
	out := TopUDPPorts(20)
	seen := make(map[int]bool, len(out))
	for _, p := range out {
		if seen[p] {
			t.Errorf("TopUDPPorts(20) duplicates port %d", p)
		}
		seen[p] = true
	}
	if len(out) != 20 {
		t.Errorf("TopUDPPorts(20) length = %d, want 20", len(out))
	}
}

func TestTopUDPPortsCapAtSourceLength(t *testing.T) {
	// Asking for more than the source can supply caps to len(source-after-dedup).
	out := TopUDPPorts(10_000)
	// We trust the source has at least 60 unique entries; the exact count
	// is curated and may shift, so just sanity-check it's non-empty and
	// deduped.
	if len(out) == 0 {
		t.Fatalf("TopUDPPorts(huge) returned empty slice")
	}
	seen := make(map[int]bool, len(out))
	for _, p := range out {
		if seen[p] {
			t.Errorf("TopUDPPorts(huge) duplicates port %d", p)
		}
		seen[p] = true
	}
}

func TestTopUDPPortsZeroOrNegative(t *testing.T) {
	if got := TopUDPPorts(0); got != nil {
		t.Errorf("TopUDPPorts(0) = %v, want nil", got)
	}
	if got := TopUDPPorts(-5); got != nil {
		t.Errorf("TopUDPPorts(-5) = %v, want nil", got)
	}
}

// =============================================================================
// probeUDPPort against a live local UDP server (loopback)
// =============================================================================

// startUDPEcho opens a UDP listener on a random loopback port and echoes
// any datagram it receives. Returns the port and a cleanup function.
func startUDPEcho(t *testing.T) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.Port, func() {
		close(done)
		pc.Close()
	}
}

func TestProbeUDPPortOpenWhenEchoResponds(t *testing.T) {
	port, stop := startUDPEcho(t)
	defer stop()

	state := probeUDPPort(context.Background(), net.ParseIP("127.0.0.1"), port, 500*time.Millisecond)
	if state != "open" {
		t.Errorf("state = %q, want %q", state, "open")
	}
}

func TestProbeUDPPortOpenFilteredOnNoResponse(t *testing.T) {
	// No listener: kernel won't ICMP-unreach a 127.0.0.1 destination
	// reliably across platforms, so we expect "open|filtered" via the
	// timeout path. Pick a port nothing is bound to.
	state := probeUDPPort(context.Background(), net.ParseIP("127.0.0.1"), 65534, 200*time.Millisecond)
	if state != "open|filtered" && state != "filtered" {
		// "filtered" is acceptable on systems where the loopback path
		// does produce an ECONNREFUSED for the unbound port.
		t.Errorf("state = %q, want open|filtered or filtered", state)
	}
}

// =============================================================================
// scanUDP end-to-end with the engine
// =============================================================================

func TestScanUDPOnlyReturnsOpenForLiveEcho(t *testing.T) {
	port, stop := startUDPEcho(t)
	defer stop()

	res := Scan(context.Background(), "127.0.0.1", Options{
		Protocols:      []string{"udp"},
		UDPPorts:       []int{port, 65533}, // one open, one almost-certainly-silent
		Concurrency:    2,
		PerPortTimeout: 300 * time.Millisecond,
	}, 5*time.Second)

	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if res.Stats.Total != 2 {
		t.Errorf("Total = %d, want 2", res.Stats.Total)
	}
	if res.Stats.Open != 1 {
		t.Errorf("Open = %d, want 1", res.Stats.Open)
	}
	// The unbound port should land in OpenFiltered or Filtered depending
	// on platform.
	if res.Stats.OpenFiltered+res.Stats.Filtered != 1 {
		t.Errorf("expected the other port in OpenFiltered+Filtered, got OF=%d F=%d",
			res.Stats.OpenFiltered, res.Stats.Filtered)
	}
	// The open entry must carry Proto=udp.
	if len(res.Ports) == 0 {
		t.Fatalf("Ports empty")
	}
	foundOpen := false
	for _, p := range res.Ports {
		if p.Proto != "udp" {
			t.Errorf("port %d: Proto=%q, want udp", p.Port, p.Proto)
		}
		if p.Port == port {
			if p.State != "open" {
				t.Errorf("echo port: State=%q, want open", p.State)
			}
			foundOpen = true
		}
	}
	if !foundOpen {
		t.Errorf("echo port %d not in Ports", port)
	}
}

func TestScanProtocolsDefaultsToTCP(t *testing.T) {
	// Regression guard for the back-compat contract: Options.Protocols
	// nil means TCP-only. We stub the TCP dialer and the UDP dialer; only
	// the TCP one should be called.
	prevTCP, prevUDP := dialer, udpDialer
	defer func() { dialer = prevTCP; udpDialer = prevUDP }()

	var tcpCalls, udpCalls int64
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt64(&tcpCalls, 1)
		return nil, &timeoutError{}
	}
	udpDialer = func(ctx context.Context, addr string) (net.Conn, error) {
		atomic.AddInt64(&udpCalls, 1)
		return nil, &timeoutError{}
	}

	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:          []int{1, 2, 3},
		Concurrency:    1,
		PerPortTimeout: 50 * time.Millisecond,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if tcpCalls != 3 {
		t.Errorf("tcpCalls = %d, want 3", tcpCalls)
	}
	if udpCalls != 0 {
		t.Errorf("udpCalls = %d, want 0 (UDP must not run when Protocols is empty)", udpCalls)
	}
}

func TestScanBothProtocolsRunSequentially(t *testing.T) {
	prevTCP, prevUDP := dialer, udpDialer
	defer func() { dialer = prevTCP; udpDialer = prevUDP }()

	var tcpCalls, udpCalls int64
	dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt64(&tcpCalls, 1)
		return nil, &timeoutError{}
	}
	udpDialer = func(ctx context.Context, addr string) (net.Conn, error) {
		atomic.AddInt64(&udpCalls, 1)
		return nil, &timeoutError{}
	}

	res := Scan(context.Background(), "127.0.0.1", Options{
		Protocols:      []string{"tcp", "udp"},
		Ports:          []int{1, 2},
		UDPPorts:       []int{53, 123, 161},
		Concurrency:    2,
		PerPortTimeout: 50 * time.Millisecond,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
	if tcpCalls != 2 {
		t.Errorf("tcpCalls = %d, want 2", tcpCalls)
	}
	if udpCalls != 3 {
		t.Errorf("udpCalls = %d, want 3", udpCalls)
	}
	if res.Stats.Total != 5 {
		t.Errorf("Stats.Total = %d, want 5", res.Stats.Total)
	}
}

// =============================================================================
// helpers
// =============================================================================

func startsWith(haystack, prefix []byte) bool {
	if len(haystack) < len(prefix) {
		return false
	}
	for i, b := range prefix {
		if haystack[i] != b {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Unused but kept handy for future tests that want a host:port string
// formatted the same way the engine does internally.
var _ = func(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}
var _ = fmt.Sprintf
