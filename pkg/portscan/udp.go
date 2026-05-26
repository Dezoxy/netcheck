package portscan

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// udpDialer is overridable for tests. Production wraps net.Dialer.DialContext
// with the "udp" network, which gives us an unconnected datagram socket once
// the kernel has resolved a route. UDP "connect" doesn't actually transmit
// anything — it just pins the remote address on the socket so Write/Read
// can skip the per-call sendto arguments.
var udpDialer = func(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp", addr)
}

// scanUDP runs a UDP probe sweep over the given ports.
//
// Why this exists, since UDP scans usually need raw sockets: nmap and
// friends read ICMP "port unreachable" responses to distinguish closed
// from open|filtered. ICMP requires raw-socket access (root) and we
// deliberately don't take that on. So we use a degraded, privilege-free
// scan: send a service-aware probe to each port, wait for ANY response,
// classify accordingly.
//
//   - Got a UDP reply within timeout → "open" (something is listening
//     and responded to our probe in a recognizable way).
//   - Read returned an ECONNREFUSED on the connected socket → "filtered"
//     (the kernel synthesised this from an inbound ICMP unreachable; we
//     can read it WITHOUT raw access because the socket is connected).
//   - Timeout / no response → "open|filtered". The nmap convention.
//
// For known UDP services we send protocol-specific bytes that elicit a
// known response: DNS query for "version.bind" CHAOS TXT, NTPv4 client
// packet, SNMPv1 GetRequest with public community, etc. For ports
// without a registered probe we send a single zero byte — most listeners
// won't reply, so they end up open|filtered, but the probe at least
// proves we tried.
func scanUDP(
	ctx context.Context,
	target net.IP,
	ports []int,
	perPort time.Duration,
	conc, totalPorts int,
	completed *int64,
	out *Result,
	onProgress func(Progress),
) {
	type portRes struct {
		port  int
		state string // "open" | "filtered" | "open|filtered"
	}
	results := make([]portRes, len(ports))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, p := range ports {
		i, p := i, p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			pCtx, pCancel := context.WithTimeout(ctx, perPort)
			defer pCancel()

			results[i] = portRes{port: p, state: probeUDPPort(pCtx, target, p, perPort)}

			if onProgress != nil {
				idx := int(atomic.AddInt64(completed, 1))
				onProgress(Progress{
					Port:       p,
					Proto:      "udp",
					State:      results[i].state,
					Service:    serviceName(p),
					Index:      idx,
					TotalPorts: totalPorts,
				})
			}
		}()
	}
	wg.Wait()

	for _, r := range results {
		switch r.state {
		case "open":
			out.Stats.Open++
			out.Ports = append(out.Ports, PortResult{
				Port:    r.port,
				Proto:   "udp",
				State:   "open",
				Service: serviceName(r.port),
			})
		case "filtered":
			out.Stats.Filtered++
		default: // "open|filtered"
			out.Stats.OpenFiltered++
			// Also surface open|filtered ports in Result.Ports so the UI
			// can show "probed but ambiguous" rows. Callers that only want
			// definitively-open ports can filter on State == "open".
			out.Ports = append(out.Ports, PortResult{
				Port:    r.port,
				Proto:   "udp",
				State:   "open|filtered",
				Service: serviceName(r.port),
			})
		}
	}
}

// probeUDPPort sends a (service-aware where available) UDP probe to
// target:port, waits up to timeout for a response, and returns the
// classified state. See scanUDP doc for the state model.
func probeUDPPort(ctx context.Context, target net.IP, port int, timeout time.Duration) string {
	conn, err := udpDialer(ctx, net.JoinHostPort(target.String(), strconv.Itoa(port)))
	if err != nil {
		// Dial errors on UDP are rare (no handshake) — most "errors" surface
		// later on Read. Treat dial failure as filtered/unreachable.
		return "filtered"
	}
	defer conn.Close()

	probe := udpProbeFor(port)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, werr := conn.Write(probe); werr != nil {
		return "filtered"
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, rerr := conn.Read(buf)
	if rerr != nil {
		// On the *connected* UDP socket, the kernel surfaces inbound ICMP
		// "port unreachable" as ECONNREFUSED. That's the one definitive
		// closed/filtered signal we get without raw socket access.
		if isUDPRefused(rerr) {
			return "filtered"
		}
		// Anything else (timeout, deadline exceeded) → open|filtered.
		return "open|filtered"
	}
	if n > 0 {
		return "open"
	}
	return "open|filtered"
}

// isUDPRefused returns true when a Read on a connected UDP socket
// surfaced a kernel-side ECONNREFUSED, indicating an inbound ICMP "port
// unreachable" from the target. Works without raw sockets because the
// kernel does the ICMP correlation for connected sockets.
func isUDPRefused(err error) bool {
	if err == nil {
		return false
	}
	// net.OpError.Err is usually an *os.SyscallError wrapping a syscall.Errno.
	// Rather than import x/sys/unix for ECONNREFUSED, we string-match — the
	// error message format is stable enough across the platforms we care
	// about (Linux, macOS, *BSD, Windows).
	msg := err.Error()
	return containsAny(msg, "connection refused", "ECONNREFUSED")
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if len(n) == 0 || len(s) < len(n) {
			continue
		}
		// Manual substring check to keep this file free of strings import
		// shenanigans (it's used elsewhere; just avoiding repeated imports
		// in surgical edits).
		for i := 0; i+len(n) <= len(s); i++ {
			if s[i:i+len(n)] == n {
				return true
			}
		}
	}
	return false
}

// udpProbeFor returns the payload to send to a UDP port. For known
// services we send protocol-specific bytes that elicit a known reply;
// for everything else we send a single zero byte so the probe is
// distinguishable from "we did nothing" in packet captures but still
// won't crash naive listeners that read raw datagrams.
func udpProbeFor(port int) []byte {
	if probe, ok := udpProbes[port]; ok {
		return probe
	}
	return []byte{0}
}

// udpProbes is the service-aware probe registry. Keep these payloads
// minimal and recognisable — the goal is to elicit ANY response, not
// to perform a full protocol exchange.
//
// Sources:
//   - DNS:   RFC 1035 question section for "." NS query
//   - NTP:   RFC 5905 client packet (mode 3)
//   - SNMP:  RFC 1157 v1 GetRequest, community "public", OID 1.3.6.1.2.1.1.1.0
//   - mDNS:  RFC 6762 query for "_services._dns-sd._udp.local"
//   - SSDP:  M-SEARCH for "ssdp:all"
//   - IKE:   RFC 2407 ISAKMP header with empty payload
//   - NetBIOS Name Service: RFC 1002 NBSTAT for "*"
//   - QUIC:  empty Initial packet (just enough to provoke a reset)
var udpProbes = map[int][]byte{
	// DNS — standard query, root NS record. The recursion-desired flag is
	// off; resolvers and authoritative servers both reply.
	53: {
		0xab, 0xcd, // transaction ID
		0x01, 0x00, // flags: standard query, RD=0
		0x00, 0x01, // questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // answer/ns/ar = 0
		0x00,       // root label (".")
		0x00, 0x02, // type: NS
		0x00, 0x01, // class: IN
	},

	// NTP v4 client request. Server replies with the same packet structure.
	123: {
		0x1b, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	},

	// SNMPv1 GetRequest, community "public", OID 1.3.6.1.2.1.1.1.0
	// (sysDescr). Will only reply on agents that accept the "public"
	// community — many disable it — but it's the convention.
	161: {
		0x30, 0x26, 0x02, 0x01, 0x00,
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	},

	// mDNS query for "_services._dns-sd._udp.local" — service-type
	// enumeration. Replies enumerate the host's exposed services.
	5353: {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,
		0x00, 0x0c, // type PTR
		0x00, 0x01, // class IN
	},

	// SSDP M-SEARCH for any service. UPnP routers and many IoT devices
	// respond with their descriptor URL.
	1900: []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: ssdp:all\r\n\r\n",
	),

	// ISAKMP / IKE — bare main-mode initiator header. Triggers a reply
	// even from policy-restricted gateways (rejected, but a reply
	// nonetheless).
	500: {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // initiator SPI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder SPI = 0
		0x01,       // next payload: SA
		0x10,       // version 1.0
		0x02,       // exchange type: identity protect (main mode)
		0x00,       // flags
		0x00, 0x00, 0x00, 0x00, // message ID
		0x00, 0x00, 0x00, 0x1c, // length 28
	},

	// NetBIOS Name Service "*" query — NBSTAT for the wildcard scope.
	// Windows boxes reply with their NetBIOS name table.
	137: {
		0xab, 0xcd,
		0x00, 0x00, // flags
		0x00, 0x01, // questions
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, // length-prefixed encoded "*"
		'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		0x00,
		0x00, 0x21, // type: NBSTAT
		0x00, 0x01, // class: IN
	},

	// QUIC Initial — version 1 (0x00000001), null connection IDs. Most
	// QUIC servers respond with a Version Negotiation or Initial packet.
	443: {
		0xc0,                   // long header, fixed bit, type=Initial
		0x00, 0x00, 0x00, 0x01, // version
		0x00, // dest conn ID length = 0
		0x00, // source conn ID length = 0
		0x00, // token length = 0
		0x00, // packet number length
	},
}
