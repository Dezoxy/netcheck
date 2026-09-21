package portscan

import (
	"context"
	"errors"
	"net"
	"time"
)

// Scanning this machine has a false positive the network cannot produce on
// its own: TCP simultaneous open. The scanner dials ports concurrently, and
// the kernel picks each dial's source port from the same ephemeral range it
// is scanning. When dial A's source port is dial B's target and vice versa,
// the two SYNs cross, both dials "connect" to each other, and two ports with
// nothing listening are reported open. Self-connect (a dial whose source port
// is its own target) is the one-socket case. macOS allocates ephemeral ports
// sequentially, which makes this routine when scanning next to a listener.
//
// A real listener accepts a second connection; a crossed pair does not repeat,
// because the ephemeral ports have moved on. So an open result on a local
// target is confirmed with one more dial. Remote targets cannot cross-connect
// with this machine's own sockets and get no extra traffic.

var errCrossConnected = errors.New("connected to one of the scanner's own sockets, not a listener")

// confirmLocalOpen reports whether conn, a successful dial to addr on this
// machine, reached a real listener. It does not close conn.
func confirmLocalOpen(ctx context.Context, conn net.Conn, addr string, timeout time.Duration) bool {
	if connectedToSelf(conn) {
		return false
	}
	cCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	again, err := dialer(cCtx, "tcp", addr)
	if err != nil {
		return false
	}
	defer again.Close()
	return !connectedToSelf(again)
}

func connectedToSelf(c net.Conn) bool {
	return c.LocalAddr().String() == c.RemoteAddr().String()
}

// isLocalIP reports whether ip is an address of this machine: loopback,
// unspecified, or assigned to one of its interfaces.
func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}
