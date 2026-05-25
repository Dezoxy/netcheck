package check

import (
	"context"
	"net"
	"time"
)

// TCPResult holds the outcome of a single TCP connect attempt.
type TCPResult struct {
	Addr string
	Err  error
	Took time.Duration
}

// TCP attempts a TCP connection to ip:port and reports the round-trip time.
// The connection is closed immediately after a successful connect.
func TCP(ctx context.Context, ip net.IP, port string) TCPResult {
	addr := net.JoinHostPort(ip.String(), port)
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	took := time.Since(start)
	if err != nil {
		return TCPResult{Addr: addr, Err: err, Took: took}
	}
	conn.Close()
	return TCPResult{Addr: addr, Took: took}
}
