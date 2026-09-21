package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeConn is a net.Conn with chosen endpoints and no I/O.
type fakeConn struct{ local, remote net.Addr }

func (c fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c fakeConn) Close() error                     { return nil }
func (c fakeConn) LocalAddr() net.Addr              { return c.local }
func (c fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c fakeConn) SetDeadline(time.Time) error      { return nil }
func (c fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c fakeConn) SetWriteDeadline(time.Time) error { return nil }

func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

func TestCrossConnectedPortsAreNotReportedOpen(t *testing.T) {
	refused := errors.New("connect: connection refused")
	tests := []struct {
		name      string
		host      string
		dial      func(call int, port int) (net.Conn, error) // call is 1-based per port
		wantOpen  bool
		wantDials int
	}{
		{
			name: "crossed pair on loopback: confirmation refused",
			host: "127.0.0.1",
			dial: func(call, port int) (net.Conn, error) {
				if call == 1 {
					// Connected, but to another of our own sockets.
					return fakeConn{local: tcpAddr("127.0.0.1", port+1), remote: tcpAddr("127.0.0.1", port)}, nil
				}
				return nil, refused
			},
			wantOpen:  false,
			wantDials: 2,
		},
		{
			name: "self-connect on loopback: rejected without redialing",
			host: "127.0.0.1",
			dial: func(_, port int) (net.Conn, error) {
				return fakeConn{local: tcpAddr("127.0.0.1", port), remote: tcpAddr("127.0.0.1", port)}, nil
			},
			wantOpen:  false,
			wantDials: 1,
		},
		{
			name: "real listener on loopback: confirmed open",
			host: "127.0.0.1",
			dial: func(call, port int) (net.Conn, error) {
				return fakeConn{local: tcpAddr("127.0.0.1", 50000+call), remote: tcpAddr("127.0.0.1", port)}, nil
			},
			wantOpen:  true,
			wantDials: 2,
		},
		{
			name: "remote target: one dial, no confirmation traffic",
			host: "192.0.2.10", // TEST-NET-1, never local
			dial: func(_, port int) (net.Conn, error) {
				return fakeConn{local: tcpAddr("198.51.100.5", 50000), remote: tcpAddr("192.0.2.10", port)}, nil
			},
			wantOpen:  true,
			wantDials: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const port = 4242
			var mu sync.Mutex
			calls := 0
			orig := dialer
			t.Cleanup(func() { dialer = orig })
			dialer = func(_ context.Context, _, addr string) (net.Conn, error) {
				if addr != net.JoinHostPort(tt.host, strconv.Itoa(port)) {
					t.Errorf("unexpected dial to %s", addr)
				}
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				return tt.dial(n, port)
			}

			res := Scan(context.Background(), tt.host, Options{
				Ports:          []int{port},
				PerPortTimeout: 100 * time.Millisecond,
				BannerTimeout:  -1,
			}, 2*time.Second)
			if res.Err != nil {
				t.Fatalf("scan error: %v", res.Err)
			}

			if gotOpen := res.Stats.Open == 1; gotOpen != tt.wantOpen {
				t.Errorf("open = %v, want %v (stats %+v)", gotOpen, tt.wantOpen, res.Stats)
			}
			if !tt.wantOpen && res.Stats.Closed != 1 {
				t.Errorf("a rejected port should count as closed, got stats %+v", res.Stats)
			}
			if calls != tt.wantDials {
				t.Errorf("dials = %d, want %d", calls, tt.wantDials)
			}
		})
	}
}

func TestIsLocalIP(t *testing.T) {
	for _, tt := range []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"192.0.2.10", false}, // TEST-NET-1
		{"8.8.8.8", false},
	} {
		if got := isLocalIP(net.ParseIP(tt.ip)); got != tt.want {
			t.Errorf("isLocalIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
