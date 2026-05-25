// Package portscan performs a TCP connect scan against a host across a list
// of ports. Active — opens many parallel TCP handshakes to the target. Gated
// behind the v1.5 authorization flag at the cmd layer.
//
// "Connect scan" only — netcheck does not implement SYN scans (which require
// raw sockets and root) or UDP scans. The result is what `nc -z` would tell
// you, but parallel and structured.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dialer is overridable for tests.
var dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// Result is the full scan output. Only OPEN ports are included in Ports —
// per-port closed/filtered detail would be too noisy to surface, and the
// counts live in Stats.
type Result struct {
	Host      string
	IP        string // resolved IP (if hostname was given)
	Ports     []PortResult
	Stats     Stats
	StartedAt time.Time
	Took      time.Duration
	Err       error
}

// PortResult is one open port.
type PortResult struct {
	Port    int
	Service string // best-guess service from the builtin port→service map
	Banner  string // best-effort banner grab; first printable line, may be empty
}

// Stats summarises the scan.
type Stats struct {
	Total    int // total ports scanned
	Open     int
	Closed   int // RST received
	Filtered int // timeout / no response — could be firewall, could be down
}

// Options control the scan behaviour.
type Options struct {
	Ports          []int         // exact port list. If nil, falls back to TopPorts(Top).
	Top            int           // when Ports is nil, use the top-N nmap-style ports. 0/<0 → 100.
	Concurrency    int           // parallel dials. 0/<0 → 50.
	PerPortTimeout time.Duration // per-dial timeout. 0/<0 → 2s.

	// BannerTimeout is the deadline for the banner-grab read after a successful
	// connect. 0 → 500ms default. Negative → banner grab disabled.
	//
	// Banner grab is "best effort": for ports that speak first (SSH, SMTP,
	// FTP, POP3, IMAP, etc.) we just read; for known HTTP ports we send a
	// minimal `GET /` probe; for TLS-wrapped ports we skip entirely (use
	// `netcheck tls` for those).
	BannerTimeout time.Duration

	// OnProgress, if non-nil, is called once per port as each result is
	// known — open (with service name from the builtin map), closed (RST),
	// or filtered (timeout / no route). The order is completion order, not
	// the original port list order.
	//
	// CALLED CONCURRENTLY from the scan goroutines. Implementations must be
	// safe to invoke from multiple goroutines simultaneously. The intended
	// pattern for the HTTP/SSE handler is to push events onto a buffered
	// channel and let a single emitter goroutine flush them to the response
	// writer.
	OnProgress func(Progress)
}

// Progress is one per-port event surfaced via Options.OnProgress.
type Progress struct {
	Port       int
	State      string // "open" | "closed" | "filtered"
	Service    string // for open ports, from the builtin map
	Index      int    // 1-based completion order within this scan
	TotalPorts int    // total scanned in this run (constant per scan)
}

// Scan resolves host, opens parallel TCP connections to each port, and
// returns a Result. Returns Err set on resolution failure.
func Scan(ctx context.Context, host string, opts Options, overallTimeout time.Duration) Result {
	started := time.Now()
	out := Result{Host: host, StartedAt: started}

	if strings.TrimSpace(host) == "" {
		out.Err = errors.New("empty host")
		out.Took = time.Since(started)
		return out
	}

	c, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	// Resolve up front so we can record the IP and avoid re-resolving per
	// port. If host already is an IP, LookupIP returns it.
	ips, err := net.DefaultResolver.LookupIP(c, "ip", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no addresses resolved")
		}
		out.Err = fmt.Errorf("resolve %s: %w", host, err)
		out.Took = time.Since(started)
		return out
	}
	// Prefer IPv4 to match `nc` defaults — most port-scan use cases assume v4.
	target := ips[0]
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			target = ip
			break
		}
	}
	out.IP = target.String()

	// Resolve port list.
	ports := opts.Ports
	if len(ports) == 0 {
		top := opts.Top
		if top <= 0 {
			top = 100
		}
		ports = TopPorts(top)
	}
	out.Stats.Total = len(ports)

	// Concurrency cap.
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 50
	}
	perPort := opts.PerPortTimeout
	if perPort <= 0 {
		perPort = 2 * time.Second
	}
	// 0 → 500ms default; <0 → disabled. A small budget keeps the wall-clock
	// impact bounded — the read fires only on already-open ports, and the
	// per-port goroutine is the same one that already held the connect slot.
	bannerTimeout := opts.BannerTimeout
	if bannerTimeout == 0 {
		bannerTimeout = 500 * time.Millisecond
	}

	type portRes struct {
		port   int
		open   bool
		banner string
		errStr string
	}
	results := make([]portRes, len(ports))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	// completed counter for OnProgress.Index. atomic increment because
	// callbacks fire from many goroutines.
	var completed int64
	totalPorts := len(ports)

	for i, p := range ports {
		i, p := i, p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			pCtx, pCancel := context.WithTimeout(c, perPort)
			defer pCancel()
			conn, err := dialer(pCtx, "tcp", net.JoinHostPort(target.String(), strconv.Itoa(p)))
			pr := portRes{port: p}
			if err != nil {
				pr.errStr = err.Error()
			} else {
				pr.open = true
				// Banner grab is best-effort. Errors are swallowed —
				// banner is optional information, not a reason to fail
				// the port result.
				if bannerTimeout > 0 {
					pr.banner = grabBanner(conn, p, bannerTimeout)
				}
				conn.Close()
			}
			results[i] = pr
			if opts.OnProgress != nil {
				idx := int(atomic.AddInt64(&completed, 1))
				state := "open"
				if !pr.open {
					if isFiltered(pr.errStr) {
						state = "filtered"
					} else {
						state = "closed"
					}
				}
				opts.OnProgress(Progress{
					Port:       p,
					State:      state,
					Service:    serviceName(p),
					Index:      idx,
					TotalPorts: totalPorts,
				})
			}
		}()
	}
	wg.Wait()

	for _, r := range results {
		switch {
		case r.open:
			out.Stats.Open++
			out.Ports = append(out.Ports, PortResult{
				Port:    r.port,
				Service: serviceName(r.port),
				Banner:  r.banner,
			})
		case isFiltered(r.errStr):
			out.Stats.Filtered++
		default:
			out.Stats.Closed++
		}
	}

	sort.Slice(out.Ports, func(i, j int) bool { return out.Ports[i].Port < out.Ports[j].Port })
	out.Took = time.Since(started)
	return out
}

// isFiltered classifies an error string as "filtered" (timeout / drop) vs
// "closed" (active RST or refused). Heuristic, but reliable for the common
// platforms.
func isFiltered(errStr string) bool {
	if errStr == "" {
		return false
	}
	lc := strings.ToLower(errStr)
	if strings.Contains(lc, "timeout") || strings.Contains(lc, "deadline exceeded") ||
		strings.Contains(lc, "i/o timeout") {
		return true
	}
	if strings.Contains(lc, "no route to host") {
		return true
	}
	return false
}

// TopPorts returns the top-N most-likely-open TCP ports per the nmap default.
// Capped at the length of nmapTop1000 (currently 1000).
func TopPorts(n int) []int {
	if n <= 0 {
		return nil
	}
	if n > len(nmapTop1000) {
		n = len(nmapTop1000)
	}
	out := make([]int, n)
	copy(out, nmapTop1000[:n])
	return out
}

// ParsePortList accepts a comma-separated list with optional dash-ranges
// (e.g. "22,80,443,8000-8010") and returns a deduped sorted []int.
func ParsePortList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty port list")
	}
	seen := map[int]bool{}
	var out []int
	for _, chunk := range strings.Split(s, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		if i := strings.IndexByte(chunk, '-'); i >= 0 {
			lo, err := strconv.Atoi(strings.TrimSpace(chunk[:i]))
			if err != nil {
				return nil, fmt.Errorf("bad port %q: %w", chunk, err)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(chunk[i+1:]))
			if err != nil {
				return nil, fmt.Errorf("bad port %q: %w", chunk, err)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("bad port range %q", chunk)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(chunk)
		if err != nil {
			return nil, fmt.Errorf("bad port %q: %w", chunk, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port out of range: %d", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

// serviceName returns the IANA-ish best-guess service for a port, or "" when
// we don't have a hint. Match nmap's tcp default reads — small but covers
// the common cases.
func serviceName(p int) string {
	if name, ok := commonServices[p]; ok {
		return name
	}
	return ""
}

// grabBanner is the per-port banner-grab routine. Strategy:
//
//   - TLS-wrapped ports (443, 465, 636, 993, 995, 8443, ...): skip entirely.
//     We can't read plaintext from a TLS endpoint, and `netcheck tls` exists
//     for that. Sending a probe would only generate noise.
//   - HTTP-ish ports: send a minimal `GET / HTTP/1.0` probe so the server has
//     something to respond to (HTTP servers don't speak first).
//   - Anything else: just read. Catches SSH, SMTP, FTP, POP3, IMAP, MySQL,
//     Redis, MongoDB, Memcached, and a long tail of TCP services that banner
//     on connect.
//
// Errors are swallowed: a closed read or short response just means we got no
// banner, not that the port itself failed. Returns "" when there's nothing to
// surface.
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	if isTLSWrappedPort(port) {
		return ""
	}
	// One deadline covers both write and read — banner grab budget is fixed.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if isHTTPPort(port) {
		// Single-shot probe — don't care about the write error, the read
		// deadline is what bounds us. Empty Host is fine for capturing
		// `Server:` headers from most stacks.
		_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nUser-Agent: netcheck\r\nAccept: */*\r\n\r\n"))
	}

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return cleanBanner(buf[:n], port)
}

// cleanBanner extracts the most informative single line from a raw banner
// buffer. For HTTP-ish ports we prefer the `Server:` header if present (the
// status line varies less and is less informative); otherwise we take the
// first non-empty printable line. Output is capped at 200 chars.
func cleanBanner(b []byte, port int) string {
	lines := splitLines(b)
	if isHTTPPort(port) {
		for _, ln := range lines {
			if hasPrefixFold(ln, "Server:") {
				return truncateBanner(strings.TrimSpace(ln[len("Server:"):]))
			}
		}
		// Fall back to the status line if no Server header.
		for _, ln := range lines {
			if strings.HasPrefix(ln, "HTTP/") {
				return truncateBanner(ln)
			}
		}
	}
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		return truncateBanner(ln)
	}
	return ""
}

// splitLines splits raw bytes on \r and \n, filtering non-printable ASCII
// (replacing with "."). Binary protocols (MySQL handshake, MongoDB OP_MSG)
// still produce *something* readable — a fingerprint, not a clean banner,
// but enough to identify the service.
func splitLines(b []byte) []string {
	var out []string
	var cur []byte
	for _, c := range b {
		if c == '\r' || c == '\n' {
			out = append(out, string(cur))
			cur = cur[:0]
			continue
		}
		if c >= 32 && c < 127 {
			cur = append(cur, c)
		} else {
			cur = append(cur, '.')
		}
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func truncateBanner(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// isHTTPPort returns true for ports that typically speak plain HTTP and don't
// banner on connect. Used to decide whether to send a GET probe before
// reading.
func isHTTPPort(p int) bool {
	switch p {
	case 80, 81, 88, 591, 3000, 5000, 5800, 5985, 7001, 7080, 8000, 8008,
		8009, 8080, 8081, 8088, 8090, 8181, 8888, 9000, 9090, 9091, 9999:
		return true
	}
	return false
}

// isTLSWrappedPort returns true for ports that speak TLS from byte zero —
// banner grab would either fail (no plaintext bytes) or send a probe that
// looks like garbage to the TLS handshake. `netcheck tls` handles these.
func isTLSWrappedPort(p int) bool {
	switch p {
	case 443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995,
		2376, 5061, 5223, 5349, 6697, 8443, 9443:
		return true
	}
	return false
}

// commonServices is the small port→service hint map. Not exhaustive; the
// idea is to be informative for the well-known ports without shipping a
// full /etc/services equivalent.
var commonServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	514:   "syslog",
	587:   "smtp-submission",
	636:   "ldaps",
	873:   "rsync",
	993:   "imaps",
	995:   "pop3s",
	1025:  "msrpc",
	1433:  "mssql",
	1521:  "oracle",
	2049:  "nfs",
	2375:  "docker",
	2376:  "docker-tls",
	3000:  "node-dev",
	3306:  "mysql",
	3389:  "rdp",
	5000:  "upnp/uwsgi",
	5432:  "postgresql",
	5601:  "kibana",
	5672:  "amqp",
	5900:  "vnc",
	5984:  "couchdb",
	6379:  "redis",
	8000:  "http-alt",
	8080:  "http-proxy",
	8081:  "http-alt",
	8443:  "https-alt",
	8888:  "http-alt",
	9000:  "sonarqube/php-fpm",
	9092:  "kafka",
	9200:  "elasticsearch",
	9300:  "elasticsearch-cluster",
	11211: "memcached",
	15672: "rabbitmq-mgmt",
	27017: "mongodb",
	50000: "sap",
}

// nmapTop1000 — the first slice (top 100) of nmap's default TCP port list.
// We carry 1000 so `--top 1000` works.
//
// Source: ordered by frequency from nmap-services. We freeze it here so
// scans are reproducible without an external file.
var nmapTop1000 = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}
