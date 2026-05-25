package route

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Hop is one row of traceroute output.
type Hop struct {
	N       int
	Probes  []HopProbe
	Timeout bool // all probes timed out
	Raw     string
}

// HopProbe is one probe sample for a hop.
type HopProbe struct {
	Host string
	IP   string
	RTT  time.Duration
}

// IPs returns the distinct IPs seen in this hop's probes.
func (h *Hop) IPs() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range h.Probes {
		if p.IP == "" || seen[p.IP] {
			continue
		}
		seen[p.IP] = true
		out = append(out, p.IP)
	}
	return out
}

// hopLineRe matches a line that starts with a hop number. The body is parsed
// manually so we can handle host-switches mid-line on asymmetric paths.
var hopLineRe = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
var rttRe = regexp.MustCompile(`([0-9]+\.?[0-9]*)\s*ms`)
var ipRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)`)

// ParseHopLine parses one line of traceroute output into a Hop.
// Returns nil if the line is not a hop line (header, blank, etc).
func ParseHopLine(line string) *Hop {
	m := hopLineRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	n, _ := strconv.Atoi(m[1])
	rest := strings.TrimSpace(m[2])
	hop := &Hop{N: n, Raw: line}

	// Quick check: if the rest is just stars and whitespace, it's a full timeout.
	if onlyStars(rest) {
		hop.Timeout = true
		return hop
	}

	// Find RTTs and IPs independently. macOS/Linux traceroute interleaves
	// "host (ip)  rtt ms  rtt ms  rtt ms" but may switch hosts mid-line on
	// asymmetric paths. We pair each RTT with the most-recent IP seen to its left.
	rtts := rttRe.FindAllStringSubmatchIndex(rest, -1)
	ips := ipRe.FindAllStringIndex(rest, -1)

	// Filter out IPs that are actually part of an RTT (e.g. "1.234" inside "1.234 ms")
	ips = filterIPsInsideRTTs(ips, rtts)

	if len(rtts) == 0 {
		// No RTTs parsed — treat as timeout-ish but keep raw line.
		hop.Timeout = true
		return hop
	}

	for _, rttIdx := range rtts {
		val, _ := strconv.ParseFloat(rest[rttIdx[2]:rttIdx[3]], 64)
		probe := HopProbe{RTT: time.Duration(val * float64(time.Millisecond))}

		// Pick the IP whose start index is the largest one still <= this RTT's start.
		var chosenIP string
		for _, ipIdx := range ips {
			if ipIdx[0] < rttIdx[0] {
				chosenIP = rest[ipIdx[0]:ipIdx[1]]
			} else {
				break
			}
		}
		probe.IP = chosenIP
		probe.Host = hostBefore(rest, chosenIP)
		hop.Probes = append(hop.Probes, probe)
	}
	return hop
}

func onlyStars(s string) bool {
	stripped := strings.ReplaceAll(s, "*", "")
	return strings.TrimSpace(stripped) == ""
}

func filterIPsInsideRTTs(ips, rtts [][]int) [][]int {
	var out [][]int
	for _, ip := range ips {
		inside := false
		for _, rtt := range rtts {
			if ip[0] >= rtt[0] && ip[1] <= rtt[1] {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, ip)
		}
	}
	return out
}

// hostBefore returns a likely hostname token preceding the IP in the line.
// Returns "" if the token before is the IP itself or numeric.
func hostBefore(line, ip string) string {
	if ip == "" {
		return ""
	}
	idx := strings.Index(line, ip)
	if idx <= 0 {
		return ""
	}
	left := strings.TrimRight(line[:idx], " \t(")
	fields := strings.Fields(left)
	if len(fields) == 0 {
		return ""
	}
	tok := fields[len(fields)-1]
	if net.ParseIP(tok) != nil {
		return ""
	}
	tok = strings.TrimRight(tok, ":,")
	if tok == "" || tok == ip {
		return ""
	}
	return tok
}
