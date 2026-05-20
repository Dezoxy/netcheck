// netcheck is a small CLI that analyzes the path between your machine and a
// target — DNS, TCP, TLS, HTTP, redirects, timing, traceroute, IP ownership,
// and DNS resolver comparison.
//
// All real logic lives in the cmd/ and internal/ packages.
package main

import (
	"netcheck/cmd"
	"netcheck/internal/ipinfo"
)

func main() {
	// Wire the canonical User-Agent into the RDAP client before any lookups run.
	ipinfo.SetUserAgent("netcheck/" + cmd.Version)
	cmd.Run()
}
