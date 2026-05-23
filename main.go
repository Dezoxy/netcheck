// netcheck is a small CLI that analyzes the path between your machine and a
// target — DNS, TCP, TLS, HTTP, redirects, timing, traceroute, IP ownership,
// and DNS resolver comparison.
//
// All real logic lives in the cmd/ and internal/ packages.
package main

import (
	"netcheck/cmd"
	"netcheck/internal/check"
	"netcheck/internal/ipinfo"
	"netcheck/internal/secheaders"
	"netcheck/internal/subenum"
	"netcheck/internal/techdetect"
)

func main() {
	// Load config (default-search + env) before anything else so subcommand
	// flag defaults can pull from it.
	cmd.LoadConfig()

	// Wire the canonical User-Agent into both leaf packages before any lookup
	// or HTTP request runs. config.UserAgent wins if set; otherwise we send
	// "netcheck/<version>".
	ua := cmd.UserAgent()
	ipinfo.SetUserAgent(ua)
	check.SetUserAgent(ua)
	secheaders.SetUserAgent(ua)
	techdetect.SetUserAgent(ua)
	subenum.SetUserAgent(ua)

	cmd.Run()
}
