// netcheck is a small CLI that analyzes the path between your machine and a
// target — DNS, TCP, TLS, HTTP, redirects, timing, traceroute, IP ownership,
// and DNS resolver comparison.
//
// All real logic lives in the cmd/ and internal/ packages.
package main

import (
	"github.com/Dezoxy/netcheck/cmd"
	"github.com/Dezoxy/netcheck/pkg/check"
	"github.com/Dezoxy/netcheck/pkg/ipinfo"
	"github.com/Dezoxy/netcheck/pkg/pathenum"
	"github.com/Dezoxy/netcheck/pkg/reverseip"
	"github.com/Dezoxy/netcheck/pkg/secheaders"
	"github.com/Dezoxy/netcheck/pkg/subenum"
	"github.com/Dezoxy/netcheck/pkg/takeover"
	"github.com/Dezoxy/netcheck/pkg/techdetect"
	"github.com/Dezoxy/netcheck/pkg/wayback"
)

func main() {
	// Load config (default-search + env) before anything else so subcommand
	// flag defaults can pull from it.
	cmd.LoadConfig()

	// Wire the canonical User-Agent into both leaf packages before any lookup
	// or HTTP request runs. config.UserAgent wins if set; otherwise we send
	// "github.com/Dezoxy/netcheck/<version>".
	ua := cmd.UserAgent()
	ipinfo.SetUserAgent(ua)
	check.SetUserAgent(ua)
	secheaders.SetUserAgent(ua)
	techdetect.SetUserAgent(ua)
	subenum.SetUserAgent(ua)
	reverseip.SetUserAgent(ua)
	wayback.SetUserAgent(ua)
	takeover.SetUserAgent(ua)
	pathenum.SetUserAgent(ua)

	cmd.Run()
}
