// Package cmd hosts the netcheck CLI surface. main calls Run.
package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"

	"netcheck/internal/check"
	"netcheck/internal/config"
	"netcheck/internal/ipinfo"
)

// Version is the canonical netcheck version string, surfaced via `--version`
// and wired into the RDAP/HTTP User-Agent at startup.
const Version = "0.7.0"

// loadedConfig is the merged config (file + env + defaults) used by every
// subcommand to seed flag defaults. Populated by LoadConfig (called from main).
var loadedConfig = config.Defaults()

// LoadConfig loads the config from the default search path or NETCHECK_CONFIG
// and stashes it for subcommand flag defaults. main.go calls this once at
// startup before Run. Errors are non-fatal — a missing file is fine; a parse
// error is logged to stderr and we fall back to defaults.
func LoadConfig() *config.Config {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v (using defaults)\n", err)
	}
	loadedConfig = cfg
	return cfg
}

// LoadedConfig returns the active config. Used by main.go to wire User-Agents
// into the leaf packages.
func LoadedConfig() *config.Config { return loadedConfig }

// addConfigFlag registers `--config` on the given flagset. Each subcommand
// uses this to allow per-invocation config overrides.
func addConfigFlag(fs *flag.FlagSet) *string {
	return fs.String("config", "", "path to config file (overrides default search and NETCHECK_CONFIG)")
}

// applyConfigOverride re-loads config from the explicit --config path (if any)
// and updates loadedConfig. Call this after fs.Parse but before reading any
// other defaults from loadedConfig.
func applyConfigOverride(configPath string) {
	if configPath == "" {
		return
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v (using defaults)\n", err)
		return
	}
	loadedConfig = cfg
}

// UserAgent returns the User-Agent string the leaf packages should use.
// Prefers config override, falls back to "netcheck/<version>".
func UserAgent() string {
	if loadedConfig != nil && loadedConfig.UserAgent != "" {
		return loadedConfig.UserAgent
	}
	return "netcheck/" + Version
}

// Run dispatches an os.Args invocation. Bare `netcheck` on an interactive
// terminal drops into the menu; otherwise the first positional is treated as
// a subcommand or full-check target.
func Run() {
	if len(os.Args) < 2 {
		if stdinIsTTY() {
			RunMenu(nil)
			return
		}
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "menu":
		RunMenu(os.Args[2:])
	case "dns":
		RunDNS(os.Args[2:])
	case "route":
		RunRoute(os.Args[2:])
	case "ip":
		RunIP(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Printf("netcheck %s\n", Version)
	default:
		RunFull(os.Args[1:])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "netcheck %s\n\n", Version)
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  netcheck                       interactive menu (when run on a terminal)")
	fmt.Fprintln(os.Stderr, "  netcheck menu                  interactive menu (explicit)")
	fmt.Fprintln(os.Stderr, "  netcheck <target>              full check (DNS, TCP, TLS, HTTP)")
	fmt.Fprintln(os.Stderr, "  netcheck dns <host>            compare DNS resolvers")
	fmt.Fprintln(os.Stderr, "  netcheck route <host>          trace the network path with per-hop ASN")
	fmt.Fprintln(os.Stderr, "  netcheck ip <ip|host>          show IP ownership, RDAP, reverse DNS, and CDN hints")
	fmt.Fprintln(os.Stderr, "  netcheck help                  show this message")
	fmt.Fprintln(os.Stderr, "  netcheck version               show version")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "examples:")
	fmt.Fprintln(os.Stderr, "  netcheck google.com")
	fmt.Fprintln(os.Stderr, "  netcheck --insecure https://expired.badssl.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns google.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns --type MX,TXT cloudflare.com")
	fmt.Fprintln(os.Stderr, "  netcheck dns --resolver 1.0.0.1 --resolver 8.8.4.4 google.com")
	fmt.Fprintln(os.Stderr, "  netcheck route google.com")
	fmt.Fprintln(os.Stderr, "  netcheck route --no-asn --max-hops 20 1.1.1.1")
	fmt.Fprintln(os.Stderr, "  netcheck ip cloudflare.com")
	fmt.Fprintln(os.Stderr, "  netcheck ip 8.8.8.8")
	fmt.Fprintln(os.Stderr, "  netcheck dns --resolver tls://1.1.1.1 cloudflare.com   # DoT")
	fmt.Fprintln(os.Stderr, "  netcheck dns --resolver https://cloudflare-dns.com/dns-query cloudflare.com   # DoH")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Every subcommand also accepts --output text|json|markdown|html and --config <path>.")
	fmt.Fprintln(os.Stderr, "Config search: --config flag → NETCHECK_CONFIG env → ~/.config/netcheck/config.yaml")
}

// annotateDNS enriches a check.DNSResult with per-IP ASN/PTR/CDN info.
// Lives in cmd (not check or ipinfo) because it orchestrates across both
// packages — keeping it here avoids any cycle between them.
func annotateDNS(ctx context.Context, d *check.DNSResult, asnC *ipinfo.ASNCache) {
	if d.Err != nil {
		return
	}
	if asnC == nil {
		asnC = ipinfo.DefaultASNCache
	}
	all := append([]net.IP{}, d.A...)
	all = append(all, d.AAAA...)
	ips := ipinfo.UniqueIPs(all)
	if len(ips) == 0 {
		return
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	info := make(map[string]ipinfo.DNSIPInfo, len(ips))
	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipStr := ip.String()
			res := ipinfo.LookupDNSIP(ctx, ipStr, asnC)
			mu.Lock()
			info[ipStr] = res
			mu.Unlock()
		}()
	}
	wg.Wait()
	d.IPInfo = info
}
