# netcheck

[![CI](https://github.com/Dezoxy/netcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Dezoxy/netcheck/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/Dezoxy/netcheck?sort=semver)](https://github.com/Dezoxy/netcheck/releases/latest) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A single command that explains what actually happens between your machine and a URL — DNS, TCP, TLS, HTTP, redirects, timing, IP ownership, CDN, traceroute, and resolver disagreements.

```
$ netcheck google.com

NETCHECK REPORT
Target: https://google.com
Time:   2026-05-21 22:17:23

DNS
  [OK] A     142.251.143.238  AS15169 GOOGLE (CDN: Google)
  [OK] AAAA  2a00:1450:400d:813::200e  AS15169 GOOGLE (CDN: Google)
  lookup time: 68ms

TCP
  [OK] IPv4 142.251.143.238:443 reachable (4ms)
  [OK] IPv6 [2a00:1450:400d:813::200e]:443 reachable (5ms)

TLS
  [OK] Certificate valid
    Subject:   *.google.com
    Issuer:    WR2
    Protocol:  TLS 1.3 (cipher TLS_AES_128_GCM_SHA256)
    Expires:   2026-07-13 (54 days)

HTTP
  [OK] Status:    200
    Final URL: https://www.google.com/
    Redirects: 1
  Timing:  DNS 6ms · Connect 17ms · TLS 40ms · TTFB 328ms · Total 774ms

Summary
  [OK] DNS  [OK] TCP  [OK] TLS  [OK] HTTP
```

## Install

**macOS via Homebrew** _(coming once the tap is activated — see [docs/PUBLISHING.md](docs/PUBLISHING.md))_:

```bash
brew tap dezoxy/netcheck
brew install netcheck
```

**Windows via Scoop** _(coming once the bucket is activated — same doc)_:

```powershell
scoop bucket add netcheck https://github.com/Dezoxy/scoop-netcheck
scoop install netcheck
```

**Pre-built binary** — download the archive for your platform from the [latest release](https://github.com/Dezoxy/netcheck/releases/latest), or curl one-liner:

```bash
# macOS Apple Silicon
curl -L https://github.com/Dezoxy/netcheck/releases/latest/download/netcheck_1.4.1_darwin_arm64.tar.gz | tar xz
sudo mv netcheck /usr/local/bin/

# Linux amd64 (Homebrew Cask is macOS-only — Linux users use this path)
curl -L https://github.com/Dezoxy/netcheck/releases/latest/download/netcheck_1.4.1_linux_amd64.tar.gz | tar xz
sudo mv netcheck /usr/local/bin/

# Windows: download netcheck_1.4.1_windows_amd64.zip, unzip, run netcheck.exe
```

Available platforms: `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`, `windows_amd64`, `windows_arm64`. Each archive bundles `README.md`, `LICENSE`, and `config.example.yaml`. SHA256s in `checksums.txt`.

**From source** (requires Go 1.22+):

```bash
git clone https://github.com/Dezoxy/netcheck.git
cd netcheck
make build      # → ./bin/netcheck
make install    # → $GOBIN (usually ~/go/bin)
```

### Shell completions (optional)

`netcheck completion <shell>` prints a completion script to stdout. Pipe it into the right place for your shell:

```bash
# bash (per-user — works on Linux and macOS with bash-completion installed)
netcheck completion bash > ~/.local/share/bash-completion/completions/netcheck

# zsh — drop into any directory on your $fpath, then re-init compinit
netcheck completion zsh > "${fpath[1]}/_netcheck"

# fish
netcheck completion fish > ~/.config/fish/completions/netcheck.fish

# PowerShell (current session — add to $PROFILE to persist)
netcheck completion powershell | Out-String | Invoke-Expression
```

Completes subcommand names and a few flag values (`--output text|json|markdown|html`). Open a new shell after installing.

## What it does

netcheck has four checks, an interactive terminal menu, and a local web
workbench for visual full checks. Run the checks from a terminal; pipe the
output through `jq`; run `netcheck` with no arguments to get the menu; or start
`netcheck app` for the browser UI.

| Command | Asks |
|---|---|
| `netcheck <target>` | Can I reach this URL? What's the full path — DNS, TCP, TLS, HTTP, redirects, timing? Who owns the IP? |
| `netcheck dns <host>` | Do Cloudflare, Google, Quad9, my system resolver, and any DoH/DoT resolver agree on this hostname's IPs? |
| `netcheck route <host>` | What's the network path to this host, and who owns each hop? |
| `netcheck ip <ip\|host>` | Who owns this IP? What's its ASN, reverse DNS, RDAP record, CDN affiliation? |
| `netcheck headers <url>` | Is the site sending the security headers (HSTS, CSP, X-Frame-Options, etc.) it should be? |
| `netcheck tech <url>` | What's behind this site? CMS, JS framework, server, CDN, language — fingerprinted from one passive GET. |
| `netcheck subs <domain>` | Which subdomains exist? Enumerated from Certificate Transparency logs (crt.sh + CertSpotter). |
| `netcheck reverse <ip>` | What else lives on this IP? Reverse DNS + Hackertarget + optional Shodan (via API key in config). |
| `netcheck arch <domain>` | What does the Wayback Machine remember about this domain? First/last seen, total snapshots, recent URLs. |
| `netcheck tls <host>` | Full TLS audit: protocol matrix, cipher suites, cert chain, expiry. *Active — requires `--i-have-authorization`.* |
| `netcheck takeover <domain>` | Is this domain's CNAME pointing at an unclaimed third-party service? *Active — requires `--i-have-authorization`.* |
| `netcheck ports <host>` | Parallel TCP connect scan (top-100 by default). *Active — requires `--i-have-authorization`.* |
| `netcheck enum <url>` | HTTP path enumeration against a wordlist. *Active — requires `--i-have-authorization`.* |
| `netcheck diff <a.json> <b.json>` | What changed between two saved JSON reports? Exits 1 on changes, 0 if identical. |
| `netcheck watch -- <cmd> ...` | Re-run a sub-command on an interval and print the diff between iterations. |
| `netcheck menu` | Interactive picker for any of the above. Offers to save results after each run. |
| `netcheck app` | Local web workbench for a visual full check from the same Go engine. |
| `netcheck config show` | What config is netcheck actually using right now? |

Every command accepts `--output text|json|markdown|html` (default `text`) and `--out <file>` (write to file with `Saved to <abs-path>` echoed to stderr). The text format is byte-stable across `v1.x`; the JSON schema is versioned (`"netcheck_version"` field) and stable per [STABILITY.md](STABILITY.md).

## Examples

### Quick full check

```bash
netcheck google.com
netcheck https://expired.badssl.com           # see the TLS section flag this
netcheck --insecure https://self-signed.badssl.com    # inspect without verifying
```

### Local web app

```bash
netcheck app
netcheck app --listen 127.0.0.1:8787
```

Open `http://127.0.0.1:8787/` for the React/PWA workbench. The app serves from
the Go binary and uses the same full-check engine as the CLI. Its current UI
scope is visual full checks, recent checks, and JSON export; DNS compare, route,
and IP info stay on the CLI for now.

### Compare DNS resolvers

```bash
netcheck dns google.com
netcheck dns --type MX,TXT cloudflare.com
netcheck dns --resolver tls://1.1.1.1 cloudflare.com                       # DoT
netcheck dns --resolver doh://dns.google/dns-query cloudflare.com          # DoH
netcheck dns --no-defaults --resolver 1.0.0.1 google.com                   # pinned single resolver
```

### Trace the path

```bash
netcheck route google.com
netcheck route --max-hops 20 --no-asn 1.1.1.1
```

### IP ownership

```bash
netcheck ip 1.1.1.1
netcheck ip cloudflare.com    # resolves the host and reports each IP
```

### Security headers report card

```bash
netcheck headers https://news.ycombinator.com
netcheck headers --output json https://github.com | jq '.summary'
```

Grades the major security-relevant response headers (HSTS, Content-Security-Policy,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and
flags information-disclosure headers (Server, X-Powered-By). One HTTP GET — passive,
indistinguishable from a normal browser visit.

### Tech fingerprint

```bash
netcheck tech https://wordpress.org
netcheck tech --output json https://shopify.com | jq '.matches[] | {name, category}'
```

Identifies the stack from one passive GET — CMS (WordPress, Drupal, Ghost, Magento,
Shopify, WooCommerce), JS framework (Next.js, Nuxt, Angular, React, Vue), server
(nginx, Apache, Caddy, IIS, LiteSpeed), CDN (Cloudflare, Fastly, CloudFront, Akamai,
BunnyCDN), language / web framework (PHP, Laravel, Django, Rails, ASP.NET), and
common libraries (jQuery, Bootstrap). Each match comes with a confidence tier and the
evidence that triggered it. Catalogue grows over time — not part of the v1.x JSON
stability promise.

### Subdomain enumeration

```bash
netcheck subs example.com
netcheck subs --output json microsoft.com | jq '.subdomains | length'
```

Queries public Certificate Transparency log aggregators (crt.sh and CertSpotter) in
parallel, dedupes the union, filters to names that actually belong to the target
domain, and lists each subdomain with which source(s) reported it. Passive — netcheck
never talks to the target. If one source is flaking (crt.sh notoriously 502s), the
run still succeeds with the surviving source and the failure shows up in the
"Source errors" section.

### Reverse IP lookup

```bash
netcheck reverse 1.1.1.1
netcheck reverse --output json 8.8.8.8 | jq '.hostnames | length'
```

Lists other hostnames pointing at the given IP. Sources: system reverse DNS (`PTR`),
Hackertarget's free reverse-IP API, and **optionally Shodan** when
`apis.shodan_api_key` is set in `~/.config/netcheck/config.yaml`. Shodan adds the
most signal (its scan database tracks hostnames seen on the IP), so it's worth
getting a free key at https://account.shodan.io/ if you do this often. Same
resilience as `subs` — one source failing doesn't fail the run.

### Wayback / historical snapshots

```bash
netcheck arch example.com
netcheck arch --output json example.com | jq '.first, .last, .total'
```

Queries archive.org's CDX API for historical snapshots of the domain and its
subdomains. Returns total snapshot count, first/last seen dates, and a sample of
the most-recent unique URLs the Wayback Machine has indexed. Useful for finding
abandoned admin paths, old API endpoints, or historical hostnames that no longer
resolve. No API key needed.

### Active scanning (v1.5)

**Active commands send traffic to the target.** They refuse to run unless you
confirm authorization — pass `--i-have-authorization` (or set
`NETCHECK_AUTHORIZED=1`). Running these against systems you do not own and do
not have permission to test is illegal in most jurisdictions. See
[docs/ETHICS.md](docs/ETHICS.md) for the legal landscape and what
"authorized" means in this project.

```bash
# TLS audit — protocols, ciphers, cert chain.
netcheck tls --i-have-authorization cloudflare.com

# Subdomain takeover — checks the CNAME against a catalog of services
# (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Bitbucket Cloud, Ghost).
netcheck takeover --i-have-authorization foo.example.com

# TCP port scan (default: top-100 nmap-style ports, 50-way concurrent).
netcheck ports --i-have-authorization scanme.nmap.org
netcheck ports --i-have-authorization --ports 22,80,443,8000-8010 host.example.com

# HTTP path enumeration (~70-entry builtin wordlist, or --wordlist file).
netcheck enum --i-have-authorization https://target.example.com
netcheck enum --i-have-authorization --wordlist /path/to/SecLists/Discovery/Web-Content/common.txt https://target.example.com
```

Once you've thought about it, `export NETCHECK_AUTHORIZED=1` for the session
instead of typing `--i-have-authorization` on every call.

### Diff and watch

```bash
# Compare two saved JSON reports. Exits 1 on changes, 0 if identical —
# script-friendly for cron alerting.
netcheck diff yesterday.json today.json

# Re-run a scan every 5 minutes and print whatever changed since the previous
# iteration. The `--` separator avoids flag conflicts between watch and the
# wrapped sub-command.
netcheck watch --interval 5m -- ports --i-have-authorization example.com

# Same thing with snapshots saved to disk (filename = ISO timestamp + kind):
netcheck watch --interval 10m --out-dir ./netcheck-snaps -- subs example.com
```

Per-kind diff handling is built in: ports (opened / closed / banner changes),
subdomains (added / removed), headers (grade regressions), tech (versions),
TLS (cert issuer + expiry, new findings), and more. Timing fields are
ignored — only meaningful changes show up.

### Pipe into other tools

```bash
# What's the redirect chain?  (-j is shorthand for --output json)
netcheck -j google.com | jq '.http.hops'

# Which hops timed out on a traceroute?
netcheck route -j google.com | jq '.hops[] | select(.timeout)'

# Save a shareable HTML report  (-o is shorthand for --out)
netcheck ip --output html -o /tmp/report.html 1.1.1.1 && open /tmp/report.html

# Send a Markdown summary in a ticket
netcheck dns --output markdown cloudflare.com | pbcopy
```

The `-j` / `-o` shortcuts are equivalent to `--output json` / `--out`. The long forms still work; the short forms exist to keep one-liners terse.

> Flags come before the positional argument: `netcheck dns -j cloudflare.com`, not `netcheck dns cloudflare.com -j`.

## Config file

Optional YAML at `~/.config/netcheck/config.yaml`. Every key is optional — missing files and missing keys fall back to compiled-in defaults.

```yaml
timeout: 10s
user_agent: my-internal-monitor/1.0
follow_redirects: true
max_redirects: 10
prefer_ipv6: false

resolvers:
  - name: cloudflare-doh
    address: https://cloudflare-dns.com/dns-query
    type: doh
  - name: quad9-dot
    address: 9.9.9.9
    type: dot
```

**Search order:** `--config <path>` flag → `NETCHECK_CONFIG` env → `$XDG_CONFIG_HOME/netcheck/config.yaml` → `~/.config/netcheck/config.yaml`.

**Env overrides:** `NETCHECK_TIMEOUT` and `NETCHECK_USER_AGENT` win over the file when set — handy for CI/ops.

Run `netcheck config show` to see what's actually loaded. See [config.example.yaml](config.example.yaml) for the full schema.

## Use as a library

Every check engine lives under `netcheck/pkg/` and is importable from your own Go programs. The JSON schema types in `pkg/report` are the same ones the CLI emits — the wire format is the contract.

```bash
go get github.com/Dezoxy/netcheck@latest
```

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Dezoxy/netcheck/pkg/dnscompare"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Built-in resolver set (Cloudflare/Google/Quad9) + the system resolver.
	resolvers := append([]dnscompare.Resolver{}, dnscompare.DefaultResolvers...)
	resolvers = append(resolvers, dnscompare.SystemResolvers()...)

	res := dnscompare.Compare(ctx, resolvers, "google.com", "A", 5*time.Second)
	verdict := res.Verdict()

	fmt.Fprintf(os.Stderr, "resolvers agree: %v\n", verdict.Agree)
	_ = json.NewEncoder(os.Stdout).Encode(res)
}
```

Public packages:

| Package | What it does |
|---|---|
| `pkg/check` | Full check (DNS + TCP + TLS + HTTP) |
| `pkg/dnscompare` | Multi-resolver DNS query comparison |
| `pkg/route` | Traceroute + per-hop ASN |
| `pkg/ipinfo` | RDAP, reverse DNS, CDN classification |
| `pkg/secheaders`, `pkg/techdetect`, `pkg/subenum`, `pkg/reverseip`, `pkg/wayback` | Passive recon engines |
| `pkg/tlsaudit`, `pkg/takeover`, `pkg/portscan`, `pkg/pathenum` | Active scanning engines |
| `pkg/report` | Versioned JSON schemas + text/Markdown/HTML renderers |
| `pkg/diff` | Structured diff between two saved reports |
| `pkg/target` | URL / host normalization |

Stability: exported names are stable across `v2.x`. Catalogue-style packages (`pkg/techdetect`, `pkg/secheaders`) keep stable result *shapes*, but the set of detections they emit grows over time — don't pin tests to "exactly these matches." Active-scanning packages still require the same `i_have_authorization` boundary as the CLI; see [docs/ETHICS.md](docs/ETHICS.md).

`internal/config` and `internal/webui` are deliberately not part of the public API — they're the CLI's config-file format and embedded web-app bundle.

## Caveats

- **DNS results aren't universal.** GeoDNS, anycast, ECS, and CDN load-balancing all mean different resolvers (and different clients) legitimately get different IPs for the same hostname. `netcheck dns` makes that visible — disagreement isn't an error.
- **Traceroute is heuristic.** Routers can drop, rate-limit, or reorder ICMP/UDP probes. A missing hop doesn't always mean a broken route, and the path for TCP traffic may differ from what traceroute shows.
- **Browser behavior may differ.** netcheck doesn't use HSTS cache, HTTP/3, cookies, browser extensions, or VPN settings. It tells you what a fresh `curl` would see, not what your Chrome will do.
- **macOS `/etc/resolv.conf`** points at internal loopback resolvers; `netcheck dns` uses just the first one for table readability.

## Stability

`v1.0.0` commits to backward compatibility for the entire `v1.x` series: CLI flags, exit codes, JSON schema, and config file keys are frozen. See [STABILITY.md](STABILITY.md) for the full contract.

If you're using netcheck in a script, pin the major version (`v1.x.y`) and `--output json` against the schema version in the output.

## Contributing

PRs welcome. The codebase is small (~3000 lines), unit-tested where the logic isn't network-bound, and uses `make verify` / `make coverage` for local checks. CI runs `gofmt`, `go vet`, `staticcheck`, `go test -race`, and a cross-platform build matrix on every PR.

```bash
make verify     # gofmt + vet + build + version
make coverage   # tests with per-function coverage summary
make app        # rebuild the React/PWA assets and run the local web app
```

The released binary already embeds the web assets. Building the app UI from
source also needs Node.js/npm for the frontend under `web/`.

See [docs/netcheck_tool_project_plan.md](docs/netcheck_tool_project_plan.md) for architecture notes.

## License

MIT — see [LICENSE](LICENSE).

---

<details>
<summary>Roadmap and project history</summary>

The full release history is in [CHANGELOG.md](CHANGELOG.md). Architecture notes and feature plans live in [docs/netcheck_tool_project_plan.md](docs/netcheck_tool_project_plan.md).

| Version | Status | Highlights |
|---|---|---|
| v0.1 | shipped | URL parsing, DNS, TCP, TLS, HTTP, redirects, httptrace timing |
| v0.2 | shipped | DNS resolver compare across A/AAAA/CNAME/MX/TXT/NS/SOA |
| v0.3 | shipped | Traceroute wrapper with per-hop ASN annotation |
| v0.3.1 | shipped | Interactive menu mode |
| v0.4 | shipped | IP info command with RDAP and CDN detection |
| v0.4.1–0.4.2 | shipped | Roadmap snapshot + `cmd/` + `internal/` refactor |
| v0.5 | shipped | `--output json\|markdown\|html` on every command |
| v0.6 | shipped | YAML config file + DoT/DoH resolver types |
| v0.6.1 | shipped | Menu offers to save results in any format |
| v0.7 | shipped | Tests, GitHub Actions CI, cross-platform build matrix |
| v0.8 | shipped | `goreleaser` release automation |
| v0.9 | shipped | `config show`, `--out` flag, Windows version-info, staticcheck |
| **v1.0** | **shipped** | **Stability promise** |
| v1.0.1 | shipped | Test coverage 20.8% → 85.4% project-wide; every package above 82%. Run* functions return exit codes; no more direct os.Exit. |
| v1.1.0 | shipped | Local React/PWA workbench via `netcheck app`; same full-check Go engine exposed through the local JSON API. |
| v1.2.0 | shipped | Web app: DNS / Route / IP tabs wired end-to-end, saved-reports CRUD, recent rerun |
| v1.3.x | shipped | Build & release hardening: `make app` leaves `./bin/netcheck`, npm-ci stamp, goreleaser-in-same-workflow as release-please |
| **v1.4.0** | **shipped** | **Pentest-tooling tier (passive + active in one release).** Passive: `subs` (CT logs), `reverse` (PTR / Hackertarget / optional Shodan), `tech` (Wappalyzer-style fingerprinting), `headers` (security-header report card), `arch` (archive.org CDX). Active (gated behind `--i-have-authorization` per [ETHICS.md](docs/ETHICS.md)): `tls` (protocol/cipher matrix), `takeover` (CNAME-takeover detection), `ports` (parallel TCP connect scan), `enum` (HTTP path enumeration). |
| v1.5+ | unscheduled | HTTP/3 / QUIC test, Prometheus exporter, TUI mode, native TCP traceroute, historical comparison, browser-like mode |

</details>
