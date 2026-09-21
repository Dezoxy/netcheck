# netcheck

[![CI](https://github.com/Dezoxy/netcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Dezoxy/netcheck/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Dezoxy/netcheck?sort=semver)](https://github.com/Dezoxy/netcheck/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A single command that explains what actually happens between your machine and
> a URL — DNS, TCP, TLS, HTTP, redirects, timing, IP ownership, CDN, traceroute,
> and resolver disagreements.

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

**macOS via Homebrew** _(coming once the tap is activated — see the
[release runbook](docs/operations/release-and-distribution.md))_:

```bash
brew tap dezoxy/netcheck
brew install netcheck
```

**Windows via Scoop** _(coming once the bucket is activated — same doc)_:

```powershell
scoop bucket add netcheck https://github.com/Dezoxy/scoop-netcheck
scoop install netcheck
```

**Docker / OCI image** — published to GitHub Container Registry on every release:

```bash
# Web workbench on http://127.0.0.1:8787
docker run --rm -p 127.0.0.1:8787:8787 ghcr.io/dezoxy/netcheck

# One-off CLI run
docker run --rm ghcr.io/dezoxy/netcheck dns google.com
```

Tags: `latest`, `<major>.<minor>` (e.g. `2.9`), and the exact version (`2.9.0`).
`linux/amd64` only. The image is `distroless/static:nonroot` wrapped around the
static binary — no shell, no package manager, and **no `traceroute`**, so
`netcheck route` is the one command that doesn't work in the container (see
[Caveats](#caveats)). The default command binds `0.0.0.0:8787` because a
container-local loopback bind would be unreachable; publish it to `127.0.0.1` as
above unless you actually want it on the LAN.

**Pre-built binary** — download the archive for your platform from the [latest
release](https://github.com/Dezoxy/netcheck/releases/latest), or curl one-liner
(set `V` to the release you want):

```bash
V=2.9.0

# macOS Apple Silicon
curl -L https://github.com/Dezoxy/netcheck/releases/download/v$V/netcheck_${V}_darwin_arm64.tar.gz | tar xz
sudo mv netcheck /usr/local/bin/

# Linux amd64 (Homebrew Cask is macOS-only — Linux users use this path)
curl -L https://github.com/Dezoxy/netcheck/releases/download/v$V/netcheck_${V}_linux_amd64.tar.gz | tar xz
sudo mv netcheck /usr/local/bin/

# Windows: download netcheck_${V}_windows_amd64.zip, unzip, run netcheck.exe
```

Available platforms: `linux_amd64`, `linux_arm64`, `darwin_amd64`,
`darwin_arm64`, `windows_amd64`, `windows_arm64`. Each archive bundles
`README.md`, `LICENSE`, and `config.example.yaml`. SHA256s in `checksums.txt`.

**From source** (requires Go 1.25+ — the `go` directive in [go.mod](go.mod) is
the source of truth):

```bash
git clone https://github.com/Dezoxy/netcheck.git
cd netcheck
make build      # → ./bin/netcheck
make install    # → $GOBIN (usually ~/go/bin)
```

### Shell completions (optional)

`netcheck completion <shell>` prints a completion script to stdout. Pipe it into
the right place for your shell:

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

Completes subcommand names and a few flag values
(`--output text|json|markdown|html`). Open a new shell after installing.

## What it does

netcheck has fifteen checks, an interactive terminal menu, and a local web
workbench that drives every one of them. Run the checks from a terminal; pipe
the output through `jq`; run `netcheck` with no arguments to get the menu; or
start `netcheck app` for the browser UI.

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
| `netcheck whois <domain>` | Who's the sponsoring registrar? RDAP first, classic port-43 WHOIS as fallback, manual-lookup URL when neither publishes it. |
| `netcheck tls <host>` | Full TLS audit: protocol matrix, cipher suites, cert chain, expiry. *Active — requires `--i-have-authorization`.* |
| `netcheck takeover <domain>` | Is this domain's CNAME pointing at an unclaimed third-party service? *Active — requires `--i-have-authorization`.* |
| `netcheck ports <host>` | Parallel TCP connect scan (top-100 by default) with banner grabbing, plus an optional service-aware UDP pass. *Active — requires `--i-have-authorization`.* |
| `netcheck enum <url>` | HTTP path enumeration against a wordlist. *Active — requires `--i-have-authorization`.* |
| `netcheck audit <target>` | Run the passive suite in parallel and emit one consolidated report. `--active` adds tls + takeover + ports + enum. |
| `netcheck diff <a.json> <b.json>` | What changed between two saved JSON reports? Exits 1 on changes, 0 if identical. |
| `netcheck watch -- <cmd> ...` | Re-run a sub-command on an interval and print the diff between iterations. |
| `netcheck menu` | Interactive picker for any of the above. Offers to save results after each run. |
| `netcheck app` | Local web workbench — every check above, from the same Go engine, in a browser. |
| `netcheck config show` | What config is netcheck actually using right now? |

Every command accepts `--output text|json|markdown|html` (or `-j` for json) and
`--out <file>` (or `-o`; `-` means stdout). Text output is written for humans
and its exact wording and spacing can shift between releases — if you're
parsing, use `--output json`: the JSON schema is versioned
(`"netcheck_version"`, currently `1.0.0`) and stable per
[STABILITY.md](STABILITY.md). Upgrading from v1? See
[MIGRATING.md](MIGRATING.md) — two JSON field renames + a Go import-path change.

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

Open `http://127.0.0.1:8787/` for the React/PWA workbench. The assets are
embedded in the Go binary (`go:embed`) — there's nothing to install and nothing
phones home. It calls the same engines the CLI does, over a local JSON API.

What's in it:

- **All fifteen checks**, grouped as Network / Passive recon / Active scanning
  / Aggregate. The active four sit behind an in-UI authorization checkbox that
  mirrors `--i-have-authorization`.
- **Live port-scan progress** — the ports scan streams over SSE
  (`/api/check/ports/stream`) instead of blocking until the last port answers.
- **Saved reports** — save, list, reload, delete, and diff two saved runs.
  Stored as JSON under `~/.config/netcheck/saved-reports/` (or
  `$XDG_DATA_HOME/netcheck/saved-reports/`).
- **HUD surfaces** — Cmd/Ctrl-K command palette, a live event stream, a
  telemetry strip (events/sec + mean latency over a 60s window), and a Target
  Topography view rendered from the last traceroute.

The API is documented in [STABILITY.md](STABILITY.md#web-app-http-api-netcheck-app)
and is stable for `v2.x` — the HTML/CSS/JS assets are not (filenames change every
build).

### Compare DNS resolvers

```bash
netcheck dns google.com
netcheck dns --type MX,TXT cloudflare.com
netcheck dns --dnssec cloudflare.com                                       # DO bit + DNSKEY/DS/RRSIG/NSEC
netcheck dns --resolver tls://1.1.1.1 cloudflare.com                       # DoT
netcheck dns --resolver doh://dns.google/dns-query cloudflare.com          # DoH
netcheck dns --no-defaults --resolver 1.0.0.1 google.com                   # pinned single resolver
```

Record types come in three tiers. Without `--type`, netcheck scans tier 1 —
`A, AAAA, CNAME, NS, MX, TXT, SOA, CAA` — the broadly useful, low-noise set.
Tier 2 (`SRV, PTR, NAPTR, HINFO, HTTPS, SVCB, SPF`) is situational, and tier 3
(`DNSKEY, DS, RRSIG, NSEC, NSEC3, CDS, CDNSKEY`) is what `--dnssec` turns on
along with the DO bit. Any of them can be requested explicitly via `--type`.
`--dnssec` fetches DNSSEC records so you can see them; it does **not** validate
the chain of trust.

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
evidence that triggered it. Catalogue grows over time — the JSON *envelope* is
stable per [STABILITY.md](STABILITY.md), but the set of detected names isn't.

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

### Registrar lookup

```bash
netcheck whois example.com
netcheck whois -j example.com | jq '.registrar, .source'
```

Answers one question — who sponsors this domain — and answers it three ways in
descending order of quality. RDAP first (structured, gives registrar name, IANA
ID, and URL). If the TLD's RDAP service exposes no registrar, it falls back to a
classic port-43 WHOIS query for the name. If neither publishes it (`.hu` and
other GDPR-stripped ccTLDs), the report says "not found" and hands you the
registry's manual web-whois URL. The `source` field tells you which path
answered. Passive — netcheck never touches the domain itself.

### Active scanning

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

# TCP port scan (default: top-100 nmap-style ports, 50-way concurrent,
# best-effort banner grab on whatever answers).
netcheck ports --i-have-authorization scanme.nmap.org
netcheck ports --i-have-authorization --ports 22,80,443,8000-8010 host.example.com

# UDP too (service-aware probes, top-50 UDP ports, no root needed).
netcheck ports --i-have-authorization --udp host.example.com
netcheck ports --i-have-authorization --udp-only --udp-ports 53,123,161 host.example.com

# HTTP path enumeration (~70-entry builtin wordlist, or --wordlist file).
netcheck enum --i-have-authorization https://target.example.com
netcheck enum --i-have-authorization --wordlist /path/to/SecLists/Discovery/Web-Content/common.txt https://target.example.com
```

Once you've thought about it, `export NETCHECK_AUTHORIZED=1` for the session
instead of typing `--i-have-authorization` on every call.

### Aggregate audit

```bash
# Passive suite in parallel: ip + headers + tech + subs + arch.
netcheck audit example.com

# Everything, including the active tier (tls + takeover + ports + enum).
netcheck audit --active --i-have-authorization example.com

netcheck audit -j example.com | jq '.errors'
```

One target, one consolidated report, every sub-check running concurrently. IP
targets fall back to `ip + reverse` (the rest need a hostname). Sub-checks fail
independently — a flaking crt.sh doesn't sink the run; the failure lands in
`errors` keyed by sub-command and everything else still reports. `--active` is
gated on `--i-have-authorization` exactly like the individual active commands.

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

The `-j` / `-o` shortcuts are equivalent to `--output json` / `--out`. The long
forms still work; the short forms exist to keep one-liners terse.

> Flags come before the positional argument: `netcheck dns -j cloudflare.com`,
> not `netcheck dns cloudflare.com -j`.

## Config file

Optional YAML at `~/.config/netcheck/config.yaml`. Every key is optional —
missing files and missing keys fall back to compiled-in defaults.

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

**Search order:** `--config <path>` flag → `NETCHECK_CONFIG` env →
`$XDG_CONFIG_HOME/netcheck/config.yaml` → `~/.config/netcheck/config.yaml`.

**Env overrides:** `NETCHECK_TIMEOUT` and `NETCHECK_USER_AGENT` win over the
file when set — handy for CI/ops.

Run `netcheck config show` to see what's actually loaded. See
[config.example.yaml](config.example.yaml) for the full schema.

## Use as a library

Every check engine lives under `netcheck/pkg/` and is importable from your own
Go programs. The JSON schema types in `pkg/report` are the same ones the CLI
emits — the wire format is the contract.

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
| `pkg/ipinfo` | RDAP (IP + domain), port-43 WHOIS, reverse DNS, CDN classification |
| `pkg/secheaders`, `pkg/techdetect`, `pkg/subenum`, `pkg/reverseip`, `pkg/wayback` | Passive recon engines |
| `pkg/eventbus`, `pkg/telemetry` | In-process pub/sub + derived metrics behind the web app's live event stream, telemetry strip, and topology view |
| `pkg/tlsaudit`, `pkg/takeover`, `pkg/portscan`, `pkg/pathenum` | Active scanning engines |
| `pkg/report` | Versioned JSON schemas + text/Markdown/HTML renderers |
| `pkg/diff` | Structured diff between two saved reports |
| `pkg/target` | URL / host normalization |

Stability: exported names are stable across `v2.x`. Catalogue-style packages
(`pkg/techdetect`, `pkg/secheaders`) keep stable result *shapes*, but the set of
detections they emit grows over time — don't pin tests to "exactly these
matches." Active-scanning packages still require the same `i_have_authorization`
boundary as the CLI; see [docs/ETHICS.md](docs/ETHICS.md).

`internal/config` and `internal/webui` are deliberately not part of the public
API — they're the CLI's config-file format and embedded web-app bundle.

## Caveats

- **DNS results aren't universal.** GeoDNS, anycast, ECS, and CDN load-balancing
  all mean different resolvers (and different clients) legitimately get
  different IPs for the same hostname. `netcheck dns` makes that visible —
  disagreement isn't an error.
- **Traceroute is heuristic.** Routers can drop, rate-limit, or reorder ICMP/UDP
  probes. A missing hop doesn't always mean a broken route, and the path for TCP
  traffic may differ from what traceroute shows.
- **Browser behavior may differ.** netcheck doesn't use HSTS cache, HTTP/3,
  cookies, browser extensions, or VPN settings. It tells you what a fresh `curl`
  would see, not what your Chrome will do.
- **macOS `/etc/resolv.conf`** points at internal loopback resolvers;
  `netcheck dns` uses just the first one for table readability.
- **`netcheck route` shells out.** It wraps the system `traceroute` (`tracert`
  on Windows) and parses its output, so it needs that binary on `PATH` — it
  exits 2 if there isn't one. That's also why `route` is the one command the
  container image can't run.

## Stability

`v2.0.0` commits to backward compatibility for the entire `v2.x` series: CLI
flags, exit codes, JSON schema, config file keys, **and the public `pkg/` Go
API** are frozen. See [STABILITY.md](STABILITY.md) for the full contract.

If you're using netcheck in a script, pin the major version (`v2.x.y`) and
`--output json` against the schema version (`"netcheck_version": "1.0.0"`) in
the output. Migrating from v1.x? See [MIGRATING.md](MIGRATING.md) — the breakage
is contained to two JSON field renames and a Go import-path change.

## Contributing

PRs welcome. Roughly 35k lines of Go (plus the React front-end under `web/`),
unit-tested wherever the logic isn't network-bound, with `make verify` /
`make coverage` for local checks. CI runs `golangci-lint`, `go test -race` with
a coverage summary, an ESLint + Prettier + `tsc` + Vite pass over `web/`, and a
cross-platform build matrix on every PR; a weekly Trivy scan covers vulns,
secrets, and config.

```bash
make verify     # gofmt + vet + build + version
make coverage   # tests with per-function coverage summary
make app        # rebuild the React/PWA assets and run the local web app
```

The released binary already embeds the web assets. Building the app UI from
source also needs Node.js/npm for the frontend under `web/`.

Commit messages follow [conventional
commits](https://www.conventionalcommits.org/) — release-please reads them to
pick the next version and write the changelog. Local git hooks (lefthook) run
the same linters CI does; setup is in [CONTRIBUTING.md](CONTRIBUTING.md).
All other documentation is indexed in [docs/README.md](docs/README.md).

## License

MIT — see [LICENSE](LICENSE).

---

<details>
<summary>Roadmap and project history</summary>

The full release history is in [CHANGELOG.md](CHANGELOG.md). The original
project plan is archived in
[docs/history/](docs/history/2026-05-project-plan.md).

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
| v1.5.0 | shipped | The nine v1.4 commands wired into the React workbench |
| v1.6.0 | shipped | `netcheck audit` aggregate command; Homebrew Cask + Scoop scaffolding (still `skip_upload`) |
| v1.7.0 | shipped | Audit mode in the web workbench |
| v1.8.0 | shipped | Shell completions (bash/zsh/fish/powershell); banner grab on open ports |
| v1.9.0 | shipped | `netcheck diff` + `netcheck watch` — history mode |
| v1.10.0 | shipped | SSE streaming for the ports scan (live progress in the web UI) |
| **v2.0.0** | **shipped** | **Public `pkg/` API, module path → `github.com/Dezoxy/netcheck`, JSON field normalization, `-j`/`-o` shortcuts. See [MIGRATING.md](MIGRATING.md).** |
| v2.1–v2.2 | shipped | Web UI redesign; UDP port scan (service-aware, privilege-free) |
| v2.3–v2.5 | shipped | DNS record-type tiers + DNSSEC inspection; report error boundary; non-null JSON slices |
| v2.6 | shipped | HUD redesign: Tailwind v4 tokens, side nav, Cmd/Ctrl-K palette, live event stream, telemetry strip, target topography |
| v2.7–v2.8 | shipped | `netcheck whois` — RDAP registrar lookup with port-43 WHOIS and manual-lookup fallbacks |
| v2.9.0 | shipped | Container image published to `ghcr.io/dezoxy/netcheck` on every release |
| unscheduled | — | HTTP/3 / QUIC test, Prometheus exporter, TUI mode, native TCP traceroute, browser-like mode |

</details>
