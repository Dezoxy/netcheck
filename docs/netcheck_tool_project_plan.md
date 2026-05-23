# NetCheck / WebPath Project Plan

## 1. Project Goal

Build a CLI tool that analyzes a website or domain and explains what happens between your machine and the target.

Example usage:

```bash
netcheck google.com
netcheck https://facebook.com
netcheck dns google.com
netcheck route google.com
```

The tool should help answer questions like:

- Does DNS resolution work?
- Which IP addresses are returned?
- Does IPv4 work?
- Does IPv6 work?
- Can I connect to port 80 or 443?
- Is the TLS certificate valid?
- What HTTP status do I get?
- Is there a redirect?
- Which CDN or ASN owns the IP?
- What route does traffic take from my machine?
- Are different DNS resolvers returning different results?

---

## 2. Recommended Language

## Primary choice: Go

Go is the best fit for this project because:

| Reason | Why it matters |
|---|---|
| Single binary | Easy to run on macOS, Linux, Proxmox, and servers |
| Strong networking support | DNS, TCP, HTTP, and TLS are well-supported |
| Fast startup | Good for CLI tools |
| Cross-platform | Can build for macOS, Linux, and Windows |
| DevOps-friendly | Many major infrastructure tools are written in Go |
| Easy deployment | No virtual environment or dependency mess |

Recommended approach:

```text
Use Go from the beginning.
```

Python would be faster for a throwaway prototype, but Go is better for a serious CLI tool.

---

## 3. Project Name Ideas

| Name | Feeling |
|---|---|
| `netcheck` | Simple and clear |
| `webpath` | Shows the path from your machine to the website |
| `routepeek` | Focuses on routing visibility |
| `dnspath` | DNS-focused |
| `linktrace` | Good for tracing links and routes |
| `packetstory` | Fun, but less professional |

Recommended name:

```text
netcheck
```

Alternative favorite:

```text
webpath
```

---

## 4. MVP Scope

The first version should stay small and useful.

Command:

```bash
netcheck google.com
```

MVP checks:

1. Parse the target.
2. Normalize the URL.
3. Resolve DNS records.
4. Show A records.
5. Show AAAA records.
6. Test TCP connection to port 443.
7. Check TLS certificate.
8. Perform HTTP request.
9. Follow redirects.
10. Show basic timing summary.

MVP should not include native traceroute yet.

Reason:

```text
DNS + TCP + TLS + HTTP already gives a very useful first version.
```

---

## 5. Example MVP Output

```text
NETCHECK REPORT
Target: https://google.com
Time: 2026-05-19 19:12

DNS
✓ A     142.250.184.206
✓ AAAA  2a00:1450:400d:80e::200e
DNS lookup time: 14ms

TCP
✓ 142.250.184.206:443 reachable
TCP connect time: 21ms

TLS
✓ Certificate valid
Issuer: Google Trust Services
Expires: 2026-08-12
Days remaining: 85

HTTP
✓ Status: 301 Moved Permanently
Final URL: https://www.google.com/
Redirects: 1
Server: gws

Summary
✓ DNS works
✓ TCP works
✓ TLS works
✓ HTTP works
```

---

## 6. Feature Roadmap

## Phase 1 — Basic URL Analyzer

Command:

```bash
netcheck https://example.com
```

Features:

| Feature | Description |
|---|---|
| URL parsing | Detect scheme, hostname, and port |
| DNS lookup | Resolve A and AAAA records |
| TCP check | Test connection to port 80 or 443 |
| TLS check | Certificate issuer, expiry, validity, SANs |
| HTTP request | Status code, headers, redirects |
| Timing | DNS, TCP, TLS, and HTTP duration |

Goal:

```text
Create a working tool that can diagnose basic website reachability.
```

---

## Phase 2 — DNS Deep Test

Command:

```bash
netcheck dns google.com
```

Features:

| Feature | Description |
|---|---|
| System resolver test | Use the OS default resolver |
| Cloudflare resolver | Test 1.1.1.1 |
| Google resolver | Test 8.8.8.8 |
| Quad9 resolver | Test 9.9.9.9 |
| Custom resolver | Allow user-defined DNS servers |
| Record types | A, AAAA, CNAME, MX, TXT, NS, SOA |
| Result comparison | Show differences between resolvers |
| DNS timing | Measure resolver response time |

Example output:

```text
Resolver       A Record            Time
System         142.250.184.206     18ms
Cloudflare     142.250.184.206     12ms
Google         142.250.184.206     21ms
Quad9          142.250.184.206     24ms
```

Goal:

```text
Make DNS behavior visible and comparable.
```

---

## Phase 3 — Route / Traceroute

Command:

```bash
netcheck route google.com
```

Initial implementation:

```text
Call the system traceroute command.
```

Platform mapping:

| Platform | Command |
|---|---|
| macOS | `traceroute` |
| Linux | `traceroute` or `tracepath` |
| Windows | `tracert` |

Important note:

```text
Traceroute output is not always reliable because routers may block or deprioritize ICMP/UDP packets.
```

Goal:

```text
Show the approximate network path without overengineering native traceroute too early.
```

Later improvement:

```text
Implement native TCP traceroute in Go.
```

---

## Phase 4 — ASN / IP Ownership

Status: shipped in v0.4.

Command:

```bash
netcheck ip 142.250.184.206
```

Features:

| Feature | Description |
|---|---|
| ASN lookup | Show autonomous system number |
| Organization | Show network owner |
| Country | Show registered country |
| Prefix | Show IP network range |
| CDN detection | Identify Cloudflare, Google, Meta, Akamai, Fastly, etc. |

Example output:

```text
IP: 142.250.184.206
ASN: AS15169
Org: Google LLC
Country: US
Network: 142.250.0.0/15
```

Possible sources:

| Source | Notes |
|---|---|
| Team Cymru DNS | Good for ASN lookup |
| RDAP | Modern replacement for whois |
| ipinfo.io | Easy, but API-limited |
| PeeringDB | More advanced network info |

Recommended start:

```text
Use Team Cymru DNS + RDAP.
```

---

## Phase 5 — Report Export

Commands:

```bash
netcheck google.com --json
netcheck google.com --markdown
netcheck google.com --html
```

Formats:

| Format | Use case |
|---|---|
| Human text | Normal CLI usage |
| JSON | Automation and scripting |
| Markdown | Documentation and notes |
| HTML | Shareable report |
| Prometheus metrics | Future monitoring integration |

Goal:

```text
Make the tool useful both for humans and automation.
```

---

## 7. Command Design

Recommended commands:

```bash
netcheck google.com
netcheck full google.com
netcheck dns google.com
netcheck http https://google.com
netcheck tls google.com
netcheck route google.com
netcheck ip 142.250.184.206
```

Future commands:

```bash
netcheck compare google.com facebook.com
netcheck monitor google.com --every 30s
netcheck export google.com --format markdown
netcheck doh google.com --resolver cloudflare
netcheck dot google.com --resolver cloudflare
```

Default behavior:

```bash
netcheck google.com
```

Should run a smart full check that is useful but not too slow.

---

## 8. Repository Structure

### Current layout

Split into `cmd/` (CLI and local app surface), `internal/` (reusable check
primitives and embedded app assets), and `web/` (React/PWA source). Each
`internal/` subpackage has a single responsibility and earns its own test file.

```text
netcheck/
├── main.go                          # entry — calls cmd.Run()
├── cmd/                             # package cmd — CLI surface
│   ├── root.go                      # usage, version, dispatch
│   ├── full.go                      # `netcheck <target>` (full check)
│   ├── app.go                       # `netcheck app` local HTTP API + asset server
│   ├── dns.go                       # `netcheck dns`
│   ├── route.go                     # `netcheck route`
│   ├── ip.go                        # `netcheck ip`
│   └── menu.go                      # `netcheck menu`
├── internal/
│   ├── target/                      # URL/host normalization
│   │   ├── target.go                # parseTarget
│   │   ├── normalize.go             # normalizeHost
│   │   └── *_test.go
│   ├── check/                       # full-check primitives
│   │   ├── dns.go                   # lookupDNS, DNSResult
│   │   ├── tcp.go                   # checkTCP, TCPResult
│   │   ├── tls.go                   # checkTLS, TLSResult
│   │   ├── http.go                  # checkHTTP, HTTPResult
│   │   └── *_test.go
│   ├── dnscompare/                  # multi-resolver compare
│   │   ├── compare.go
│   │   ├── resolvers.go
│   │   └── *_test.go
│   ├── route/                       # traceroute wrapper + parser
│   │   ├── route.go
│   │   ├── parser.go
│   │   └── *_test.go
│   ├── ipinfo/                      # IP enrichment
│   │   ├── ipinfo.go                # orchestration
│   │   ├── asn.go                   # Team Cymru DNS
│   │   ├── rdap.go                  # RDAP HTTP
│   │   ├── cdn.go                   # static CDN classification
│   │   └── *_test.go
│   ├── report/                      # rendering
│   │   ├── text.go                  # v0.4: human output
│   │   ├── json.go                  # v0.5
│   │   ├── markdown.go              # v0.5
│   │   ├── html.go                  # v0.5
│   │   └── *_test.go
│   ├── config/                      # v0.6
│   │   ├── config.go
│   │   └── *_test.go
│   └── webui/                       # embedded React/PWA production assets
│       ├── assets.go
│       └── dist/
├── web/                             # React/PWA app source, Vite build
│   ├── src/
│   └── public/
├── testdata/                        # parser fixtures, RDAP/Cymru samples
├── bin/                             # build output (gitignored)
├── .github/workflows/               # v0.7 (CI) + v0.8 (release)
│   ├── ci.yml
│   └── release.yml
├── Makefile
├── go.mod, go.sum
├── README.md
├── config.example.yaml              # v0.6
└── docs/netcheck_tool_project_plan.md
```

### Why this layout

| Path | Purpose |
|---|---|
| `cmd/` | Thin CLI command definitions — flag parsing, output dispatch. No check logic. |
| `internal/target/` | URL parsing and host normalization. Used by every command. |
| `internal/check/` | The four check primitives behind the `full` command (DNS, TCP, TLS, HTTP). |
| `internal/dnscompare/` | Multi-resolver DNS comparison engine and verdict. |
| `internal/route/` | Traceroute exec + output parser; platform-aware. |
| `internal/ipinfo/` | ASN (Cymru), RDAP, CDN classification. Reusable as a library. |
| `internal/report/` | All output formats — keeps text/JSON/MD/HTML in one place. |
| `internal/config/` | Config-file loading and env-var overrides (v0.6). |
| `internal/webui/` | Production web assets embedded into the Go binary. |
| `web/` | React/PWA source for the local browser workbench. |
| `testdata/` | Fixtures for parser tests (traceroute output, RDAP JSON, Cymru TXT). |
| `.github/workflows/` | CI (v0.7) and release automation (v0.8). |

`internal/` is enforced by Go itself — external code cannot import it, so we keep freedom to refactor the check primitives without breaking anyone.

---

## 9. Recommended Go Libraries

| Purpose | Library |
|---|---|
| CLI framework | `github.com/spf13/cobra` |
| DNS queries | `github.com/miekg/dns` |
| Config handling | `github.com/spf13/viper` |
| Tables | `github.com/olekukonko/tablewriter` |
| Colors | `github.com/fatih/color` |
| HTTP | Go standard library |
| TLS | Go standard library |
| JSON | Go standard library |
| OS commands | Go standard library |

Keep dependencies limited in the MVP.

MVP dependency recommendation:

```text
cobra only
```

Then add `miekg/dns` when building the DNS deep-test phase.

---

## 10. Config Design

Config file path:

```bash
~/.config/netcheck/config.yaml
```

Example config:

```yaml
resolvers:
  - name: cloudflare
    address: 1.1.1.1
  - name: google
    address: 8.8.8.8
  - name: quad9
    address: 9.9.9.9

timeout: 5s
user_agent: netcheck/0.1
follow_redirects: true
max_redirects: 10
prefer_ipv6: false
```

---

## 11. Important Technical Considerations

## DNS results are not universal

DNS can return different IPs depending on:

- Your location
- Your ISP
- Your DNS resolver
- IPv4 vs IPv6
- Anycast routing
- CDN load balancing
- DNS ECS behavior

The tool should avoid saying:

```text
This is the real IP.
```

Better wording:

```text
These are the IPs returned by this resolver at this time.
```

---

## Traceroute can be misleading

Some routers:

- Block ICMP
- Rate-limit traceroute packets
- Hide internal hops
- Return no response
- Route differently for TCP/UDP/ICMP

The tool should explain:

```text
A missing hop does not always mean a broken route.
```

---

## Browser behavior may differ from CLI behavior

Browsers can use:

- Cookies
- HSTS cache
- HTTP/3
- QUIC
- Extensions
- Proxy settings
- VPN settings
- Apple Private Relay
- DNS-over-HTTPS
- Cached DNS

The CLI result may not perfectly match Chrome or Safari.

Future feature:

```bash
netcheck browser-like google.com
```

---

## IPv6 should be first-class

The tool should clearly show:

```text
IPv4 DNS: available
IPv6 DNS: available
IPv4 TCP: OK
IPv6 TCP: failed
```

This is useful for debugging mobile networks, home ISPs, Cloudflare, and VPN setups.

---

## DNS-over-HTTPS and DNS-over-TLS

Future commands:

```bash
netcheck doh google.com --resolver cloudflare
netcheck dot google.com --resolver cloudflare
```

Useful resolver types:

| Type | Example |
|---|---|
| Classic DNS UDP | `1.1.1.1:53` |
| DNS over TCP | `1.1.1.1:53` |
| DNS over TLS | `1.1.1.1:853` |
| DNS over HTTPS | `https://cloudflare-dns.com/dns-query` |
| NextDNS DoH | User-specific NextDNS endpoint |

---

## 12. Error Handling Strategy

The tool should explain failures in plain language.

Examples:

```text
DNS lookup failed.
Possible reasons:
- Domain does not exist
- DNS resolver is unreachable
- Network is offline
- DNS filtering blocked the domain
```

```text
TCP connection failed.
Possible reasons:
- Server is down
- Port is blocked
- Firewall is blocking traffic
- IPv6 route is broken
```

```text
TLS check failed.
Possible reasons:
- Certificate expired
- Hostname mismatch
- Self-signed certificate
- TLS interception
```

---

## 13. Testing Plan

## Unit tests

Test these components:

- URL parser
- Port detection
- Output formatting
- Config loading
- DNS response parsing
- HTTP redirect handling
- TLS certificate parsing

## Integration tests

Use known stable targets:

```text
example.com
cloudflare.com
google.com
```

Use failure cases:

```text
nonexistent.invalid
expired.badssl.com
self-signed.badssl.com
wrong.host.badssl.com
```

## Manual tests

Test from:

- Home network
- Mobile hotspot
- VPN on
- VPN off
- IPv6 enabled
- IPv6 disabled
- Cloudflare DNS
- NextDNS
- ISP DNS

---

## 14. Security and Privacy Considerations

The tool should not send unnecessary data anywhere.

Important choices:

| Area | Recommendation |
|---|---|
| Telemetry | No telemetry by default |
| API keys | Optional only |
| Config | Store locally |
| Reports | Generated locally |
| Logs | Avoid storing queried domains unless user asks |
| DNS tests | Be clear when using external resolvers |

---

## 15. Nice Future Features

| Feature | Why it is useful |
|---|---|
| HTTP/3 / QUIC test | Browser-like modern web debugging |
| Proxy test | Compare direct vs proxy route |
| VPN detection | Show if traffic exits through VPN |
| Cloudflare detection | Useful for CDN troubleshooting |
| NextDNS profile test | Useful for your DNS setup |
| Prometheus exporter | Homelab monitoring |
| Web app modes beyond full check | Visual DNS compare, route, and IP inspection |
| TUI mode | Pretty terminal dashboard |
| Historical comparison | Compare today vs yesterday |
| Screenshot report | Shareable diagnostic report |

---

## 16. Suggested Version Plan

## v0.1 — MVP (shipped)

- URL parsing
- DNS A/AAAA lookup with system resolver
- TCP connection test
- TLS certificate check
- HTTP status and redirects
- Basic timing summary
- Human-readable CLI output

## v0.2 — DNS Compare (shipped)

- Multiple resolver support
- Cloudflare, Google, Quad9 presets
- A/AAAA/CNAME/MX/TXT/NS/SOA records
- DNS timing table and verdict

## v0.3 — Route (shipped)

- System traceroute wrapper (macOS/Linux `traceroute`, Windows `tracert`)
- Platform detection and flag mapping
- Streamed hop parsing with multi-probe RTTs
- Per-hop Team Cymru ASN annotation (skipped on private/link-local IPs)
- Warning when hops time out

## v0.3.1 — Menu (shipped)

- Interactive menu (`netcheck menu` or bare `netcheck` on a TTY)
- Input normalization (scheme/path/query/port/quote stripping)
- Build output moved to `./bin/`

## v0.4 — IP Info (shipped)

- `netcheck ip <ip|host>` subcommand
- Team Cymru ASN lookup (extended from route)
- RDAP query via `rdap.org` bootstrap (org, abuse contact, registry, prefix)
- Static CDN classification (ASN map + PTR suffix patterns) with confidence
- DNS section of `full` check now shows per-IP ASN + CDN hint
- First unit tests (cdn, rdap, ip)

## v0.4.1 — Planning update

- Project plan updated with locked v0.4 → v1.0 rollout
- Folder structure (section 8) updated to reflect v0.4 file inventory and target layout
- Docs only — no code changes
- Version constant bumped so the planning snapshot has a git tag

## v0.4.2 — Folder structure refactor

- Move source from flat root into `cmd/` + `internal/` per section 8
- Split `checks.go` into `internal/check/{dns,tcp,tls,http}.go`
- Promote `parseTarget` / `normalizeHost` into `internal/target/`
- Split `report.go` so v0.5 can drop in `json.go` / `markdown.go` / `html.go` cleanly
- Keep CLI surface unchanged — refactor is internal-only
- Add `testdata/` for parser fixtures

## v0.5 — Export (shipped)

- `--output text|json|markdown|html` on all four commands (default `text`)
- Versioned JSON schema with `netcheck_version` + `kind` discriminator (`"full"`, `"dns"`, `"route"`, `"ip"`)
- Markdown renders with GitHub-flavored tables and inline code spans
- HTML is single-file self-contained with inline CSS (no external requests)
- Conversion functions live in `internal/report/jsonschema.go` so internal
  types can evolve without breaking the wire schema
- Text format is unchanged from earlier versions — existing automation that
  reads stdout keeps working
- Menu still uses text only; "export last result to file" deferred to v0.5.1
- Skipped (separate features later): YAML, Prometheus metrics

## v0.6 — Config file + DoH/DoT (shipped)

- `~/.config/netcheck/config.yaml` per section 10
- Override-able defaults: `timeout`, `user_agent`, `follow_redirects`, `max_redirects`, `prefer_ipv6`, `resolvers`
- Env vars: `NETCHECK_CONFIG`, `NETCHECK_TIMEOUT`, `NETCHECK_USER_AGENT` (the last two override config-file values)
- `--config /path/to/file` flag on every subcommand for ad-hoc overrides
- Resolver types delivered as `--resolver` URL syntax (`udp://`, `tcp://`, `tls://`, `dot://`, `https://`, `doh://`) rather than separate `netcheck doh`/`netcheck dot` subcommands — fewer commands, same functionality
- DoT via miekg/dns `tcp-tls` net; DoH via RFC 8484 wire-format POST
- Config-defined resolvers added to every `netcheck dns` run; `--no-config-resolvers` skips them
- User-Agent now consistently applied across both check.HTTP (was hardcoded `netcheck/0.1` before) and ipinfo.RDAP
- `config.example.yaml` ships in repo
- New dependency: `gopkg.in/yaml.v3` (BSD-licensed, small)

## v0.7 — Tests + CI (shipped)

- Unit tests: `target.Parse` / `target.NormalizeHost` (87.8% coverage), `route.ParseHopLine` (35%), `dnscompare.Verdict` (27.3%), `cmd.ParseFormat`
- GitHub Actions workflow at `.github/workflows/ci.yml` running on push and PR:
  - `gofmt -l` check (fails if any file needs formatting)
  - `go vet ./...`
  - `go test -race -coverprofile=coverage.out ./...`
  - Coverage summary printed in the run log
- Cross-platform build matrix: linux/darwin/windows × amd64/arm64 (6 combinations)
- README status badge linked to the CI workflow
- `make coverage` target for local runs (writes `coverage.out`, prints per-function summary)
- `staticcheck` / `golangci-lint`: deferred — `gofmt` + `vet` cover the bulk;
  add them in v0.7.1 if specific issues come up in real use

## v0.8 — Release automation (shipped)

- `.goreleaser.yml` builds 6 binaries on every tag push (linux/darwin/windows × amd64/arm64), packs them into `tar.gz`/`zip` archives with `README.md` + `LICENSE` + `config.example.yaml`, and computes a `checksums.txt` (SHA256)
- `.github/workflows/release.yml` runs goreleaser when a `v*` tag is pushed; uploads all artifacts to the matching GitHub release page
- `cmd.Version` switched from `const` to `var` so build-time `-X` ldflags inject the version. Makefile uses `git describe`; goreleaser uses the tag. Local `go build` defaults to `"dev"`
- Auto-generated release notes from commits since the previous tag, with `feat:`/`fix:` grouping and noise filters (merge commits, docs/test/chore commits)
- `LICENSE` file (MIT) added — bundled into every archive
- **Skipped (separate features later):**
  - Homebrew tap — needs a separate repo and ongoing maintenance; defer to v0.8.1
  - Code signing (Windows SmartScreen, macOS Gatekeeper) — requires paid certs; v1.0+ concern
  - SBOM generation — low demand for a CLI utility; goreleaser can add later via plugins

## v0.9 — Release candidate (shipped)

Polish pass to prepare for the v1.0 API freeze.

**New commands / flags:**
- `netcheck config show` subcommand — prints active config (source path,
  resolved values, env-resolved User-Agent, configured resolvers). Supports
  `--output text|json|markdown|html` like every other command
- `--out <file>` flag on every command — writes the result to a file with
  auto-created parent directories; "Saved to <abs-path>" to stderr.
  Mirrors the menu's save flow for non-interactive use

**Reliability:**
- Route exit code fix — now returns 1 when no hops were collected at all
  (previously always returned 0). DNS/full/ip already behaved correctly
- `staticcheck` added as a CI step before `go test`. Repo is clean today;
  the gate catches future regressions in patterns staticcheck recognizes
- Windows polish: `winres/winres.json` defines version-info resource;
  goreleaser regenerates `.syso` files (amd64 + arm64) before each release.
  Windows .exe now shows ProductName, FileDescription, FileVersion,
  CompanyName in Task Manager / right-click Properties

**Tests:**
- `cmd/menu_save_test.go` — sanitize, defaultFilename, expandPath, defaultSaveDir
- `cmd/dns_test.go` — `configResolverToDNS` matrix for all 5 type values
- `internal/route/route_test.go` — `BuildArgs` flag mapping per platform,
  `InstallHint` sanity
- `internal/ipinfo/ipinfo_test.go` — NormalizeIP, UniqueIPs, CleanASNOrg,
  NormalizeASN, IsPrivateOrSpecial, DNSInfoSuffix, cymruQueryName
- `internal/ipinfo/rdap_http_test.go` — RDAP HTTP round-trip with httptest
  (`lookupRDAPAt` testable seam)
- `internal/dnscompare/doh_test.go` — DoH RFC 8484 wire-format round-trip
  with httptest, using miekg/dns Pack/Unpack on both sides

**Coverage gains:**
- ipinfo: 38% → 61%
- dnscompare: 27% → 64%
- route: 35% → 44%
- cmd: 2% → 7%

**Deliberately deferred to the v1.0 launch PR itself:**
- asciinema demo — better timing once v1.0 actually ships
- Big README rewrite — happens with v1.0
- /etc/netcheck/config.yaml system-wide path — niche, easy add later

## v1.0 — Stable (shipped)

The "stop adding things and ship what you have" release.

**Stability commitment (documented in `STABILITY.md`):**
- CLI flags, subcommands, and exit codes are frozen for the v1.x series
- JSON schema is versioned (`netcheck_version`) and stable per version
- Config file schema (`~/.config/netcheck/config.yaml`) is stable
- `NETCHECK_*` env vars are stable
- Deprecation policy: removing anything takes one full minor release of warning

**Documentation:**
- `STABILITY.md` — the full backward-compatibility contract
- `CHANGELOG.md` — Keep-a-Changelog format snapshot of v0.1 → v1.0
- `README.md` — rewritten for first-time visitors: stronger pitch, demo above the install section, roadmap moved to a collapsible at the bottom
- Release badge added next to the CI badge

**Deferred (post-v1.0):**
- asciinema cast in README — needs interactive recording; will land in v1.0.1
  with a real terminal capture rather than a synthesized one
- `netcheck.1` man page — defer until someone asks; CLI is well-documented
  via `--help` and the README
- GitHub Pages landing page — over-investment for a CLI; README is enough
- Announcement (HN / r/golang / etc.) — separate from the PR; ship first

## v1.1 — Local web app (shipped)

- `netcheck app` starts a local HTTP workbench on `127.0.0.1:8787` by default
- React/PWA production assets are built from `web/` and embedded in
  `internal/webui/dist/`
- The app API reuses the full-check DNS/TCP/TLS/HTTP pipeline through
  `BuildFullReport`
- Current UI scope: visual full checks, recent checks, JSON export, and
  installable homescreen metadata
- DNS compare, route, and IP info remain CLI-only until their app panels are
  designed and wired

## v1.2 — Web app full wiring (shipped)

- DNS / Route / IP tabs in the React workbench, each backed by its own
  `POST /api/check/{dns,route,ip}` endpoint
- Saved-reports CRUD on `~/.config/netcheck/saved-reports/<id>.json`,
  surfaced as a saved-reports panel in the UI
- "Recent" rerun fixed: clicking a recent entry replays the same target
  with the same options, not just refilling the input

## v1.3.x — Build & release hardening (shipped)

- `make app` leaves `./bin/netcheck` so subsequent runs don't rebuild
- `npm ci` only re-runs when `web/package-lock.json` changes
  (`web/node_modules/.install-stamp` pattern)
- `release-please` + `goreleaser` consolidated into a single workflow
  (`releases_created`-gated downstream job) so binaries reliably attach
  to every release. Manual backfill via `gh workflow run release.yml -f tag=vX.Y.Z`
- `.gitignore` + Makefile guards against macOS Finder / iCloud conflict
  copies leaking into `internal/webui/dist/`

## v1.4 — Passive recon (shipped)

The pentest-tooling direction starts here. Everything in v1.4 is **passive**:
public-data lookups only, no authenticated probes, no active scanning of the
target. No `--i-have-authorization` gate needed — these queries are no
different from typing a hostname into a web search.

| Command | Source(s) | Notes |
|---|---|---|
| `netcheck subs <domain>` | crt.sh, CertSpotter API | Enumerate subdomains via Certificate Transparency logs. Dedupe + filter wildcards. |
| `netcheck reverse <ip>` | Reverse DNS PTRs, Hackertarget API (optional Shodan via config-supplied API key) | Other domains hosted on this IP. |
| `netcheck tech <url>` | HTTP response headers + HTML body fingerprinting | Wappalyzer-style detection of CDNs, frameworks, server software, common JS libs. |
| `netcheck headers <url>` | One HTTP GET, parse response headers | Security-header report card: HSTS (incl. preload), CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Per-header pass / weak / missing grade. |
| `netcheck arch <domain>` | archive.org CDX API (optional DNSDB) | Wayback Machine snapshots + historical DNS / hostname surface. |

Design constraints:

- Each command supports `--output text|json|markdown|html` and `--out <file>`,
  matching the v0.5+ contract.
- New JSON schema variants extend the existing `kind` discriminator (new
  `"kind": "headers"`, `"kind": "subs"`, etc.). These are additive changes —
  per the schema rule in `internal/report/jsonschema.go`, additive changes do
  not bump `netcheck_version`. Only a breaking change (rename/remove/retype)
  bumps it.
- Web app modes added in step with the CLI commands so the workbench keeps
  feature parity.
- HTTP-bound commands reuse `internal/check` plumbing (timeouts, redirects,
  TLS settings) — no new HTTP client.
- API keys (Shodan, DNSDB) live in `config.yaml` under a new `apis:` block;
  commands degrade gracefully when keys are absent (skip that source,
  annotate in output).

Suggested shipping order — smallest blast radius first:

1. `headers` — no external API, pure HTTP response parsing
2. `tech` — same HTTP, plus body inspection
3. `subs` — CT logs are well-behaved public APIs
4. `reverse` — multiple sources, dedupe logic
5. `arch` — archive.org pagination is the only fiddly bit

## v1.5 — Active scanning (planned)

The pentest direction graduates to commands that actually probe the
target. All four require explicit user confirmation (`--i-have-authorization`
flag or `NETCHECK_AUTHORIZED=1` env var) before doing anything. The
refusal banner names the command, both opt-in mechanisms, and points
the user at [docs/ETHICS.md](ETHICS.md) for what "authorized" means.

| Command | What it does | Probe shape |
|---|---|---|
| `netcheck tls <host>` | Probes every TLS version (1.0–1.3) and every cipher suite Go knows about against the target. Grades deprecated protocols, weak ciphers, expired/expiring/self-signed certs. | ~30 TCP+TLS handshakes, parallel, cipher phase capped at 10 concurrent. |
| `netcheck takeover <domain>` | Resolves CNAME, matches against a built-in catalog of takeover-able services (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Bitbucket Cloud, Ghost), and verifies with one HTTP GET. Verdicts: vulnerable / unverifiable / safe / unknown. | 1 DNS lookup + 1 HTTP GET. Gated despite the small surface because the OUTPUT identifies a vulnerability with exploit-ready detail. |
| `netcheck ports <host>` | TCP connect scan, default top-100 nmap-ordered ports. Open ports annotated with service hints from a builtin map. | Parallel TCP handshakes (50-way default). No SYN scan, no UDP. |
| `netcheck enum <url>` | HTTP path enumeration against a builtin or user-supplied wordlist. Categorizes by status: found / redirect / blocked / auth-required / server-error. 404s and 410s are dropped. | One HTTP GET per wordlist entry (10-way default). Builtin list is ~70 high-signal paths; `--wordlist` overrides. |

Design constraints:

- Authorization gate is enforced at the CLI layer (`cmd/authz.go`). The
  inner Go packages (`internal/tlsaudit`, `takeover`, `portscan`,
  `pathenum`) have no notion of authorization — they're library code
  callable from tests and a future HTTP API surface; the gate is the
  CLI's job. This is the standard "guard at the entry point" pattern.
- Refusal exit code is `2` (bad invocation), same as missing positional
  arguments. The refusal banner is human-readable, not part of the
  stable contract. The flag/env-var existence and exit code ARE part
  of the contract — see STABILITY.md.
- New JSON `"kind"` discriminators: `"tls-audit"`, `"takeover"`,
  `"ports"`, `"enum"`. Additive — no `SchemaVersion` bump.
- No raw-socket dependence. SYN scans, ICMP active probing, and
  similar require root and unsanitized OS dependencies. We stay in
  the `net.Dial` happy path.
- `internal/tlsaudit` and `internal/portscan` don't have a SetUserAgent
  hook — they speak raw TCP/TLS, no HTTP headers to set. Other v1.5
  packages do.

Suggested shipping order — same logic as v1.4, smallest blast radius
first; this is the order the implementation went:

1. **Ethics gate + ETHICS.md** — the prerequisite for everything else.
2. **`tls`** — well-defined finite probe surface, no wordlist or catalog
   to maintain.
3. **`takeover`** — small catalog (8 providers), the rest is fingerprint
   matching.
4. **`ports`** — straightforward parallel `net.Dial`; embedded port list.
5. **`enum`** — needs the builtin wordlist + `--wordlist` plumbing.

Verified during implementation:
- `tls` against cloudflare.com revealed they accept TLS 1.0/1.1 and
  several weak RSA-KEX ciphers. Real signal.
- `takeover` against `www.netflix.com` returned "unknown" — their CNAME
  is internal CDN, not in our catalog. Correct conservative output.
- `ports --top 20 scanme.nmap.org` returned 22/ssh + 80/http exactly as
  Nmap's "you may scan this" test target documents.
- `enum http://scanme.nmap.org` found a 403 on `.svn/entries` — Apache
  default config has the rule even though the file doesn't exist.

## v1.6+ — Unscheduled

- HTTP/3 / QUIC test
- Prometheus exporter
- TUI mode
- Historical comparison (today vs. yesterday)
- Proxy / VPN detection
- Browser-like mode (HSTS cache, cookies, HTTP/3, extensions)
- Native TCP traceroute (avoids needing system `traceroute`)
- Banner-grab option for `ports` (read first line of response from open
  ports to identify service version)

Out of scope, full stop — these are owned by other tools and adding them
would dilute the netcheck story:

- Exploitation frameworks (leave to Metasploit)
- CVE matching at scale (leave to nuclei)
- Intercepting web proxy (leave to Burp / ZAP)
- Credential brute-force (leave to Hydra)

---

## 17. GitHub Actions Ideas

Recommended CI checks:

```text
Go fmt
Go vet
Go test
Staticcheck
Build Linux binary
Build macOS binary
Build Windows binary
Release artifact generation
```

Possible workflow files:

```text
.github/workflows/test.yml
.github/workflows/build.yml
.github/workflows/release.yml
```

---

## 18. Learning Value

This project teaches:

- DNS resolution
- A and AAAA records
- TCP connection flow
- TLS certificates
- HTTP status codes
- Redirects
- CDN behavior
- IPv4 vs IPv6
- Traceroute limitations
- ASN and BGP basics
- CLI design
- Go project structure
- Cross-platform tooling
- Testable DevOps-style code

This is a very strong portfolio project because it combines networking, system tooling, and practical troubleshooting.

---

## 19. First Implementation Checklist

Start with this checklist:

```text
[ ] Create Git repo
[ ] Initialize Go module
[ ] Add Cobra CLI
[ ] Create root command
[ ] Accept target argument
[ ] Normalize URL
[ ] Extract hostname
[ ] Resolve A records
[ ] Resolve AAAA records
[ ] Test TCP 443
[ ] Fetch TLS certificate
[ ] Send HTTP GET request
[ ] Follow redirects
[ ] Print clean report
[ ] Add simple errors
[ ] Add README examples
[ ] Add basic tests
```

---

## 20. Recommended Starting Command

```bash
mkdir netcheck
cd netcheck
go mod init github.com/YOUR_USERNAME/netcheck
go get github.com/spf13/cobra
```

Then create:

```text
main.go
cmd/root.go
internal/dnscheck/dns.go
internal/httpcheck/http.go
internal/tlscheck/tls.go
internal/report/report.go
```

---

## 21. Final Recommendation

Build the first version in Go and keep it small.

Best first goal:

```text
A clean CLI that takes one domain and shows DNS, TCP, TLS, HTTP, redirects, and timing.
```

Do not start with traceroute, DoH, BGP, or a web UI.

Those are great later features, but the MVP should prove the core idea first.
