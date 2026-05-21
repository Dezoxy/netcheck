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

**Pre-built binary** — download the archive for your platform from the [latest release](https://github.com/Dezoxy/netcheck/releases/latest), or curl one-liner:

```bash
# macOS Apple Silicon
curl -L https://github.com/Dezoxy/netcheck/releases/latest/download/netcheck_1.0.0_darwin_arm64.tar.gz | tar xz
sudo mv netcheck /usr/local/bin/

# Linux amd64
curl -L https://github.com/Dezoxy/netcheck/releases/latest/download/netcheck_1.0.0_linux_amd64.tar.gz | tar xz
sudo mv netcheck /usr/local/bin/

# Windows: download netcheck_1.0.0_windows_amd64.zip, unzip, run netcheck.exe
```

Available platforms: `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`, `windows_amd64`, `windows_arm64`. Each archive bundles `README.md`, `LICENSE`, and `config.example.yaml`. SHA256s in `checksums.txt`.

**From source** (requires Go 1.22+):

```bash
git clone https://github.com/Dezoxy/netcheck.git
cd netcheck
make build      # → ./bin/netcheck
make install    # → $GOBIN (usually ~/go/bin)
```

## What it does

netcheck has four checks plus an interactive menu. Run any of them from a terminal; pipe the output through `jq`; or just run `netcheck` with no arguments to get the menu.

| Command | Asks |
|---|---|
| `netcheck <target>` | Can I reach this URL? What's the full path — DNS, TCP, TLS, HTTP, redirects, timing? Who owns the IP? |
| `netcheck dns <host>` | Do Cloudflare, Google, Quad9, my system resolver, and any DoH/DoT resolver agree on this hostname's IPs? |
| `netcheck route <host>` | What's the network path to this host, and who owns each hop? |
| `netcheck ip <ip\|host>` | Who owns this IP? What's its ASN, reverse DNS, RDAP record, CDN affiliation? |
| `netcheck menu` | Interactive picker for any of the above. Offers to save results after each run. |
| `netcheck config show` | What config is netcheck actually using right now? |

Every command accepts `--output text|json|markdown|html` (default `text`) and `--out <file>` (write to file with `Saved to <abs-path>` echoed to stderr). The text format is byte-stable across `v1.x`; the JSON schema is versioned (`"netcheck_version"` field) and stable per [STABILITY.md](STABILITY.md).

## Examples

### Quick full check

```bash
netcheck google.com
netcheck https://expired.badssl.com           # see the TLS section flag this
netcheck --insecure https://self-signed.badssl.com    # inspect without verifying
```

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

### Pipe into other tools

```bash
# What's the redirect chain?
netcheck --output json google.com | jq '.http.hops'

# Which hops timed out on a traceroute?
netcheck route --output json google.com | jq '.hops[] | select(.timeout)'

# Save a shareable HTML report
netcheck ip --output html --out /tmp/report.html 1.1.1.1 && open /tmp/report.html

# Send a Markdown summary in a ticket
netcheck dns --output markdown cloudflare.com | pbcopy
```

> Flags come before the positional argument: `netcheck dns --output json cloudflare.com`, not `netcheck dns cloudflare.com --output json`.

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
```

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
| v1.1+ | unscheduled | HTTP/3 / QUIC test, Prometheus exporter, TUI mode, native TCP traceroute, historical comparison, browser-like mode |

</details>
