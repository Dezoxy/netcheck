# netcheck

A CLI tool that analyzes what happens between your machine and a target website or domain — DNS, TCP, TLS, HTTP, redirects, timing, IP ownership, CDN hints, traceroute, and per-resolver DNS comparison.

## Install

```bash
git clone https://github.com/Dezoxy/netcheck.git
cd netcheck
make build              # produces ./bin/netcheck
# or, to put it on your PATH:
make install            # installs into $GOBIN (~/go/bin) via `go install`
```

Requires Go 1.22+. The CLI keeps Go dependencies light; `netcheck dns` uses [`miekg/dns`](https://github.com/miekg/dns), while ASN/IP ownership data comes from public Team Cymru DNS and RDAP lookups. Run `make help` to see all targets.

## Usage

### Interactive menu

Run with no arguments on a terminal and netcheck drops into an interactive menu:

```bash
netcheck            # opens menu when stdin is a TTY
netcheck menu       # always opens the menu, even when piped
```

```
netcheck 0.4.0 — interactive menu

  1) Full check (DNS, TCP, TLS, HTTP)
  2) DNS compare across resolvers
  3) Route (traceroute + per-hop ASN)
  4) IP / ASN info
  q) Quit

Choose: 2
Host: https://Google.com/search?q=hi
  → normalized to: google.com
...
```

Input is normalized before each check: surrounding whitespace and quotes are stripped, schemes/paths/queries/ports are removed for `dns` and `route`, and the full-check parser auto-prefixes `https://` when missing. After a check finishes, press Enter to return to the menu; type `q` to quit.

When stdin is **not** a terminal (e.g. piped from a script), bare `netcheck` keeps its old behavior and prints usage — so existing automation doesn't accidentally hang waiting for menu input.

### Full check (DNS, TCP, TLS, HTTP)

```bash
netcheck google.com
netcheck https://example.com
netcheck --insecure https://expired.badssl.com
netcheck --timeout 5s example.com
```

Sample output:

```
NETCHECK REPORT
Target: https://google.com
Time:   2026-05-19 22:17:23

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
    Chain:     3 cert(s)
    SANs:      [*.google.com *.appengine.google.com ...] (+132 more)
  handshake time: 53ms

HTTP
  [OK] Status:    200
    Protocol:  HTTP/1.1
    Server:    gws
    Final URL: https://www.google.com/
    Redirects: 1
      1. 301  https://google.com
  Timing (first request):
    DNS:     6ms
    Connect: 17ms
    TLS:     40ms
    TTFB:    328ms
    Total:   774ms

Summary
  [OK] DNS
  [OK] TCP
  [OK] TLS
  [OK] HTTP
```

Exit code `1` if any check fails (DNS, TCP, TLS, HTTP).

### DNS resolver compare

```bash
netcheck dns google.com
netcheck dns --type MX,TXT cloudflare.com
netcheck dns --resolver 1.0.0.1 --resolver 8.8.4.4 example.com
netcheck dns --no-defaults --resolver 1.1.1.1 cloudflare.com
```

Queries System, Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), and Quad9 (`9.9.9.9`) in parallel and shows whether they agree.

Flags:

| Flag | Default | Description |
|---|---|---|
| `--type` | `A,AAAA` | Comma-separated record types: A, AAAA, CNAME, MX, TXT, NS, SOA |
| `--resolver` | — | Additional resolver `host[:port]` (repeatable) |
| `--timeout` | `5s` | Per-query timeout |
| `--no-system` | `false` | Skip the system resolver |
| `--no-defaults` | `false` | Skip built-in resolvers |

Exit code `1` if any resolver returns a transport error or non-`NOERROR` rcode. Resolvers returning different answers (common for GeoDNS) is **not** treated as failure — the verdict line surfaces the split.

Sample output:

```
DNS COMPARE
Host:  google.com
Time:  2026-05-19 22:24:10

A records
  RESOLVER    ADDRESS       TIME  ANSWER
  System      127.0.2.2:53  29ms  142.251.38.206
  Cloudflare  1.1.1.1:53    11ms  142.251.38.206
  Google      8.8.8.8:53    19ms  192.178.25.174
  Quad9       9.9.9.9:53    17ms  142.251.20.100
                                  142.251.20.101
  Verdict: resolvers disagree (3 distinct answer sets)
    Set 1 (System, Cloudflare):
      142.251.38.206
    Set 2 (Google):
      192.178.25.174
    Set 3 (Quad9):
      142.251.20.100
      142.251.20.101
```

### Route (traceroute + per-hop ASN)

```bash
netcheck route google.com
netcheck route --max-hops 20 1.1.1.1
netcheck route --no-asn --no-resolve example.com
```

Wraps the system `traceroute` (`tracert` on Windows), streams hops as they arrive, and annotates each public IP with its origin ASN via Team Cymru's DNS service (no API key needed). Private and link-local hops are skipped for ASN.

Flags:

| Flag | Default | Description |
|---|---|---|
| `--max-hops` | `30` | Maximum number of hops |
| `--probes` | `3` | Probes per hop |
| `--wait` | `2` | Per-probe wait in seconds |
| `--no-resolve` | `false` | Skip reverse DNS for each hop |
| `--no-asn` | `false` | Skip Team Cymru ASN annotation |
| `--timeout` | `60s` | Overall traceroute timeout |

Sample output:

```
ROUTE
Host:  google.com  (142.250.184.206)
Time:  2026-05-20 14:02:11
Tool:  /usr/sbin/traceroute [-m 30 -q 3 -w 2]

  HOP  ADDRESS                                RTT                      ASN
  1    10.0.0.1                               1.23ms  1.15ms  1.04ms
  2    * * *                                  *   *   *
  3    1.2.3.4                                10.2ms  9.8ms  10.5ms    AS7922 COMCAST-7922
  ...
  8    142.250.184.206                        18.1ms  17.9ms  18.0ms   AS15169 GOOGLE

  Reached 142.250.184.206 in 8 hops
  1 hop(s) timed out — routers commonly drop or rate-limit probes; missing hops do not always mean a broken route.
```

Requires the system `traceroute` (or `tracert`) on `PATH`. macOS ships it at `/usr/sbin/traceroute`; on Debian/Ubuntu install with `sudo apt install traceroute`.

### IP / ASN info

```bash
netcheck ip 142.250.184.206
netcheck ip cloudflare.com
netcheck ip --timeout 5s 8.8.8.8
```

Shows reverse DNS, origin ASN, prefix, country, registry, RDAP abuse contact, and static CDN classification. Hostnames are resolved to all A/AAAA records and each address is shown separately.

Sample output:

```
IP INFO
Target:   142.250.184.206
Time:     2026-05-20 15:38:19
Reverse:  fra24s11-in-f14.1e100.net
ASN:      AS15169 GOOGLE (Google LLC)
Country:  US
Prefix:   142.250.184.0/24
Registry: arin
CDN:      Google (high confidence - ASN match + 1e100.net PTR)
Abuse:    network-abuse@google.com
```

## Roadmap

See [netcheck_tool_project_plan.md](netcheck_tool_project_plan.md) for the full plan.

| Version | Status | Features |
|---|---|---|
| v0.1 | shipped | URL parsing, DNS, TCP, TLS, HTTP, redirects, httptrace timing |
| v0.2 | shipped | DNS resolver compare, A/AAAA/CNAME/MX/TXT/NS/SOA, custom resolvers |
| v0.3 | shipped | Traceroute wrapper with per-hop ASN annotation (Team Cymru) |
| v0.3.1 | shipped | Interactive menu mode with input normalization |
| v0.4 | shipped | Standalone IP info command, RDAP abuse/registry lookup, CDN detection, DNS ASN hints |
| v0.4.1 | shipped | Planning update — locked v0.5 → v1.0 rollout, folder structure documented |
| v0.4.2 | shipped | Refactored flat `package main` into `cmd/` + `internal/` per the documented layout |
| v0.5 | planned | `--output text\|json\|markdown\|html` on every command; versioned JSON schema |
| v0.6 | planned | YAML config file (`~/.config/netcheck/config.yaml`) + DoH/DoT resolvers |
| v0.7 | planned | Fill test coverage gaps, GitHub Actions CI, build matrix, status badge |
| v0.8 | planned | `goreleaser` cross-platform release binaries, checksums, optional Homebrew tap |
| v0.9 | planned | Release candidate — CLI surface freeze, doc pass, asciinema demo |
| v1.0 | planned | Stability promise (no breaking changes in v1.x), final docs, optional man page |

## Caveats

- **DNS results aren't universal.** GeoDNS, anycast, ECS, and CDN load-balancing all mean different resolvers (and different clients) legitimately get different IPs. `netcheck dns` makes that visible.
- **Traceroute is heuristic.** Routers can drop, rate-limit, or reorder ICMP/UDP probes. A missing hop does not always mean a broken route, and the path for TCP traffic may differ from what traceroute shows.
- **Browser behavior may differ.** CLI doesn't use HSTS cache, HTTP/3, cookies, extensions, or VPN settings the way your browser does.
- **macOS `/etc/resolv.conf`** points at internal loopback resolvers; `netcheck dns` uses just the first one for readability.
