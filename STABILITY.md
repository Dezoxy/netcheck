# Stability promise

Starting with **v2.0.0**, netcheck commits to backward compatibility for the entire `v2.x` series. The contract is:

- Existing CLI invocations keep working.
- Existing scripts and pipelines parsing netcheck's JSON keep working.
- Existing config files keep loading.
- Existing Go programs importing `github.com/Dezoxy/netcheck/pkg/...` keep compiling.

If something must change in a breaking way, it earns a **v3.0.0**, not a `v2.x` release. For what changed in v1 → v2, see [MIGRATING.md](MIGRATING.md).

## What's stable

### CLI flags

These flag names, their semantics, and the commands they're attached to are stable through `v2.x`:

In the table below, "every check" means: `full`, `dns`, `route`, `ip`, `headers`, `tech`, `subs`, `reverse`, `arch`, `whois`, `tls`, `takeover`, `ports`, `enum`, `audit`. `app`, `menu`, `watch`, `completion` are control-plane subcommands and don't register the per-check flag set.

| Flag | Commands | Behavior |
|---|---|---|
| `--config <path>` | every check + `config show` | Override config file lookup |
| `--output text\|json\|markdown\|html` | every check + `config show` + `diff` | Output format. `text` is the default. |
| `-j` | every check + `config show` + `diff` | Shortcut for `--output json`. Last-write-wins with `--output`. |
| `--out <file>` | every check + `config show` + `diff` | Write to file instead of stdout. `-` means stdout. |
| `-o <file>` | every check + `config show` + `diff` | Shortcut for `--out`. |
| `--timeout <duration>` | every check | Per-check or overall timeout (semantic varies by command — see `--help`) |
| `--insecure` | full, headers, tech, enum, audit | Skip TLS verification |
| `--i-have-authorization` | tls, takeover, ports, enum, audit (with `--active`) | Confirm authorization to actively probe the target (also: `NETCHECK_AUTHORIZED=1`). See [docs/ETHICS.md](docs/ETHICS.md). |
| `--type <list>` | dns | Comma-separated record types |
| `--resolver <addr>` | dns | Additional resolver (repeatable; URL syntax supported) |
| `--no-system` | dns | Skip the system resolver |
| `--no-defaults` | dns | Skip built-in resolvers (Cloudflare/Google/Quad9) |
| `--no-config-resolvers` | dns | Skip resolvers defined in config |
| `--dnssec` | dns | Set the DO bit so resolvers return DNSSEC records. Fetches, does not validate. |
| `--max-hops <n>` | route | Max hops |
| `--probes <n>` | route | Probes per hop |
| `--wait <n>` | route | Per-probe wait in seconds |
| `--no-resolve` | route | Skip reverse DNS per hop |
| `--no-asn` | route | Skip Team Cymru ASN lookup |
| `--ports <list>` | ports | Explicit port list (e.g. `22,80,443,8000-8010`) |
| `--top <n>` | ports | Scan the top-N nmap-style ports |
| `--concurrency <n>` | ports, enum | Parallel dials / requests |
| `--per-port-timeout <duration>` | ports | Per-port connect timeout |
| `--no-banners` | ports | Disable best-effort banner grab on open ports |
| `--banner-timeout <duration>` | ports | Per-port banner-grab read deadline |
| `--udp` | ports | Also run a UDP pass (service-aware probes, top-50 UDP ports) |
| `--udp-only` | ports | Run the UDP pass and skip TCP |
| `--udp-ports <list>` | ports | Explicit UDP port list. Implies `--udp`. |
| `--wordlist <file>` | enum | Override the builtin wordlist |
| `--per-path-timeout <duration>` | enum | Per-request timeout |
| `--follow-redirects` | enum | Follow HTTP redirects during enumeration |
| `--active` | audit | Include the active sub-checks (tls, takeover, ports, enum) |
| `--interval <duration>` | watch | How often to re-run the wrapped subcommand |
| `--out-dir <dir>` | watch | Save each snapshot to this directory |
| `--max-runs <n>` | watch | Stop after N iterations (0 = forever) |
| `--quiet` | watch, diff | Suppress non-essential messages |
| `--listen <addr>` | app | HTTP listen address (default `127.0.0.1:8787`) |
| `--auth` | app | Require the start-up token even on a loopback-only bind (always required on a non-loopback bind or with `--allowed-host`) |
| `--allowed-host <name>` | app | Extra hostname the server answers to, e.g. behind a reverse proxy (repeatable or comma-separated). IP addresses and `localhost` always work. |

### Subcommands

All stable for `v2.x`:

`full` (default), `dns`, `route`, `ip`, `headers`, `tech`, `subs`, `reverse`, `arch`, `whois`, `tls`, `takeover`, `ports`, `enum`, `audit`, `diff`, `watch`, `app`, `menu`, `config show`, `completion`, `help`, `version`.

### Web app HTTP API (`netcheck app`)

When `netcheck app` is running, it exposes JSON endpoints on the listen address. All are stable for `v2.x` — new endpoints may be added; existing ones won't change shape.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/healthz` | `{"status": "ok"}` |
| `POST` | `/api/check/full` | Body: `{"target": "<url-or-host>", "insecure": <bool>}`. Returns `FullJSON`. |
| `POST` | `/api/check/dns` | Multi-resolver DNS compare. Returns `DNSCompareJSON`. |
| `POST` | `/api/check/route` | Traceroute. Returns `RouteJSON`. |
| `POST` | `/api/check/ip` | RDAP + reverse + CDN. Returns `IPInfoJSON`. |
| `POST` | `/api/check/headers` | Security-header audit. Returns `HeadersJSON`. |
| `POST` | `/api/check/tech` | Tech fingerprinting. Returns `TechJSON`. |
| `POST` | `/api/check/subs` | CT-log subdomain enum. Returns `SubsJSON`. |
| `POST` | `/api/check/reverse` | Other hostnames on an IP. Returns `ReverseJSON`. |
| `POST` | `/api/check/arch` | Wayback Machine snapshots. Returns `ArchJSON`. |
| `POST` | `/api/check/whois` | RDAP/WHOIS registrar lookup. Returns `WhoisJSON`. |
| `POST` | `/api/check/tls` | TLS protocol+cipher matrix. **Requires `"i_have_authorization": true`.** Returns `TLSAuditJSON`. |
| `POST` | `/api/check/takeover` | Subdomain-takeover check. **Auth-gated.** Returns `TakeoverJSON`. |
| `POST` | `/api/check/ports` | TCP connect scan. **Auth-gated.** Returns `PortScanJSON`. |
| `POST` | `/api/check/ports/stream` | Same body as `/api/check/ports`. **Auth-gated.** Returns `text/event-stream` with `progress` and `done` frames. |
| `POST` | `/api/check/enum` | HTTP path enumeration. **Auth-gated.** Returns `PathEnumJSON`. |
| `POST` | `/api/check/audit` | Aggregate. Returns `AuditJSON`. With `"active": true`, also requires `"i_have_authorization": true`. |
| `GET` | `/api/reports` | List saved reports (metadata only). |
| `POST` | `/api/reports` | Save a report. |
| `GET` | `/api/reports/{id}` | Fetch one saved report by id. |
| `DELETE` | `/api/reports/{id}` | Delete one saved report by id. |
| `POST` | `/api/diff` | Body: `{"old": <report>, "new": <report>}`. Returns `diff.Report`. |
| `GET` | `/api/events/stream` | `text/event-stream` of check lifecycle events, for the UI's live event stream. |
| `GET` | `/api/telemetry` | Derived metrics over a rolling 60s window (events/sec, mean latency, 60-sample sparkline). |
| `GET` | `/api/topology` | Node/edge snapshot of the last traced target, for the topography view. |

Auth-gated endpoints return `403` with `{"error": "...", "how_to_enable": "..."}` when `i_have_authorization` is missing or false.

The web UI assets served at `/` (HTML, CSS, JS, icons, service worker, manifest) are **not** part of the stability promise — asset filenames change with each build. Only the `/api/*` endpoints are covered.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks succeeded (or, for `diff`: no changes detected) |
| `1` | At least one check failed (or, for `diff`: changes detected) |
| `2` | Bad invocation — unparseable flag, missing/extra positional, missing required system tool, unsupported scheme |

`diff`'s convention mirrors `diff(1)` / `git diff --exit-code`: exit 1 means "there is output you should care about," not "an error happened." This is intentional and lets cron use `netcheck diff a.json b.json && echo unchanged || alert`.

### JSON schema

The schema version is in every JSON output as `"netcheck_version"`. The current value is `"1.0.0"`. Within a schema major version:

- Field names won't be renamed.
- Field types won't change.
- Fields won't be removed.
- New **optional** fields may be added — JSON consumers should ignore unknown fields.

The `"kind"` discriminator is stable. Current values: `"full"`, `"dns"`, `"route"`, `"ip"`, `"headers"`, `"tech"`, `"subs"`, `"reverse"`, `"arch"`, `"whois"`, `"tls-audit"`, `"takeover"`, `"ports"`, `"enum"`, `"audit"`, `"config"`.

If a breaking schema change becomes necessary, the schema version bumps (e.g. to `"2.0.0"`) and the old version stays available behind an opt-out flag for at least one minor release.

### Go library API (`pkg/`)

Exported names under `github.com/Dezoxy/netcheck/pkg/...` are stable for `v2.x`:

- Type names, field names, function signatures of exported identifiers don't change.
- Behavior of documented entry points stays.
- New methods/fields may be added; existing ones won't be removed or renamed.

The public packages are:

| Package | Purpose |
|---|---|
| `pkg/check` | Full DNS+TCP+TLS+HTTP probe primitives |
| `pkg/dnscompare` | Multi-resolver DNS comparison |
| `pkg/route` | Traceroute + per-hop ASN |
| `pkg/ipinfo` | RDAP (IP + domain), port-43 WHOIS, reverse DNS, CDN classification |
| `pkg/secheaders` | Security-header report card |
| `pkg/techdetect` | Passive CMS/framework/server fingerprinting |
| `pkg/subenum` | Certificate-Transparency subdomain enumeration |
| `pkg/reverseip` | Other hostnames on the same IP |
| `pkg/wayback` | Wayback Machine historical snapshots |
| `pkg/tlsaudit` | TLS protocol+cipher matrix and cert audit |
| `pkg/takeover` | Subdomain-takeover heuristic check |
| `pkg/portscan` | Parallel TCP connect scan |
| `pkg/pathenum` | HTTP path / wordlist enumeration |
| `pkg/report` | Versioned JSON schemas + text/markdown/HTML renderers |
| `pkg/diff` | Structured diff between two report JSONs |
| `pkg/target` | URL / host normalization |
| `pkg/eventbus` | In-process pub/sub for check lifecycle events |
| `pkg/telemetry` | Derived metrics + topology snapshots computed from the event stream |

Anything under `internal/` (currently `internal/config` and `internal/webui`) is enforced-unstable by Go's `internal/` rule.

### Config file schema (`~/.config/netcheck/config.yaml`)

Keys named in `config.example.yaml` are stable. New keys may be added; existing keys keep their meaning. API keys under `apis.*` are always optional — commands degrade gracefully when a key is absent.

### Environment variables

`NETCHECK_CONFIG`, `NETCHECK_TIMEOUT`, `NETCHECK_USER_AGENT`, `NETCHECK_AUTHORIZED`, `NETCHECK_APP_TOKEN`, `NETCHECK_APP_TOKEN_FILE` — stable. New `NETCHECK_*` variables may be added.

## What's NOT covered

These can change between any two releases:

- **Text output, line by line.** The structure stays (DNS section, TCP section, etc.) but exact spacing, color, separators, or wording of human-prose lines can be tweaked. Use `--output json` if you're parsing.
- **`--help` and `--version` wording.** Format may shift; the underlying flags remain.
- **Error message text.** Error categories are stable (via exit codes); exact strings aren't.
- **Default resolver list.** Cloudflare/Google/Quad9 may grow or shrink based on operator availability. Use `--no-defaults --resolver ...` for a pinned set.
- **Bundled CDN ASN map** (`pkg/ipinfo/cdn.go`). New CDN providers get added over time.
- **`netcheck tech` fingerprint catalogue.** New detectors get added; existing ones may have their `name`, `category`, or `confidence` adjusted as the rules improve. The JSON envelope is stable; the *contents* of `matches` aren't. Don't pin tests to "exactly these matches."
- **`netcheck subs` source list.** crt.sh and CertSpotter today. Sources may grow or shrink. JSON envelope stable; which sources contribute per-subdomain isn't.
- **`netcheck reverse` source list.** Same — `ptr`, `hackertarget`, optionally `shodan`. The set can grow or shrink.
- **`netcheck whois` lookup path.** RDAP first, port-43 WHOIS as fallback, manual-lookup URL when neither publishes a registrar. Which path answers for a given TLD depends on that registry and can change. The `source` field and the rest of the envelope are stable; which value it holds isn't.
- **`netcheck takeover` provider catalog.** The list of services we fingerprint grows as more services become documented as takeover-able. Existing providers' CNAME-pattern regex may be refined.
- **`netcheck ports` builtin port list.** `TopPorts(N)` returns the first N of the embedded nmap top-1000. The bytes are frozen for reproducibility today, but if a future release ships nmap's newer ordering, the list will change. `--ports` explicit lists are obviously stable in shape.
- **`netcheck enum` builtin wordlist.** The default wordlist is curated for high-signal coverage and will be revised. The output schema is stable; the *list of paths probed by default* isn't. Point `--wordlist` at a fixed file for reproducible enumerations.

### Active-scanning gate

`netcheck tls`, `takeover`, `ports`, `enum`, and `audit --active` refuse to run without either:
- `--i-have-authorization` on the command line, OR
- `NETCHECK_AUTHORIZED=1` (also `true` / `yes`, case-insensitive) in the environment.

This is a stable contract — neither variant will be removed in `v2.x`. The refusal banner text isn't stable; the exit code (2) and the existence of the gate are.

## Deprecation policy

If a flag, subcommand, env var, config key, or exported Go API needs to be removed:

1. **One full minor release** with the item still working but emitting a deprecation warning to stderr (CLI) or `// Deprecated:` godoc comment (library).
2. The same release ships its replacement.
3. The next minor release may remove the deprecated item.

So if `--foo` is deprecated in `v2.4`, the earliest it goes away is `v2.5`. Patch releases (`v2.4.x`) won't remove anything.

## Versioning

netcheck follows [SemVer](https://semver.org/):

- **Patch** (`v2.0.x`): bug fixes, dependency updates, performance improvements, documentation.
- **Minor** (`v2.x.0`): new subcommands, new flags, new optional output fields, new CDN providers, new resolver types — all backward-compatible.
- **Major** (`v3.0.0`): breaking changes to anything in "What's stable" above.

The version in the binary (`netcheck version`) matches the git tag.
