# Stability promise

Starting with **v1.0.0**, netcheck commits to backward compatibility for the entire `v1.x` series. The contract is:

- Existing CLI surface keeps working.
- Existing scripts and pipelines parsing netcheck's output keep working.
- Existing config files keep loading.

If something must change in a breaking way, it earns a **v2.0.0**, not a `v1.x` release.

## What's stable (covered by the promise)

### CLI flags

These flag names, their semantics, and the commands they're attached to are stable through `v1.x`:

| Flag | Commands | Behavior |
|---|---|---|
| `--config <path>` | full, dns, route, ip, headers, tech, subs, reverse, arch, config show | Override config file lookup |
| `--output text\|json\|markdown\|html` | full, dns, route, ip, headers, tech, subs, reverse, arch, config show | Output format |
| `--out <file>` | full, dns, route, ip, headers, tech, subs, reverse, arch, config show | Write to file instead of stdout |
| `--timeout <duration>` | full, dns, route, ip, headers, tech, subs, reverse, arch | Per-check or overall timeout (semantic varies by command, documented in `--help`) |
| `--insecure` | full, headers, tech | Skip TLS verification |
| `--type <list>` | dns | Comma-separated record types |
| `--resolver <addr>` | dns | Additional resolver (repeatable; URL syntax supported) |
| `--no-system` | dns | Skip the system resolver |
| `--no-defaults` | dns | Skip built-in resolvers (Cloudflare/Google/Quad9) |
| `--no-config-resolvers` | dns | Skip resolvers defined in config |
| `--max-hops <n>` | route | Max hops |
| `--probes <n>` | route | Probes per hop |
| `--wait <n>` | route | Per-probe wait in seconds |
| `--no-resolve` | route | Skip reverse DNS per hop |
| `--no-asn` | route | Skip Team Cymru ASN lookup |
| `--listen <addr>` | app | HTTP listen address (default `127.0.0.1:8787`) |

### Subcommands

`full` (default), `dns`, `route`, `ip`, `headers`, `tech`, `subs`, `reverse`, `arch`, `app`, `menu`, `config show`, `help`, `version` — all stable.

### Web app HTTP API (`netcheck app`)

When `netcheck app` is running, it exposes two HTTP endpoints on the listen address. Both are stable for v1.x; new endpoints may be added, existing ones won't change shape.

| Method | Path | Request | Response |
|---|---|---|---|
| `GET` | `/api/healthz` | (none) | `{"status": "ok"}` with `200 OK` |
| `POST` | `/api/check/full` | `{"target": "<url-or-host>", "insecure": <bool>}` (JSON body) | `200 OK` with the same `FullJSON` schema the CLI emits (`"kind": "full"`, `"netcheck_version": "0.5.0"`). On bad input: `400` with `{"error": "<message>"}`. |

The web UI assets served at `/` (HTML, CSS, JS, icons, service worker, manifest) are **not** part of the stability promise — their structure and asset names may change between releases. Only the `/api/*` endpoints are covered.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks succeeded |
| `1` | At least one check failed (network, certificate, DNS, no hops, etc.) |
| `2` | Bad invocation — unparseable flag, missing/extra positional argument, missing required system tool (e.g. `traceroute`), unsupported scheme |

Scripts can rely on these.

### JSON schema

The schema version is in every JSON output as `"netcheck_version"`. The current value is `"0.5.0"`. Within a schema version:

- Field names won't be renamed.
- Field types won't change.
- Fields won't be removed.
- New **optional** fields may be added — JSON consumers should ignore unknown fields.

The `"kind"` discriminator (`"full"` / `"dns"` / `"route"` / `"ip"` / `"headers"` / `"tech"` / `"subs"` / `"reverse"` / `"arch"` / `"config"`) is stable.

If a breaking schema change becomes necessary, the schema version bumps (e.g. to `"1.0.0"`) and the old version stays available behind an opt-out flag for at least one minor release.

### Config file schema (`~/.config/netcheck/config.yaml`)

Keys named in `config.example.yaml` (`timeout`, `user_agent`, `follow_redirects`, `max_redirects`, `prefer_ipv6`, `resolvers[].name/.address/.type`, `apis.shodan_api_key`) are stable. New keys may be added; existing keys keep their meaning. API keys under `apis.*` are always optional — commands degrade gracefully when a key is absent.

### Environment variables

`NETCHECK_CONFIG`, `NETCHECK_TIMEOUT`, `NETCHECK_USER_AGENT` — stable. New `NETCHECK_*` variables may be added.

## What's NOT covered

These can change between any two releases:

- **Text output, line by line.** The structure stays (DNS section, TCP section, etc.) but exact spacing, color, separators, or wording of human-prose lines (e.g. the "Verdict: …" sentence) can be tweaked. Use `--output json` if you're parsing.
- **`--help` and `--version` wording.** Format may shift; the underlying flags remain.
- **Internal Go API.** Anything under `internal/` is enforced-unstable by Go's `internal/` rule. We will move, split, rename, or rewrite these packages freely.
- **Error message text.** Error categories are stable (via exit codes); exact strings aren't.
- **Default resolver list.** Cloudflare/Google/Quad9 may grow or shrink based on operator availability. Use `--no-defaults --resolver ...` for a pinned set.
- **Bundled CDN ASN map** (`internal/ipinfo/cdn.go`). New CDN providers get added over time.
- **`netcheck tech` fingerprint catalogue.** New detectors get added; existing ones may have their `name`, `category`, or `confidence` adjusted as we improve the rules. The JSON envelope (`kind`, `url`, `matches[]`, field names) is stable; the *contents* of `matches` aren't.
- **`netcheck subs` source list.** We currently query crt.sh and CertSpotter. New sources may be added; existing ones may be removed if they go away. The JSON envelope (`kind`, `domain`, `subdomains[]`, `source_errors`, field names) is stable; which sources contribute to the `sources[]` field per subdomain isn't.
- **`netcheck reverse` source list.** Same as subs — the set of reverse-IP sources (currently `ptr`, `hackertarget`, optionally `shodan`) can grow or shrink. JSON envelope stable, source contents aren't.

## Deprecation policy

If a flag, subcommand, env var, or config key needs to be removed:

1. **One full minor release** with the item still working but emitting a deprecation warning to stderr.
2. The same release ships its replacement.
3. The next minor release may remove the deprecated item.

So if `--foo` is deprecated in `v1.4`, the earliest it goes away is `v1.5`. Patch releases (`v1.4.x`) won't remove anything.

## Versioning

netcheck follows [SemVer](https://semver.org/):

- **Patch** (`v1.0.x`): bug fixes, dependency updates, performance improvements, documentation.
- **Minor** (`v1.x.0`): new subcommands, new flags, new optional output fields, new CDN providers, new resolver types — all backward-compatible.
- **Major** (`v2.0.0`): breaking changes to anything in "What's stable" above.

The version in the binary (`netcheck version`) matches the git tag.
