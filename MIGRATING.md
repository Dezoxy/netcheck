# Migrating from v1.x to v2.0

v2.0 is the first netcheck release that's intentionally not backward-compatible with v1.x. The breakage is contained to four areas; if you don't use any of them, you don't have to do anything.

## TL;DR by user type

| If you… | …you need to |
|---|---|
| Run `netcheck` from a terminal | Nothing. Every v1.x invocation still works. |
| Pipe `--output json` into `jq`/scripts | Update two field names if your scripts read them (`chain_count`, `resolve_ms`). Pin to `netcheck_version: "1.0.0"` in your script. |
| Have `netcheck` checked into a Go project as a library | Update import paths. `netcheck/...` → `github.com/Dezoxy/netcheck/pkg/...`. |
| Have a downstream `replace netcheck => …` directive | Update the module path on both sides of the `replace`. |
| Use the web app via `netcheck app` (UI only) | Nothing. The UI is unchanged from the user's perspective. |
| Hit the `/api/check/*` endpoints from your own code | Two JSON field renames (same as the CLI). Endpoint URLs and request bodies are unchanged. |

## 1. JSON schema field renames

Two field names changed. The schema version moved from `0.5.0` to `1.0.0` to signal the discontinuity — pin against this in your scripts.

| Kind | Before (v1.x) | After (v2.x) |
|---|---|---|
| `tls-audit` | `cert.chain_len` | `cert.chain_count` |
| `ip` | `resolve_took_ms` | `resolve_ms` |

The `chain_count` name was already used by the full check's `tls.chain_count`; v2 just makes the tls-audit field match. `resolve_ms` aligns with every other duration field in the schemas (`took_ms`, `dns_ms`, `connect_ms`, `tls_ms`, `ttfb_ms`, `total_ms`, `rtt_ms` — all `<phase>_ms`).

Everything else is identical: same kinds, same envelope, same `kind` discriminators, same per-kind shape.

### Script migration

```bash
# Before
netcheck ip --output json cloudflare.com | jq '.resolve_took_ms'
netcheck tls --i-have-authorization example.com:443 -j | jq '.cert.chain_len'

# After
netcheck ip -j cloudflare.com | jq '.resolve_ms'
netcheck tls --i-have-authorization example.com:443 -j | jq '.cert.chain_count'
```

Note the new `-j` shortcut for `--output json` while you're at it — additive in v2, no migration needed.

## 2. Go library import paths

netcheck's module path changed from `netcheck` to `github.com/Dezoxy/netcheck`, and the check engines moved out from under `internal/` into `pkg/`. Both changes were necessary to make the library actually importable from outside the repo — `module netcheck` was not a valid Go import path for external consumers.

### Find-and-replace

| Before | After |
|---|---|
| `netcheck/internal/check` | `github.com/Dezoxy/netcheck/pkg/check` |
| `netcheck/internal/dnscompare` | `github.com/Dezoxy/netcheck/pkg/dnscompare` |
| `netcheck/internal/route` | `github.com/Dezoxy/netcheck/pkg/route` |
| `netcheck/internal/ipinfo` | `github.com/Dezoxy/netcheck/pkg/ipinfo` |
| `netcheck/internal/secheaders` | `github.com/Dezoxy/netcheck/pkg/secheaders` |
| `netcheck/internal/techdetect` | `github.com/Dezoxy/netcheck/pkg/techdetect` |
| `netcheck/internal/subenum` | `github.com/Dezoxy/netcheck/pkg/subenum` |
| `netcheck/internal/reverseip` | `github.com/Dezoxy/netcheck/pkg/reverseip` |
| `netcheck/internal/wayback` | `github.com/Dezoxy/netcheck/pkg/wayback` |
| `netcheck/internal/tlsaudit` | `github.com/Dezoxy/netcheck/pkg/tlsaudit` |
| `netcheck/internal/takeover` | `github.com/Dezoxy/netcheck/pkg/takeover` |
| `netcheck/internal/portscan` | `github.com/Dezoxy/netcheck/pkg/portscan` |
| `netcheck/internal/pathenum` | `github.com/Dezoxy/netcheck/pkg/pathenum` |
| `netcheck/internal/report` | `github.com/Dezoxy/netcheck/pkg/report` |
| `netcheck/internal/diff` | `github.com/Dezoxy/netcheck/pkg/diff` |
| `netcheck/internal/target` | `github.com/Dezoxy/netcheck/pkg/target` |

Mechanical fix:

```bash
find . -name '*.go' -print0 | xargs -0 sed -i '' \
  -E 's|"netcheck/internal/(check\|diff\|dnscompare\|ipinfo\|pathenum\|portscan\|report\|reverseip\|route\|secheaders\|subenum\|takeover\|target\|techdetect\|tlsaudit\|wayback)|"github.com/Dezoxy/netcheck/pkg/\1|g'

# Then in your go.mod
go get github.com/Dezoxy/netcheck@v2.0.0
go mod tidy
```

If you had a `replace netcheck => /path/to/local/clone` for development, update both sides:

```
replace github.com/Dezoxy/netcheck => /path/to/local/clone
```

`internal/config` and `internal/webui` stay internal — they were tied to the CLI binary and never intended for external import.

## 3. What did NOT change in v2.0

Worth calling out so you don't go looking:

- **CLI subcommand names** — all v1.x subcommands keep their names. `full`, `dns`, `route`, `ip`, `headers`, `tech`, `subs`, `reverse`, `arch`, `tls`, `takeover`, `ports`, `enum`, `audit`, `diff`, `watch`, `app`, `menu`, `config show`, `completion`.
- **CLI flag names** — `--output`, `--out`, `--config`, `--insecure`, `--i-have-authorization`, `--type`, `--resolver`, `--no-defaults`, `--max-hops`, `--no-asn`, etc. Same flags, same semantics.
- **Exit codes** — `0` ok, `1` check failed, `2` bad invocation. `netcheck diff` uses the `git diff --exit-code` convention (`1` = changes detected), unchanged from v1.9.
- **Config file shape** — every key in `config.example.yaml` works as before.
- **Environment variables** — `NETCHECK_CONFIG`, `NETCHECK_TIMEOUT`, `NETCHECK_USER_AGENT`, `NETCHECK_AUTHORIZED`.
- **Web app URLs** — `/api/check/*`, `/api/reports`, etc.

## 4. New goodies you'll probably enjoy

These are additive (no migration needed) but worth knowing:

- `-j` is `--output json`. `-o` is `--out`. Useful for one-liners.
- `netcheck diff <a.json> <b.json>` for structured comparison of two saved reports.
- `netcheck watch [--interval N] -- <subcommand> ...` for re-run-and-diff workflows.
- `netcheck completion {bash|zsh|fish|powershell}` for shell completion.
- `netcheck ports` now banner-grabs on open ports by default. Disable with `--no-banners`.
- `POST /api/check/ports/stream` returns live SSE progress (used by the web app).
- Every check engine is importable as a Go library under `github.com/Dezoxy/netcheck/pkg/...` — see the "Use as a library" section in [README.md](README.md).

See [STABILITY.md](STABILITY.md) for the full v2.x contract.
