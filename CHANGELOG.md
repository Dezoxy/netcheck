# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning follows [SemVer](https://semver.org/) — see [STABILITY.md](STABILITY.md) for the v1.x compatibility promise.

Per-release notes are also generated automatically by `goreleaser` and attached to each [GitHub release](https://github.com/Dezoxy/netcheck/releases).

## [1.0.1]

- **Test coverage push: 20.8% → 85.4% project-wide.**
  - Golden-file tests for the entire `internal/report` rendering package (text, Markdown, HTML across all 4 commands). 0% → 84.7%.
  - httptest-based tests for `internal/check` HTTP, TLS, TCP, plus DNS lookup. 0% → 89.9%.
  - Fake-binary harness for `internal/route` Stream and Find tests. 43.9% → 90.6%.
  - ASNCache + RDAP cache tests in `internal/ipinfo`. 61.3% → 87.4%.
  - `recordValue` + `ParseTypes` + `EnsurePort` + `SystemResolvers` in `internal/dnscompare`. 64.4% → 85.6%.
  - End-to-end tests for every `RunX` function in `cmd/`, including subprocess-style stdin capture for the interactive menu. 7% → 83.7%.
  - Config file `resolvePath` and parse-error tests. 82.6% → 95.7%.
- **Refactor:** `RunFull`, `RunDNS`, `RunRoute`, `RunIP`, `RunConfigShow` now return an `int` exit code instead of calling `os.Exit` directly. `cmd.Run()` is the only `os.Exit` caller now. This is a pure refactor — exit codes are unchanged. Makes the runners testable without subprocess gymnastics.
- **`route.BuildArgs` / `route.InstallHint`** factored into `buildArgsFor(goos, ...)` / `installHintFor(goos)` testable internals. The exported API is unchanged.
- **Stable clock** for the report package's text IP renderer via a `nowFn` package var, so golden tests are deterministic.
- **Testable RDAP base URL:** `lookupRDAPAt(ctx, client, baseURL, ip)` extracted from `lookupRDAP` so httptest can substitute the bootstrap URL.

## [1.0.0] — Stable

- **Stability promise** — `STABILITY.md` documents the v1.x backward-compatibility contract for CLI flags, exit codes, JSON schema, and config file keys.
- **README rewrite** for first-time visitors: stronger pitch up top, demo block above install, roadmap and project history moved to a collapsible section at the bottom.
- **CHANGELOG.md** snapshotting v0.1 → v0.9.1.

## [0.9.1]

- Gate CI build matrix on the test job (`needs: test`). Builds no longer kick off in parallel with tests; tests must pass first.

## [0.9.0]

- New `netcheck config show` subcommand prints the active config (source file, resolved values, env-overridden User-Agent, configured resolvers). Supports `--output text|json|markdown|html`.
- New `--out <file>` flag on every command — writes the result to a file with auto-created parent directories; prints `Saved to <abs-path>` to stderr. Mirrors the menu's save flow for non-interactive use.
- **Reliability:**
  - Route exit code now returns `1` when zero hops are collected. Aligns with the other commands.
  - `staticcheck` added to CI before `go test`. Repo passes today; the gate catches future regressions.
- **Windows polish:** `winres/winres.json` defines a version-info resource; goreleaser regenerates `.syso` files (amd64 + arm64) before each release using the git tag. Windows .exe now shows ProductName, FileDescription, FileVersion, CompanyName in Task Manager and right-click Properties.
- **Tests:** new `cmd/menu_save_test.go`, `cmd/dns_test.go`, `internal/route/route_test.go`, `internal/ipinfo/ipinfo_test.go`, plus `httptest`-based mocks for RDAP and DoH HTTP round-trips. Coverage on `ipinfo` 38% → 61%, `dnscompare` 27% → 64%, `route` 35% → 44%.

## [0.8.1]

- Release pipeline now runs `go test -race ./...` as a goreleaser `before` hook. Releases refuse to ship if tests fail, regardless of whether `ci.yml` ran on the tagged commit. Closes the gap where a red commit could be tagged and published.

## [0.8.0]

- **Release automation via [`goreleaser`](https://goreleaser.com/).** Every `v*` tag triggers a release workflow that produces six cross-platform binaries (`linux/darwin/windows × amd64/arm64`) packaged as `.tar.gz` / `.zip` archives bundling `netcheck`, `README.md`, `LICENSE`, and `config.example.yaml`. SHA256 checksums in `checksums.txt`. Release notes auto-generated from commits since the previous tag.
- `cmd.Version` switched from `const` to `var` — build-time `-ldflags "-X netcheck/cmd.Version=…"` injects the value. `make build` uses `git describe`; goreleaser uses the clean tag; plain `go build` defaults to `"dev"`.
- `LICENSE` (MIT) added — bundled in every release archive.

## [0.7.1]

- Opt CI workflows into Node 24 via `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` ahead of GitHub's June 2026 Node 20 deprecation.

## [0.7.0]

- **Unit tests** for the pure-logic packages: `target.Parse` (94%), `target.NormalizeHost` (88%), `route.ParseHopLine` (93%), `dnscompare.Verdict` (full), `cmd.ParseFormat` (full).
- **GitHub Actions CI** (`.github/workflows/ci.yml`): `gofmt -l`, `go vet`, `go test -race -coverprofile` on push and PR.
- **Cross-platform build matrix** — verifies the binary compiles for all 6 supported targets on every PR.
- **Status badge** in the README. `make coverage` target for local runs.

## [0.6.1]

- Menu now offers to save each result as text / JSON / Markdown / HTML after every action. Auto-detects working-dir (saves into `bin/`) vs. installed (prompts with `~/Documents` as default). Files named `netcheck-<kind>-<host>-<timestamp>.<ext>`.

## [0.6.0]

- **YAML config file** at `~/.config/netcheck/config.yaml` (with `XDG_CONFIG_HOME` and `NETCHECK_CONFIG` lookup paths). Override-able defaults: `timeout`, `user_agent`, `follow_redirects`, `max_redirects`, `prefer_ipv6`, `resolvers`. Env vars `NETCHECK_TIMEOUT` and `NETCHECK_USER_AGENT` override file when set. Per-subcommand `--config <path>` flag for ad-hoc overrides.
- **DNS-over-TLS** and **DNS-over-HTTPS** resolver types via URL-style `--resolver` syntax: `tls://`, `dot://`, `https://`, `doh://`, `tcp://`, `udp://`. Bare `host[:port]` still means UDP — no breaking changes.
- Config-defined resolvers are added to every `netcheck dns` invocation; `--no-config-resolvers` skips them for one run.
- Side fix: `check.HTTP`'s hardcoded `netcheck/0.1` User-Agent is gone; main.go wires the real version (or config override) into both `check` and `ipinfo` at startup.

## [0.5.0]

- **`--output text|json|markdown|html`** on every command. Default `text` is byte-identical to v0.4.2 — no automation breakage.
- **Versioned JSON schema** (`"netcheck_version": "0.5.0"`) with a `"kind"` discriminator (`"full"` / `"dns"` / `"route"` / `"ip"`).
- **Markdown** with GitHub-flavored tables. **HTML** is single-file self-contained with inline CSS — no external requests, opens offline.

## [0.4.2]

- **Refactor:** flat `package main` split into `cmd/` + `internal/{target,check,dnscompare,route,ipinfo,report}`. `main.go` shrinks from 133 lines to 17. Git tracked most file moves as renames so `git blame` still works.

## [0.4.1]

- **Planning update:** project plan §16 rewritten with concrete scope per version from v0.4.1 through v1.0, plus a deferred-features section for v1.1+.

## [0.4]

- New `netcheck ip <ip|host>` subcommand. Reverse DNS, Team Cymru ASN, RDAP (org / abuse contact / registry), static CDN classification with confidence.
- DNS section of the `full` check now annotates each IP with ASN + CDN hint.
- First unit tests (cdn, rdap, ip).

## [0.3.1]

- **Interactive menu** (`netcheck menu` or bare `netcheck` on a terminal). Input normalization: strips schemes, paths, queries, ports, surrounding whitespace, and quotes.
- Build output moved to `./bin/`.

## [0.3.0]

- New `netcheck route <host>` subcommand. System `traceroute` / `tracert` wrapper. Streams hops as they arrive, parses multi-probe RTTs and partial timeouts. Per-hop Team Cymru ASN annotation (skipped on private/link-local IPs).

## [0.2.0]

- New `netcheck dns <host>` subcommand. Queries System, Cloudflare, Google, and Quad9 in parallel. Reports per-record-type with an agree/disagree verdict. Supports `--type` (A, AAAA, CNAME, MX, TXT, NS, SOA), `--resolver` (repeatable), `--no-system`, `--no-defaults`.

## [0.1.0]

- Initial release. `netcheck <target>` runs DNS, TCP, TLS, and HTTP checks with `httptrace` timing breakdown and redirect chain.

[1.0.1]: https://github.com/Dezoxy/netcheck/releases/tag/v1.0.1
[1.0.0]: https://github.com/Dezoxy/netcheck/releases/tag/v1.0.0
[0.9.1]: https://github.com/Dezoxy/netcheck/releases/tag/v0.9.1
[0.9.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.9.0
[0.8.1]: https://github.com/Dezoxy/netcheck/releases/tag/v0.8.1
[0.8.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.8.0
[0.7.1]: https://github.com/Dezoxy/netcheck/releases/tag/v0.7.1
[0.7.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.7.0
[0.6.1]: https://github.com/Dezoxy/netcheck/releases/tag/v0.6.1
[0.6.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.6.0
[0.5.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.5.0
[0.4.2]: https://github.com/Dezoxy/netcheck/releases/tag/v0.4.2
[0.4.1]: https://github.com/Dezoxy/netcheck/releases/tag/v0.4.1
[0.4]: https://github.com/Dezoxy/netcheck/releases/tag/v0.4
[0.3.1]: https://github.com/Dezoxy/netcheck/releases/tag/v0.3.1
[0.3.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.3
[0.2.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.2
[0.1.0]: https://github.com/Dezoxy/netcheck/releases/tag/v0.1
