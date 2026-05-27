# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning follows [SemVer](https://semver.org/) — see [STABILITY.md](STABILITY.md) for the v1.x compatibility promise.

Per-release notes are also generated automatically by `goreleaser` and attached to each [GitHub release](https://github.com/Dezoxy/netcheck/releases).

## [2.3.0](https://github.com/Dezoxy/netcheck/compare/v2.2.0...v2.3.0) (2026-05-27)


### Features

* **dnscompare:** expand queryable record types and add scan-type tiers ([#84](https://github.com/Dezoxy/netcheck/issues/84)) ([31d3c89](https://github.com/Dezoxy/netcheck/commit/31d3c892fa59ec833552c8d460411bd7c387eeed))

## [2.2.0](https://github.com/Dezoxy/netcheck/compare/v2.1.0...v2.2.0) (2026-05-27)


### Features

* R-13 UDP port scan (service-aware, privilege-free) ([#80](https://github.com/Dezoxy/netcheck/issues/80)) ([c6577c2](https://github.com/Dezoxy/netcheck/commit/c6577c26fd206b6934fd572549aa74f77c350498))
* **web:** R-10 visual fidelity polish (brand mark + card glow + central Run Check) ([#73](https://github.com/Dezoxy/netcheck/issues/73)) ([33f3ab2](https://github.com/Dezoxy/netcheck/commit/33f3ab27bf3540bef407692f1c177e82c94c1a53))
* **web:** R-11 polish v2 — glassy sidebar + brand-in-sidebar + atom icon ([#76](https://github.com/Dezoxy/netcheck/issues/76)) ([7bb7e30](https://github.com/Dezoxy/netcheck/commit/7bb7e30d75b2fa128748fdce91fd318705c84482))
* **web:** R-12 interactive loading overlay (progress ring + cycling status) ([#78](https://github.com/Dezoxy/netcheck/issues/78)) ([7c8d691](https://github.com/Dezoxy/netcheck/commit/7c8d69196972cfae40d90bd24cd13d12e911851c))


### Bug fixes

* **web:** anchor sidenav brand + nav to the top (R-11 follow-up) ([#77](https://github.com/Dezoxy/netcheck/issues/77)) ([c558768](https://github.com/Dezoxy/netcheck/commit/c5587686df77c16017f3c3b08cd9917e6049ab28))
* **web:** show results after landing Run Check (Codex P1 follow-up to [#73](https://github.com/Dezoxy/netcheck/issues/73)) ([#74](https://github.com/Dezoxy/netcheck/issues/74)) ([4105ee7](https://github.com/Dezoxy/netcheck/commit/4105ee7a3bfe9941459d8e8e2bb24c6fc8c0bb6f))

## [2.1.0](https://github.com/Dezoxy/netcheck/compare/v2.0.1...v2.1.0) (2026-05-26)


### Features

* **web:** R-1 design tokens, AppShell, landing (redesign 1/9) ([#63](https://github.com/Dezoxy/netcheck/issues/63)) ([230192a](https://github.com/Dezoxy/netcheck/commit/230192a94dcc5d7f7f4667e4fd5c351bebacca2b))
* **web:** R-2 ModeCards + category-level auth banner (redesign 2/9) ([#64](https://github.com/Dezoxy/netcheck/issues/64)) ([37c5131](https://github.com/Dezoxy/netcheck/commit/37c5131d3a88b5e81a9e6153433f0142521c5184))
* **web:** R-4 Network workbench touch-ups (redesign 4/9) ([#66](https://github.com/Dezoxy/netcheck/issues/66)) ([6593d61](https://github.com/Dezoxy/netcheck/commit/6593d61c689c8caf1513b9748187446d3d258595))
* **web:** R-6 Scanning workbench touch-ups (redesign 6/9) ([#68](https://github.com/Dezoxy/netcheck/issues/68)) ([7c4296c](https://github.com/Dezoxy/netcheck/commit/7c4296c5b9a5ee4980175c44f9c49e41e726b6cd))
* **web:** R-9 mobile polish (redesign 9/9) ([#71](https://github.com/Dezoxy/netcheck/issues/71)) ([a8c5958](https://github.com/Dezoxy/netcheck/commit/a8c59584361c83c6f2e8b6dd9d1ea216b9033c3a))

## [2.0.1](https://github.com/Dezoxy/netcheck/compare/v2.0.0...v2.0.1) (2026-05-25)


### Documentation

* STABILITY for v2.x + MIGRATING from v1.x (v2 cleanup 4/4) ([#61](https://github.com/Dezoxy/netcheck/issues/61)) ([5efa08c](https://github.com/Dezoxy/netcheck/commit/5efa08c87e6a57526d256c469a3ec32a29abecc0))

## [2.0.0](https://github.com/Dezoxy/netcheck/compare/v1.10.0...v2.0.0) (2026-05-25)


### ⚠ BREAKING CHANGES

* public pkg/ + module path → github.com/Dezoxy/netcheck (v2 cleanup 3/4) ([#60](https://github.com/Dezoxy/netcheck/issues/60))
* **schema:** normalize JSON field names (v2 cleanup 2/4) ([#58](https://github.com/Dezoxy/netcheck/issues/58))

### Features

* **cli:** -j and -o shortcut flags (v2 cleanup 1/4) ([#57](https://github.com/Dezoxy/netcheck/issues/57)) ([a179378](https://github.com/Dezoxy/netcheck/commit/a1793783c0ed4918279ce246b206ee69bfae02ca))
* public pkg/ + module path → github.com/Dezoxy/netcheck (v2 cleanup 3/4) ([#60](https://github.com/Dezoxy/netcheck/issues/60)) ([ee1803d](https://github.com/Dezoxy/netcheck/commit/ee1803df1329d6b98a7434a5d5dcb925ff5d4856))
* **schema:** normalize JSON field names (v2 cleanup 2/4) ([#58](https://github.com/Dezoxy/netcheck/issues/58)) ([2e99c04](https://github.com/Dezoxy/netcheck/commit/2e99c0405a45d5746a450f0161061e37ceb0883c))

## [1.10.0](https://github.com/Dezoxy/netcheck/compare/v1.9.0...v1.10.0) (2026-05-25)


### Features

* **app:** SSE streaming for ports scan (live progress in web UI) ([#54](https://github.com/Dezoxy/netcheck/issues/54)) ([66bc257](https://github.com/Dezoxy/netcheck/commit/66bc25746c96354493f1682fcc297b5b42183c9b))

## [1.9.0](https://github.com/Dezoxy/netcheck/compare/v1.8.0...v1.9.0) (2026-05-25)


### Features

* `netcheck diff` and `netcheck watch` (history mode) ([#52](https://github.com/Dezoxy/netcheck/issues/52)) ([515ebf5](https://github.com/Dezoxy/netcheck/commit/515ebf50a93b101cd2728ca0cc249c925e797d96))

## [1.8.0](https://github.com/Dezoxy/netcheck/compare/v1.7.0...v1.8.0) (2026-05-25)


### Features

* **cli:** shell completions (bash, zsh, fish, powershell) ([#49](https://github.com/Dezoxy/netcheck/issues/49)) ([e7f2511](https://github.com/Dezoxy/netcheck/commit/e7f2511be0a8fd221fc09157091c45a2f50cc661))
* **ports:** banner grab on open ports ([#50](https://github.com/Dezoxy/netcheck/issues/50)) ([db2069a](https://github.com/Dezoxy/netcheck/commit/db2069a44f4b14f682a571812eea5b93cc25437c))

## [1.7.0](https://github.com/Dezoxy/netcheck/compare/v1.6.1...v1.7.0) (2026-05-25)


### Features

* **web:** add audit mode to the React workbench ([#45](https://github.com/Dezoxy/netcheck/issues/45)) ([4728993](https://github.com/Dezoxy/netcheck/commit/47289938d0e65625dab622d86c0d83e425b7b092))

## [1.6.1](https://github.com/Dezoxy/netcheck/compare/v1.6.0...v1.6.1) (2026-05-25)


### Bug fixes

* **web:** kill the tsc incremental cache that bricks local builds ([#43](https://github.com/Dezoxy/netcheck/issues/43)) ([16a93fa](https://github.com/Dezoxy/netcheck/commit/16a93fa112f27499a431c115b467974ee0ce0782))

## [1.6.0](https://github.com/Dezoxy/netcheck/compare/v1.5.0...v1.6.0) (2026-05-25)


### Features

* **audit:** add `netcheck audit <target>` aggregate command ([#41](https://github.com/Dezoxy/netcheck/issues/41)) ([1a12ce5](https://github.com/Dezoxy/netcheck/commit/1a12ce5e4d5298f6c6102fb97f36a44963584369))
* **release:** Homebrew Cask + Scoop bucket scaffolding (skip_upload, flip to enable) ([#40](https://github.com/Dezoxy/netcheck/issues/40)) ([e46bf79](https://github.com/Dezoxy/netcheck/commit/e46bf79ded327e7adf66d10f4ea95c7504733294))

## [1.5.0](https://github.com/Dezoxy/netcheck/compare/v1.4.1...v1.5.0) (2026-05-24)


### Features

* **web:** wire 9 v1.4 commands into the React workbench ([#38](https://github.com/Dezoxy/netcheck/issues/38)) ([21c79b2](https://github.com/Dezoxy/netcheck/commit/21c79b29bd248572a0f4d408fec1d70541945879))

## [1.4.1](https://github.com/Dezoxy/netcheck/compare/v1.4.0...v1.4.1) (2026-05-24)


### Documentation

* align README/CHANGELOG/plan with what v1.4.0 actually shipped ([#36](https://github.com/Dezoxy/netcheck/issues/36)) ([70016e9](https://github.com/Dezoxy/netcheck/commit/70016e9e9d1fc3bdc8b2f8636477bead4d7c4fa6))

## [1.4.0](https://github.com/Dezoxy/netcheck/compare/v1.3.3...v1.4.0) (2026-05-23)

> **Active-scanning suite. Read [`docs/ETHICS.md`](docs/ETHICS.md) before using these.**

### Features

* **authz:** ethics gate infrastructure (`--i-have-authorization` flag, `NETCHECK_AUTHORIZED` env var) + [`docs/ETHICS.md`](docs/ETHICS.md) — every v1.4 active-scanning command refuses to run without explicit opt-in.
* **tls:** `netcheck tls <host>` — full TLS audit. Probes every TLS protocol (1.0–1.3) and every cipher suite Go can offer; captures cert chain; grades deprecated protocols, weak ciphers, expired/expiring/self-signed certs.
* **takeover:** `netcheck takeover <domain>` — CNAME → built-in catalog (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Bitbucket Cloud, Ghost) → vulnerability verdict via HTTP fingerprint match.
* **ports:** `netcheck ports <host>` — parallel TCP connect scan. Default top-100 nmap ports, `--ports` for explicit lists with dash-ranges, builtin port→service map.
* **enum:** `netcheck enum <url>` — HTTP path enumeration against a ~70-entry builtin wordlist (or `--wordlist`). Categorizes by status: found / redirect / blocked / auth-required / server-error.
* v1.5 active scanning (tls, takeover, ports, enum) behind --i-have-authorization gate ([#34](https://github.com/Dezoxy/netcheck/issues/34)) ([1eadaae](https://github.com/Dezoxy/netcheck/commit/1eadaaeea1681425f139c4808d46ed278633d87b))

> **Note on the version number:** This release bundles what the roadmap and PRs called "v1.4 passive recon" AND "v1.5 active scanning" under a single `v1.4.0` tag. The split was a planning artefact — release-please cut one minor version for everything because the passive-recon PR (#32) squash-merged with a `docs:` title that didn't trigger an auto-bump. See [STABILITY.md](STABILITY.md) and [`docs/netcheck_tool_project_plan.md`](docs/netcheck_tool_project_plan.md) for the corrected timeline.

## [1.3.3](https://github.com/Dezoxy/netcheck/compare/v1.3.2...v1.3.3) (2026-05-23)

> Despite the `chore(main): release 1.3.3` label release-please applied, **this release actually shipped the v1.4 passive-recon suite as well as the roadmap docs.** The squash-merge subject of PR #32 was `docs(roadmap):` which release-please correctly classified as Documentation, but the PR's body contained five `feat:` sub-commits whose code went out the door. The Features bullets below are the corrected accounting.

### Features

* **headers:** `netcheck headers <url>` — security-header report card. Grades HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy as pass / weak / missing; calls out Server / X-Powered-By disclosure.
* **tech:** `netcheck tech <url>` — Wappalyzer-style fingerprinting from one passive GET. Detects CMS (WordPress, Drupal, Ghost, Joomla, Magento), JS framework (Next.js, Nuxt, React, Vue, Angular), server (nginx, Apache, Caddy, IIS, LiteSpeed), CDN (Cloudflare, Fastly, CloudFront, Akamai, BunnyCDN), language/framework (PHP, Laravel, Django, Rails, ASP.NET), and common libraries (jQuery, Bootstrap). ~25 detectors, with a `<meta name="generator">` fallback for non-cataloged stacks.
* **subs:** `netcheck subs <domain>` — subdomain enumeration from public Certificate Transparency log aggregators (crt.sh + CertSpotter), in parallel. Dedupes the union, filters wildcards, surfaces per-finding `sources[]`.
* **reverse:** `netcheck reverse <ip>` — other hostnames on an IP. Sources: system reverse DNS (PTR), Hackertarget, and optional Shodan when `apis.shodan_api_key` is set in the config.
* **arch:** `netcheck arch <domain>` — Wayback Machine historical snapshots via archive.org's CDX API. Reports total count, first/last-seen dates, and a sample of the most-recent unique URLs.
* **config:** new `apis:` block in `config.example.yaml` for optional API keys (currently just `shodan_api_key`). `netcheck config show` reports `set` / `(not set)` per key — never the value itself.
* **security:** `.env` and `.env.*` added to `.gitignore` so accidental secret leakage is harder.

### Documentation

* **roadmap:** add v1.4 passive recon plan ([#32](https://github.com/Dezoxy/netcheck/issues/32)) ([0ed5b05](https://github.com/Dezoxy/netcheck/commit/0ed5b05e131d287162e9e1d34242cbc1cdcaae2a))

## [1.3.2](https://github.com/Dezoxy/netcheck/compare/v1.3.1...v1.3.2) (2026-05-22)


### Bug fixes

* **ci:** run goreleaser in same workflow as release-please (binaries still missing on v1.3.1) ([#29](https://github.com/Dezoxy/netcheck/issues/29)) ([94d9d8f](https://github.com/Dezoxy/netcheck/commit/94d9d8f824ba519b983ac4d8e7fd591a13be7758))

## [1.3.1](https://github.com/Dezoxy/netcheck/compare/v1.3.0...v1.3.1) (2026-05-22)


### Bug fixes

* **ci:** trigger release workflow on release-published (binaries missing on v1.1.2 / v1.2.0 / v1.3.0) ([#27](https://github.com/Dezoxy/netcheck/issues/27)) ([4ff0433](https://github.com/Dezoxy/netcheck/commit/4ff0433d86fe9df95e100f56be9b9af690579c6a))

## [1.3.0](https://github.com/Dezoxy/netcheck/compare/v1.2.0...v1.3.0) (2026-05-22)


### Features

* **build:** make app produces ./bin/netcheck + skips redundant npm ci ([661ca82](https://github.com/Dezoxy/netcheck/commit/661ca82a857e52f82c693327fc9bad72554c15f1))
* **build:** make app produces ./bin/netcheck + skips redundant npm ci ([3606d67](https://github.com/Dezoxy/netcheck/commit/3606d67456434e68272f17b3f99a7d6d1b46d99c))

## [1.2.0](https://github.com/Dezoxy/netcheck/compare/v1.1.2...v1.2.0) (2026-05-22)


### Features

* **app:** wire DNS, Route, IP endpoints + saved-reports CRUD ([ebb6a48](https://github.com/Dezoxy/netcheck/commit/ebb6a48141d44be99a5fa03b21ac72a786dbce2f))
* **web:** mode-switching, DNS/Route/IP panels, saved reports, recent rerun ([a347137](https://github.com/Dezoxy/netcheck/commit/a347137c562353940fe8a448b73bb7b916e599e5))
* wire DNS/Route/IP web tabs + saved-reports + recent rerun ([078a757](https://github.com/Dezoxy/netcheck/commit/078a757b87c2e1d55cb1714e8dc66b0716d1f0f3))

## [1.1.2](https://github.com/Dezoxy/netcheck/compare/v1.1.1...v1.1.2) (2026-05-22)


### Bug fixes

* use npm ci in web-build to prevent lockfile drift ([59d8d1f](https://github.com/Dezoxy/netcheck/commit/59d8d1f97e8367b7d5136fd64e279aedb8b543e6))
* use npm ci in web-build to prevent lockfile drift ([6af2341](https://github.com/Dezoxy/netcheck/commit/6af23412e8717c31a136a2c125e62310da19a5ef))

## [1.1.0]

- **Local React/PWA workbench:** `netcheck app` serves an embedded browser UI
  on `127.0.0.1:8787` for visual full checks, recent checks, and JSON export.
- **Shared Go full-check path:** the local JSON API reuses the same
  DNS/TCP/TLS/HTTP orchestration as the CLI through `BuildFullReport`.
- **Web app delivery:** Vite-built frontend assets live in `web/`, are embedded
  in the Go binary, and include homescreen/PWA metadata.
- **Web app coverage:** local API tests cover full-check success, insecure TLS,
  JSON validation, command startup failures, and embedded workbench assets.
- **CI/report reliability:** report expiry golden tests use the report clock,
  and GitHub workflows use Node 24 action majors.

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

[1.1.0]: https://github.com/Dezoxy/netcheck/releases/tag/v1.1.0
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
