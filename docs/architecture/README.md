# Architecture

## System

Netcheck: a single-binary network diagnostics CLI with a local web workbench.

## Purpose

Explain what happens between the user's machine and a target (DNS, TCP, TLS,
HTTP, routing, IP ownership, resolver disagreement), and, with explicit
authorisation, run active checks against hosts the user may test. It runs on
the user's own machine; there is no hosted service.

## Reading paths

The Documentation tab and the PDF are built from [overview/](overview/):

1. [Overview](overview/01-netcheck.md): what netcheck is, its building blocks
   and where it runs.
2. [Scope](overview/02-scope.md): what is in and out, the trust boundary and
   the known limits.
3. [Glossary](overview/03-glossary.md).

Per-audience reading paths, requirements, decisions and the risk register are
not written yet; they follow in a separate change once each has evidence
behind it.

## Architecture model

- [workspace.dsl](workspace.dsl) is the entry point; fragments are in
  [model/](model/). [styles-shared.dsl](model/styles-shared.dsl) is copied
  unchanged from architecture-base.
- The model follows the `architecture-views` and `architecture-docs` skills in
  [.agents/skills/](../../.agents/skills/), copied from
  [Dezoxy/architecture-base](https://github.com/Dezoxy/architecture-base).

```bash
make arch-view    # http://localhost:8080/workspace/1
make arch-check   # Structurizr validate + inspect; fails on an inspect ERROR
make arch-docs    # documentation consistency, including 80-column prose
make arch-pdf     # Documentation tab + every view as one PDF, in generated/
```

The Structurizr and Pandoc image pins are at the top of the architecture block
in the root [Makefile](../../Makefile). `workspace.json`, `.structurizr/` and
`generated/` are gitignored: every view uses automatic layout.

## View register

| Key | Audience | Question | Scope / abstraction | Selection rule | Omitted on purpose | Source evidence | Update trigger | Visual check |
|---|---|---|---|---|---|---|---|---|
| SystemContext | Everyone | What does netcheck talk to, and who uses it? | System context | `include *` | Other Websites (a security finding, shown in Security) | `cmd/root.go`, `pkg/*` clients, `web/index.html` | A new external service, user type or dependency | Checked 2026-09-21 (PNG, 2026.09.19): readable, no overlaps |
| Containers | Engineers | What are the building blocks, and how does the workbench reach the probe engine? | Containers + user + Google Fonts | Named elements | Probe targets and lookup services (ProbeDependencies) | `main.go`, `cmd/app.go`, `internal/webui/assets.go`, `web/` | A new runtime mode, store or API transport | Checked 2026-09-21 (PNG, 2026.09.19): readable after rank spacing fix |
| ProbeDependencies | Engineers | Which external services do the CLI and the local web server query or probe? | CLI, server and external systems | Named elements | Workbench, saved reports, users | `pkg/dnscompare`, `pkg/ipinfo`, `pkg/subenum`, `pkg/reverseip`, `pkg/wayback` | An external endpoint added or removed | Checked 2026-09-21 (PNG, 2026.09.19): readable; server and CLI arrows cross between rows, none through a box |
| Security | CTO, engineers | Who can reach the unauthenticated local web server, and what can it do on their behalf? | Containers across the browser and machine boundary | Named elements | Lookup services (no trust decision there) | `cmd/app.go` routes, `requireAuthInBody`, `cmd/authz.go` | Any auth, Origin/Host or bind-address change | Checked 2026-09-21 (PNG, 2026.09.19): readable, no overlaps |
| ActiveScanFlow | Engineers, stakeholders | What happens when the user runs an authorised port scan and saves it? | Runtime, 5 steps | Model relationships in order | The CLI path (same engine, same gate) | `cmd/app.go` ports stream handler, `web/src/api.ts` | A change to the scan gate, streaming or save path | Checked 2026-09-21 (PNG, 2026.09.19): readable, no overlaps |
| WorkstationDeployment | CTO, operators | Where does netcheck run when installed on the user's machine? | Workstation environment | `include *` | Homebrew/Scoop (not publishing) | `.goreleaser.yml` builds, `cmd/app.go` bind default | New OS/arch target or install channel | Checked 2026-09-21 (PNG, 2026.09.19): readable, no overlaps |
| ContainerDeployment | CTO, operators | Where does netcheck run when started from the GHCR image? | Container environment | `include *` | Other architectures (image is amd64 only) | `Dockerfile`, `.goreleaser.yml` dockers | Image, base, user or bind change | Checked 2026-09-21 (PNG, 2026.09.19): readable, no overlaps |

## Key decisions

No ADRs yet. The first ones (single static binary with the UI embedded,
loopback-by-default local server, consent flag for active checks) need their
original rationale confirmed before they are written; where it was never
recorded, the ADR will say so.

## Known risks

Recorded in the Scope page until the risk register exists. The local web
server now refuses cross-origin requests and unknown host names and caps the
scan concurrency an API caller can ask for; it still has no authentication, so
any non-browser client that reaches its port can use it.
