# 3. Serve the web workbench from the binary, bound to loopback by default

Date: 2026-05-22

## Status

Accepted

## Context

v1.1 added a visual workbench for people who prefer a browser to a terminal.
It needed a server to run checks, since a browser cannot open raw DNS, TCP or
TLS connections itself.

This record was written on 2026-09-21 from the archived project plan (v1.1)
and the code.

## Decision drivers

- Keep decision 1's single binary: no separate web server or assets to
  install.
- Reuse the CLI's probe engine rather than build a second one.
- The original reason for binding to loopback was **not recorded**. The only
  later note is the release runbook's description of `127.0.0.1` as "correct
  for a laptop".

## Considered options

Not recorded.

## Decision

`netcheck app` starts an HTTP server in the same binary. The React workbench
is built into `internal/webui/dist/` and embedded with `go:embed`, and the API
calls the same `pkg/` code as the CLI. The server binds `127.0.0.1:8787`
unless `--listen` says otherwise; the container image passes `0.0.0.0:8787`
because a loopback bind inside a container is unreachable.

## Consequences

Positive:

- One install gives both the CLI and the workbench, with identical results.
- By default only processes on the same machine can reach the server.

Negative / accepted trade-offs:

- The server has no authentication and, as built, no cross-origin or `Host`
  checks. Loopback keeps other machines out but not web pages in the user's
  own browser (RISK-001).
- The built UI is committed and can drift from `web/` (TD-001).
- The container image is reachable from wherever its port is published.

## Risks

- RISK-001

## Related

- Requirements: C-01, C-06
- Architecture views: Containers, Security, WorkstationDeployment,
  ContainerDeployment
- Other ADRs: decision 1
