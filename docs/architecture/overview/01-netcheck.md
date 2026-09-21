# Netcheck

## Overview

netcheck explains what happens between the user's machine and a target: DNS
resolution and resolver disagreement, TCP, TLS, HTTP and redirects, timing, IP
ownership, CDN detection and the network route. With explicit authorisation it
also runs active checks such as port scans, TLS audits, path enumeration and
subdomain-takeover detection.

It is one statically linked Go binary. There is no hosted service, account or
backend: every instance runs on hardware the user controls, and every probe
leaves from the user's own network.

### Who uses it

Developers, SREs and network engineers diagnosing hosts they operate or are
authorised to test. The active checks are gated behind an explicit
authorisation flag; the rules are in
[ETHICS.md](https://github.com/Dezoxy/netcheck/blob/main/docs/ETHICS.md).

![Netcheck system context](embed:SystemContext)

### How it is built

The binary has two entry points over one probe engine (the packages under
`pkg/`):

- **CLI**: one diagnostic per invocation, an interval `watch`, or an
  interactive menu. Output is text, JSON, Markdown or HTML.
- **Local web server** (`netcheck app`): serves a React workbench embedded in
  the binary, plus a JSON and server-sent-events API over the same engine. It
  binds `127.0.0.1:8787` by default and has no authentication.

Saved reports are the only state the server keeps: one JSON file per report
in the user's data directory.

![Netcheck containers](embed:Containers)

Both entry points query the same external services. None needs an API key
except Shodan, which is used only when a key is configured.

![External services netcheck queries](embed:ProbeDependencies)

### Where it runs

On the user's workstation (macOS, Linux or Windows; amd64 or arm64), or as
the `ghcr.io/dezoxy/netcheck` container image (linux/amd64), which runs only
the web server.

![Netcheck on a workstation](embed:WorkstationDeployment)

![Netcheck from the container image](embed:ContainerDeployment)

### Compatibility promise

For v2.x, CLI flags, subcommands, `/api/*` shapes, exit codes, the JSON
schema, the exported `pkg/` API and configuration keys stay backward
compatible. Text output, default resolvers and fingerprint catalogues are
explicitly not covered. The full contract is in
[STABILITY.md](https://github.com/Dezoxy/netcheck/blob/main/STABILITY.md).
