# 1. Ship netcheck as a single static Go binary

Date: 2026-05-19

## Status

Accepted

## Context

netcheck is a diagnostics tool people reach for on laptops, servers and
homelab hosts, often while something is already broken. It has to start fast,
install without a toolchain and speak DNS, TCP, TLS and HTTP well.

This record was written on 2026-09-21 from the reasoning in the archived
project plan (§2, "Recommended Language"), which predates the first release.

## Decision drivers

- One file to run on macOS, Linux, Windows and servers, with no runtime or
  virtual environment to manage.
- Strong standard-library support for DNS, TCP, HTTP and TLS.
- Fast startup, which matters for a command-line tool.
- Cross-compilation for every target from one machine.

## Considered options

1. Go
2. Python

## Decision

Build netcheck in Go and ship it as one statically linked binary
(`CGO_ENABLED=0`, constraint C-01). When the web workbench arrived it was
embedded into the same binary rather than shipped separately; see decision 3.

## Consequences

Positive:

- Install is "download one file"; the container image can be
  `distroless/static` with nothing else inside.
- CI cross-compiles all six OS and architecture targets (QA-02).

Negative / accepted trade-offs:

- The plan records that Python would have been faster for a throwaway
  prototype; that speed was given up for a tool meant to last.
- Anything not in Go's standard library or a pure-Go module has to be shelled
  out to or done without: `route` calls the system `traceroute` (TD-002).

## Related

- Requirements: C-01, C-02, QA-02
- Architecture views: WorkstationDeployment, ContainerDeployment
- Other ADRs: decision 3
