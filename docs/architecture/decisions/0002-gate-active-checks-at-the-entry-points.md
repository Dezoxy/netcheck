# 2. Gate active checks behind explicit authorisation at the entry points

Date: 2026-05-23

## Status

Accepted

## Context

v1.5 (shipped inside the v1.4.0 release) added checks that probe a target in
ways it could treat as an attack: TLS audits, takeover checks, port scans and
path enumeration. Running those against hosts the user may not test has legal
and ethical consequences, set out in the responsible-use policy
(`docs/ETHICS.md`, written in the same change).

This record was written on 2026-09-21 from the v1.5 design constraints in the
archived project plan and from the code.

## Decision drivers

- Nobody should run an active check by accident (C-05).
- The probe packages should stay reusable library code, callable from tests
  and other programs (P-05).
- No privileged operations (C-04).

## Considered options

Alternatives were not recorded. The plan describes the chosen shape as the
standard "guard at the entry point" pattern and gives no competing design.

## Decision

Every active command refuses to run unless the user passes
`--i-have-authorization` or sets `NETCHECK_AUTHORIZED`; refusal exits with code
2 and points at the policy. The API applies the same rule: an active endpoint
answers 403 unless the JSON body sets `i_have_authorization`. The check lives
only in `cmd/` (`cmd/authz.go`, `requireAuthInBody` in `cmd/app.go`); packages
under `pkg/` have no notion of authorisation. Active probes use ordinary
`net.Dial` connections: no SYN scans, raw sockets or ICMP.

## Consequences

Positive:

- Passive checks need no ceremony; active ones cannot start by accident.
- The flag, the environment variable and exit code 2 are part of the v2.x
  contract (STABILITY.md), so scripts can rely on them.

Negative / accepted trade-offs:

- The gate proves intent, not authorisation: it trusts whoever sets the flag.
  Through the local web server, that can currently be any web page
  (RISK-001).
- Go programs importing `pkg/` get no gate at all, by design.

## Risks

- RISK-001, RISK-002

## Related

- Requirements: C-04, C-05, QA-04
- Architecture views: Security, ActiveScanFlow
- Other ADRs: none
