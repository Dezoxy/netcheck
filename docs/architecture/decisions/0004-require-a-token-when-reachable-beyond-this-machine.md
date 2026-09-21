# 4. Require a token when the web server is reachable beyond this machine

Date: 2026-09-21

## Status

Accepted

## Context

After cross-origin and `Host` checks were added (RISK-001, RISK-002), the
local web server still had no authentication (RISK-003). Browsers could no
longer drive it from other sites, but any non-browser client that reached its
port could, including active scans with the authorisation flag.

How far that reaches depends on deployment. On a laptop, `netcheck app` binds
loopback, and a process already running as the same user could run the
`netcheck` binary directly, so a token adds little there. The exposure is when
the server is reachable from other machines: the container image binds
`0.0.0.0`, and the maintainer publishes it on a subdomain behind Caddy,
Traefik, nginx or a Cloudflare Tunnel. A proxy connects over loopback, so the
bind address alone does not reveal that the server is public.

STABILITY.md freezes the `/api/*` contract for v2.x, so requiring
authentication for existing local scripts would be a breaking change.

## Decision drivers

- Close RISK-003 where it is real: anything reachable from other machines.
- Keep v2.x compatible for local scripts (C-03).
- Work unchanged behind a reverse proxy or tunnel on a subdomain.
- One secret, no user store (C-06: no server-side accounts).

## Considered options

1. Token only on a non-loopback bind. Rejected: a reverse proxy or tunnel on
   the same host connects over loopback, so a public subdomain would stay
   open.
2. Token always, with an opt-out. Rejected for v2.x: it breaks every existing
   script that calls the local API and would need a v3 release.
3. Token only when the user asks for it. Rejected: container and subdomain
   deployments would stay exposed unless people knew to set it.
4. Token whenever the server is reachable beyond this machine: a non-loopback
   bind, or any `--allowed-host` name, which only makes sense behind a proxy.
   Chosen.

For the browser experience, a token the user pastes into the workbench was
considered and rejected in favour of a sign-in URL that sets a cookie.

## Decision

`netcheck app` generates a random 256-bit token at start-up, or takes
`NETCHECK_APP_TOKEN` (at least 16 characters) so the token survives restarts.
It is required on `/api/*` when the server binds a non-loopback address or
has any `--allowed-host`; `--auth` requires it on loopback too.

A browser opens the start-up URL once (`/?token=…`). The server sets an
`HttpOnly`, `SameSite=Strict` cookie that lasts 30 days, `Secure` when the request arrived over
HTTPS directly or per `X-Forwarded-Proto`, and redirects to the same page
without the token. Scripts send `Authorization: Bearer <token>`. The static
workbench and `/api/healthz` stay public: the workbench is the same bundle as
in the public repository and holds no data, and health checks need no secret.

Implemented in `cmd/app_auth.go`, behind the cross-origin and `Host` checks of
`cmd/app_security.go`.

## Consequences

Positive:

- Container and subdomain deployments are protected by default, with no
  change for `netcheck app` on a laptop.
- Behind a proxy, the cookie is scoped to the subdomain and marked `Secure`.

Negative / accepted trade-offs:

- Anyone who can read the start-up output has the token: `docker logs`, a
  shared terminal. A token from `NETCHECK_APP_TOKEN` is not printed.
- One token for everyone; there are no per-user identities or revocation
  other than restarting with a new token.
- On a shared multi-user machine the loopback default stays open to other
  local accounts unless `--auth` is set.

## Risks

- RISK-003 (mitigated)

## Related

- Requirements: C-03, C-06, QA-04
- Architecture views: Security, ContainerDeployment
- Other ADRs: decision 2, decision 3
