## Roadmap

There are no dates. Items are ordered by what the current risks and debt ask
for first; everything else is unscheduled, as the original plan left it.

### Next

- Decide whether the local web server needs authentication (RISK-003), for
  example a per-session token printed at start-up. Worth it once the server
  is meant to be reached from other machines.

### Unscheduled

- Native TCP traceroute, removing the dependency on the system tool (TD-002).
- Multi-arch container images with `linux/arm64` (TD-004).
- HTTP/3 and QUIC checks.
- A browser-like mode (HSTS cache, cookies, HTTP/3) that narrows the gap
  principle P-02 describes.
- Proxy and VPN detection.
- A Prometheus exporter and a terminal UI.
- Activating the Homebrew tap and Scoop bucket (configured, not publishing;
  see the release runbook in `docs/operations/`).

### Out of scope

Owned by other tools, so not planned at all (principle P-06): exploitation
frameworks, CVE matching at scale, intercepting web proxies and credential
brute-forcing.
