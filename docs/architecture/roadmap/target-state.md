## Roadmap

There are no dates. Items are ordered by what the current risks and debt ask
for first; everything else is unscheduled, as the original plan left it.

### Next

- Nothing scheduled. RISK-003 was mitigated by decision 4; per-user access
  would be the next step if netcheck is ever shared between people.

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
