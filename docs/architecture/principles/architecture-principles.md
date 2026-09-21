## Architecture principles

The rules netcheck's design follows. Most were written down before the first
release, in the archived project plan; the source column says where.

| ID | Principle | Rationale | Implication | Source |
|---|---|---|---|---|
| P-01 | Report what was observed, not a single truth. | DNS answers vary by resolver, location, ISP, IP family, anycast and CDN balancing. | Output says "the IPs this resolver returned at this time", never "the real IP". DNS compare exists to show disagreement. | Plan §11 |
| P-02 | Explain ambiguity instead of hiding it. | Routers drop, rate-limit or hide traceroute probes; browsers add caches, HTTP/3 and proxies a CLI does not have. | A missing hop is reported as missing, not as a broken route; CLI results are not presented as what a browser would see. | Plan §11 |
| P-03 | IPv4 and IPv6 are equal. | Many real faults are one address family working while the other fails (mobile networks, home ISPs, VPNs). | Checks report each family's DNS and connectivity separately. | Plan §11 |
| P-04 | Nothing leaves the machine except the checks themselves. | A diagnostics tool sees which hosts its user cares about. | No telemetry; API keys are optional; config and reports are local files. Known exception: TD-003. | Plan §14 |
| P-05 | Guard at the entry point. | Library code should be callable from tests and other programs without policy baked in. | The authorisation gate lives in `cmd/` (CLI and API handlers); packages under `pkg/` have no notion of it. See decision 2. | Plan, v1.5 design constraints |
| P-06 | Stay a diagnostics tool. | Other tools own exploitation, CVE matching at scale, intercepting proxies and credential brute-force; adding them would blur what netcheck is for. | Those features are out of scope, not merely unscheduled. See the roadmap. | Plan, "Unscheduled" |
| P-07 | Extend contracts additively. | Integrators parse JSON and call the Go API (C-03). | New report types add a `kind`; new fields are optional. A breaking change waits for a major version. | STABILITY.md; plan, v1.4 design constraints |
