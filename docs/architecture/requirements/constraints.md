## Constraints

Fixed conditions the design works within. Each is observed in the code or
configuration, or is a stated commitment; the source column says which.

| ID | Constraint | Source | Consequence |
|---|---|---|---|
| C-01 | netcheck ships as one statically linked binary with `CGO_ENABLED=0`; the web UI is embedded, not served from separate files. | `.goreleaser.yml` builds, `internal/webui/assets.go`; decision 1 | No system libraries at runtime; the container image can be `distroless/static`. The committed UI bundle must be rebuilt when `web/` changes (TD-001). |
| C-02 | The minimum Go version is 1.25. | `go.mod` | Standard-library features up to 1.25 are available to every build, including `http.CrossOriginProtection`. |
| C-03 | Everything listed in STABILITY.md stays backward compatible for all of v2.x: flags, subcommands, `/api/*` shapes, exit codes, the JSON schema, the exported `pkg/` API, config keys and `NETCHECK_*` variables. | [STABILITY.md](https://github.com/Dezoxy/netcheck/blob/main/STABILITY.md) | Changes to those surfaces are additive only; a removal or rename means v3. |
| C-04 | No privileged operations: no raw sockets, SYN scans or ICMP probing. netcheck runs as an ordinary user and stays on `net.Dial`. | Archived project plan, v1.5 design constraints; `pkg/portscan` | Port scans are TCP connect scans. `route` relies on the operating system's `traceroute` (TD-002). |
| C-05 | Active checks run only after explicit authorisation from the user. | `cmd/authz.go`, `requireAuthInBody` in `cmd/app.go`; decision 2 | Every active command and endpoint refuses by default; see the responsible-use policy. |
| C-06 | netcheck runs only on hardware the user controls. There is no hosted service, account or server-side data. | The model's deployment environments | There is no central place to enforce policy, collect errors or push updates; every safeguard has to live in the binary. |
