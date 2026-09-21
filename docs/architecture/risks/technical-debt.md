## Technical debt

Known shortcuts and their cost. None is urgent on its own; each has a trigger
that would make it worth paying down.

| ID | Debt | Evidence | Cost today | Pay down when |
|---|---|---|---|---|
| TD-001 | **Paid down 2026-09-21.** The built web UI (`internal/webui/dist/`) is committed, because `go:embed` and `go install` need it. It had drifted from `web/`. | Rebuilding on `main` after the September 2026 dependency updates produced different asset files than the committed ones. | None now: CI rebuilds it on every pull request and fails if the committed files differ. The build is byte-identical across macOS and Linux on the Node major pinned in `web/.nvmrc`. | Reopen if the drift check has to be disabled, for example because builds stop being reproducible. |
| TD-002 | `netcheck route` shells out to the operating system's `traceroute` or `tracert`. | `pkg/route`; the container image has no such binary. | `route` fails in the container image and depends on each OS's tool and output format. | Native TCP traceroute (roadmap) is picked up. |
| TD-003 | The workbench loads its fonts from Google Fonts. | `web/index.html` links `fonts.googleapis.com` and `fonts.gstatic.com`. | Every workbench load contacts a third party, which bends principle P-04 and fails offline. | Any privacy-motivated change, or offline use matters. Self-hosting the two fonts removes it. |
| TD-004 | **Paid down 2026-09-21.** The container image was built for linux/amd64 only. | `.goreleaser.yml` now uses `dockers_v2` with `linux/amd64` and `linux/arm64`. | None now: arm64 hosts (Apple silicon servers, Raspberry Pi) run it natively. | Reopen if a platform has to be dropped from the image. |
