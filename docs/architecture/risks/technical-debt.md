## Technical debt

Known shortcuts and their cost. None is urgent on its own; each has a trigger
that would make it worth paying down.

| ID | Debt | Evidence | Cost today | Pay down when |
|---|---|---|---|---|
| TD-001 | The built web UI (`internal/webui/dist/`) is committed, and nothing checks it still matches `web/`. | Rebuilding on `main` after the September 2026 dependency updates produced different asset files than the committed ones. | The binary can embed a UI older than its source; reviews of `web/` changes do not show the shipped bundle. | A release ships a stale UI, or a `web/` change needs to reach users quickly. |
| TD-002 | `netcheck route` shells out to the operating system's `traceroute` or `tracert`. | `pkg/route`; the container image has no such binary. | `route` fails in the container image and depends on each OS's tool and output format. | Native TCP traceroute (roadmap) is picked up. |
| TD-003 | The workbench loads its fonts from Google Fonts. | `web/index.html` links `fonts.googleapis.com` and `fonts.gstatic.com`. | Every workbench load contacts a third party, which bends principle P-04 and fails offline. | Any privacy-motivated change, or offline use matters. Self-hosting the two fonts removes it. |
| TD-004 | The container image is built for linux/amd64 only. | `.goreleaser.yml` `dockers` section. | Arm64 hosts (Apple silicon servers, Raspberry Pi) run it under emulation or not at all. | Someone needs the image on arm64 (roadmap). |
