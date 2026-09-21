# Release and distribution

Runbook for the channels a release publishes to: the container image, the
Homebrew Cask and the Scoop bucket.

netcheck's release pipeline can publish to three channels alongside the GitHub release:

- **Container image** at `ghcr.io/dezoxy/netcheck` →
  `docker run ghcr.io/dezoxy/netcheck` (Linux/amd64). **Active.**
- **Homebrew Cask** at `Dezoxy/homebrew-netcheck` →
  `brew install dezoxy/netcheck/netcheck` (macOS). Wired, not pushing.
- **Scoop bucket** at `Dezoxy/scoop-netcheck` →
  `scoop bucket add netcheck https://github.com/Dezoxy/scoop-netcheck && scoop install netcheck`
  (Windows). Wired, not pushing.

The brew/scoop half is **wired but not active** — every release builds the Cask
file + Scoop manifest into `dist/` for inspection, then stops short of pushing
to the tap/bucket repos. Most of this document walks you through flipping that
switch; the container image below is already live.

> **Linux Homebrew users**: Cask is macOS-only. You keep the existing
> direct-download path from the GitHub release page
> (`netcheck_*_linux_*.tar.gz`). If we ever want a Linux-brew formula, that's a
> separate addition.

## Current status

Last verified 2026-08-25; update this list, not a separate TODO file.

- [x] Container image live on GHCR and public since v2.9.0: every release
  pushes `ghcr.io/dezoxy/netcheck:{version,major.minor,latest}` with the
  built-in `GITHUB_TOKEN`.
- [x] Empty tap and bucket repos exist:
  [Dezoxy/homebrew-netcheck](https://github.com/Dezoxy/homebrew-netcheck) and
  [Dezoxy/scoop-netcheck](https://github.com/Dezoxy/scoop-netcheck).
- [x] `.goreleaser.yml` has `homebrew_casks:` and `scoops:` blocks, both
  `skip_upload: true`.
- [x] `release-please.yml` and `release.yml` pass `GORELEASER_PAT` with a
  `|| ''` fallback, so releases stay green while the secret is absent.
- [x] Local dry-run (`goreleaser release --snapshot --clean --skip=publish`)
  produces a valid Cask and Scoop manifest.
- [ ] Create the `GORELEASER_PAT` token and repository secret (Step 2).
- [ ] Flip `skip_upload` to `false` and verify the first push (Steps 3–4).

---

## Container image (GHCR)

Unlike the tap and bucket, this one is on. `goreleaser release` packages the
prebuilt `linux/amd64` binary with the repo [`Dockerfile`](../../Dockerfile) and
pushes to GHCR during the release job.

| Piece | Where |
|---|---|
| goreleaser config | `dockers:` block in [`.goreleaser.yml`](../../.goreleaser.yml) |
| Registry login | `docker/login-action` step in [`.github/workflows/release-please.yml`](../../.github/workflows/release-please.yml) |
| Credentials | The workflow's built-in `GITHUB_TOKEN` — no PAT needed, because GHCR lives in the same org. The job declares `packages: write`. |

Tags pushed per release: `:<version>` (e.g. `2.9.0`), `:<major>.<minor>` (`2.9`), and `:latest`.

**Base image:** `gcr.io/distroless/static:nonroot` — no shell, no package
manager, runs as uid 65532. The binary is `CGO_ENABLED=0` static with the web UI
embedded, so nothing else is needed at runtime. One consequence: there is no
`traceroute` in the image, so `netcheck route` exits 2 inside the container.
Every other command works.

**The default `CMD` is `app --listen 0.0.0.0:8787`.** The CLI defaults to
`127.0.0.1` — correct for a laptop, useless in a container where loopback is the
container's own. Bind the published port to loopback on the host
(`-p 127.0.0.1:8787:8787`) if you don't want the workbench on your LAN.

### Package visibility — already public

A newly created GHCR package is **private**, and until someone flips it
`docker pull ghcr.io/dezoxy/netcheck` fails for anyone not logged in — including
the homelab host. This was flipped after the first image push (v2.9.0);
anonymous pulls work. Recorded here because it's invisible in the repo and easy
to forget if the package is ever recreated:

1. https://github.com/users/Dezoxy/packages/container/netcheck/settings (or the repo's Packages sidebar).
2. **Danger Zone → Change visibility → Public**.

To keep a package private instead, give the pulling host a read-only token:

```bash
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u Dezoxy --password-stdin
```

### Verify a release

```bash
docker pull ghcr.io/dezoxy/netcheck:latest
docker run --rm ghcr.io/dezoxy/netcheck version
docker run --rm -p 127.0.0.1:8787:8787 ghcr.io/dezoxy/netcheck   # then open http://127.0.0.1:8787/
```

### Not wired: Docker Hub

Deliberately skipped. To add it: a second entry under `image_templates`
(`docker.io/{{ .Env.DOCKERHUB_USERNAME }}/netcheck`), `DOCKERHUB_USERNAME` /
`DOCKERHUB_TOKEN` secrets, and a second `docker/login-action` step. Multi-arch
(`linux/arm64`) would need `docker_manifests:` plus a per-arch build — not worth
it until something actually needs ARM.

---

## Step 1 — Create the tap and bucket repos

Both must exist before goreleaser can push to them. Two empty GitHub repos under
your `Dezoxy` account:

| Repo | Visibility | What goreleaser writes |
|---|---|---|
| `Dezoxy/homebrew-netcheck` | Public (required by Homebrew) | `Casks/netcheck.rb`, one commit per release |
| `Dezoxy/scoop-netcheck` | Public (required by Scoop) | `bucket/netcheck.json`, one commit per release |

The names matter:

- `homebrew-netcheck` — Homebrew CLI auto-prepends `homebrew-` when you
  `brew tap dezoxy/netcheck`. Without the prefix, the tap won't work.
- `scoop-netcheck` — convention, not enforced; install path is just the repo URL.

Create both as empty repos. No README, no .gitignore — goreleaser's first push
will populate them.

## Step 2 — Create a Personal Access Token

The workflow's default `GITHUB_TOKEN` is scoped to the current repo only and
can't push elsewhere. We need a cross-repo token.

1. https://github.com/settings/tokens (classic) → **Generate new token (classic)**.
2. Note: e.g. `netcheck goreleaser tap+bucket`.
3. Expiration: your call. Reminder to rotate if it's not "no expiration".
4. **Scopes:** `repo` (full control of private repos). Cask + bucket repos are
   public so technically `public_repo` is enough — but the token is
   single-purpose, full `repo` is fine and survives if you ever go private.
5. **Generate token** → copy the value once.

Now add it as a secret on the `Dezoxy/netcheck` repo:

1. `Dezoxy/netcheck` → **Settings** → **Secrets and variables** → **Actions**.
2. **New repository secret**.
3. Name: `GORELEASER_PAT` (exactly — both workflow files reference this).
4. Value: the token you just copied.
5. **Add secret**.

The workflows already wire `GORELEASER_PAT: ${{ secrets.GORELEASER_PAT || '' }}`
into goreleaser's env, with a `|| ''` fallback so the pipeline doesn't break if
the secret is missing. Once the secret exists, the env var becomes the real PAT
and goreleaser can push.

## Step 3 — Flip `skip_upload`

Edit `.goreleaser.yml`, find both `skip_upload: true` lines (one in
`homebrew_casks:`, one in `scoops:`), change to `false` (or just delete the line
— `false` is the default).

```diff
 homebrew_casks:
   - name: netcheck
     repository:
       owner: Dezoxy
       name: homebrew-netcheck
       token: "{{ .Env.GORELEASER_PAT }}"
-    skip_upload: true
+    skip_upload: false
```

```diff
 scoops:
   - name: netcheck
     repository:
       owner: Dezoxy
       name: scoop-netcheck
       token: "{{ .Env.GORELEASER_PAT }}"
-    skip_upload: true
+    skip_upload: false
```

Commit, push, merge into `main`. Cut the next release tag through the usual
release-please flow.

## Step 4 — Verify

The next release-please-triggered run should produce:

- A new commit in `Dezoxy/homebrew-netcheck` adding `Casks/netcheck.rb` with the
  current version's URLs + SHA256s.
- A new commit in `Dezoxy/scoop-netcheck` adding `bucket/netcheck.json` with the same.

End-to-end install test:

```bash
# macOS — Cask
brew tap dezoxy/netcheck
brew install netcheck
netcheck version

# Windows PowerShell — Scoop
scoop bucket add netcheck https://github.com/Dezoxy/scoop-netcheck
scoop install netcheck
netcheck version
```

## Local dry-run

You can test the goreleaser config locally without pushing anything:

```bash
go install github.com/goreleaser/goreleaser/v2@latest
goreleaser release --snapshot --clean --skip=publish
```

The Cask file lands at `dist/homebrew/Casks/netcheck.rb` and the Scoop manifest
at `dist/scoop/bucket/netcheck.json`. Inspect both; they're the bytes that will
eventually get pushed.

The same run also builds the container image locally (`--snapshot` skips the
push), so it needs a running Docker daemon. Without one, add `--skip=docker`.

## macOS Gatekeeper note

netcheck binaries are not Apple-notarized (no Developer Program). Unsigned
binaries trip Gatekeeper's "cannot be opened because the developer cannot be
verified" error.

The Cask's `postflight` block runs `xattr -dr com.apple.quarantine` on the
installed binary to strip the quarantine attribute — same workaround
goreleaser's own docs recommend. Users get a one-time install through
`brew install` without manual intervention.

If we ever join the Apple Developer Program ($99/year) and notarize, the
`postflight` block can be removed.

## Rolling back

If something goes wrong and the tap or bucket has a bad commit:

```bash
# In Dezoxy/homebrew-netcheck (or scoop-netcheck):
git revert HEAD
git push
```

Users will get the previous version on their next `brew update` /
`scoop update`. No need to re-cut the netcheck release itself.

Or just delete the cask/manifest file entirely; users fall through to
direct-download from the GitHub release page.
