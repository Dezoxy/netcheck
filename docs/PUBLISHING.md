# Publishing — Homebrew Cask + Scoop bucket

netcheck's release pipeline can publish to two third-party channels alongside the GitHub release:

- **Homebrew Cask** at `Dezoxy/homebrew-netcheck` → `brew install dezoxy/netcheck/netcheck` (macOS).
- **Scoop bucket** at `Dezoxy/scoop-netcheck` → `scoop bucket add netcheck https://github.com/Dezoxy/scoop-netcheck && scoop install netcheck` (Windows).

The pipeline is **wired but not active** — every release builds the Cask file + Scoop manifest into `dist/` for inspection, then stops short of pushing to the tap/bucket repos. This document walks you through flipping the switch when you're ready.

> **Linux Homebrew users**: Cask is macOS-only. You keep the existing direct-download path from the GitHub release page (`netcheck_*_linux_*.tar.gz`). If we ever want a Linux-brew formula, that's a separate addition.

---

## Step 1 — Create the tap and bucket repos

Both must exist before goreleaser can push to them. Two empty GitHub repos under your `Dezoxy` account:

| Repo | Visibility | What goreleaser writes |
|---|---|---|
| `Dezoxy/homebrew-netcheck` | Public (required by Homebrew) | `Casks/netcheck.rb`, one commit per release |
| `Dezoxy/scoop-netcheck` | Public (required by Scoop) | `bucket/netcheck.json`, one commit per release |

The names matter:

- `homebrew-netcheck` — Homebrew CLI auto-prepends `homebrew-` when you `brew tap dezoxy/netcheck`. Without the prefix, the tap won't work.
- `scoop-netcheck` — convention, not enforced; install path is just the repo URL.

Create both as empty repos. No README, no .gitignore — goreleaser's first push will populate them.

## Step 2 — Create a Personal Access Token

The workflow's default `GITHUB_TOKEN` is scoped to the current repo only and can't push elsewhere. We need a cross-repo token.

1. https://github.com/settings/tokens (classic) → **Generate new token (classic)**.
2. Note: e.g. `netcheck goreleaser tap+bucket`.
3. Expiration: your call. Reminder to rotate if it's not "no expiration".
4. **Scopes:** `repo` (full control of private repos). Cask + bucket repos are public so technically `public_repo` is enough — but the token is single-purpose, full `repo` is fine and survives if you ever go private.
5. **Generate token** → copy the value once.

Now add it as a secret on the `Dezoxy/netcheck` repo:

1. `Dezoxy/netcheck` → **Settings** → **Secrets and variables** → **Actions**.
2. **New repository secret**.
3. Name: `GORELEASER_PAT` (exactly — both workflow files reference this).
4. Value: the token you just copied.
5. **Add secret**.

The workflows already wire `GORELEASER_PAT: ${{ secrets.GORELEASER_PAT || '' }}` into goreleaser's env, with a `|| ''` fallback so the pipeline doesn't break if the secret is missing. Once the secret exists, the env var becomes the real PAT and goreleaser can push.

## Step 3 — Flip `skip_upload`

Edit `.goreleaser.yml`, find both `skip_upload: true` lines (one in `homebrew_casks:`, one in `scoops:`), change to `false` (or just delete the line — `false` is the default).

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

Commit, push, merge into `main`. Cut the next release tag through the usual release-please flow.

## Step 4 — Verify

The next release-please-triggered run should produce:

- A new commit in `Dezoxy/homebrew-netcheck` adding `Casks/netcheck.rb` with the current version's URLs + SHA256s.
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

The Cask file lands at `dist/homebrew/Casks/netcheck.rb` and the Scoop manifest at `dist/scoop/bucket/netcheck.json`. Inspect both; they're the bytes that will eventually get pushed.

## macOS Gatekeeper note

netcheck binaries are not Apple-notarized (no Developer Program). Unsigned binaries trip Gatekeeper's "cannot be opened because the developer cannot be verified" error.

The Cask's `postflight` block runs `xattr -dr com.apple.quarantine` on the installed binary to strip the quarantine attribute — same workaround goreleaser's own docs recommend. Users get a one-time install through `brew install` without manual intervention.

If we ever join the Apple Developer Program ($99/year) and notarize, the `postflight` block can be removed.

## Rolling back

If something goes wrong and the tap or bucket has a bad commit:

```bash
# In Dezoxy/homebrew-netcheck (or scoop-netcheck):
git revert HEAD
git push
```

Users will get the previous version on their next `brew update` / `scoop update`. No need to re-cut the netcheck release itself.

Or just delete the cask/manifest file entirely; users fall through to direct-download from the GitHub release page.
