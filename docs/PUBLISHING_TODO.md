# PUBLISHING — outstanding steps

Status as of this commit: **scaffolding shipped, tap + bucket repos created, not yet pushing.**

Full walkthrough in [PUBLISHING.md](PUBLISHING.md); this file is the minimal checklist of what's still required to make `brew install netcheck` and `scoop install netcheck` work.

## Done

- [x] Empty repos exist: [Dezoxy/homebrew-netcheck](https://github.com/Dezoxy/homebrew-netcheck), [Dezoxy/scoop-netcheck](https://github.com/Dezoxy/scoop-netcheck).
- [x] `.goreleaser.yml` has `homebrew_casks:` and `scoops:` blocks pointing at those repos.
- [x] `release-please.yml` and `release.yml` thread `GORELEASER_PAT` into the goreleaser step env, with a `|| ''` fallback so the pipeline stays green while the secret doesn't exist.
- [x] Both publishers default to `skip_upload: true` — every release builds artefacts into `./dist/` for inspection but doesn't push.
- [x] Local dry-run verified: `goreleaser release --snapshot --clean --skip=publish` produces a valid `dist/homebrew/Casks/netcheck.rb` and `dist/scoop/bucket/netcheck.json`.

## TODO (~10 minutes total)

### 1. Create the cross-repo Personal Access Token

The workflow's default `GITHUB_TOKEN` can only push to `Dezoxy/netcheck`. The tap and bucket repos need a different token.

1. Open https://github.com/settings/tokens (Tokens (classic), **not** fine-grained).
2. **Generate new token (classic)**.
3. Note: `netcheck goreleaser tap+bucket`.
4. Expiration: no expiration, or set a reminder to rotate. Single-purpose token, low risk if you keep it long-lived.
5. **Scopes: `repo`** (the whole repo group). Both tap repos are public so `public_repo` would technically suffice, but `repo` covers any future private-repo work.
6. **Generate** → copy the token (you only see it once).

### 2. Add it as a repo secret

1. https://github.com/Dezoxy/netcheck/settings/secrets/actions.
2. **New repository secret**.
3. Name: `GORELEASER_PAT` — exact spelling, both workflow files reference this.
4. Value: the token from step 1.
5. **Add secret**.

### 3. Flip `skip_upload: true` → `false`

Open a tiny PR editing `.goreleaser.yml`:

```diff
 homebrew_casks:
   - name: netcheck
     repository:
       owner: Dezoxy
       name: homebrew-netcheck
       token: "{{ .Env.GORELEASER_PAT }}"
-    skip_upload: true
+    skip_upload: false
…
 scoops:
   - name: netcheck
     repository:
       owner: Dezoxy
       name: scoop-netcheck
       token: "{{ .Env.GORELEASER_PAT }}"
-    skip_upload: true
+    skip_upload: false
```

Use a `feat(release):` subject (so release-please bumps the version + cuts a release that includes the change). Merge.

### 4. Watch the next release populate the repos

The next release-please-triggered run pushes:

- A commit to `Dezoxy/homebrew-netcheck` adding `Casks/netcheck.rb`.
- A commit to `Dezoxy/scoop-netcheck` adding `bucket/netcheck.json`.

Smoke-test:

```bash
# macOS
brew tap dezoxy/netcheck
brew install netcheck
netcheck version

# Windows PowerShell
scoop bucket add netcheck https://github.com/Dezoxy/scoop-netcheck
scoop install netcheck
netcheck version
```

When both work, edit `README.md` to remove the "_(coming once activated)_" qualifiers next to the install commands.

## If something goes wrong

The repos are public and empty. If the first goreleaser push produces a bad commit, revert it in the tap/bucket repo directly:

```bash
git -C path/to/homebrew-netcheck revert HEAD && git -C path/to/homebrew-netcheck push
```

Or just delete the cask/manifest file. Users fall through to the direct-download path on the release page.

Bigger emergency: re-set `skip_upload: true`, merge that as a hotfix, take stock without a publishing pipeline biting you on every release.
