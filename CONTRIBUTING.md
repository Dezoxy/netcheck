# Contributing to netcheck

Most work in this repo follows the same loop: branch off `main`, commit
along the conventional-commits format, push, open a PR. The pre-commit
pipeline catches the common mistakes before CI does.

## One-time setup

```bash
# Tooling: lefthook (hook runner), golangci-lint (Go lint), gitleaks (secrets).
brew install lefthook golangci-lint gitleaks

# Install the hooks into .git/hooks (one command per clone).
lefthook install

# Install the JS-side hook dependencies (prettier, eslint, commitlint).
cd web && npm install
```

Linux without homebrew:

```bash
go install github.com/evilmartians/lefthook@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Gitleaks: https://github.com/gitleaks/gitleaks/releases
```

## What runs when

### `git commit` — auto-fixing, sub-second, blocks on real findings

| Hook              | Scope              | Action                                                |
| ----------------- | ------------------ | ----------------------------------------------------- |
| `gofmt`           | staged `*.go`      | auto-fix + re-stage                                   |
| `go vet`          | whole module       | error on real bugs                                    |
| `golangci-lint`   | whole module       | curated linter set (errcheck, staticcheck, bodyclose…) |
| `prettier`        | staged `web/src/*` | auto-fix + re-stage                                   |
| `eslint`          | staged `web/src/*` | `--fix` then error on the rest                        |
| `gitleaks`        | staged diff        | block on secret-like strings                          |
| `large-files`     | staged             | block on files >512 KB                                |

### `git commit -m` — message gate

`commitlint` enforces the [conventional-commits](https://www.conventionalcommits.org/)
spec on the message header. release-please reads these to decide the
next semver bump and the changelog text, so messages like
`fix(portscan): close UDP socket on dial error` matter.

Allowed types: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`,
`perf`, `test`, `build`, `ci`, `revert`.

### `git push` — slower checks before CI sees them

| Hook              | Scope              | Action                                  |
| ----------------- | ------------------ | --------------------------------------- |
| `go test -race`   | whole module       | mirrors CI exactly                      |
| `tsc --noEmit`    | web                | full TypeScript typecheck               |
| `go mod tidy -diff` | go.mod / go.sum  | error if a `go mod tidy` would change anything |

### Emergency override

```bash
LEFTHOOK=0 git commit -m "..."     # skip all pre-commit hooks
git commit --no-verify -m "..."    # same, native git flag
```

Use sparingly — the hooks usually catch real things.

## Bypassing a specific finding

- **Go lint false positive**: add the path/pattern to `.golangci.yml`
  under `linters.exclusions.rules` with a comment explaining why.
- **Gitleaks false positive**: add the path or regex to `.gitleaks.toml`
  under `[allowlist]` with a comment.
- **ESLint false positive**: prefer `// eslint-disable-next-line <rule> -- <reason>`
  inline. Disabling rules globally requires a config edit and PR.
- **Prettier disagreement**: it doesn't have opinions you can override
  per-file. Adjust `.prettierrc.json` if there's a real style call to make.

## CI relationship

CI (`.github/workflows/ci.yml`) runs `golangci-lint` against the same
`.golangci.yml` the pre-commit hook uses, followed by `go test -race`.
The local hooks are a strict superset — if `lefthook run pre-commit`
and `lefthook run pre-push` pass locally, CI passes too.
