# netcheck

Repository instructions for coding agents. `AGENTS.md` is a byte-identical
copy: edit this file, then `cp CLAUDE.md AGENTS.md` (`make arch-docs` checks).

## Architecture authoring

- For Structurizr model/view work, read
  `.agents/skills/architecture-views/SKILL.md`.
- For architecture documentation beyond diagrams, read
  `.agents/skills/architecture-docs/SKILL.md`. Use both for mixed requests.
- These skills come from architecture-base. Apply this repo's own evidence, paths,
  tool pins and checks. Do not copy the base repo's fictional Payment Platform.
- Use automatic layout and verify rendered readability. Export PNG/SVG manually;
  do not add export automation unless requested.
- Title documents under `docs/architecture/overview/` with `##`, not `#`.
  Structurizr hides a level-1 heading from the page and the navigation, and the
  PDF will not show you the problem. `make arch-docs` enforces it.
- Before opening a pull request, follow `.agents/skills/docs-sync/SKILL.md`:
  fix the documentation claims the branch made false, in the same branch.
- The skills, `scripts/check_docs_consistency.py`, the two PDF scripts and
  `docs/architecture/model/styles-shared.dsl` are copies. Fix them in
  architecture-base first, then copy back; the only local setting is
  `SELF_REPO` in the checker.
