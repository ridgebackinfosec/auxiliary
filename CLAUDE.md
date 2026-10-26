# auxiliary — project notes for Claude

## Shorthands

- **`bcp`** — "bump, commit, push". When the user says `bcp`:
  1. **Bump the version** in `pyproject.toml` (the single source of version
     truth) per semver for the pending change, and add a matching dated
     section to `CHANGELOG.md` (Keep a Changelog format) if not already
     present. If the pending work already carries the correct bump, keep it —
     don't double-bump.
  2. **Commit** all pending changes with a clear message (end it with the
     `Co-Authored-By` attribution line).
  3. **Push** to the remote. This repo is trunk-based: work lands on `main`
     (tracked by `origin/main`), so fast-forward `main` to the new commit and
     `git push origin main`.

## Repo conventions

- Version is single-sourced in `pyproject.toml`; `CHANGELOG.md` follows
  Keep a Changelog.
- Tests use the stdlib `unittest` runner: `python -m unittest discover -s tests`.
