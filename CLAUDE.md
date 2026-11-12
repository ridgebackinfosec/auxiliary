# auxiliary — project notes for Claude

## Branching

This repo is **not** trunk-based. Work lands on `develop`; `main` is the release
branch.

- All work happens on `develop`. Branch from it, push to it.
- **Never push, commit, or merge to `main`.** The maintainer opens the
  `develop` → `main` PR by hand.
- Actions owns tagging and releases. Never create a tag.
- Never run `git add` / `git commit` outside the `bcp` command below unless
  explicitly asked.
- After any change, end with a suggested one-line commit message in
  conventional-commit form, under 72 characters where possible (`feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `chore:`; `!` for breaking).

## Shorthands

- **`bcp`** — "bump, commit, push". When the user says `bcp`, do these in order
  and **stop at the first failure**:
  1. **Regenerate docs.** Run `python scripts/generate_doc_examples.py`. A
     dirty tree afterwards means the docs were about to ship stale -- commit the
     regenerated output *with* the change, never revert it.
  2. **Run the full suite**: `pytest`. Report real output; never summarize a red
     suite as green.
  3. **Bump the version** in `pyproject.toml` (the single source of version
     truth) per semver for the pending change, and move the `## [Unreleased]`
     content in `CHANGELOG.md` into a dated `## [X.Y.Z] - YYYY-MM-DD` section,
     leaving `[Unreleased]` as an empty header. The date format is not
     optional — `release.yml` fails without it.
  4. **Commit and push to `develop`** (which must be the current branch). Commit
     messages end with the `Co-Authored-By` attribution line.

  Version bumps are never unilateral: present the compiled changelog list and the
  proposed version number and wait for confirmation before editing files.

## Repo conventions

- Version is single-sourced in `pyproject.toml`. There is no `__version__`
  constant anywhere in the tree, by design — `auxiliary --version` reads the
  installed distribution metadata via `importlib.metadata`. Do not reintroduce a
  second version string; a stale duplicate in a root `__init__.py` silently broke
  every release from 1.6.2 through 1.9.0.
- `CHANGELOG.md` follows Keep a Changelog. Update `## [Unreleased]` in the **same
  change** as any user-visible edit — not later, not when asked. Sections:
  Added / Changed / Deprecated / Removed / Fixed / Security. Append to existing
  `[Unreleased]` content; never replace it. Skip the changelog only for internal
  refactors with no observable change, pure doc edits, test-only changes, and
  CI/tooling changes.
- Tests run under `pytest` (configured in `pyproject.toml`; `testpaths = tests`,
  `pythonpath = ["."]`). The suite is written with `unittest.TestCase`, so
  `python -m unittest discover -s tests` also works and is a useful cross-check.
- **Never hand-edit between `<!-- BEGIN GENERATED: name -->` and
  `<!-- END GENERATED: name -->`.** Those regions are owned by
  `scripts/generate_doc_examples.py`; change the renderer or the capture
  function and re-run it. Prose and captions around the markers are hand-owned
  and safe to edit. The examples are captured from the real renderers
  (`cli.print_help()`, `format_compact_line()`, `format_matched_section()`,
  `build_diagram()`) using the sample data in `docs/fixtures/`, never from real
  engagement data. `tests/test_doc_examples.py` fails when they go stale, and
  also when a flag documented in a folder README no longer exists in that
  tool's `--help`.
- Rich is a **docs-only** extra (`pip install -e ".[docs]"`), imported only from
  `scripts/` and `tests/`. Never add it to `[project.dependencies]` or
  `requirements.txt`; the `test-package` CI job fails if it reaches the wheel.
- Every code change updates the docs it invalidates in the same change:
  docstrings, the top-level `README.md` index, and the per-folder `README.md`
  for the tool you touched (`dns/`, `network/`, `web/`, `files/`, `firewall/`,
  `nessus/`, `pivot/`).
- Design specs, implementation plans, and scratch analysis do not belong in the
  repo. Only shipped documentation lands in the tree.

## CI/CD

Four files carry the automation. Read them before editing and preserve the
comments explaining why a check is soft-failed — deleting that comment loses the
reason.

- `.github/workflows/release.yml` — fires on a push to `main` touching
  `pyproject.toml`. Validates plain semver (`X.Y.Z`, no `v` prefix, no
  pre-release suffix), skips if the tag already exists, extracts release notes
  via `scripts/extract_changelog.py`, builds, tags, and publishes with the sdist
  and wheel attached.
- `.github/workflows/test.yml` — suite on push/PR to `main` and `develop`.
  Linux covers Python 3.9–3.13; Windows and macOS cover 3.11 and 3.13.
  `black --check` and `mypy` are soft-failed for now; `test-package` installs
  the built wheel and smoke-tests the CLI.
- `.github/workflows/security.yml` — bandit and pip-audit (soft, reports
  uploaded) plus CodeQL (hard gate), on push/PR and a Monday cron.
- `.github/dependabot.yml` — monthly pip updates targeting `develop`, with the
  dev toolchain batched into one PR.

Rules: pin actions to a major tag; never add a step that pushes to `main`,
force-pushes, or auto-merges; never add a publish-to-registry step without
asking. A workflow change is only truly verified once it has run on GitHub.
