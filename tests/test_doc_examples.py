#!/usr/bin/env python3
"""Guards that keep the documentation honest.

Two different kinds of rot are covered here:

1. Generated examples going stale -- someone changes a renderer and forgets to
   re-run the generator. The generator alone only means the docs *can* be
   current; this test is what makes them current.
2. Documented flags drifting from the program -- v1.9.0 had to fix a
   `--ranges-file` flag that lived in the README and the CLI help long after the
   real flag became `--targets-file`. Nothing failed when it drifted.

Written with unittest.TestCase so `python -m unittest discover -s tests` keeps
working alongside pytest, with pytest marks applied at module level.
"""

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "generate_doc_examples.py"

# Exit code the generator uses for "an optional prerequisite is missing"
# (Rich not installed, fixture absent). That is not a drift failure.
EXIT_PREREQ_MISSING = 3

try:  # pytest marks are optional so the unittest runner still works.
    import pytest

    pytestmark = [pytest.mark.slow, pytest.mark.integration]
except ImportError:  # pragma: no cover
    pass


def _tool_scripts_by_folder():
    """Map folder -> [script paths], derived from the CLI's own registry so a
    newly registered tool is covered automatically instead of needing this list
    updated by hand."""
    sys.path.insert(0, str(REPO_ROOT))
    import cli

    folders = {}
    for info in cli.TOOLS.values():
        package, _, module = info["module"].partition(".")
        folders.setdefault(package, set()).add("%s/%s.py" % (package, module))
    return {k: sorted(v) for k, v in folders.items()}


def _documented_flags(readme: Path):
    """Flags from the first column of the README's option tables, e.g. a row
    `| `-f, --targets-file` | ... |` yields {-f, --targets-file}."""
    flags = set()
    for line in readme.read_text(encoding="utf-8").split("\n"):
        match = re.match(r"^\|\s*`([^`]+)`\s*\|", line)
        if not match:
            continue
        for token in match.group(1).split(","):
            token = token.strip()
            if token.startswith("-"):
                flags.add(token.split()[0].split("=")[0])
    return flags


def _help_text(scripts):
    """Combined --help for every tool documented in one folder's README.

    COLUMNS is pinned wide so argparse never wraps an option string across
    lines, which would make a present flag look missing.
    """
    env = dict(os.environ, COLUMNS="200")
    blob = ""
    for script in scripts:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / script), "--help"],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
            timeout=120,
        )
        blob += result.stdout
    return blob


class GeneratedDocExamplesTests(unittest.TestCase):
    @unittest.skipIf(
        sys.platform == "win32",
        "generated output cannot be byte-identical on Windows (path separators), "
        "and releases are not cut from Windows",
    )
    def test_generated_doc_examples_are_current(self):
        # A subprocess, not an in-process import: the generator manipulates
        # sys.path and COLUMNS, which would leak into the rest of the suite.
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == EXIT_PREREQ_MISSING:
            self.skipTest(result.stderr.strip() or "doc-example prerequisites missing")
        self.assertEqual(
            result.returncode,
            0,
            "Documentation examples are out of date.\n\n"
            + result.stderr
            + "\nRegenerate with:  python scripts/generate_doc_examples.py",
        )


class DocumentedFlagsTests(unittest.TestCase):
    """Every flag a folder README documents must exist in that tool's --help."""

    def test_documented_flags_exist(self):
        folders = _tool_scripts_by_folder()
        failures = []
        for folder, scripts in sorted(folders.items()):
            readme = REPO_ROOT / folder / "README.md"
            if not readme.exists():
                continue
            flags = _documented_flags(readme)
            if not flags:
                continue
            # One folder README documents BOTH of its tools, so the flags must
            # be checked against the union -- checking one alone reports the
            # other tool's flags as missing.
            blob = _help_text(scripts)
            missing = sorted(f for f in flags if f not in blob)
            if missing:
                failures.append(
                    "%s/README.md documents flags that no longer exist in %s: %s"
                    % (folder, ", ".join(scripts), ", ".join(missing))
                )
        self.assertEqual(failures, [], "\n".join(failures))


class PivotSubcommandsTests(unittest.TestCase):
    """pivot/README.md tabulates subcommands rather than flags, and the pivot
    tool is the only one exposing build_parser(), so this can be exact in both
    directions -- an undocumented new subcommand fails too."""

    def test_documented_subcommands_match_parser(self):
        sys.path.insert(0, str(REPO_ROOT))
        from pivot import reverse_ssh_tunnel as rt

        real = set()
        for action in rt.build_parser()._actions:
            if getattr(action, "choices", None):
                real |= set(action.choices)

        readme = REPO_ROOT / "pivot" / "README.md"
        documented = set()
        for line in readme.read_text(encoding="utf-8").split("\n"):
            match = re.match(r"^\|\s*[^|]*\|\s*`([a-z][a-z-]*)`\s*\|", line)
            if match:
                documented.add(match.group(1))

        self.assertTrue(documented, "no subcommands parsed out of pivot/README.md")
        self.assertEqual(
            sorted(documented - real),
            [],
            "pivot/README.md documents subcommands the parser does not have",
        )
        self.assertEqual(
            sorted(real - documented),
            [],
            "pivot subcommands exist that pivot/README.md does not document",
        )


if __name__ == "__main__":
    unittest.main()
