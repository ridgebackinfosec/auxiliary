#!/usr/bin/env python3
"""Capture documentation examples from the real renderers and inject them into
the Markdown docs.

Every command output, terminal screen and settings table shown in the docs is
produced by this script from the code that actually renders it -- never typed by
hand. Hand-written output rots silently: nothing fails when it drifts, so it
stays wrong for months and the first person to notice is someone following a
README that no longer matches the program.

    python scripts/generate_doc_examples.py              # write
    python scripts/generate_doc_examples.py --check      # exit non-zero on drift
    python scripts/generate_doc_examples.py --only NAME  # iterate on one

Rich is used here and in tests/test_doc_examples.py ONLY, to wrap captured
terminal output in an SVG. It is a `docs` extra and must never become a runtime
dependency: no shipped module imports it, this script is not part of the
distribution, and the packaging job fails the build if Rich reaches the wheel.
"""

import argparse
import contextlib
import difflib
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SVG_DIR = REPO_ROOT / "docs" / "images" / "examples"
FIXTURE = REPO_ROOT / "docs" / "fixtures" / "webtech_sample.json"

# The generator imports the tools, so the repo root has to be importable
# regardless of the directory this is invoked from.
sys.path.insert(0, str(REPO_ROOT))

MAX_DIFF_LINES = 40
REGEN_COMMAND = "python scripts/generate_doc_examples.py"

# A version string in captured output would make the docs drift on every
# release. `cli.print_help()` prints the "--version" usage line but not the
# number; this catches a regression that started printing it.
VERSION_LEAK_RE = re.compile(r"\b\d+\.\d+\.\d+\b")


@dataclass
class Example:
    """One generated screen.

    `capture` receives the shared context dict. For "svg" and "text" it PRINTS
    (stdout is redirected to a buffer); for "markdown" it RETURNS the finished
    Markdown instead, because that content is not terminal output.
    """

    name: str
    width: int
    capture: Callable[[dict], Optional[str]]
    kind: str = "svg"
    targets: List[str] = field(default_factory=list)
    title: str = "auxiliary"
    alt: str = ""
    # Checked against the captured text; a non-empty result fails the run.
    forbid_version: bool = False


# ---------------------------------------------------------------------------
# Capture functions. Each calls the REAL renderer -- never a reimplementation.
# A stub returning a constant would put fabricated numbers in the README, which
# is worse than the stale screenshot it replaced.
# ---------------------------------------------------------------------------


def _webtech_live_feed(ctx: dict) -> None:
    """The concurrent scan feed, printed as each host finishes (out of order).

    Colour is the point of this one: green `done` / red `FAIL` is the state
    signal an operator reads at a glance, which a monochrome code fence loses.
    """
    from web.webtech_fingerprint import format_compact_line

    data = ctx["webtech"]
    total = data["total"]
    for host in data["hosts"]:
        print(
            format_compact_line(
                host["index"],
                total,
                host["url"],
                host["ok"],
                host["detail"],
                use_color=True,
            )
        )


def _webtech_matched(ctx: dict) -> None:
    """The end-of-run "=== MATCHED: <term> ===" triage block for --match."""
    from web.webtech_fingerprint import format_matched_section

    data = ctx["webtech"]
    term = data["match_term"]
    hits = []
    for host in data["hosts"]:
        versions = [
            "%s %s" % (c["name"], c["version"])
            for c in host["components"]
            if term.lower() in c["name"].lower()
        ]
        if versions:
            hits.append((host["host"], versions))
    print(format_matched_section(term, hits))


def _cli_help(ctx: dict) -> None:
    """`auxiliary --help` -- the tool catalog and examples."""
    import cli

    cli.print_help()


def _reverse_ssh_diagram(ctx: dict) -> str:
    """The reverse-SSH pivot diagram. Mermaid, which GitHub renders natively,
    so this is injected as Markdown rather than as a picture of a diagram."""
    from pivot.reverse_ssh_tunnel import build_diagram

    return "```mermaid\n" + build_diagram(sequence=False).rstrip("\n") + "\n```"


EXAMPLES = [
    Example(
        "webtech-live-feed",
        92,
        _webtech_live_feed,
        kind="svg",
        targets=["web/README.md"],
        title="aux-webtech -f targets.txt -o results/",
        alt="The webtech concurrent scan feed: green 'done' and red 'FAIL' per host",
    ),
    Example(
        "webtech-matched",
        92,
        _webtech_matched,
        kind="text",
        targets=["web/README.md"],
    ),
    Example(
        "cli-help",
        100,
        _cli_help,
        kind="text",
        targets=["README.md"],
        forbid_version=True,
    ),
    Example(
        "reverse-ssh-diagram",
        100,
        _reverse_ssh_diagram,
        kind="markdown",
        targets=["pivot/README.md"],
    ),
]


# ---------------------------------------------------------------------------
# Capture mechanics
# ---------------------------------------------------------------------------


def build_context() -> dict:
    return {"webtech": json.loads(FIXTURE.read_text(encoding="utf-8"))}


def mask(text: str) -> str:
    """Scrub machine-specific values from PROSE output.

    Deliberately not used on table cells: substitutions change string length,
    and masking text a layout engine has already measured either shifts every
    column after it or silently fails to match a value that has been wrapped
    across lines. Renderer INPUT is masked instead -- here, by the fixture
    already containing placeholder hosts and versions. Regexes are unanchored
    because a \\b before a digit fails when a style escape ends in a letter.
    """
    text = text.replace(str(Path.home()), "/home/operator")
    text = text.replace(str(REPO_ROOT), "/opt/auxiliary")
    return text


def capture(example: Example, ctx: dict) -> str:
    """Run one example's capture, returning the raw captured text (ANSI intact
    for svg). Console width is pinned so output cannot reflow per machine."""
    if example.kind == "markdown":
        result = example.capture(ctx)
        if not isinstance(result, str):
            raise TypeError(
                "markdown example %r must RETURN a string, got %r"
                % (example.name, type(result).__name__)
            )
        return mask(result).rstrip("\n")

    buffer = io.StringIO()
    prev_columns = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = str(example.width)
    try:
        with contextlib.redirect_stdout(buffer):
            example.capture(ctx)
    finally:
        if prev_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = prev_columns

    text = mask(buffer.getvalue()).rstrip("\n")

    if example.forbid_version:
        leak = VERSION_LEAK_RE.search(re.sub(r"\x1b\[[0-9;]*m", "", text))
        if leak:
            raise ValueError(
                "example %r captured a version string (%r). Committing it would "
                "make the docs drift on every release -- mask it or stop "
                "printing it." % (example.name, leak.group(0))
            )
    return text


def render_svg(example: Example, ansi_text: str) -> str:
    """Re-render the captured ANSI as a faux-terminal SVG, so the SVG and the
    text show exactly the same thing. force_terminal keeps colour alive through
    a non-TTY capture; legacy_windows=False keeps output host-independent."""
    from rich.console import Console
    from rich.text import Text

    console = Console(
        file=io.StringIO(),
        record=True,
        width=example.width,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )
    console.print(Text.from_ansi(ansi_text), end="")
    return console.export_svg(title=example.title)


def rel_path(from_file: Path, to_file: Path) -> str:
    """Path for an <img src>, relative to the Markdown file doing the linking."""
    return os.path.relpath(to_file, from_file.parent).replace(os.sep, "/")


def block_for(example: Example, text: str, target: Path) -> str:
    """The content that goes between the markers for one target file."""
    if example.kind == "svg":
        src = rel_path(target, SVG_DIR / (example.name + ".svg"))
        alt = example.alt or example.name
        return '<img src="%s" alt="%s">' % (src, alt)
    if example.kind == "text":
        return "```text\n" + text + "\n```"
    return text


# ---------------------------------------------------------------------------
# Marker injection
# ---------------------------------------------------------------------------


def marker_re(name: str) -> re.Pattern:
    """Matches a marker pair and everything between it, including an EMPTY pair
    (newly added markers with nothing yet generated into them)."""
    return re.compile(
        r"(<!-- BEGIN GENERATED: %s -->)\n?.*?\n?(<!-- END GENERATED: %s -->)"
        % (re.escape(name), re.escape(name)),
        re.DOTALL,
    )


def inject(content: str, name: str, block: str) -> str:
    # A function replacement is used so the block is inserted literally --
    # backslashes and \g references in generated output must not be interpreted.
    return marker_re(name).sub(
        lambda m: m.group(1) + "\n" + block + "\n" + m.group(2), content, count=1
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def plan_outputs(only: Optional[str]) -> dict:
    """Compute every file this run would write: {Path: new_content}."""
    ctx = build_context()
    selected = [e for e in EXAMPLES if only is None or e.name == only]
    if only and not selected:
        raise SystemExit(
            "unknown example %r. Known: %s"
            % (only, ", ".join(e.name for e in EXAMPLES))
        )

    outputs = {}
    missing_markers = []

    for example in selected:
        text = capture(example, ctx)

        if example.kind == "svg":
            outputs[SVG_DIR / (example.name + ".svg")] = render_svg(example, text)

        for target_name in example.targets:
            target = REPO_ROOT / target_name
            content = outputs.get(target)
            if content is None:
                content = target.read_text(encoding="utf-8")
            if not marker_re(example.name).search(content):
                missing_markers.append((target_name, example.name))
                continue
            outputs[target] = inject(
                content, example.name, block_for(example, text, target)
            )

    if missing_markers:
        for target_name, name in missing_markers:
            print(
                "warning: %s has no '<!-- BEGIN GENERATED: %s -->' markers; the "
                "example would be generated but never shown." % (target_name, name),
                file=sys.stderr,
            )
        raise SystemExit(1)

    return outputs


def do_write(outputs: dict) -> int:
    changed = []
    for path, content in sorted(outputs.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old != content:
            path.write_text(content, encoding="utf-8")
            changed.append(path)
    if changed:
        for path in changed:
            print("updated %s" % path.relative_to(REPO_ROOT))
    else:
        print("all documentation examples already current")
    return 0


def do_check(outputs: dict) -> int:
    stale = []
    diff_lines = []
    for path, content in sorted(outputs.items()):
        old = path.read_text(encoding="utf-8") if path.exists() else ""
        if old != content:
            rel = str(path.relative_to(REPO_ROOT))
            stale.append(rel)
            diff_lines.extend(
                difflib.unified_diff(
                    old.splitlines(),
                    content.splitlines(),
                    fromfile=rel + " (committed)",
                    tofile=rel + " (regenerated)",
                    lineterm="",
                    n=1,
                )
            )

    if not stale:
        print("all documentation examples are current")
        return 0

    print("Documentation examples are out of date.\n", file=sys.stderr)
    for line in diff_lines[:MAX_DIFF_LINES]:
        print(line, file=sys.stderr)
    if len(diff_lines) > MAX_DIFF_LINES:
        print(
            "... (%d more diff lines suppressed)" % (len(diff_lines) - MAX_DIFF_LINES),
            file=sys.stderr,
        )
    print("\nStale files:", file=sys.stderr)
    for rel in stale:
        print("  - %s" % rel, file=sys.stderr)
    print("\nRegenerate with:  %s" % REGEN_COMMAND, file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Capture documentation examples from the real renderers."
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed output is stale",
    )
    ap.add_argument(
        "--only", metavar="NAME", help="generate a single example (for iterating)"
    )
    args = ap.parse_args()

    if not FIXTURE.exists():
        print("fixture not found: %s" % FIXTURE, file=sys.stderr)
        return 3  # distinct code: the drift test SKIPS on this, never fails

    try:
        import rich  # noqa: F401
    except ImportError:
        print(
            "Rich is required to generate documentation examples: "
            'pip install -e ".[docs]"',
            file=sys.stderr,
        )
        return 3

    outputs = plan_outputs(args.only)
    return do_check(outputs) if args.check else do_write(outputs)


if __name__ == "__main__":
    sys.exit(main())
