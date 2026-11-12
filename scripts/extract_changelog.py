#!/usr/bin/env python3
"""Extract changelog section for a specific version from CHANGELOG.md."""

import re
import sys
from pathlib import Path


def extract_changelog_section(changelog_path: Path, version: str) -> str:
    """Extract changelog content for a specific version."""
    if not changelog_path.exists():
        raise FileNotFoundError(f"CHANGELOG.md not found at {changelog_path}")

    content = changelog_path.read_text(encoding="utf-8")

    # Pattern matches: ## [version] - YYYY-MM-DD
    version_pattern = rf"## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}"
    version_match = re.search(version_pattern, content)
    if not version_match:
        raise ValueError(
            f"Version [{version}] not found in CHANGELOG.md. "
            f"Expected format: ## [{version}] - YYYY-MM-DD"
        )

    start_pos = version_match.end()
    next_match = re.search(r"\n## \[\d+\.\d+\.\d+\]", content[start_pos:])
    if next_match:
        section_content = content[start_pos : start_pos + next_match.start()]
    else:
        section_content = content[start_pos:]

    lines = section_content.strip().split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python extract_changelog.py <version>", file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1]
    changelog_path = Path("CHANGELOG.md")
    output_path = Path("release_notes.md")

    try:
        notes = extract_changelog_section(changelog_path, version)
        output_path.write_text(f"# Release v{version}\n\n{notes}\n", encoding="utf-8")
        print(f"Successfully extracted changelog for version {version}")
        print(f"Release notes written to {output_path}")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("\nAvailable versions in CHANGELOG.md:", file=sys.stderr)
        if changelog_path.exists():
            for v in re.findall(r"## \[(\d+\.\d+\.\d+)\]", changelog_path.read_text(encoding="utf-8")):
                print(f"  - {v}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
