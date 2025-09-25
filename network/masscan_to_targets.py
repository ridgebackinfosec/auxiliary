#!/usr/bin/env python3
"""
masscan_to_targets.py

Extract IPv4 addresses from masscan/scan output and write a deduped, sorted list.

Equivalent to:
  grep -oE "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b" masscan_output | sort -u > targets

Usage:
  python masscan_to_targets.py masscan_output --output targets
  cat masscan_output | python masscan_to_targets.py - --output targets
  python masscan_to_targets.py masscan_output --no-validate   # permissive (like grep)
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path
import ipaddress

# permissive IPv4-like regex (same structure as your grep)
IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

def read_lines(path: str):
    if path == "-" or path == "/dev/stdin":
        return sys.stdin.read().splitlines()
    return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()

def extract_ips_from_text(text_lines, validate: bool = True):
    ips = []
    for ln in text_lines:
        for m in IP_RE.findall(ln):
            if not validate:
                ips.append(m)
            else:
                try:
                    # strict validation (0-255)
                    _ = ipaddress.IPv4Address(m)
                    ips.append(m)
                except Exception:
                    # skip invalid like 999.999.999.999
                    continue
    return ips

def numeric_sort(ips):
    return sorted(set(ips), key=lambda s: tuple(int(p) for p in s.split(".")))

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Extract IPv4 addresses from masscan output and write deduped sorted targets.")
    p.add_argument("input", nargs="?", default="masscan_output",
                   help="Input file path, or '-' for stdin (default: masscan_output)")
    p.add_argument("--output", "-o", type=Path, default=Path("targets"),
                   help="Output file path (default: ./targets)")
    p.add_argument("--no-validate", action="store_true",
                   help="Do not validate octets (behave exactly like permissive grep regex).")
    p.add_argument("--keep-order", action="store_true",
                   help="Keep first-seen order instead of sorting (still dedupes).")
    args = p.parse_args(argv)

    try:
        lines = read_lines(args.input)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        return 2

    ips = extract_ips_from_text(lines, validate=not args.no_validate)

    if not ips:
        print("No IPs extracted.", file=sys.stderr)
        # still create empty targets file to match pipeline behavior
        args.output.write_text("", encoding="utf-8")
        return 0

    if args.keep_order:
        # preserve first-seen order while deduping
        seen = set()
        ordered = []
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            ordered.append(ip)
        final = ordered
    else:
        final = numeric_sort(ips)

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("\n".join(final) + ("\n" if final and not final[-1].endswith("\n") else ""), encoding="utf-8")
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        return 3

    print(f"Wrote {len(final)} unique target(s) to {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
