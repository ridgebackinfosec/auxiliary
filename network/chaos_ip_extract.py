#!/usr/bin/env python3
"""
chaos_ip_extract.py

Extract valid IPv4 addresses from an input file, deduplicate, sort,
write to an output file, and print summary.

Usage:
    python chaos_ip_extract.py --input ~/chaos --output ~/order

Notes:
 - Only matches dotted decimal IPv4 addresses (0.0.0.0 to 255.255.255.255).
 - Deduplication and sorting are automatic.
 - Prints the count and the final list to stdout.
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

# Regex for IPv4 octets 0-255
IPV4_RE = re.compile(
    r"\b("
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r")\b"
)

def extract_ips(text: str) -> list[str]:
    """Return list of valid IPv4 addresses from text (may include duplicates)."""
    return [m[0] for m in IPV4_RE.findall(text)]

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Extract, dedupe, and sort IPv4 addresses from a file")
    p.add_argument("-i", "--input", type=Path, default=Path.home() / "chaos",
                   help="Input file to scan for IPs (default: ~/chaos)")
    p.add_argument("-o", "--output", type=Path, default=Path.home() / "order",
                   help="Output file to save sorted unique IPs (default: ~/order)")
    args = p.parse_args(argv)

    try:
        text = args.input.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        return 2

    ips = extract_ips(text)
    unique_sorted = sorted(set(ips), key=lambda ip: tuple(int(o) for o in ip.split(".")))

    try:
        args.output.write_text("\n".join(unique_sorted) + ("\n" if unique_sorted else ""), encoding="utf-8")
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        return 3

    # Print summary
    print("Number of unique IPs:")
    print(len(unique_sorted))
    print()
    print(f"\"{args.output.name}\" contents:")
    for ip in unique_sorted:
        print(ip)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
