#!/usr/bin/env python3
"""
reverse_dns.py

Perform reverse DNS lookups on a list of IPs.

Modes:
  - hostnames  -> Extract hostnames only (dedupe + sort).
  - ip-map     -> Output "IP (hostname)" lines, preserving input order.

Defaults:
  - Input:  ip_list.txt
  - Output: dns_results.txt
  - Mode:   hostnames
  - Includes aliases in hostnames mode unless --no-aliases is set.

Usage examples:
  python reverse_dns.py --mode hostnames --input ip_list.txt --output dns_results.txt
  python reverse_dns.py --mode ip-map   --input in-scope    --output resolved_ips.txt
"""
from __future__ import annotations
import argparse
import socket
from pathlib import Path

def load_ips(path: Path) -> list[str]:
    ips = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        ips.append(s)
    return ips

def reverse_lookup(ip: str, include_aliases: bool = True) -> list[str]:
    """Return a list of hostnames for the given IP (may be empty)."""
    names: list[str] = []
    try:
        primary, aliases, _ = socket.gethostbyaddr(ip)
        if primary:
            names.append(primary.rstrip("."))
        if include_aliases:
            for a in aliases:
                a = a.rstrip(".")
                if a and a not in names:
                    names.append(a)
    except Exception:
        pass  # no PTR found / lookup error
    return names

def run_hostnames_mode(ips: list[str], output: Path, include_aliases: bool):
    results: set[str] = set()
    for ip in ips:
        for name in reverse_lookup(ip, include_aliases=include_aliases):
            results.add(name)
    sorted_names = sorted(results, key=lambda s: (s.lower(), s))
    output.write_text("\n".join(sorted_names) + ("\n" if sorted_names else ""), encoding="utf-8")
    print(f"[hostnames mode] Wrote {len(sorted_names)} unique hostnames to {output}")

def run_ip_map_mode(ips: list[str], output: Path):
    lines: list[str] = []
    for ip in ips:
        names = reverse_lookup(ip, include_aliases=False)
        hostname = names[0] if names else "unknown"
        lines.append(f"{ip} ({hostname})")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[ip-map mode] Wrote {len(lines)} IP-to-hostname mappings to {output}")

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Reverse DNS lookups on a list of IPs")
    p.add_argument("-i", "--input", type=Path, default=Path("ip_list.txt"),
                   help="Input file of IP addresses (default: ip_list.txt)")
    p.add_argument("-o", "--output", type=Path, default=Path("dns_results.txt"),
                   help="Output file (default: dns_results.txt)")
    p.add_argument("--mode", choices=["hostnames", "ip-map"], default="hostnames",
                   help="Output mode: 'hostnames' (dedupe/sort) or 'ip-map' (IP + hostname)")
    p.add_argument("--no-aliases", action="store_true",
                   help="Ignore alias hostnames in hostnames mode.")
    args = p.parse_args(argv)

    if not args.input.exists():
        print(f"Input file '{args.input}' not found!")
        return 1

    ips = load_ips(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    if args.mode == "hostnames":
        run_hostnames_mode(ips, args.output, include_aliases=not args.no_aliases)
    else:
        run_ip_map_mode(ips, args.output)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
