#!/usr/bin/env python3
"""
gobuster_to_eyewitness.py

Convert Gobuster directory/listing output into a simple newline-separated
list of full URLs suitable for tools like EyeWitness.

Usage:
    python gobuster_to_eyewitness.py gobuster_output.txt http://example.com urls_for_eyewitness.txt

Notes:
 - This script extracts the first meaningful token from each line and treats
   it as a path or URL. Typical Gobuster lines like:
       /admin (Status: 200)
   will yield: http://example.com/admin
 - If the token already looks like a full URL (http/https), it is kept (and
   normalized).
 - By default duplicates are preserved to mirror the original behavior, but
   use --dedupe to remove duplicates while preserving order.
"""
from __future__ import annotations
import argparse
import sys
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

def first_token(line: str) -> str | None:
    # Trim whitespace
    s = line.strip()
    if not s:
        return None
    # Gobuster typically prints: /path (Status: 200) or /path
    # split on whitespace and commas to get the first token
    token = re.split(r'[\s,]+', s, maxsplit=1)[0]
    # strip surrounding quotes if present
    token = token.strip('"\'')
    return token or None

def looks_like_url(s: str) -> bool:
    p = urlparse(s)
    return bool(p.scheme and p.netloc)

def normalize_path_token(token: str) -> str:
    """
    If token looks like '/path' or 'path', return token with a leading slash where sensible.
    If token is already 'http(s)://...', return it unchanged.
    """
    if looks_like_url(token):
        return token
    # If token begins with '/', keep it
    if token.startswith("/"):
        return token
    # If token is something like 'index.html' or 'admin', prepend '/'
    return "/" + token

def convert_lines(lines, base_url: str, dedupe: bool = False):
    seen = set()
    out = []
    for ln in lines:
        tok = first_token(ln)
        if not tok:
            continue
        # If token already a full URL, keep it; otherwise convert to path then join
        if looks_like_url(tok):
            full = tok
        else:
            path = normalize_path_token(tok)
            full = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        if dedupe:
            if full in seen:
                continue
            seen.add(full)
        out.append(full)
    return out

def main(argv=None):
    p = argparse.ArgumentParser(description="Convert gobuster output to a newline list of full URLs")
    p.add_argument("gobuster_file", help="Gobuster output file (use - for stdin)")
    p.add_argument("base_url", help="Base URL (e.g. http://example.com). If token is already a URL it will be used as-is.")
    p.add_argument("output_file", help="Path to write resulting URLs")
    p.add_argument("--dedupe", action="store_true", help="Remove duplicate URLs (preserve first occurrence)")
    args = p.parse_args(argv)

    gobuster_path = args.gobuster_file
    base_url = args.base_url
    out_path = Path(args.output_file)

    # Basic validation of base_url
    if not looks_like_url(base_url):
        print(f"Error: base_url does not look like a full URL: {base_url}", file=sys.stderr)
        return 2

    # Read input
    try:
        if gobuster_path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            lines = Path(gobuster_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except FileNotFoundError:
        print(f"Error: gobuster output file not found: {gobuster_path}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        return 4

    urls = convert_lines(lines, base_url, dedupe=args.dedupe)

    # Ensure parent dir exists
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        out_path.write_text("\n".join(urls) + ("\n" if urls and not urls[-1].endswith("\n") else ""), encoding="utf-8")
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        return 5

    print(f"URLs have been saved to {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
