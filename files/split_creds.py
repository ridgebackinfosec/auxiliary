#!/usr/bin/env python3
"""
split_creds.py

Split credential dumps of the form "username:password[:...]" into two files:
 - one file with usernames (one per line)
 - one file with passwords (one per line)

Features added:
 - --dedupe-users / --dedupe-passwords : remove duplicates (preserve first occurrence)
 - --sort {none,users,passwords,both}  : sort output (lexicographic)
 - --ignore-no-delim                   : skip lines without the delimiter (instead of emitting empty password)
 - --strip                             : strip surrounding whitespace and surrounding quotes from fields

Default behavior preserves order and duplicates, and splits on the first delimiter (':').

Examples:
  python split_creds.py
  python split_creds.py --glob "unique-creds-*.txt" --users users.txt --passwords pws.txt --dedupe-users --sort users --strip
"""
from __future__ import annotations
import argparse
from pathlib import Path
import glob
import sys
from typing import Iterable, List, Tuple, Set

def iter_input_lines(pattern: str) -> Iterable[str]:
    for p in sorted(glob.glob(pattern)):
        ppath = Path(p)
        try:
            with ppath.open("r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    yield ln.rstrip("\n\r")
        except Exception as e:
            print(f"Warning: could not read {p}: {e}", file=sys.stderr)
            continue

def sanitize_field(s: str, do_strip: bool) -> str:
    if not do_strip:
        return s
    s = s.strip()
    # remove matching surrounding single or double quotes
    if len(s) >= 2 and ((s[0] == s[-1]) and s[0] in ("'", '"')):
        s = s[1:-1]
    return s.strip()

def split_line(line: str, delimiter: str, ignore_no_delim: bool, do_strip: bool) -> Tuple[str, str] | None:
    if delimiter in line:
        user, pw = line.split(delimiter, 1)
        user = sanitize_field(user, do_strip)
        pw = sanitize_field(pw, do_strip)
        return user, pw
    else:
        if ignore_no_delim:
            return None
        # awk-like behavior: username is whole line, password empty
        user = sanitize_field(line, do_strip)
        return user, ""

def apply_dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out

def maybe_sort_list(lst: List[str], do_sort: bool) -> List[str]:
    if not do_sort:
        return lst
    return sorted(lst, key=lambda s: (s.lower(), s))

def process(
    pattern: str,
    users_out: Path,
    pw_out: Path,
    delimiter: str = ":",
    dedupe_users: bool = False,
    dedupe_passwords: bool = False,
    sort_mode: str = "none",  # one of "none","users","passwords","both"
    ignore_no_delim: bool = False,
    do_strip: bool = False,
) -> int:
    # Read and split
    users: List[str] = []
    pws: List[str] = []
    total_lines = 0
    skipped_lines = 0

    for ln in iter_input_lines(pattern):
        total_lines += 1
        res = split_line(ln, delimiter, ignore_no_delim, do_strip)
        if res is None:
            skipped_lines += 1
            continue
        user, pw = res
        users.append(user)
        pws.append(pw)

    if total_lines == 0:
        print(f"No files matched pattern: {pattern}", file=sys.stderr)
        return 2

    # Dedupe (preserve first occurrence)
    if dedupe_users:
        users = apply_dedupe_preserve_order(users)
    if dedupe_passwords:
        pws = apply_dedupe_preserve_order(pws)

    # Sorting
    sort_mode = sort_mode.lower()
    if sort_mode not in ("none", "users", "passwords", "both"):
        print(f"Invalid sort mode: {sort_mode}", file=sys.stderr)
        return 3

    if sort_mode in ("users", "both"):
        users = maybe_sort_list(users, do_sort=True)
    if sort_mode in ("passwords", "both"):
        pws = maybe_sort_list(pws, do_sort=True)

    # If lengths differ due to dedupe differences (e.g., dedupe-users True but not dedupe-passwords),
    # we will still write line-by-line up to the min length and then append remaining items for the longer list.
    # This mirrors expected behavior when users/passwords lists are independent.
    max_len = max(len(users), len(pws))
    # Prepare output directories
    users_out.parent.mkdir(parents=True, exist_ok=True)
    pw_out.parent.mkdir(parents=True, exist_ok=True)

    # Write users and passwords files. We write entire lists independently (not zipping),
    # matching original behavior where each output contains N lines corresponding to processed lines.
    try:
        with users_out.open("w", encoding="utf-8", errors="ignore") as uf:
            for u in users:
                uf.write(u + "\n")
        with pw_out.open("w", encoding="utf-8", errors="ignore") as pf:
            for p in pws:
                pf.write(p + "\n")
    except Exception as e:
        print(f"Error writing outputs: {e}", file=sys.stderr)
        return 4

    # Summary
    print(f"Processed {total_lines} line(s) across files matching: {pattern}")
    if skipped_lines:
        print(f"Skipped {skipped_lines} line(s) with no delimiter (ignore_no_delim=True).")
    print(f"Wrote {len(users)} username line(s) to: {users_out}")
    print(f"Wrote {len(pws)} password line(s) to: {pw_out}")
    return 0

def main(argv=None):
    p = argparse.ArgumentParser(description="Split user:pass credential files into two files (users, passwords).")
    p.add_argument("--glob", type=str, default="unique-creds-*.txt",
                   help="Input glob pattern to match credential files (default: unique-creds-*.txt)")
    p.add_argument("--users", type=Path, default=Path("pitchfork_users"),
                   help="Output file for usernames (default: pitchfork_users)")
    p.add_argument("--passwords", type=Path, default=Path("pitchfork_passwords"),
                   help="Output file for passwords (default: pitchfork_passwords)")
    p.add_argument("--delimiter", type=str, default=":",
                   help="Delimiter to split user and password on (default: ':')")
    p.add_argument("--dedupe-users", action="store_true",
                   help="Remove duplicate usernames (preserve first occurrence).")
    p.add_argument("--dedupe-passwords", action="store_true",
                   help="Remove duplicate passwords (preserve first occurrence).")
    p.add_argument("--sort", choices=["none", "users", "passwords", "both"], default="none",
                   help="Sort output: 'none' (default), 'users', 'passwords', or 'both'.")
    p.add_argument("--ignore-no-delim", action="store_true",
                   help="Ignore lines that do not contain the delimiter (instead of emitting empty password).")
    p.add_argument("--strip", action="store_true",
                   help="Strip surrounding whitespace and surrounding quotes from extracted fields.")
    args = p.parse_args(argv)

    return process(
        args.glob,
        args.users,
        args.passwords,
        delimiter=args.delimiter,
        dedupe_users=args.dedupe_users,
        dedupe_passwords=args.dedupe_passwords,
        sort_mode=args.sort,
        ignore_no_delim=args.ignore_no_delim,
        do_strip=args.strip,
    )

if __name__ == "__main__":
    raise SystemExit(main())
