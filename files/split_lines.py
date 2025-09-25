#!/usr/bin/env python3
"""
split_lines.py

Split a text file into fixed-size line batches, with numeric suffixes and a custom
prefix/suffix—similar to:
  split -l 1000 -d --numeric-suffixes=1 --additional-suffix=.txt targets target_batches/targets_batch_

Usage examples:
  python split_lines.py --input targets --outdir target_batches --prefix targets_batch_ --lines 1000
  # custom numbering width/start and suffix
  python split_lines.py -i targets -o target_batches -p targets_batch_ -n 500 -s 1 -w 2 --suffix .txt
  # read from stdin
  cat targets | python split_lines.py -i - -o target_batches -p targets_batch_
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

def open_input(path_str: str):
    if path_str == "-" or path_str == "/dev/stdin":
        return sys.stdin
    return open(path_str, "r", encoding="utf-8", errors="ignore")

def batch_writer(outdir: Path, prefix: str, suffix: str, start: int, width: int):
    """Generator yielding (file_handle, filename) for successive batch indices."""
    idx = start
    while True:
        name = f"{prefix}{str(idx).zfill(width)}{suffix}"
        fpath = outdir / name
        fh = open(fpath, "w", encoding="utf-8", errors="ignore")
        yield fh, fpath
        fh.close()
        idx += 1

def split_file(
    input_path: str,
    outdir: Path,
    prefix: str,
    suffix: str,
    lines_per_file: int,
    start: int,
    width: int,
) -> tuple[int, int]:
    outdir.mkdir(parents=True, exist_ok=True)

    # Prepare first output file
    idx = start
    written_files = 0
    written_lines = 0
    current_count = 0
    current_path = outdir / f"{prefix}{str(idx).zfill(width)}{suffix}"
    out = open(current_path, "w", encoding="utf-8", errors="ignore")

    with open_input(input_path) as inp:
        for line in inp:
            out.write(line)
            written_lines += 1
            current_count += 1
            if current_count >= lines_per_file:
                out.close()
                written_files += 1
                idx += 1
                current_count = 0
                current_path = outdir / f"{prefix}{str(idx).zfill(width)}{suffix}"
                out = open(current_path, "w", encoding="utf-8", errors="ignore")

    # Close the last file; if it’s empty remove it
    out.close()
    if current_count == 0:
        try:
            current_path.unlink(missing_ok=True)  # last file was empty
        except TypeError:
            # Python <3.8 fallback
            if current_path.exists():
                current_path.unlink()
    else:
        written_files += 1

    return written_files, written_lines

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Split a text file into fixed-size line batches with numeric suffixes.")
    p.add_argument("-i", "--input", default="targets",
                   help="Input file path or '-' for stdin (default: targets)")
    p.add_argument("-o", "--outdir", type=Path, default=Path("target_batches"),
                   help="Output directory (default: target_batches)")
    p.add_argument("-p", "--prefix", default="targets_batch_",
                   help="Output filename prefix (default: targets_batch_)")
    p.add_argument("--suffix", default=".txt",
                   help="Output filename suffix (default: .txt)")
    p.add_argument("-n", "--lines", type=int, default=1000,
                   help="Lines per output file (default: 1000)")
    p.add_argument("-s", "--start", type=int, default=1,
                   help="Starting numeric suffix (default: 1)")
    p.add_argument("-w", "--width", type=int, default=2,
                   help="Zero-pad width for numeric suffix (default: 2)")
    args = p.parse_args(argv)

    if args.lines <= 0:
        print("Error: --lines must be a positive integer", file=sys.stderr)
        return 2
    if args.start < 0:
        print("Error: --start must be >= 0", file=sys.stderr)
        return 2
    if args.width <= 0:
        print("Error: --width must be a positive integer", file=sys.stderr)
        return 2

    try:
        files, lines = split_file(
            input_path=args.input,
            outdir=args.outdir,
            prefix=args.prefix,
            suffix=args.suffix,
            lines_per_file=args.lines,
            start=args.start,
            width=args.width,
        )
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Wrote {files} file(s) with a total of {lines} line(s) to {args.outdir}/")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
