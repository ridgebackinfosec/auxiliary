#!/usr/bin/env python3
"""
add_out_of_scope.py

Add out-of-scope IP addresses and CIDR ranges to the nessusd.rules file.

This tool automates the process of adding "reject" rules to Nessus configuration
to exclude out-of-scope systems from scanning. It safely inserts reject entries
just before the "default accept" line, creates backups, and prevents duplicates.

Usage examples:
  # Dry-run: preview what would be added
  python add_out_of_scope.py --input out-of-scope.txt

  # Apply changes from file
  python add_out_of_scope.py --input out-of-scope.txt --apply

  # Add single IP address
  python add_out_of_scope.py --ip 10.10.11.34 --apply

  # Add multiple IPs and ranges
  python add_out_of_scope.py --ip 10.10.11.34 --ip 192.168.1.0/24 --apply

  # Custom rules file location
  python add_out_of_scope.py --input systems.txt --rules-file /custom/path/nessusd.rules --apply
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


def validate_ip_or_cidr(value: str) -> str:
    """
    Validate an IPv4 address or CIDR range.

    Args:
        value: IP address (e.g., "10.10.11.34") or CIDR range (e.g., "192.168.1.0/24")

    Returns:
        The validated IP/CIDR string

    Raises:
        ValueError: If the value is not a valid IPv4 address or CIDR range
    """
    try:
        # Try parsing as network (handles both single IPs and CIDR)
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        raise ValueError(f"Invalid IPv4 address or CIDR range: {value}")


def load_ips_from_file(file_path: Path) -> list[str]:
    """
    Load IP addresses from a file, one per line.

    Args:
        file_path: Path to the file containing IPs

    Returns:
        List of IP addresses/CIDR ranges

    Note:
        - Ignores empty lines and lines starting with #
        - Validates each IP/CIDR before adding to the list
    """
    if not file_path.exists():
        print(f"Error: Input file not found: {file_path}", file=sys.stderr)
        raise FileNotFoundError(f"File not found: {file_path}")

    ips: list[str] = []
    line_num = 0

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Error: Failed to read file {file_path}: {e}", file=sys.stderr)
        raise

    for raw_line in content.splitlines():
        line_num += 1
        line = raw_line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Validate the IP/CIDR
        try:
            validated = validate_ip_or_cidr(line)
            ips.append(validated)
        except ValueError as e:
            print(f"Warning: Line {line_num} - {e}", file=sys.stderr)
            continue

    return ips


def extract_existing_rejects(rules_content: str) -> set[str]:
    """
    Extract existing reject rules from nessusd.rules content.

    Args:
        rules_content: Content of the nessusd.rules file

    Returns:
        Set of IP addresses/CIDR ranges that are already rejected
    """
    existing = set()
    # Match lines like "reject 10.10.11.34" or "reject 192.168.1.0/24"
    reject_pattern = re.compile(r'^\s*reject\s+(\S+)', re.IGNORECASE)

    for line in rules_content.splitlines():
        match = reject_pattern.match(line)
        if match:
            existing.add(match.group(1))

    return existing


def insert_reject_rules(rules_content: str, new_ips: list[str]) -> tuple[str, int]:
    """
    Insert new reject rules before the "default accept" line.

    Args:
        rules_content: Original nessusd.rules content
        new_ips: List of IPs/CIDR ranges to add as reject rules

    Returns:
        Tuple of (modified content, number of rules added)

    Raises:
        ValueError: If "default accept" line is not found
    """
    lines = rules_content.splitlines()

    # Find the "default accept" line
    default_accept_idx = -1
    for i, line in enumerate(lines):
        if re.match(r'^\s*default\s+accept\s*$', line, re.IGNORECASE):
            default_accept_idx = i
            break

    if default_accept_idx == -1:
        raise ValueError("Could not find 'default accept' line in nessusd.rules")

    # Build the reject rules
    reject_lines = [f"reject {ip}" for ip in new_ips]

    # Insert reject rules just before "default accept"
    modified_lines = (
        lines[:default_accept_idx] +
        reject_lines +
        lines[default_accept_idx:]
    )

    # Join with newlines and ensure final newline
    modified_content = "\n".join(modified_lines) + "\n"

    return modified_content, len(reject_lines)


def create_backup(rules_file: Path) -> Path:
    """
    Create a timestamped backup of the nessusd.rules file.

    Args:
        rules_file: Path to the nessusd.rules file

    Returns:
        Path to the backup file
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = rules_file.with_suffix(f".rules.backup.{timestamp}")

    try:
        backup_path.write_text(
            rules_file.read_text(encoding="utf-8", errors="ignore"),
            encoding="utf-8"
        )
        return backup_path
    except Exception as e:
        print(f"Error: Failed to create backup: {e}", file=sys.stderr)
        raise


def check_permissions(rules_file: Path) -> bool:
    """
    Check if we have write permissions for the rules file.

    Args:
        rules_file: Path to the nessusd.rules file

    Returns:
        True if we have write permissions, False otherwise
    """
    # Check if file exists and is writable
    if rules_file.exists():
        return os.access(rules_file, os.W_OK)

    # If file doesn't exist, check if parent directory is writable
    parent = rules_file.parent
    return parent.exists() and os.access(parent, os.W_OK)


def main(argv: Optional[list[str]] = None) -> int:
    """
    Main entry point for add_out_of_scope tool.

    Args:
        argv: Command-line arguments (defaults to sys.argv if None)

    Returns:
        Exit code: 0 for success, 1 for file errors, 2 for permission denied
    """
    p = argparse.ArgumentParser(
        description="Add out-of-scope systems to nessusd.rules file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run: preview what would be added
  %(prog)s --input out-of-scope.txt

  # Apply changes from file
  %(prog)s --input out-of-scope.txt --apply

  # Add single IP
  %(prog)s --ip 10.10.11.34 --apply

  # Add multiple IPs and ranges
  %(prog)s --ip 10.10.11.34 --ip 192.168.1.0/24 --apply
        """
    )

    p.add_argument(
        "--input",
        "-i",
        type=Path,
        metavar="FILE",
        help="File containing IP addresses/CIDR ranges (one per line)"
    )

    p.add_argument(
        "--ip",
        action="append",
        metavar="IP",
        help="IP address or CIDR range to add (can be specified multiple times)"
    )

    p.add_argument(
        "--rules-file",
        type=Path,
        default=Path("/opt/nessus/etc/nessus/nessusd.rules"),
        metavar="PATH",
        help="Path to nessusd.rules file (default: /opt/nessus/etc/nessus/nessusd.rules)"
    )

    p.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes (default is dry-run mode)"
    )

    args = p.parse_args(argv)

    # Validate that at least one input source is provided
    if not args.input and not args.ip:
        print("Error: Must specify either --input or --ip", file=sys.stderr)
        p.print_help()
        return 1

    # Collect IPs from all sources
    all_ips: list[str] = []

    # Load from file if specified
    if args.input:
        try:
            file_ips = load_ips_from_file(args.input)
            all_ips.extend(file_ips)
            print(f"Loaded {len(file_ips)} IP(s) from {args.input}")
        except (FileNotFoundError, Exception):
            return 1

    # Add command-line IPs if specified
    if args.ip:
        for ip in args.ip:
            try:
                validated = validate_ip_or_cidr(ip)
                all_ips.append(validated)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
        print(f"Added {len(args.ip)} IP(s) from command line")

    if not all_ips:
        print("Error: No valid IP addresses to process", file=sys.stderr)
        return 1

    # Remove duplicates while preserving order
    unique_ips = list(dict.fromkeys(all_ips))
    if len(unique_ips) < len(all_ips):
        print(f"Removed {len(all_ips) - len(unique_ips)} duplicate IP(s)")

    print(f"Total unique IPs to process: {len(unique_ips)}")

    # Check if nessusd.rules file exists
    if not args.rules_file.exists():
        print(f"Error: Rules file not found: {args.rules_file}", file=sys.stderr)
        return 1

    # Read the rules file
    try:
        rules_content = args.rules_file.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Error: Failed to read rules file: {e}", file=sys.stderr)
        return 1

    # Extract existing reject rules
    existing_rejects = extract_existing_rejects(rules_content)

    # Filter out IPs that are already rejected
    new_ips = [ip for ip in unique_ips if ip not in existing_rejects]

    if len(new_ips) < len(unique_ips):
        skipped = len(unique_ips) - len(new_ips)
        print(f"Skipped {skipped} IP(s) already in reject rules")

    if not new_ips:
        print("No new IPs to add. All specified IPs are already rejected.")
        return 0

    print(f"\nWill add {len(new_ips)} new reject rule(s):")
    for ip in new_ips:
        print(f"  reject {ip}")

    # If dry-run, stop here
    if not args.apply:
        print("\nDRY-RUN mode (no changes applied). Use --apply to modify the rules file.")
        return 0

    # Check permissions before attempting to modify
    if not check_permissions(args.rules_file):
        print(f"\nError: Permission denied. Cannot write to {args.rules_file}", file=sys.stderr)
        print("Tip: You may need to run this command with sudo or as root.", file=sys.stderr)
        return 2

    # Create backup
    try:
        backup_path = create_backup(args.rules_file)
        print(f"\nCreated backup: {backup_path}")
    except Exception:
        return 1

    # Insert the new reject rules
    try:
        modified_content, added_count = insert_reject_rules(rules_content, new_ips)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Write the modified content
    try:
        args.rules_file.write_text(modified_content, encoding="utf-8")
        print(f"Successfully added {added_count} reject rule(s) to {args.rules_file}")
    except Exception as e:
        print(f"Error: Failed to write rules file: {e}", file=sys.stderr)
        print(f"Your backup is safe at: {backup_path}", file=sys.stderr)
        return 1

    print("\nDone! Nessus will exclude these systems from scans.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
