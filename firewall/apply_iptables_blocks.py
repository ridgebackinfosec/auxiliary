#!/usr/bin/env python3
"""
apply_blocks.py

Add OUTPUT DROP rules with iptables for:
  - Destination IP ranges (iprange match, from a file)
  - Destination single IPs (from CLI flags and/or a file)

SAFE BY DEFAULT: runs in dry-run mode; use --apply to perform changes.

Examples:
  # Dry-run (show what would be done)
  python apply_blocks.py --ranges-file cleaned_ip_ranges.txt --ip 1.2.3.4 --ip 5.6.7.8

  # Apply ranges only (confirm interactively)
  sudo python apply_blocks.py --ranges-file cleaned_ip_ranges.txt --apply

  # Apply single IPs from a file and CLI, non-interactive, with save
  sudo python apply_blocks.py --ips-file block_ips.txt --ip 203.0.113.10 --apply --yes

  # Apply both, skip backup (not recommended) and skip saving persistent file
  sudo python apply_blocks.py -f cleaned_ip_ranges.txt --ip 198.51.100.22 --apply --yes --no-backup --no-save

  # Restore from backup (interactive selection)
  sudo python apply_blocks.py --restore

  # Restore from backup and save persistent rules
  sudo python apply_blocks.py --restore
"""
from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# ------------------ Privilege & shell helpers ------------------

def is_root() -> bool:
    """Check if the current process has root privileges.

    Returns:
        True if running as root (UID 0), False otherwise.

    Note:
        Returns False on Windows (no euid attribute).
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def run_cmd(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess:
    """Execute a shell command with optional output capture.

    Args:
        cmd: Command and arguments as a list (prevents shell injection)
        capture: If True, capture stdout/stderr for inspection

    Returns:
        CompletedProcess object containing returncode, stdout, stderr

    Note:
        Uses check=False to allow manual error handling by caller.
    """
    return subprocess.run(cmd, check=False, text=True, capture_output=capture)

# ------------------ IO helpers ------------------

def load_nonempty_lines(path: Path) -> list[str]:
    """Read lines from a file, filtering out empty lines and comments.

    Args:
        path: Path to the file to read

    Returns:
        List of non-empty, non-comment lines (stripped of whitespace)

    Note:
        Lines starting with '#' are treated as comments and skipped.
    """
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out

def ensure_backup_dir(backup_dir: Path) -> bool:
    """Ensure the backup directory exists, prompting user to create if needed.

    Args:
        backup_dir: Path to the backup directory

    Returns:
        True if directory exists or was created, False if user declined or creation failed

    Note:
        Prompts interactively if directory doesn't exist.
    """
    if backup_dir.exists():
        return True

    print(f"Directory {backup_dir} does not exist.")
    ans = input("Create it? (yes/no): ").strip().lower()
    if ans != "yes":
        print("Aborted: backup directory does not exist.")
        return False

    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {backup_dir}")
        return True
    except Exception as e:
        print(f"Error: Failed to create directory {backup_dir}: {e}", file=sys.stderr)
        return False

def list_backups(backup_dir: Path) -> list[Path]:
    """Find and list available iptables backup files.

    Args:
        backup_dir: Directory containing backup files

    Returns:
        List of backup file paths, sorted by modification time (newest first)

    Note:
        Looks for files matching pattern: rules.v4.bak-*
    """
    if not backup_dir.exists():
        return []

    backups = sorted(
        backup_dir.glob("rules.v4.bak-*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    return backups

def restore_from_backup(backup_path: Path, save_path: Path, do_save: bool) -> int:
    """Restore iptables rules from a backup file.

    Args:
        backup_path: Path to the backup file to restore from
        save_path: Path to save persistent rules if do_save is True
        do_save: Whether to save rules persistently after restoring

    Returns:
        Exit code: 0 for success, non-zero for errors

    Note:
        Requires root privileges and iptables-restore command.
    """
    if not backup_path.exists():
        print(f"Error: Backup file not found: {backup_path}", file=sys.stderr)
        return 1

    # Root check
    if not is_root():
        print("Error: restoring requires root privileges. Re-run with sudo.", file=sys.stderr)
        return 2

    print(f"Restoring iptables rules from: {backup_path}")

    try:
        # Use iptables-restore to apply the backup
        with open(backup_path, "r", encoding="utf-8") as f:
            cp = subprocess.run(
                ["iptables-restore"],
                stdin=f,
                check=False,
                text=True,
                capture_output=True
            )

        if cp.returncode != 0:
            print(f"Error: iptables-restore failed (exit {cp.returncode}).", file=sys.stderr)
            print(f"stderr: {cp.stderr}", file=sys.stderr)
            return 3

        print("Successfully restored iptables rules.")

        # Save persistent if requested
        if do_save:
            if not save_iptables_rules(save_path):
                print("Warning: Failed to save rules persistently.", file=sys.stderr)
                return 4

        return 0

    except Exception as e:
        print(f"Error: Failed to restore backup: {e}", file=sys.stderr)
        return 5

def backup_iptables_rules(backup_path: Path) -> bool:
    """Create a timestamped backup of current iptables rules.

    Args:
        backup_path: Path where the backup should be saved

    Returns:
        True if backup succeeded, False otherwise

    Note:
        Requires iptables-save command to be available and executable.
        Prints warning to stdout if backup fails.
    """
    # Ensure backup directory exists
    if not ensure_backup_dir(backup_path.parent):
        return False

    try:
        cp = run_cmd(["iptables-save"], capture=True)
        if cp.returncode != 0:
            print(f"Warning: iptables-save failed (exit {cp.returncode}).\n{cp.stderr}")
            return False
        backup_path.write_text(cp.stdout, encoding="utf-8")
        print(f"Backed up current iptables rules to: {backup_path}")
        return True
    except Exception as e:
        print(f"Failed to back up iptables rules: {e}")
        return False

def save_iptables_rules(target_path: Path) -> bool:
    """Save current iptables rules to a persistent file.

    Args:
        target_path: Path where rules should be saved (typically /etc/iptables/rules.v4)

    Returns:
        True if save succeeded, False otherwise

    Note:
        Creates parent directories if they don't exist.
        Used to persist rules across reboots on systems using iptables-persistent.
    """
    try:
        cp = run_cmd(["iptables-save"], capture=True)
        if cp.returncode != 0:
            print(f"Error: iptables-save failed (exit {cp.returncode}).\n{cp.stderr}")
            return False
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(cp.stdout, encoding="utf-8")
        print(f"Saved current iptables rules to: {target_path}")
        return True
    except Exception as e:
        print(f"Failed to save iptables rules: {e}")
        return False

# ------------------ Command builders ------------------

def cmd_for_range(dst_range: str) -> list[str]:
    """Build iptables command to DROP traffic to an IP range.

    Args:
        dst_range: IP range in format "A.B.C.D-E.F.G.H"

    Returns:
        Command list for iptables with iprange module

    Note:
        Appends rule to OUTPUT chain (blocks outbound traffic).
    """
    # iptables -A OUTPUT -m iprange --dst-range "A.B.C.D-E.F.G.H" -j DROP
    return ["iptables", "-A", "OUTPUT", "-m", "iprange", "--dst-range", dst_range, "-j", "DROP"]

def cmd_for_ip(ip: str) -> list[str]:
    """Build iptables command to DROP traffic to a single IP.

    Args:
        ip: Single IP address in dotted quad format (e.g., "192.168.1.1")

    Returns:
        Command list for iptables with destination match

    Note:
        Appends rule to OUTPUT chain (blocks outbound traffic).
    """
    # iptables -A OUTPUT -d "A.B.C.D" -j DROP
    return ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]

# ------------------ Main logic ------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Apply iptables OUTPUT DROP rules for IP ranges and/or single IPs (dry-run by default).")
    p.add_argument("--ranges-file", "-f", type=Path, default=Path("cleaned_ip_ranges.txt"),
                   help="File with destination IP ranges (one per line, e.g., 1.2.3.4-1.2.3.200). Default: cleaned_ip_ranges.txt (optional).")
    p.add_argument("--ips-file", type=Path,
                   help="File with destination IPs (one per line).")
    p.add_argument("--ip", action="append", default=[],
                   help="Destination IP to block (can repeat).")
    p.add_argument("--apply", action="store_true",
                   help="Actually apply the iptables rules. Otherwise, dry-run.")
    p.add_argument("--restore", action="store_true",
                   help="Restore iptables rules from a backup file (requires root).")
    p.add_argument("--yes", action="store_true",
                   help="Assume 'yes' to confirmation (dangerous).")
    p.add_argument("--no-backup", action="store_true",
                   help="Do not create a timestamped backup before modifying rules.")
    p.add_argument("--no-save", action="store_true",
                   help="Do not write /etc/iptables/rules.v4 after applying.")
    p.add_argument("--save-path", type=Path, default=Path("/etc/iptables/rules.v4"),
                   help="Where to write persistent rules via iptables-save. Default: /etc/iptables/rules.v4")
    args = p.parse_args(argv)

    # Handle restore mode
    if args.restore:
        backup_dir = Path("/etc/iptables")
        backups = list_backups(backup_dir)

        if not backups:
            print(f"No backup files found in {backup_dir}", file=sys.stderr)
            print("Backup files should match pattern: rules.v4.bak-*", file=sys.stderr)
            return 1

        print("Available backups (newest first):")
        for i, backup in enumerate(backups, start=1):
            mtime = datetime.fromtimestamp(backup.stat().st_mtime)
            print(f"  {i}. {backup.name} (modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')})")

        print()
        selection = input("Enter backup number to restore (or 'q' to quit): ").strip()

        if selection.lower() == 'q':
            print("Aborted by user.")
            return 0

        try:
            idx = int(selection) - 1
            if idx < 0 or idx >= len(backups):
                print(f"Error: Invalid selection. Please choose 1-{len(backups)}", file=sys.stderr)
                return 1
            selected_backup = backups[idx]
        except ValueError:
            print("Error: Invalid input. Please enter a number.", file=sys.stderr)
            return 1

        # Confirm restore
        print(f"\nYou selected: {selected_backup.name}")
        confirm = input("Proceed with restore? Type 'yes' to continue: ").strip().lower()
        if confirm != "yes":
            print("Aborted by user.")
            return 0

        # Perform restore
        do_save = not args.no_save
        return restore_from_backup(selected_backup, args.save_path, do_save)

    # Collect ranges (if file exists) and IPs (from file and CLI)
    ranges: list[str] = []
    if args.ranges_file and args.ranges_file.exists():
        ranges = load_nonempty_lines(args.ranges_file)

    ips: list[str] = []
    if args.ips_file:
        if not args.ips_file.exists():
            print(f"IPs file not found: {args.ips_file}", file=sys.stderr)
            return 1
        ips.extend(load_nonempty_lines(args.ips_file))
    # CLI --ip can repeat
    ips.extend([s.strip() for s in args.ip if s and s.strip()])

    if not ranges and not ips:
        print("No ranges or IPs provided. Nothing to do.")
        return 0

    # Build planned commands
    planned: list[list[str]] = []
    for r in ranges:
        planned.append(cmd_for_range(r))
    for ip in ips:
        planned.append(cmd_for_ip(ip))

    print("Planned iptables commands:")
    for c in planned:
        print(" ", " ".join(c))

    if not args.apply:
        print("\nDRY-RUN mode (no changes applied). Use --apply to run commands.")
        return 0

    # Confirm
    if not args.yes:
        ans = input("\nProceed to apply these rules? Type 'yes' to continue: ").strip().lower()
        if ans != "yes":
            print("Aborted by user.")
            return 2

    # Root check
    if not is_root():
        print("Error: applying requires root privileges. Re-run with sudo.", file=sys.stderr)
        return 3

    # Backup
    if not args.no_backup:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = Path(f"/etc/iptables/rules.v4.bak-{ts}")
        if not backup_iptables_rules(backup_path):
            print("Backup failed; aborting to avoid unsafe changes.", file=sys.stderr)
            return 4

    # Apply
    failures = 0
    for c in planned:
        print("Running:", " ".join(c))
        cp = run_cmd(c, capture=True)
        if cp.returncode != 0:
            failures += 1
            print(f"Command failed (exit {cp.returncode}). stdout/stderr:\n{cp.stdout}\n{cp.stderr}", file=sys.stderr)
        else:
            if "iprange" in c:
                print(f"Added DROP rule for range: {c[c.index('--dst-range') + 1]}")
            else:
                print(f"Added DROP rule for IP: {c[c.index('-d') + 1]}")

    if failures:
        print("\nOne or more iptables commands failed. Not saving persistent rules.", file=sys.stderr)
        return 5

    # Save persistent rules
    if not args.no_save:
        if not save_iptables_rules(args.save_path):
            print("Failed to save rules persistently.", file=sys.stderr)
            return 6
    else:
        print("Skipping persistent save (--no-save).")

    print("All rules added and saved successfully.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
