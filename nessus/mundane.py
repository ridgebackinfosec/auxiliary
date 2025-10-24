#!/usr/bin/env python3
# mundane.py

import sys, os, re, random, shutil, tempfile, subprocess, ipaddress, types, math
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Any, Optional, Callable, Iterable, Tuple, List, Dict, Set

# === Required dependencies (no fallbacks) ===
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.traceback import install as rich_tb_install

# --- Optional config loading (TOML) & structured logging (no behavior changes) ---
import logging
_DEFAULT_RESULTS_ROOT = 'scan_artifacts'

# Simple logger (kept inert unless you set MUNDANE_LOG_FILE). Does not change console Rich output.
_LOG = logging.getLogger("mundane")
if not _LOG.handlers:
    _LOG.setLevel(logging.INFO)
    _h = logging.NullHandler()
    _LOG.addHandler(_h)

from rich import box
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn as ProgTextColumn, TimeElapsedColumn
import pyperclip  # required

# Create a console for the interactive flow
_console_global = Console()

# Install pretty tracebacks (no try/except; fail loudly if Rich is absent)
rich_tb_install(show_locals=False)

# ========== Centralized constants ==========

# ----- Tooling & profiles (centralized) -----
PLUGIN_DETAILS_BASE = "https://www.tenable.com/plugins/nessus/"
NSE_PROFILES = [
    ("Crypto", ["ssl-enum-ciphers", "ssl-cert", "ssl-date"], False),
    ("SSH",    ["ssh2-enum-algos", "ssh-auth-methods"], False),
    ("SMB",    ["smb-security-mode", "smb2-security-mode"], False),
    ("SNMP",   ["snmp*"], True),
    ("IPMI",   ["ipmi-version"], True),
]
NETEXEC_PROTOCOLS = ["mssql","smb","ftp","ldap","nfs","rdp","ssh","vnc","winrm","wmi"]
RESULTS_ROOT: Path = Path(os.environ.get("NPH_RESULTS_ROOT", _DEFAULT_RESULTS_ROOT))
REVIEW_PREFIX: str = "REVIEW_COMPLETE-"

# ========== Colors & helpers ==========
NO_COLOR = (os.environ.get("NO_COLOR") is not None) or (os.environ.get("TERM") == "dumb")
class C:
    RESET  = "" if NO_COLOR else "\u001b[0m"
    BOLD   = "" if NO_COLOR else "\u001b[1m"
    BLUE   = "" if NO_COLOR else "\u001b[34m"
    GREEN  = "" if NO_COLOR else "\u001b[32m"
    YELLOW = "" if NO_COLOR else "\u001b[33m"
    RED    = "" if NO_COLOR else "\u001b[31m"
    CYAN   = "" if NO_COLOR else "\u001b[36m"
    MAGENTA= "" if NO_COLOR else "\u001b[35m"

def header(msg): print(f"{C.BOLD}{C.BLUE}\n{msg}{C.RESET}")
def ok(msg):     print(f"{C.GREEN}{msg}{C.RESET}")
def warn(msg):   print(f"{C.YELLOW}{msg}{C.RESET}")
def err(msg):    print(f"{C.RED}{msg}{C.RESET}")
def info(msg):   print(msg)
def fmt_action(text): return f"{C.CYAN}>> {text}{C.RESET}"
def fmt_reviewed(text): return f"{C.MAGENTA}{text}{C.RESET}"
def cyan_label(s: str) -> str: return f"{C.CYAN}{s}{C.RESET}"

def colorize_severity_label(label: str) -> str:
    L = label.strip().lower()
    if "critical" in L:
        color = C.RED
    elif "high" in L:
        color = C.YELLOW
    elif "medium" in L:
        color = C.BLUE
    elif "low" in L:
        color = C.GREEN
    elif "info" in L:
        color = C.CYAN
    else:
        color = C.MAGENTA
    return f"{C.BOLD}{color}{label}{C.RESET}"

def require_cmd(name):
    if shutil.which(name) is None:
        err(f"Required command '{name}' not found on PATH.")
        sys.exit(1)

def resolve_cmd(candidates):
    for c in candidates:
        if shutil.which(c):
            return c
    return None

def root_or_sudo_available() -> bool:
    try:
        if os.name != "nt" and os.geteuid() == 0:
            return True
    except AttributeError:
        pass
    return shutil.which("sudo") is not None

def yesno(prompt: str, default: str = "y") -> bool:
    """
    Consistent yes/no prompts with visible default: [Y/n] if default yes, [y/N] if default no.
    Accepts: y/yes/n/no (case-insensitive). Empty input = default.
    """
    default = (default or "y").lower()
    if default not in ("y", "n"):
        default = "y"
    suffix = " [Y/n] " if default == "y" else " [y/N] "
    while True:
        try:
            ans = input(prompt.rstrip() + suffix).strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to previous menu.")
            raise
        except EOFError:
            ans = ""
        if ans == "":
            return default == "y"
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        warn("Please answer 'y' or 'n'.")

def read_text_lines(path: Path):
    return [ln.rstrip("\r\n") for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines()]

def safe_print_file(path: Path, max_bytes: int = 2_000_000):
    """Print a file with a heading; guard against huge files."""
    try:
        if not path.exists():
            warn(f"(missing) {path}")
            return
        size = path.stat().st_size
        header(f"Showing: {path} ({size} bytes)")
        if size > max_bytes:
            warn(f"File is large; showing first {max_bytes} bytes.")
        with Progress(
            SpinnerColumn(style="cyan"),
            ProgTextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task("Reading file...", start=True)
            with path.open("rb") as f:
                data = f.read(max_bytes)
        try:
            print(data.decode("utf-8", errors="replace"))
        except Exception:
            print(data)
    except Exception as e:
        warn(f"Could not display file: {e}")

# === Paged viewing helpers (Raw / Grouped) ===
def _file_raw_payload_text(path: Path, max_bytes: int = 2_000_000) -> str:
    with path.open("rb") as f:
        data = f.read(max_bytes)
    return data.decode("utf-8", errors="replace")

def _file_raw_paged_text(path: Path, max_bytes: int = 2_000_000) -> str:
    if not path.exists():
        return f"(missing) {path}\n"
    size = path.stat().st_size
    lines = [f"Showing: {path} ({size} bytes)"]
    if size > max_bytes:
        lines.append(f"File is large; showing first {max_bytes} bytes.")
    lines.append(_file_raw_payload_text(path, max_bytes))
    return "\n".join(lines)

def page_text(text: str):
    """Send text through a pager if possible; otherwise print."""
    with _console_global.pager(styles=True):
        print(text, end="" if text.endswith("\n") else "\n")

def _default_page_size() -> int:
    try:
        h = shutil.get_terminal_size((80, 24)).lines
        return max(8, h - 10)
    except Exception:
        return 12

def menu_pager(text: str, page_size: Optional[int] = None):
    """
    Interactive pager that uses [N] Next / [P] Prev / [B] Back,
    mirroring the file-selection menu UX.
    Auto-exits without prompts when there’s only a single page.
    """
    lines = text.splitlines()
    if not lines:
        return
    ps = page_size or _default_page_size()
    total_pages = max(1, math.ceil(len(lines) / ps))

    if total_pages == 1:
        print(f"\nPage 1/1 — lines 1-{len(lines)} of {len(lines)}")
        print("─" * 80)
        print("\n".join(lines))
        print("─" * 80)
        return

    idx = 0
    while True:
        start = idx * ps
        end = start + ps
        chunk = lines[start:end]
        print(f"\nPage {idx+1}/{total_pages} — lines {start+1}-{min(end, len(lines))} of {len(lines)}")
        print("─" * 80)
        print("\n".join(chunk))
        print("─" * 80)
        print(fmt_action("[N] Next page / [P] Prev page / [B] Back"))
        try:
            ans = input("Action: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            return
        if ans in ("b", "back", "q", "x"):
            return
        if ans in ("n", "next"):
            if idx + 1 < total_pages:
                idx += 1
            else:
                warn("Already at last page.")
            continue
        if ans in ("p", "prev", "previous"):
            if idx > 0:
                idx -= 1
            else:
                warn("Already at first page.")
            continue
        if ans == "":
            return
        warn("Use N (next), P (prev), or B (back).")

def list_dirs(p: Path):
    return sorted([d for d in p.iterdir() if d.is_dir()], key=lambda d: d.name)

def list_files(p: Path):
    return sorted([f for f in p.iterdir() if f.is_file()], key=lambda f: f.name)

def split_host_port(token: str):
    """
    Accepts:
      - [IPv6]:port
      - [IPv6]
      - IPv4:port
      - hostname:port
      - bare IPv6
    Returns (host, port_or_None)
    """
    token = token.strip()
    if not token:
        return None, None
    if token.startswith("["):
        m = re.match(r"^\[(.+?)\](?::(\d+))?$", token)
        if m:
            return m.group(1), (m.group(2) if m.group(2) else None)
    if token.count(":") >= 2 and not re.search(r"]:\d+$", token):
        return token, None
    if ":" in token:
        h, p = token.rsplit(":", 1)
        if p.isdigit():
            return h, p
    return token, None

def parse_hosts_ports(lines):
    """Return (hosts_list, ports_str)."""
    hosts = []
    ports = set()
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        tokens = re.split(r"[\s,]+", ln)
        for t in tokens:
            host, port = split_host_port(t)
            if not host:
                continue
            hosts.append(host)
            if port:
                ports.add(port)
    hosts = list(dict.fromkeys(hosts))
    ports_str = ",".join(sorted(ports, key=lambda x: int(x))) if ports else ""
    return hosts, ports_str

def parse_file_hosts_ports_detailed(path: Path):
    """Return (hosts_order_preserved, ports_set, combos_map, had_explicit_ports)."""
    hosts = []
    ports = set()
    combos = defaultdict(set)
    lines = read_text_lines(path)
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        tokens = re.split(r"[\s,]+", ln)
        for t in tokens:
            h, p = split_host_port(t)
            if not h:
                continue
            hosts.append(h)
            if p:
                ports.add(p)
                combos[h].add(p)
    hosts = list(dict.fromkeys(hosts))
    had_explicit_ports = any(len(v) > 0 for v in combos.values())
    return hosts, ports, combos, had_explicit_ports

def write_work_files(workdir: Path, hosts, ports_str: str, udp: bool):
    workdir.mkdir(parents=True, exist_ok=True)
    tcp_ips = workdir / "tcp_ips.list"
    udp_ips = workdir / "udp_ips.list"
    tcp_sockets = workdir / "tcp_host_ports.list"

    tcp_ips.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    if udp:
        udp_ips.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    if ports_str:
        with tcp_sockets.open("w", encoding="utf-8") as f:
            for h in hosts:
                f.write(f"{h}:{ports_str}\n")
    return tcp_ips, udp_ips, tcp_sockets

def build_nmap_cmd(udp, nse_option, ips_file, ports_str, use_sudo, oabase: Path):
    cmd = []
    if use_sudo:
        cmd.append("sudo")
    cmd += ["nmap", "-A"]
    if nse_option:
        cmd.append(nse_option)
    cmd += ["-iL", str(ips_file)]
    if udp:
        cmd.append("-sU")
    if ports_str:
        cmd += ["-p", ports_str]
    cmd += ["-oA", str(oabase)]
    return cmd

def build_netexec_cmd(exec_bin: str, protocol: str, ips_file: Path, oabase: Path):
    log_path = f"{str(oabase)}.nxc.{protocol}.log"
    relay_path = None
    if protocol == "smb":
        relay_path = f"{str(oabase)}.SMB_Signing_not_required_targets.txt"
        cmd = [
            exec_bin, "smb", str(ips_file),
            "--gen-relay-list", relay_path,
            "--shares",
            "--log", log_path
        ]
    else:
        cmd = [exec_bin, protocol, str(ips_file), "--log", log_path]
    return cmd, log_path, relay_path

# ---------- Plugin details link helpers ----------

def _plugin_id_from_filename(name_or_path: Any) -> Optional[str]:
    name = name_or_path.name if isinstance(name_or_path, Path) else str(name_or_path)
    lower = name.lower()
    if lower.startswith(("review_complete", "review-complete")) and "-" in name:
        name = name.split("-", 1)[1]
    m = re.match(r"^(\d+)", name)
    return m.group(1) if m else None

def _plugin_details_line(path: Path) -> Optional[str]:
    pid = _plugin_id_from_filename(path)
    if pid:
        return f"Plugin Details: {PLUGIN_DETAILS_BASE}{pid}"
    return None

def copy_to_clipboard(s: str) -> tuple:
    """Clipboard via pyperclip; OS tool fallback if runtime environment blocks it."""
    try:
        pyperclip.copy(s)
        return True, 'Copied using pyperclip.'
    except Exception:
        enc = s.encode('utf-8')
        try:
            if sys.platform.startswith('darwin') and shutil.which('pbcopy'):
                subprocess.run(['pbcopy'], input=enc, check=True)
                return True, 'Copied using pbcopy.'
            if os.name == 'nt' and shutil.which('clip'):
                subprocess.run(['clip'], input=enc, check=True)
                return True, 'Copied using clip.'
            for tool, args in (
                ('xclip', ['xclip', '-selection', 'clipboard']),
                ('wl-copy', ['wl-copy']),
                ('xsel', ['xsel', '--clipboard', '--input']),
            ):
                if shutil.which(tool):
                    subprocess.run(args, input=enc, check=True)
                    return True, f'Copied using {tool}.'
        except subprocess.CalledProcessError as e:
            return False, f'Clipboard tool failed (exit {e.returncode}).'
        except Exception as e:
            return False, f'Clipboard error: {e}'
    return False, 'No suitable clipboard method found.'

def command_review_menu(cmd_list_or_str):
    """Display a small menu: run / copy / cancel."""
    header("Command Review")
    cmd_str = cmd_list_or_str if isinstance(cmd_list_or_str, str) else " ".join(cmd_list_or_str)
    print(cmd_str)
    print()
    print(fmt_action("[1] Run now"))
    print(fmt_action("[2] Copy command to clipboard (don’t run)"))
    print(fmt_action("[3] Cancel"))
    while True:
        try:
            choice = input("Choose: ").strip()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return "cancel"
        if choice in ("1", "r", "run"):
            return "run"
        if choice in ("2", "c", "copy"):
            return "copy"
        if choice in ("3", "x", "cancel"):
            return "cancel"
        warn("Enter 1, 2, or 3.")

def _count_severity_files(d: Path):
    files = [f for f in list_files(d) if f.suffix.lower() == ".txt"]
    reviewed = [f for f in files if f.name.lower().startswith(("review_complete", "review-complete"))]
    reviewed += [f for f in files if f.name.lower().startswith(("review_complete-", "review-complete-"))]
    reviewed = list(dict.fromkeys(reviewed))
    unreviewed = [f for f in files if f not in reviewed]
    return len(unreviewed), len(reviewed), len(files)

def _color_unreviewed(n: int) -> str:
    if n == 0: return f"{C.GREEN}{n}{C.RESET}"
    if n <= 10: return f"{C.YELLOW}{n}{C.RESET}"
    return f"{C.RED}{n}{C.RESET}"

def pretty_severity_label(name: str) -> str:
    m = re.match(r"^\d+_(.+)$", name)
    label = m.group(1) if m else name
    label = label.replace("_", " ").strip()
    return " ".join(w[:1].upper() + w[1:] for w in label.split())

def choose_from_list(items, title: str, allow_back=False, allow_exit=False):
    header(title)
    for i, it in enumerate(items, 1):
        print(f"[{i}] {it}")
    if allow_back:
        print(fmt_action("[B] Back"))
    if allow_exit:
        print(fmt_action("[X] Exit"))
    while True:
        try:
            ans = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            raise
        if allow_back and ans in ("b", "back"):
            return None
        if allow_exit and ans in ("x", "exit", "q", "quit"):
            return "exit"
        if ans.isdigit():
            i = int(ans)
            if 1 <= i <= len(items):
                return items[i-1]
        warn("Invalid choice.")

def is_review_complete(path: Path) -> bool:
    return path.name.startswith(REVIEW_PREFIX)

def rename_review_complete(path: Path):
    name = path.name
    prefix = REVIEW_PREFIX
    if is_review_complete(path):
        warn("Already marked as review complete.")
        return path
    new = path.with_name(prefix + name)
    try:
        path.rename(new)
        ok(f"Renamed to {new.name}")
        return new
    except Exception as e:
        err(f"Failed to rename: {e}")
        return path

# === NSE Profiles (single-selection) ===

def choose_nse_profile():
    header("NSE Profiles")
    for i, (name, scripts, _) in enumerate(NSE_PROFILES, 1):
        print(f"[{i}] {name} ({', '.join(scripts)})")
    print(fmt_action("[N] None (no NSE profile)"))
    print(fmt_action("[B] Back"))
    while True:
        try:
            ans = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return [], False
        if ans in ("b", "back"):
            return [], False
        if ans in ("n", "none", ""):
            return [], False
        if ans.isdigit():
            i = int(ans)
            if 1 <= i <= len(NSE_PROFILES):
                name, scripts, needs_udp = NSE_PROFILES[i-1]
                ok(f"Selected profile: {name} — including: {', '.join(scripts)}")
                return scripts[:], needs_udp
        warn("Invalid choice.")

def build_results_paths(scan_dir: Path, sev_dir: Path, plugin_filename: str):
    stem = Path(plugin_filename).stem
    sev_label = pretty_severity_label(sev_dir.name)
    out_dir = RESULTS_ROOT / scan_dir.name / sev_label / stem
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    oabase = out_dir / f"run-{ts}"
    return out_dir, oabase

# ====== Compare hosts/ports across filtered files ======
def _normalize_combos(hosts, ports_set, combos_map, had_explicit):
    if had_explicit and combos_map:
        items = []
        for h in hosts:
            ps = combos_map.get(h, set())
            items.append((h, tuple(sorted(ps, key=lambda x: int(x)))))
        return tuple(items)
    assumed = tuple(sorted(
        (h, tuple(sorted(ports_set, key=lambda x: int(x))))
        for h in hosts
    ))
    return assumed

# ---------- Rich style helpers ----------
def _severity_style(label: str) -> str:
    l = label.strip().lower()
    if "critical" in l: return "red"
    if "high"     in l: return "yellow"
    if "medium"   in l: return "magenta"
    if "low"      in l: return "green"
    if "info"     in l: return "cyan"
    return "magenta"

def _rich_severity_cell(label: str) -> Any:
    t = Text(label)
    t.stylize("bold")
    t.stylize(_severity_style(label))
    return t

def _rich_unreviewed_cell(n: int, total: int) -> Any:
    pct = 0
    if total:
        pct = round((n / total) * 100)
    t = Text(f"{n} ({pct}%)")
    if n == 0:
        t.stylize("green")
    elif n <= 10:
        t.stylize("yellow")
    else:
        t.stylize("red")
    return t

def _rich_reviewed_cell(n: int, total: int) -> Any:
    pct = 0
    if total:
        pct = round((n / total) * 100)
    t = Text(f"{n} ({pct}%)")
    t.stylize("magenta")
    return t

def _rich_total_cell(n: int) -> Any:
    t = Text(str(n))
    t.stylize("bold")
    return t

def _render_scan_table(scans):
    table = Table(title=None, box=box.SIMPLE, show_lines=False, pad_edge=False)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Scan")
    for i, sdir in enumerate(scans, 1):
        table.add_row(str(i), sdir.name)
    _console_global.print(table)

def _render_severity_table(severities, msf_summary=None):
    table = Table(title=None, box=box.SIMPLE, show_lines=False, pad_edge=False)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    # Headers now indicate percent (cells contain N (P%))
    table.add_column("Unreviewed (%)", justify="right", no_wrap=True)
    table.add_column("Reviewed (%)", justify="right", no_wrap=True)
    table.add_column("Total", justify="right", no_wrap=True)

    for i, sd in enumerate(severities, 1):
        unrev, rev, tot = _count_severity_files(sd)
        label = pretty_severity_label(sd.name)
        table.add_row(
            str(i),
            _rich_severity_cell(label),
            _rich_unreviewed_cell(unrev, tot),
            _rich_reviewed_cell(rev, tot),
            _rich_total_cell(tot),
        )

    if msf_summary:
        idx, unrev, rev, tot = msf_summary
        table.add_row(
            str(idx),
            _rich_severity_cell("Metasploit Module"),
            _rich_unreviewed_cell(unrev, tot),
            _rich_reviewed_cell(rev, tot),
            _rich_total_cell(tot),
        )

    _console_global.print(table)

def _render_file_list_table(display, sort_mode, get_counts_for, row_offset: int = 0):
    table = Table(title=None, box=box.SIMPLE, show_lines=False, pad_edge=False)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("File")
    if sort_mode == "hosts":
        table.add_column("Hosts", justify="right", no_wrap=True)

    for i, f in enumerate(display, 1):
        n = row_offset + i
        if sort_mode == "hosts":
            hc, _ps = get_counts_for(f)
            table.add_row(str(n), f.name, str(hc))
        else:
            table.add_row(str(n), f.name)

    _console_global.print(table)

def _render_compare_tables(parsed, host_intersection, host_union, port_intersection, port_union, same_hosts, same_ports, same_combos, groups_sorted):
    summary = Table(title=None, box=box.SIMPLE, show_lines=False, pad_edge=False)
    summary.add_column("Aspect")
    summary.add_column("Equal Across Files", justify="center", no_wrap=True)
    summary.add_column("Intersection Size", justify="right", no_wrap=True)
    summary.add_column("Union Size", justify="right", no_wrap=True)
    summary.add_row("Hosts", "✅" if same_hosts else "❌", str(len(host_intersection)), str(len(host_union)))
    summary.add_row("Ports", "✅" if same_ports else "❌", str(len(port_intersection)), str(len(port_union)))
    summary.add_row("Host:Port Combos", "✅" if same_combos else "❌", "-", "-")
    _console_global.print(summary)

    files_tbl = Table(title="Filtered Files", box=box.SIMPLE, show_lines=False, pad_edge=False)
    files_tbl.add_column("#", justify="right", no_wrap=True)
    files_tbl.add_column("File")
    files_tbl.add_column("Hosts", justify="right", no_wrap=True)
    files_tbl.add_column("Ports", justify="right", no_wrap=True)
    files_tbl.add_column("Explicit combos?", justify="center", no_wrap=True)

    for i, (f, hosts, ports_set, combos, had_explicit) in enumerate(parsed, 1):
        files_tbl.add_row(str(i), f.name, str(len(hosts)), str(len(ports_set)), "Yes" if had_explicit else "No")

    _console_global.print(files_tbl)

    if len(groups_sorted) > 1:
        groups = Table(title="Identical Host:Port Groups", box=box.SIMPLE, show_lines=False, pad_edge=False)
        groups.add_column("#", justify="right", no_wrap=True)
        groups.add_column("File count", justify="right", no_wrap=True)
        groups.add_column("Files (sample)")
        for i, names in enumerate(groups_sorted, 1):
            sample = "\n".join(names[:8]) + (f"\n... (+{len(names)-8} more)" if len(names) > 8 else "")
            groups.add_row(str(i), str(len(names)), sample)
        _console_global.print(groups)
    else:
        info("\nAll filtered files fall into a single identical group.")

def compare_filtered(files):
    if not files:
        warn("No files selected for comparison.")
        return []

    header("Filtered Files: Host/Port Comparison")
    info(f"Files compared: {len(files)}")

    parsed = []
    with Progress(
        SpinnerColumn(style="cyan"),
        ProgTextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Parsing files for comparison...", total=len(files))
        for f in files:
            hosts, ports_set, combos, had_explicit = parse_file_hosts_ports_detailed(f)
            parsed.append((f, hosts, ports_set, combos, had_explicit))
            progress.advance(task)

    all_host_sets = [set(h) for _, h, _, _, _ in parsed]
    all_port_sets = [set(p) for _, _, p, _, _ in parsed]
    host_intersection = set.intersection(*all_host_sets) if all_host_sets else set()
    host_union        = set.union(*all_host_sets) if all_host_sets else set()
    port_intersection = set.intersection(*all_port_sets) if all_port_sets else set()
    port_union        = set.union(*all_port_sets) if all_port_sets else set()

    host_sigs  = [tuple(sorted(h)) for _, h, _, _, _ in parsed]
    port_sigs  = [tuple(sorted(p, key=lambda x: int(x))) for _, _, p, _, _ in parsed]
    combo_sigs = [_normalize_combos(h, p, c, e) for _, h, p, c, e in parsed]

    same_hosts  = all(sig == host_sigs[0] for sig in host_sigs) if host_sigs else True
    same_ports  = all(sig == port_sigs[0] for sig in port_sigs) if port_sigs else True
    same_combos = all(sig == combo_sigs[0] for sig in combo_sigs) if combo_sigs else True

    groups_dict = defaultdict(list)
    with Progress(
        SpinnerColumn(style="cyan"),
        ProgTextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Grouping identical host:port combos...", total=len(parsed))
        for (f, h, p, c, e), sig in zip(parsed, combo_sigs):
            groups_dict[sig].append(f.name)
            progress.advance(task)

    with Progress(
        SpinnerColumn(style="cyan"),
        ProgTextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        progress.add_task("Sorting groups...", start=True)
        groups_sorted = sorted(groups_dict.values(), key=lambda names: len(names), reverse=True)

    _render_compare_tables(
        parsed,
        host_intersection, host_union, port_intersection, port_union,
        same_hosts, same_ports, same_combos,
        groups_sorted
    )
    return groups_sorted

# ====== Superset / coverage analysis across filtered files ======
def _build_item_set(hosts, ports_set, combos_map, had_explicit):
    """
    Return a set of atomic "items" for inclusion checks.
    Items are:
      - 'host:port' when a host has explicit ports (or implicit ports when had_explicit is False)
      - 'host'      when there are no ports at all for that host/file
    """
    items = set()
    if had_explicit:
        any_ports = any(bool(v) for v in combos_map.values())
        if any_ports:
            for h in hosts:
                ps = combos_map.get(h, set())
                if ps:
                    for p in ps:
                        items.add(f"{h}:{p}")
                else:
                    # Host present but no explicit ports for it — treat as bare host
                    items.add(h)
        else:
            # Defensive: had_explicit True but no ports recorded → fall back to bare hosts
            for h in hosts:
                items.add(h)
    else:
        # No explicit combos; interpret as Cartesian product hosts x ports_set, or bare hosts if no ports
        if ports_set:
            for h in hosts:
                for p in ports_set:
                    items.add(f"{h}:{p}")
        else:
            for h in hosts:
                items.add(h)
    return items

def analyze_inclusions(files):
    if not files:
        warn("No files selected for superset analysis.")
        return []

    header("Filtered Files: Superset / Coverage Analysis")
    info(f"Files analyzed: {len(files)}")

    parsed = []
    item_sets = {}
    with Progress(
        SpinnerColumn(style="cyan"),
        ProgTextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Parsing files...", total=len(files))
        for f in files:
            hosts, ports_set, combos, had_explicit = parse_file_hosts_ports_detailed(f)
            parsed.append((f, hosts, ports_set, combos, had_explicit))
            item_sets[f] = _build_item_set(hosts, ports_set, combos, had_explicit)
            progress.advance(task)

    # Build coverage map: for each file, which others does it fully include?
    cover_map = {f: set() for f in files}
    for i, a in enumerate(files):
        A = item_sets[a]
        for j, b in enumerate(files):
            if i == j:
                continue
            B = item_sets[b]
            if B.issubset(A):
                cover_map[a].add(b)

    # Maximals = files not strictly contained by any other
    maximals = []
    for a in files:
        A = item_sets[a]
        if not any((A < item_sets[b]) for b in files if b is not a):
            maximals.append(a)

    # Render summary table
    summary = Table(title=None, box=box.SIMPLE, show_lines=False, pad_edge=False)
    summary.add_column("#", justify="right", no_wrap=True)
    summary.add_column("File")
    summary.add_column("Items", justify="right", no_wrap=True)
    summary.add_column("Covers", justify="right", no_wrap=True)
    for i, f in enumerate(files, 1):
        summary.add_row(str(i), f.name, str(len(item_sets[f])), str(len(cover_map[f])))
    _console_global.print(summary)

    # Build groups with explicit root (superset) and covered list (without root)
    groups = []  # list of tuples (root_path, covered_paths_sorted)
    for mfile in sorted(maximals, key=lambda p: (-len(cover_map[p]), natural_key(p.name))):
        covered = sorted(list(cover_map[mfile]), key=lambda p: natural_key(p.name))
        groups.append((mfile, covered))

    if groups:
        groups_tbl = Table(title="Superset Coverage Groups", box=box.SIMPLE, show_lines=False, pad_edge=False)
        groups_tbl.add_column("#", justify="right", no_wrap=True)
        groups_tbl.add_column("Superset (root)")
        groups_tbl.add_column("Covers", justify="right", no_wrap=True)
        groups_tbl.add_column("Covered files (sample)")
        for i, (root, covered_list) in enumerate(groups, 1):
            sample_names = [p.name for p in covered_list[:8]]
            sample = "\n".join(sample_names) + (f"\n... (+{len(covered_list)-8} more)" if len(covered_list) > 8 else "")
            groups_tbl.add_row(str(i), root.name, str(len(covered_list)), sample or "—")
        _console_global.print(groups_tbl)
    else:
        info("\nNo coverage relationships detected (all sets are disjoint or mutually incomparable).")

    # Convert back to name groups (root + covered) for filtering behavior.
    name_groups = []
    for root, covered_list in groups:
        names = [root.name] + [p.name for p in covered_list]
        name_groups.append(names)
    return name_groups

# -------- Sorting helpers for file list --------
def natural_key(s: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', s)]

# ====== Scan overview helpers ======
_HNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')

def _is_hostname(s: str) -> bool:
    return bool(_HNAME_RE.match(s)) and len(s) <= 253

def _is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

def _is_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False

def _is_valid_token(tok: str):
    tok = tok.strip()
    if not tok:
        return False, None, None

    if tok.startswith("["):
        m = re.match(r"^\[(.+?)\](?::(\d+))?$", tok)
        if m and _is_ipv6(m.group(1)):
            port = m.group(2)
            if port is None:
                return True, m.group(1), None
            if port.isdigit() and 1 <= int(port) <= 65535:
                return True, m.group(1), port
        return False, None, None

    if tok.count(":") >= 2 and not re.search(r"]:\d+$", tok):
        return (_is_ipv6(tok), tok if _is_ipv6(tok) else None, None)

    if ":" in tok:
        h, p = tok.rsplit(":", 1)
        if p.isdigit() and 1 <= int(p) <= 65535 and (_is_hostname(h) or _is_ipv4(h)):
            return True, h, p
        return False, None, None

    if _is_hostname(tok) or _is_ipv4(tok) or _is_ipv6(tok):
        return True, tok, None

    return False, None, None

def _parse_for_overview(path: Path):
    """(hosts, ports:set, combos, had_explicit, malformed_count)"""
    hosts = []
    ports = set()
    combos = defaultdict(set)
    malformed = 0
    text = path.read_text(encoding="utf-8", errors="ignore")
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln:
            continue
        for tok in re.split(r"[\s,]+", ln):
            valid, h, p = _is_valid_token(tok)
            if not valid:
                malformed += 1
                continue
            hosts.append(h)
            if p:
                ports.add(p)
                combos[h].add(p)
    hosts = list(dict.fromkeys(hosts))
    had_explicit = any(combos[h] for h in combos)
    return hosts, ports, combos, had_explicit, malformed

def _count_reviewed_in_scan(scan_dir: Path):
    total_files = 0
    reviewed_files = 0
    for sev in list_dirs(scan_dir):
        files = [f for f in list_files(sev) if f.suffix.lower() == ".txt"]
        total_files += len(files)
        reviewed = [f for f in files if f.name.lower().startswith(("review_complete", "review-complete", "review_complete-", "review-complete-"))]
        reviewed = list(dict.fromkeys(reviewed))
        reviewed_files += len(reviewed)
    return total_files, reviewed_files

def show_scan_summary(scan_dir: Path, top_ports_n: int = 5):
    header(f"Scan Overview — {scan_dir.name}")

    severities = list_dirs(scan_dir)
    all_files = []
    for sev in severities:
        all_files.extend([f for f in list_files(sev) if f.suffix.lower() == ".txt"])

    total_files, reviewed_files = _count_reviewed_in_scan(scan_dir)

    unique_hosts = set()
    ipv4_set = set()
    ipv6_set = set()
    ports_counter = Counter()
    empties = 0
    malformed_total = 0
    combo_sig_counter = Counter()

    with Progress(
        SpinnerColumn(style="cyan"),
        ProgTextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Parsing files for overview...", total=len(all_files) or 1)
        for f in all_files:
            hosts, ports, combos, had_explicit, malformed = _parse_for_overview(f)
            malformed_total += malformed
            if not hosts:
                empties += 1
            unique_hosts.update(hosts)
            for h in hosts:
                try:
                    ip = ipaddress.ip_address(h)
                    if isinstance(ip, ipaddress.IPv4Address):
                        ipv4_set.add(h)
                    elif isinstance(ip, ipaddress.IPv6Address):
                        ipv6_set.add(h)
                except Exception:
                    pass
            for p in ports:
                ports_counter[p] += 1
            sig = _normalize_combos(hosts, ports, combos, had_explicit)
            combo_sig_counter[sig] += 1
            progress.advance(task)

    info(f"{cyan_label('Files:')} {total_files}  |  "
         f"{cyan_label('Reviewed:')} {reviewed_files}  |  "
         f"{cyan_label('Empty:')} {empties}  |  "
         f"{cyan_label('Malformed tokens:')} {malformed_total}")

    info(f"{cyan_label('Hosts:')} unique={len(unique_hosts)}  "
         f"({cyan_label('IPv4:')} {len(ipv4_set)} | {cyan_label('IPv6:')} {len(ipv6_set)})")
    if unique_hosts:
        sample = ", ".join(list(sorted(unique_hosts))[:5])
        info(f"  {cyan_label('Example:')} {sample}{' ...' if len(unique_hosts) > 5 else ''}")

    port_set = set(ports_counter.keys())
    info(f"{cyan_label('Ports:')} unique={len(port_set)}")
    if ports_counter:
        top_ports = ports_counter.most_common(top_ports_n)
        tp_str = ", ".join(f"{p} ({n} files)" for p, n in top_ports)
        info(f"  {cyan_label(f'Top {top_ports_n}:')} {tp_str}")

    multi_clusters = [c for c in combo_sig_counter.values() if c > 1]
    info(f"{cyan_label('Identical host:port groups across all files:')} {len(multi_clusters)}")
    if multi_clusters:
        sizes = sorted(multi_clusters, reverse=True)[:3]
        info("  " + cyan_label("Largest clusters:") + " " + ", ".join(f"{n} files" for n in sizes))

# === New: grouped host:ports printer ===
def print_grouped_hosts_ports(path: Path):
    try:
        hosts, _ports, combos, _had_explicit = parse_file_hosts_ports_detailed(path)
        if not hosts:
            warn(f"No hosts found in {path}")
            return
        header(f"Grouped view: {path.name}")
        for h in hosts:
            plist = sorted(combos[h], key=lambda x: int(x)) if combos[h] else []
            if plist:
                print(f"{h}:{','.join(plist)}")
            else:
                print(h)
    except Exception as e:
        warn(f"Error grouping hosts/ports: {e}")

def _grouped_payload_text(path: Path) -> str:
    hosts, _ports, combos, _had_explicit = parse_file_hosts_ports_detailed(path)
    out = []
    for h in hosts:
        plist = sorted(combos[h], key=lambda x: int(x)) if combos[h] else []
        out.append(f"{h}:{','.join(plist)}" if plist else h)
    return "\n".join(out) + ("\n" if out else "")

def _grouped_paged_text(path: Path) -> str:
    body = _grouped_payload_text(path)
    return f"Grouped view: {path.name}\n{body}"

# === New: hosts-only helpers ===
def _hosts_only_payload_text(path: Path) -> str:
    """Return hosts (IPs or FQDNs) one-per-line without any port information."""
    hosts, _ports, _combos, _had_explicit = parse_file_hosts_ports_detailed(path)
    return "\n".join(hosts) + ("\n" if hosts else "")

def _hosts_only_paged_text(path: Path) -> str:
    body = _hosts_only_payload_text(path)
    return f"Hosts-only view: {path.name}\n{body}"

# ---------- Run tools with a Rich spinner ----------

def _sudo_preflight_for_cmd(cmd) -> None:
    """
    If the command will use sudo, ensure we prompt clearly and validate credentials
    *before* showing a spinner. Centralized and backward-compatible.
    """
    try:
        needs_sudo = False
        if isinstance(cmd, list):
            needs_sudo = any(str(x) == "sudo" for x in cmd)
        elif isinstance(cmd, str):
            needs_sudo = cmd.strip().startswith("sudo ")
        if needs_sudo:
            print(fmt_action('This command may prompt for sudo...'))
        if not needs_sudo:
            return

        # If we already have cached creds, nothing will be printed.
        _chk = subprocess.run(["sudo", "-vn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if _chk.returncode != 0:
            print(fmt_action("Waiting for sudo password..."))
            try:
                subprocess.run(["sudo", "-v"], check=True)
            except KeyboardInterrupt:
                raise
            except subprocess.CalledProcessError as _e:
                raise subprocess.CalledProcessError(_e.returncode, _e.cmd)
    except Exception:
        # Non-fatal; proceed and let the command prompt naturally.
        pass
def run_command_with_progress(cmd, *, shell: bool = False, executable: Optional[str] = None) -> int:
    disp = cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd)
    if len(disp) > 120:
        disp = disp[:117] + "..."

    # Delay spinner until after sudo password (if needed)
    _sudo_preflight_for_cmd(cmd)
    try:
        def _cmd_starts_with_sudo(c):
            import os, re
            if isinstance(c, list):
                return len(c) > 0 and os.path.basename(str(c[0])) == "sudo"
            if isinstance(c, str):
                return bool(re.match(r'^\s*(?:\S*/)?sudo\b', c))
            return False

        if _cmd_starts_with_sudo(cmd):
            # Check if sudo is already validated (non-interactive); 0 => cached
            try:
                _chk = subprocess.run(["sudo", "-vn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                needs_pw = (_chk.returncode != 0)
            except Exception:
                needs_pw = True  # be conservative

            if needs_pw:
                print(f"{C.YELLOW}Waiting for sudo password...{C.RESET} (type it when prompted below)")
                # Prompt the user once, blocking, before launching the actual command.
                # This allows the spinner to only start after authentication is satisfied.
                try:
                    subprocess.run(["sudo", "-v"], check=True)
                except KeyboardInterrupt:
                    # Propagate so upstream code can handle graceful termination
                    raise
                except subprocess.CalledProcessError as _e:
                    # The user failed sudo; abort early with a useful message.
                    raise subprocess.CalledProcessError(_e.returncode, _e.cmd)
    except Exception:
        # Non-fatal: even if pre-validation fails, fallback to normal behavior.
        pass

    if isinstance(cmd, list):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    else:
        proc = subprocess.Popen(cmd, shell=True, executable=executable, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    try:
        with Progress(
            SpinnerColumn(style="cyan"),
            ProgTextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task(f"Running: {disp}", start=True)
            for line in iter(proc.stdout.readline, ""):
                print(line, end="")
                progress.refresh()
            proc.stdout.close()
            proc.wait()
            rc = proc.returncode
    except KeyboardInterrupt:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        finally:
            raise
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)
    return rc

# ---------- Wizard helpers ----------
def clone_nessus_plugin_hosts(repo_url: str, dest: Path) -> Path:
    """Clone NessusPluginHosts into dest if absent; returns the repo path."""
    if dest.exists() and (dest / "NessusPluginHosts.py").exists():
        ok(f"Repo already present: {dest}")
        return dest
    require_cmd("git")
    dest.parent.mkdir(parents=True, exist_ok=True)
    header("Cloning NessusPluginHosts")
    run_command_with_progress(["git", "clone", "--depth", "1", repo_url, str(dest)])
    ok(f"Cloned into {dest}")
    return dest

# ========== Action help & footer ==========

def _key_text(key: str, label: str, *, enabled: bool = True) -> Text:
    t = Text()
    t.append(f"[{key}] ", style="cyan")
    t.append(label, style=None if enabled else "dim")
    if not enabled:
        t.stylize("dim")
    return t

def _join_actions_texts(items: list[Text]) -> Text:
    out = Text()
    for i, it in enumerate(items):
        if i:
            out.append(" / ", style="dim")
        out.append(it)
    return out

def render_actions_footer(*, group_applied: bool, candidates_count: int, sort_mode: str, can_next: bool, can_prev: bool):
    """Two-row, two-column action footer."""
    left_row1  = _join_actions_texts([
        _key_text("Enter", "Open first match"),
        _key_text("B", "Back"),
        _key_text("?", "Help"),
    ])
    right_row1 = _join_actions_texts([
        _key_text("F", "Set filter"),
        _key_text("C", "Clear filter"),
        _key_text("O", f"Toggle sort (now: {'Hosts' if sort_mode=='hosts' else 'Name'})"),
    ])
    left_row2  = _join_actions_texts([
        _key_text("R", "Reviewed files"),
        _key_text("H", "Compare"),
        _key_text("I", "Superset analysis"),
        _key_text("M", f"Mark ALL filtered as REVIEW_COMPLETE ({candidates_count})"),
    ])
    right_items = [
        _key_text("N", "Next page", enabled=can_next),
        _key_text("P", "Prev page", enabled=can_prev),
    ]
    if group_applied:
        right_items.append(_key_text("X", "Clear group"))
    right_row2 = _join_actions_texts(right_items)

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left_row1, right_row1)
    grid.add_row(left_row2, right_row2)
    _console_global.print(grid)

def show_actions_help(*, group_applied: bool, candidates_count: int, sort_mode: str, can_next: bool, can_prev: bool):
    """Render a categorized help panel for main/MSF file lists."""
    t = Table.grid(padding=(0,1))
    t.add_row(Text("Navigation", style="bold"), _key_text("Enter", "Open first match"),
              _key_text("N", "Next page", enabled=can_next), _key_text("P", "Prev page", enabled=can_prev), _key_text("B", "Back"))
    t.add_row(Text("Filtering", style="bold"), _key_text("F", "Set filter"), _key_text("C", "Clear filter"))
    t.add_row(Text("Sorting", style="bold"), _key_text("O", f"Toggle sort (now: {'Hosts' if sort_mode=='hosts' else 'Name'})"))
    t.add_row(Text("Bulk review", style="bold"), _key_text("M", f"Mark ALL filtered as REVIEW_COMPLETE ({candidates_count})"))
    t.add_row(Text("Analysis", style="bold"),
              _key_text("H", "Compare hosts/ports (identical)"),
              _key_text("I", "Superset / coverage groups"))
    if group_applied:
        t.add_row(Text("Groups", style="bold"), _key_text("X", "Clear group filter"))
    panel = Panel(t, title="Actions", border_style="cyan")
    _console_global.print(panel)

def show_reviewed_help():
    t = Table.grid(padding=(0,1))
    t.add_row(Text("Filtering", style="bold"), _key_text("F", "Set filter"), _key_text("C", "Clear filter"))
    t.add_row(Text("Exit", style="bold"), _key_text("B", "Back"))
    panel = Panel(t, title="Reviewed Files — Actions", border_style="cyan")
    _console_global.print(panel)

# (legacy single-line builder left here unused for reference)
def footer_line(*, group_applied: bool, candidates_count: int, can_next: bool, can_prev: bool) -> str:
    right = []
    if can_next: right.append("[N] Next Page")
    if can_prev: right.append("[P] Prev Page")
    if group_applied: right.append("[X] Clear group")
    nav = "  ".join(right) if right else ""
    main = "[?] Help  [Enter] Open 1st File  [B] Back  |  [F] Filter  [C] Clear Filter  [O] Sort  [R] Reviewed List  [H] Compare  [M] Mark all reviewed ({})".format(candidates_count)
    if nav:
        main = main + "  |  " + nav
    return main

# ========== Tool selection ==========
def choose_tool():
    header("Choose a tool")
    print("[1] nmap")
    print("[2] netexec — multi-protocol")
    print("[3] Custom command (advanced)")
    print(fmt_action("[B] Back"))
    while True:
        try:
            ans = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return None
        if ans in ("b", "back", ""):
            return None if ans else "nmap"
        if ans.isdigit():
            i = int(ans)
            if i == 1: return "nmap"
            if i == 2: return "netexec"
            if i == 3: return "custom"
        warn("Invalid choice.")

def choose_netexec_protocol():
    header("NetExec: choose protocol")
    for i, p in enumerate(NETEXEC_PROTOCOLS, 1):
        print(f"[{i}] {p}")
    print(fmt_action("[B] Back"))
    print("(Press Enter for 'smb')")
    while True:
        try:
            ans = input("Choose protocol: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return None
        if ans == "":
            return "smb"
        if ans in ("b","back"):
            return None
        if ans.isdigit():
            idx = int(ans)
            if 1 <= idx <= len(NETEXEC_PROTOCOLS):
                return NETEXEC_PROTOCOLS[idx-1]
        if ans in NETEXEC_PROTOCOLS:
            return ans
        warn("Invalid choice.")

def custom_command_help(mapping: dict):
    header("Custom command")
    info("You can type any shell command. The placeholders below will be expanded:")
    for k, v in mapping.items():
        info(f"  {k:14s} -> {v}")
    print()
    info("Examples:")
    info("  httpx -l {TCP_IPS} -silent -o {OABASE}.urls.txt")
    info("  nuclei -l {OABASE}.urls.txt -o {OABASE}.nuclei.txt")
    info("  cat {TCP_IPS} | xargs -I{} sh -c 'echo {}; nmap -Pn -p {PORTS} {}'")

def render_placeholders(template: str, mapping: dict) -> str:
    s = template
    for k, v in mapping.items():
        s = s.replace(k, str(v))
    return s

# ============================================================

def main(args):
    use_sudo = root_or_sudo_available()
    if not use_sudo:
        warn("Not running as root and no 'sudo' found — some scan types (e.g., UDP) may fail.")

    export_root = Path(args.export_root)
    if not export_root.exists():
        err(f"Export root not found: {export_root}")
        sys.exit(1)

    ok(f"Using export root: {export_root.resolve()}")
    if args.no_tools:
        info("(no-tools mode: tool prompts disabled for this session)")

    reviewed_total = []
    completed_total = []
    skipped_total = []

    # Scan loop
    while True:
        scans = list_dirs(export_root)
        if not scans:
            err("No scan directories found.")
            return
        header("Select a scan")
        _render_scan_table(scans)
        print(fmt_action("[X] Exit"))
        try:
            ans = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — exiting.")
            return
        if ans in ("x", "exit", "q", "quit"):
            break
        if not ans.isdigit() or not (1 <= int(ans) <= len(scans)):
            warn("Invalid choice.")
            continue
        scan_dir = scans[int(ans)-1]

        # Overview immediately after selecting scan
        show_scan_summary(scan_dir)

        # Severity loop
        while True:
            header(f"Scan: {scan_dir.name} — choose severity")
            severities = list_dirs(scan_dir)
            if not severities:
                warn("No severity directories in this scan.")
                break

            def sev_key(p: Path):
                m = re.match(r"^(\d+)_", p.name)
                return -(int(m.group(1)) if m else 0), p.name
            severities = sorted(severities, key=sev_key)

            # Metasploit Module virtual group (menu counts)
            msf_files_for_count = []
            for sd in severities:
                for f in list_files(sd):
                    if f.suffix.lower() == ".txt" and f.name.endswith("-MSF.txt"):
                        msf_files_for_count.append((f, sd))
            has_msf = len(msf_files_for_count) > 0
            msf_total = len(msf_files_for_count)
            msf_reviewed = sum(
                1 for (f, _sd) in msf_files_for_count
                if f.name.lower().startswith(("review_complete", "review-complete", "review_complete-", "review-complete-"))
            )
            msf_unrev = msf_total - msf_reviewed

            msf_summary = (len(severities) + 1, msf_unrev, msf_reviewed, msf_total) if has_msf else None
            _render_severity_table(severities, msf_summary=msf_summary)

            print(fmt_action("[B] Back"))
            try:
                ans = input("Choose: ").strip().lower()
            except KeyboardInterrupt:
                warn("\nInterrupted — returning to scan menu.")
                break
            if ans in ("b", "back"):
                break
            options_count = len(severities) + (1 if has_msf else 0)
            if not ans.isdigit() or not (1 <= int(ans) <= options_count):
                warn("Invalid choice.")
                continue
            choice_idx = int(ans)

            # === Normal severity selected ===
            if choice_idx <= len(severities):
                sev_dir = severities[choice_idx-1]

                file_filter = ""
                reviewed_filter = ""
                group_filter = None
                sort_mode = "name"
                file_parse_cache = {}
                page_size = _default_page_size()
                page_idx = 0

                def get_counts_for(path: Path):
                    if path in file_parse_cache:
                        return file_parse_cache[path]
                    try:
                        lines = read_text_lines(path)
                        hosts, ports_str = parse_hosts_ports(lines)
                        stats = (len(hosts), ports_str)
                    except Exception:
                        stats = (0, "")
                    file_parse_cache[path] = stats
                    return stats

                while True:
                    header(f"Severity: {pretty_severity_label(sev_dir.name)}")
                    files = [f for f in list_files(sev_dir) if f.suffix.lower() == ".txt"]
                    reviewed = [f for f in files if f.name.lower().startswith(("review_complete", "review-complete", "review_complete-", "review-complete-"))]
                    unreviewed = [f for f in files if f not in reviewed]

                    candidates = [
                        u for u in unreviewed
                        if (file_filter.lower() in u.name.lower())
                        and (group_filter is None or u.name in group_filter[1])
                    ]

                    if sort_mode == "hosts":
                        display = sorted(
                            candidates,
                            key=lambda p: (-get_counts_for(p)[0], natural_key(p.name))
                        )
                    else:
                        display = sorted(candidates, key=lambda p: natural_key(p.name))

                    total_pages = max(1, math.ceil(len(display) / page_size)) if page_size > 0 else 1
                    if page_idx >= total_pages:
                        page_idx = total_pages - 1
                    start = page_idx * page_size
                    end = start + page_size
                    page_items = display[start:end]

                    try:
                        status = f"Unreviewed files ({len(unreviewed)}). Current filter: '{file_filter or '*'}'"
                        if group_filter:
                            status += f" | Group filter: #{group_filter[0]} ({len(group_filter[1])})"
                        status += f" | Sort: {'Host count ↓' if sort_mode=='hosts' else 'Name A→Z'}"
                        status += f" | Page: {page_idx+1}/{total_pages}"
                        print(status)

                        # Render the table first (list of files)
                        _render_file_list_table(page_items, sort_mode, get_counts_for, row_offset=start)

                        # Render the new two-row footer
                        can_next = page_idx + 1 < total_pages
                        can_prev = page_idx > 0
                        render_actions_footer(
                            group_applied=bool(group_filter),
                            candidates_count=len(candidates),
                            sort_mode=sort_mode,
                            can_next=can_next,
                            can_prev=can_prev,
                        )

                        ans2 = input("Choose a file number, or action: ").strip().lower()
                    except KeyboardInterrupt:
                        warn("\nInterrupted — returning to severity menu.")
                        break

                    if ans2 in ("?", "help"):
                        show_actions_help(
                            group_applied=bool(group_filter),
                            candidates_count=len(candidates),
                            sort_mode=sort_mode,
                            can_next=(page_idx + 1 < total_pages),
                            can_prev=(page_idx > 0),
                        )
                        continue

                    if ans2 in ("b", "back"):
                        break
                    if ans2 == "n":
                        if page_idx + 1 < total_pages:
                            page_idx += 1
                        else:
                            warn("Already at last page.")
                        continue
                    if ans2 == "p":
                        if page_idx > 0:
                            page_idx -= 1
                        else:
                            warn("Already at first page.")
                        continue
                    if ans2 == "f":
                        file_filter = input("Enter substring to filter by: ").strip()
                        page_idx = 0
                        continue
                    if ans2 == "c":
                        file_filter = ""
                        page_idx = 0
                        continue
                    if ans2 == "o":
                        sort_mode = "hosts" if sort_mode == "name" else "name"
                        ok(f"Sorting by {'host count (desc)' if sort_mode=='hosts' else 'name (A→Z)'}")
                        if sort_mode == "hosts":
                            missing = [p for p in candidates if p not in file_parse_cache]
                            if missing:
                                with Progress(
                                    SpinnerColumn(style="cyan"),
                                    ProgTextColumn("[progress.description]{task.description}"),
                                    TimeElapsedColumn(),
                                    console=_console_global,
                                    transient=True,
                                ) as progress:
                                    task = progress.add_task("Counting hosts in files...", total=len(missing))
                                    for p in missing:
                                        _ = get_counts_for(p)
                                        progress.advance(task)
                        page_idx = 0
                        continue
                    if ans2 == "x" and group_filter:
                        group_filter = None
                        ok("Cleared group filter.")
                        page_idx = 0
                        continue
                    if ans2 == "r":
                        header("Reviewed files (read-only)")
                        print(f"Current filter: '{reviewed_filter or '*'}'")
                        for i, f in enumerate([r for r in reviewed if (reviewed_filter.lower() in r.name.lower())], 1):
                            print(f"[{i}] {fmt_reviewed(f.name)}")
                        # actions footer under the list
                        print(fmt_action("[?] Help  [F] Set filter  [C] Clear filter  [B] Back"))
                        try:
                            choice = input("Action or [B]ack: ").strip().lower()
                        except KeyboardInterrupt:
                            warn("\nInterrupted — returning.")
                            continue
                        if choice in ("?", "help"):
                            show_reviewed_help()
                            continue
                        if choice == "f":
                            reviewed_filter = input("Enter substring to filter by: ").strip()
                            continue
                        if choice == "c":
                            reviewed_filter = ""
                            continue
                        if choice in ("b", "back"):
                            continue
                        warn("Read-only view; no file selection here.")
                        continue
                    if ans2 == "m":
                        if not candidates:
                            warn("No files match the current filter.")
                            continue
                        confirm_msg = (
                            f"You are about to rename {len(candidates)} files with prefix 'REVIEW_COMPLETE-'.\n"
                            "Type 'mark' to confirm, or anything else to cancel: "
                        )
                        confirm = input(f"{C.RED}{confirm_msg}{C.RESET}").strip().lower()
                        if confirm != "mark":
                            info("Canceled.")
                            continue
                        renamed = 0
                        with Progress(
                            SpinnerColumn(style="cyan"),
                            ProgTextColumn("[progress.description]{task.description}"),
                            TimeElapsedColumn(),
                            console=_console_global,
                            transient=True,
                        ) as progress:
                            task = progress.add_task("Marking files as REVIEW_COMPLETE...", total=len(candidates))
                            for f in candidates:
                                newp = rename_review_complete(f)
                                if newp != f or newp.name.startswith("REVIEW_COMPLETE-"):
                                    renamed += 1
                                    completed_total.append(newp.name)
                                progress.advance(task)
                        ok(f"Summary: {renamed} renamed, {len(candidates)-renamed} skipped.")
                        continue
                    if ans2 == "h":
                        if not candidates:
                            warn("No files match the current filter.")
                            continue
                        groups = compare_filtered(candidates)
                        if groups:
                            visible = min(5, len(groups))
                            opts = " | ".join(f"g{i+1}" for i in range(visible))
                            ellipsis = " | etc." if len(groups) > visible else ""
                            choice = input(
                                f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group: "
                            ).strip().lower()
                            if choice.startswith("g") and choice[1:].isdigit():
                                idx = int(choice[1:]) - 1
                                if 0 <= idx < len(groups):
                                    group_filter = (idx + 1, set(groups[idx]))
                                    ok(f"Applied group filter #{idx+1} ({len(groups[idx])} files).")
                                    page_idx = 0
                        continue
                    if ans2 == "i":
                        if not candidates:
                            warn("No files match the current filter.")
                            continue
                        groups = analyze_inclusions(candidates)
                        if groups:
                            visible = min(5, len(groups))
                            opts = " | ".join(f"g{i+1}" for i in range(visible))
                            ellipsis = " | etc." if len(groups) > visible else ""
                            choice = input(
                                f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group: "
                            ).strip().lower()
                            if choice.startswith("g") and choice[1:].isdigit():
                                idx = int(choice[1:]) - 1
                                if 0 <= idx < len(groups):
                                    group_filter = (idx + 1, set(groups[idx]))
                                    ok(f"Applied superset group #{idx+1} ({len(groups[idx])} files).")
                                    page_idx = 0
                        continue

                    if ans2 == "":
                        if not page_items:
                            warn("No files match the current page/filter.")
                            continue
                        chosen = page_items[0]
                    else:
                        if not ans2.isdigit():
                            warn("Please select a file by number, or use actions above.")
                            continue
                        global_idx = int(ans2) - 1
                        if global_idx < 0 or global_idx >= len(display):
                            warn("Invalid index.")
                            continue
                        chosen = display[global_idx]

                    lines = read_text_lines(chosen)
                    tokens = [ln for ln in lines if ln.strip()]
                    if not tokens:
                        warn("File is empty; skipping.")
                        skipped_total.append(chosen.name)
                        continue

                    hosts, ports_str = parse_hosts_ports(tokens)
                    header("Preview")
                    info(f"File: {chosen.name}")
                    _pd_line = _plugin_details_line(chosen)
                    if _pd_line:
                        info(_pd_line)
                    info(f"Hosts parsed: {len(hosts)}")
                    if hosts:
                        info(f"Example host: {hosts[0]}")
                    if ports_str:
                        info(f"Ports detected: {ports_str}")

                    try:
                        view_choice = input("\nView file? [R]aw / [G]rouped / [H]osts-only / [C] Copy / [N]one (default=N): ").strip().lower()
                    except KeyboardInterrupt:
                        continue
                    if view_choice in ("r", "raw"):
                        text = _file_raw_paged_text(chosen)
                        menu_pager(text)
                    elif view_choice in ("g", "grouped"):
                        text = _grouped_paged_text(chosen)
                        menu_pager(text)
                    elif view_choice in ("h", "hosts", "hosts-only"):
                        text = _hosts_only_paged_text(chosen)
                        menu_pager(text)
                    elif view_choice in ("c", "copy"):
                        sub = input("Copy [R]aw / [G]rouped / [H]osts-only? (default=G): ").strip().lower()
                        if sub in ("", "g", "grouped"):
                            payload = _grouped_payload_text(chosen)
                        elif sub in ("h", "hosts", "hosts-only"):
                            payload = _hosts_only_payload_text(chosen)
                        else:
                            payload = _file_raw_payload_text(chosen)
                        ok_flag, detail = copy_to_clipboard(payload)
                        if ok_flag:
                            ok("Copied to clipboard.")
                        else:
                            warn(f"{detail} Printing below for manual copy:")
                            print(payload)

                    completion_decided = False

                    if args.no_tools:
                        info("(no-tools mode active — skipping tool selection)")
                        try:
                            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                                newp = rename_review_complete(chosen)
                                completed_total.append(newp.name if newp != chosen else chosen.name)
                            else:
                                reviewed_total.append(chosen.name)
                            completion_decided = True
                        except KeyboardInterrupt:
                            continue
                        continue

                    try:
                        do_scan = yesno("\nRun a tool now?", default="n")
                    except KeyboardInterrupt:
                        continue

                    if not do_scan:
                        try:
                            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                                newp = rename_review_complete(chosen)
                                completed_total.append(newp.name if newp != chosen else chosen.name)
                            else:
                                reviewed_total.append(chosen.name)
                            completion_decided = True
                        except KeyboardInterrupt:
                            continue
                        continue

                    sample_hosts = hosts
                    if len(hosts) > 5:
                        try:
                            do_sample = yesno(f"There are {len(hosts)} hosts. Sample a subset?", default="n")
                        except KeyboardInterrupt:
                            continue
                        if do_sample:
                            while True:
                                try:
                                    k = input("How many hosts to sample? ").strip()
                                except KeyboardInterrupt:
                                    warn("\nInterrupted — not sampling.")
                                    break
                                if not k.isdigit() or int(k) <= 0:
                                    warn("Enter a positive integer.")
                                    continue
                                k = min(int(k), len(hosts))
                                sample_hosts = random.sample(hosts, k)
                                ok(f"Sampling {k} host(s).")
                                break

                    with Progress(
                        SpinnerColumn(style="cyan"),
                        ProgTextColumn("[progress.description]{task.description}"),
                        TimeElapsedColumn(),
                        console=_console_global,
                        transient=True,
                    ) as progress:
                        progress.add_task("Preparing workspace...", start=True)
                        workdir = Path(tempfile.mkdtemp(prefix="nph_work_"))
                        tcp_ips, udp_ips, tcp_sockets = write_work_files(workdir, sample_hosts, ports_str, udp=True)

                    out_dir_static = RESULTS_ROOT / scan_dir.name / pretty_severity_label(sev_dir.name) / Path(chosen.name).stem
                    out_dir_static.mkdir(parents=True, exist_ok=True)

                    tool_used = False
                    while True:
                        tool_choice = choose_tool()
                        if tool_choice is None:
                            break

                        _tmp_dir, oabase = build_results_paths(scan_dir, sev_dir, chosen.name)
                        results_dir = out_dir_static

                        nxc_relay_path = None

                        if tool_choice == "nmap":
                            try:
                                udp_ports = yesno("\nDo you want to perform UDP scanning instead of TCP?", default="n")
                            except KeyboardInterrupt:
                                break

                            try:
                                nse_scripts, needs_udp = choose_nse_profile()
                            except KeyboardInterrupt:
                                break

                            try:
                                extra = input("Enter additional NSE scripts (comma-separated, no spaces, or Enter to skip): ").strip()
                            except KeyboardInterrupt:
                                break
                            if extra:
                                for s in extra.split(","):
                                    s = s.strip()
                                    if s and s not in nse_scripts:
                                        nse_scripts.append(s)

                            extras_imply_udp = any(s.lower().startswith("snmp") or s.lower() == "ipmi-version" for s in nse_scripts)
                            if needs_udp or extras_imply_udp:
                                if not udp_ports:
                                    warn("SNMP/IPMI selected — switching to UDP scan.")
                                udp_ports = True

                            if nse_scripts:
                                info(f"{C.BOLD}NSE scripts to run:{C.RESET} {','.join(nse_scripts)}")
                            nse_option = f"--script={','.join(nse_scripts)}" if nse_scripts else ""

                            ips_file = udp_ips if udp_ports else tcp_ips
                            require_cmd("nmap")
                            cmd = build_nmap_cmd(udp_ports, nse_option, ips_file, ports_str, use_sudo, oabase)
                            display_cmd = cmd
                            artifact_note = f"Results base:  {oabase}  (nmap -oA)"

                        elif tool_choice == "netexec":
                            protocol = choose_netexec_protocol()
                            if not protocol:
                                continue
                            ips_file = tcp_ips
                            exec_bin = resolve_cmd(["nxc", "netexec"])
                            if not exec_bin:
                                warn("Neither 'nxc' nor 'netexec' was found in PATH.")
                                info("Skipping run; returning to tool menu.")
                                continue
                            cmd, nxc_log, relay_path = build_netexec_cmd(exec_bin, protocol, ips_file, oabase)
                            nxc_relay_path = relay_path
                            display_cmd = cmd
                            artifact_note = f"NetExec log:   {nxc_log}"

                        elif tool_choice == "custom":
                            mapping = {
                                "{TCP_IPS}": tcp_ips,
                                "{UDP_IPS}": udp_ips,
                                "{TCP_HOST_PORTS}": tcp_sockets,
                                "{PORTS}": ports_str or "",
                                "{WORKDIR}": workdir,
                                "{RESULTS_DIR}": results_dir,
                                "{OABASE}": oabase,
                            }
                            custom_command_help(mapping)
                            try:
                                template = input("\nEnter your command (placeholders allowed): ").strip()
                            except KeyboardInterrupt:
                                break
                            if not template:
                                warn("No command entered.")
                                continue
                            rendered = render_placeholders(template, mapping)
                            display_cmd = rendered
                            cmd = rendered
                            artifact_note = f"OABASE path:   {oabase}"

                        else:
                            warn("Unknown tool selection.")
                            continue

                        action = command_review_menu(display_cmd)

                        if action == "copy":
                            cmd_str = display_cmd if isinstance(display_cmd, str) else " ".join(display_cmd)
                            if copy_to_clipboard(cmd_str)[0]:
                                ok("Command copied to clipboard.")
                            else:
                                warn("Could not copy to clipboard automatically. Here it is to copy manually:")
                                print(cmd_str)
                        elif action == "run":
                            try:
                                tool_used = True
                                if isinstance(cmd, list):
                                    run_command_with_progress(cmd, shell=False)
                                else:
                                    shell_exec = shutil.which("bash") or shutil.which("sh")
                                    run_command_with_progress(cmd, shell=True, executable=shell_exec)
                            except KeyboardInterrupt:
                                warn("\nRun interrupted — returning to tool menu.")
                                continue
                            except subprocess.CalledProcessError as e:
                                err(f"Command exited with {e.returncode}.")
                                info("Returning to tool menu.")
                                continue
                        elif action == "cancel":
                            info("Canceled. Returning to tool menu.")
                            continue

                        header("Artifacts")
                        info(f"Workspace:     {workdir}")
                        info(f" - Hosts:      {workdir / 'tcp_ips.list'}")
                        if ports_str:
                            info(f" - Host:Ports: {workdir / 'tcp_host_ports.list'}")
                        info(f" - {artifact_note}")
                        if nxc_relay_path:
                            info(f" - Relay targets: {nxc_relay_path}")
                        info(f" - Results dir:{results_dir}")

                        try:
                            again = yesno("\nRun another command for this plugin file?", default="n")
                        except KeyboardInterrupt:
                            break
                        if not again:
                            break

                    if not completion_decided:
                        try:
                            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                                newp = rename_review_complete(chosen)
                                completed_total.append(newp.name if newp != chosen else chosen.name)
                            else:
                                reviewed_total.append(chosen.name)
                            completion_decided = True
                        except KeyboardInterrupt:
                            continue

                continue  # back to severity menu

            # === Metasploit Module (virtual) ===
            file_filter = ""
            reviewed_filter = ""
            group_filter = None
            sort_mode = "name"
            file_parse_cache = {}
            page_size = _default_page_size()
            page_idx = 0

            def get_counts_for_msf(path: Path):
                if path in file_parse_cache:
                    return file_parse_cache[path]
                try:
                    lines = read_text_lines(path)
                    hosts, ports_str = parse_hosts_ports(lines)
                    stats = (len(hosts), ports_str)
                except Exception:
                    stats = (0, "")
                file_parse_cache[path] = stats
                return stats

            while True:
                msf_files = []
                for sd in severities:
                    for f in list_files(sd):
                        if f.suffix.lower() == ".txt" and f.name.endswith("-MSF.txt"):
                            msf_files.append((f, sd))
                sev_map = {f: sd for (f, sd) in msf_files}

                header("Severity: Metasploit Module")
                files_all = [f for (f, _sd) in msf_files if f.suffix.lower() == ".txt"]
                reviewed_all = [f for f in files_all if f.name.lower().startswith(("review_complete", "review-complete", "review_complete-", "review-complete-"))]
                unreviewed_all = [f for f in files_all if f not in reviewed_all]

                candidates = [
                    u for u in unreviewed_all
                    if (file_filter.lower() in u.name.lower())
                    and (group_filter is None or u.name in group_filter[1])
                ]

                if sort_mode == "hosts":
                    display = sorted(
                        candidates,
                        key=lambda p: (-get_counts_for_msf(p)[0], natural_key(p.name))
                    )
                else:
                    display = sorted(candidates, key=lambda p: natural_key(p.name))

                total_pages = max(1, math.ceil(len(display) / page_size)) if page_size > 0 else 1
                if page_idx >= total_pages:
                    page_idx = total_pages - 1
                start = page_idx * page_size
                end = start + page_size
                page_items = display[start:end]

                try:
                    status = f"Unreviewed files ({len(unreviewed_all)}). Current filter: '{file_filter or '*'}'"
                    if group_filter:
                        status += f" | Group filter: #{group_filter[0]} ({len(group_filter[1])})"
                    status += f" | Sort: {'Host count ↓' if sort_mode=='hosts' else 'Name A→Z'}"
                    status += f" | Page: {page_idx+1}/{total_pages}"
                    print(status)

                    # File list first
                    _render_file_list_table(page_items, sort_mode, get_counts_for_msf, row_offset=start)

                    # New two-row footer
                    can_next = page_idx + 1 < total_pages
                    can_prev = page_idx > 0
                    render_actions_footer(
                        group_applied=bool(group_filter),
                        candidates_count=len(candidates),
                        sort_mode=sort_mode,
                        can_next=can_next,
                        can_prev=can_prev,
                    )

                    ans3 = input("Choose a file number, or action: ").strip().lower()
                except KeyboardInterrupt:
                    warn("\nInterrupted — returning to severity menu.")
                    break

                if ans3 in ("?", "help"):
                    show_actions_help(
                        group_applied=bool(group_filter),
                        candidates_count=len(candidates),
                        sort_mode=sort_mode,
                        can_next=(page_idx + 1 < total_pages),
                        can_prev=(page_idx > 0),
                    )
                    continue

                if ans3 in ("b", "back"):
                    break
                if ans3 == "n":
                    if page_idx + 1 < total_pages:
                        page_idx += 1
                    else:
                        warn("Already at last page.")
                    continue
                if ans3 == "p":
                    if page_idx > 0:
                        page_idx -= 1
                    else:
                        warn("Already at first page.")
                    continue
                if ans3 == "f":
                    file_filter = input("Enter substring to filter by: ").strip()
                    page_idx = 0
                    continue
                if ans3 == "c":
                    file_filter = ""
                    page_idx = 0
                    continue
                if ans3 == "o":
                    sort_mode = "hosts" if sort_mode == "name" else "name"
                    ok(f"Sorting by {'host count (desc)' if sort_mode=='hosts' else 'name (A→Z)'}")
                    if sort_mode == "hosts":
                        missing = [p for p in candidates if p not in file_parse_cache]
                        if missing:
                            with Progress(
                                SpinnerColumn(style="cyan"),
                                ProgTextColumn("[progress.description]{task.description}"),
                                TimeElapsedColumn(),
                                console=_console_global,
                                transient=True,
                            ) as progress:
                                task = progress.add_task("Counting hosts in files...", total=len(missing))
                                for p in missing:
                                    _ = get_counts_for_msf(p)
                                    progress.advance(task)
                    page_idx = 0
                    continue
                if ans3 == "x" and group_filter:
                    group_filter = None
                    ok("Cleared group filter.")
                    page_idx = 0
                    continue
                if ans3 == "r":
                    header("Reviewed files (read-only)")
                    print(f"Current filter: '{reviewed_filter or '*'}'")
                    for i, f in enumerate([r for r in reviewed_all if (reviewed_filter.lower() in r.name.lower())], 1):
                        sev_label = pretty_severity_label(sev_map[f].name)
                        sev_col = colorize_severity_label(sev_label)
                        print(f"[{i}] {fmt_reviewed(f.name)}  — {sev_col}")
                    # footer below the list
                    print(fmt_action("[?] Help  [F] Set filter  [C] Clear filter  [B] Back"))
                    try:
                        choice = input("Action or [B]ack: ").strip().lower()
                    except KeyboardInterrupt:
                        warn("\nInterrupted — returning.")
                        continue
                    if choice in ("?", "help"):
                        show_reviewed_help()
                        continue
                    if choice == "f":
                        reviewed_filter = input("Enter substring to filter by: ").strip()
                        continue
                    if choice == "c":
                        reviewed_filter = ""
                        continue
                    if choice in ("b", "back"):
                        continue
                    warn("Read-only view; no file selection here.")
                    continue
                if ans3 == "m":
                    if not candidates:
                        warn("No files match the current filter.")
                        continue
                    confirm_msg = (
                        f"You are about to rename {len(candidates)} files with prefix 'REVIEW_COMPLETE-'.\n"
                        "Type 'mark' to confirm, or anything else to cancel: "
                    )
                    confirm = input(f"{C.RED}{confirm_msg}{C.RESET}").strip().lower()
                    if confirm != "mark":
                        info("Canceled.")
                        continue
                    renamed = 0
                    with Progress(
                        SpinnerColumn(style="cyan"),
                        ProgTextColumn("[progress.description]{task.description}"),
                        TimeElapsedColumn(),
                        console=_console_global,
                        transient=True,
                    ) as progress:
                        task = progress.add_task("Marking files as REVIEW_COMPLETE...", total=len(candidates))
                        for f in candidates:
                            newp = rename_review_complete(f)
                            if newp != f or newp.name.startswith("REVIEW_COMPLETE-"):
                                renamed += 1
                                completed_total.append(newp.name)
                            progress.advance(task)
                    ok(f"Summary: {renamed} renamed, {len(candidates)-renamed} skipped.")
                    continue
                if ans3 == "h":
                    if not candidates:
                        warn("No files match the current filter.")
                        continue
                    groups = compare_filtered(candidates)
                    if groups:
                        visible = min(5, len(groups))
                        opts = " | ".join(f"g{i+1}" for i in range(visible))
                        ellipsis = " | etc." if len(groups) > visible else ""
                        choice = input(
                            f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group: "
                        ).strip().lower()
                        if choice.startswith("g") and choice[1:].isdigit():
                            idx = int(choice[1:]) - 1
                            if 0 <= idx < len(groups):
                                group_filter = (idx + 1, set(groups[idx]))
                                ok(f"Applied group filter #{idx+1} ({len(groups[idx])} files).")
                                page_idx = 0
                    continue
                if ans3 == "i":
                    if not candidates:
                        warn("No files match the current filter.")
                        continue
                    groups = analyze_inclusions(candidates)
                    if groups:
                        visible = min(5, len(groups))
                        opts = " | ".join(f"g{i+1}" for i in range(visible))
                        ellipsis = " | etc." if len(groups) > visible else ""
                        choice = input(
                            f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group: "
                        ).strip().lower()
                        if choice.startswith("g") and choice[1:].isdigit():
                            idx = int(choice[1:]) - 1
                            if 0 <= idx < len(groups):
                                group_filter = (idx + 1, set(groups[idx]))
                                ok(f"Applied superset group #{idx+1} ({len(groups[idx])} files).")
                                page_idx = 0
                    continue

                if ans3 == "":
                    if not page_items:
                        warn("No files match the current page/filter.")
                    else:
                        chosen = page_items[0]
                else:
                    if not ans3.isdigit():
                        warn("Please select a file by number, or use actions above.")
                        continue
                    global_idx = int(ans3) - 1
                    if global_idx < 0 or global_idx >= len(display):
                        warn("Invalid index.")
                        continue
                    chosen = display[global_idx]

                sev_dir_for_file = sev_map[chosen]

                lines = read_text_lines(chosen)
                tokens = [ln for ln in lines if ln.strip()]
                if not tokens:
                    warn("File is empty; skipping.")
                    skipped_total.append(chosen.name)
                    continue

                hosts, ports_str = parse_hosts_ports(tokens)
                header("Preview")
                info(f"File: {chosen.name}  — {pretty_severity_label(sev_dir_for_file.name)}")
                _pd_line = _plugin_details_line(chosen)
                if _pd_line:
                    info(_pd_line)
                info(f"Hosts parsed: {len(hosts)}")
                if hosts:
                    info(f"Example host: {hosts[0]}")
                if ports_str:
                    info(f"Ports detected: {ports_str}")

                try:
                    view_choice = input("\nView file? [R]aw / [G]rouped / [H]osts-only / [C] Copy / [N]one (default=N): ").strip().lower()
                except KeyboardInterrupt:
                    continue
                if view_choice in ("r", "raw"):
                    text = _file_raw_paged_text(chosen)
                    menu_pager(text)
                elif view_choice in ("g", "grouped"):
                    text = _grouped_paged_text(chosen)
                    menu_pager(text)
                elif view_choice in ("h", "hosts", "hosts-only"):
                    text = _hosts_only_paged_text(chosen)
                    menu_pager(text)
                elif view_choice in ("c", "copy"):
                    sub = input("Copy [R]aw / [G]rouped / [H]osts-only? (default=G): ").strip().lower()
                    if sub in ("", "g", "grouped"):
                        payload = _grouped_payload_text(chosen)
                    elif sub in ("h", "hosts", "hosts-only"):
                        payload = _hosts_only_payload_text(chosen)
                    else:
                        payload = _file_raw_payload_text(chosen)
                    ok_flag, detail = copy_to_clipboard(payload)
                    if ok_flag:
                        ok("Copied to clipboard.")
                    else:
                        warn(f"{detail} Printing below for manual copy:")
                        print(payload)

                completion_decided = False

                if args.no_tools:
                    info("(no-tools mode active — skipping tool selection)")
                    try:
                        if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                            newp = rename_review_complete(chosen)
                            completed_total.append(newp.name if newp != chosen else chosen.name)
                        else:
                            reviewed_total.append(chosen.name)
                        completion_decided = True
                    except KeyboardInterrupt:
                        continue
                    continue

                try:
                    do_scan = yesno("\nRun a tool now?", default="n")
                except KeyboardInterrupt:
                    continue

                if not do_scan:
                    try:
                        if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                            newp = rename_review_complete(chosen)
                            completed_total.append(newp.name if newp != chosen else chosen.name)
                        else:
                            reviewed_total.append(chosen.name)
                        completion_decided = True
                    except KeyboardInterrupt:
                        continue
                    continue

                sample_hosts = hosts
                if len(hosts) > 5:
                    try:
                        do_sample = yesno(f"There are {len(hosts)} hosts. Sample a subset?", default="n")
                    except KeyboardInterrupt:
                        continue
                    if do_sample:
                        while True:
                            try:
                                k = input("How many hosts to sample? ").strip()
                            except KeyboardInterrupt:
                                warn("\nInterrupted — not sampling.")
                                break
                            if not k.isdigit() or int(k) <= 0:
                                warn("Enter a positive integer.")
                                continue
                            k = min(int(k), len(hosts))
                            sample_hosts = random.sample(hosts, k)
                            ok(f"Sampling {k} host(s).")
                            break

                with Progress(
                    SpinnerColumn(style="cyan"),
                    ProgTextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                    console=_console_global,
                    transient=True,
                ) as progress:
                    progress.add_task("Preparing workspace...", start=True)
                    workdir = Path(tempfile.mkdtemp(prefix="nph_work_"))
                    tcp_ips, udp_ips, tcp_sockets = write_work_files(workdir, sample_hosts, ports_str, udp=True)

                out_dir_static = RESULTS_ROOT / scan_dir.name / pretty_severity_label(sev_dir_for_file.name) / Path(chosen.name).stem
                out_dir_static.mkdir(parents=True, exist_ok=True)

                tool_used = False
                while True:
                    tool_choice = choose_tool()
                    if tool_choice is None:
                        break

                    _tmp_dir, oabase = build_results_paths(scan_dir, sev_dir_for_file, chosen.name)
                    results_dir = out_dir_static

                    nxc_relay_path = None

                    if tool_choice == "nmap":
                        try:
                            udp_ports = yesno("\nDo you want to perform UDP scanning instead of TCP?", default="n")
                        except KeyboardInterrupt:
                            break

                        try:
                            nse_scripts, needs_udp = choose_nse_profile()
                        except KeyboardInterrupt:
                            break

                        try:
                            extra = input("Enter additional NSE scripts (comma-separated, no spaces, or Enter to skip): ").strip()
                        except KeyboardInterrupt:
                            break
                        if extra:
                            for s in extra.split(","):
                                s = s.strip()
                                if s and s not in nse_scripts:
                                    nse_scripts.append(s)

                        extras_imply_udp = any(s.lower().startswith("snmp") or s.lower() == "ipmi-version" for s in nse_scripts)
                        if needs_udp or extras_imply_udp:
                            if not udp_ports:
                                warn("SNMP/IPMI selected — switching to UDP scan.")
                            udp_ports = True

                        if nse_scripts:
                            info(f"{C.BOLD}NSE scripts to run:{C.RESET} {','.join(nse_scripts)}")
                        nse_option = f"--script={','.join(nse_scripts)}" if nse_scripts else ""

                        ips_file = udp_ips if udp_ports else tcp_ips
                        require_cmd("nmap")
                        cmd = build_nmap_cmd(udp_ports, nse_option, ips_file, ports_str, use_sudo, oabase)
                        display_cmd = cmd
                        artifact_note = f"Results base:  {oabase}  (nmap -oA)"

                    elif tool_choice == "netexec":
                        protocol = choose_netexec_protocol()
                        if not protocol:
                            continue
                        ips_file = tcp_ips
                        exec_bin = resolve_cmd(["nxc", "netexec"])
                        if not exec_bin:
                            warn("Neither 'nxc' nor 'netexec' was found in PATH.")
                            info("Skipping run; returning to tool menu.")
                            continue
                        cmd, nxc_log, relay_path = build_netexec_cmd(exec_bin, protocol, ips_file, oabase)
                        nxc_relay_path = relay_path
                        display_cmd = cmd
                        artifact_note = f"NetExec log:   {nxc_log}"

                    elif tool_choice == "custom":
                        mapping = {
                            "{TCP_IPS}": tcp_ips,
                            "{UDP_IPS}": udp_ips,
                            "{TCP_HOST_PORTS}": tcp_sockets,
                            "{PORTS}": ports_str or "",
                            "{WORKDIR}": workdir,
                            "{RESULTS_DIR}": results_dir,
                            "{OABASE}": oabase,
                        }
                        custom_command_help(mapping)
                        try:
                            template = input("\nEnter your command (placeholders allowed): ").strip()
                        except KeyboardInterrupt:
                            break
                        if not template:
                            warn("No command entered.")
                            continue
                        rendered = render_placeholders(template, mapping)
                        display_cmd = rendered
                        cmd = rendered
                        artifact_note = f"OABASE path:   {oabase}"

                    else:
                        warn("Unknown tool selection.")
                        continue

                    action = command_review_menu(display_cmd)

                    if action == "copy":
                        cmd_str = display_cmd if isinstance(display_cmd, str) else " ".join(display_cmd)
                        if copy_to_clipboard(cmd_str)[0]:
                            ok("Command copied to clipboard.")
                        else:
                            warn("Could not copy to clipboard automatically. Here it is to copy manually:")
                            print(cmd_str)
                    elif action == "run":
                        try:
                            tool_used = True
                            if isinstance(cmd, list):
                                run_command_with_progress(cmd, shell=False)
                            else:
                                shell_exec = shutil.which("bash") or shutil.which("sh")
                                run_command_with_progress(cmd, shell=True, executable=shell_exec)
                        except KeyboardInterrupt:
                            warn("\nRun interrupted — returning to tool menu.")
                            continue
                        except subprocess.CalledProcessError as e:
                            err(f"Command exited with {e.returncode}.")
                            info("Returning to tool menu.")
                            continue
                    elif action == "cancel":
                        info("Canceled. Returning to tool menu.")
                        continue

                    header("Artifacts")
                    info(f"Workspace:     {workdir}")
                    info(f" - Hosts:      {workdir / 'tcp_ips.list'}")
                    if ports_str:
                        info(f" - Host:Ports: {workdir / 'tcp_host_ports.list'}")
                    info(f" - {artifact_note}")
                    if nxc_relay_path:
                        info(f" - Relay targets: {nxc_relay_path}")
                    info(f" - Results dir:{results_dir}")

                    try:
                        again = yesno("\nRun another command for this plugin file?", default="n")
                    except KeyboardInterrupt:
                        break
                    if not again:
                        break

                if not completion_decided:
                    try:
                        if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                            newp = rename_review_complete(chosen)
                            completed_total.append(newp.name if newp != chosen else chosen.name)
                        else:
                            reviewed_total.append(chosen.name)
                        completion_decided = True
                    except KeyboardInterrupt:
                        continue

    header("Session Summary")
    info(f"Reviewed (not renamed): {len(reviewed_total)}")
    if reviewed_total:
        for n in reviewed_total:
            print(f" - {n}")
    info(f"Marked complete: {len(completed_total)}")
    if completed_total:
        for n in completed_total:
            print(f" - {n}")
    info(f"Skipped (empty): {len(skipped_total)}")
    if skipped_total:
        for n in skipped_total:
            print(f" - {n}")
    ok("Done.")

# ------------------------------
# Typer CLI (required)
# ------------------------------
app = typer.Typer(no_args_is_help=True, add_completion=False, help="mundane — faster review & tooling runner")
_console = _console_global

@app.callback()
def _root():
    """Modern CLI for mundane."""
    return

@app.command(help="Interactive review (calls the existing flow).")
def review(
    export_root: Path = typer.Option(Path("./nessus_plugin_hosts"), "--export-root", "-r", help="Scan exports root."),
    no_tools: bool = typer.Option(False, "--no-tools", help="Disable tool prompts (review-only)."),
):
    args = types.SimpleNamespace(export_root=str(export_root), no_tools=no_tools)
    try:
        main(args)
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")

@app.command(help="Preview a plugin file (raw or grouped).")
def view(
    file: Path = typer.Argument(..., exists=True, readable=True),
    grouped: bool = typer.Option(False, "--grouped", "-g", help="Show host:port,port,..."),
):
    if grouped:
        print_grouped_hosts_ports(file)
    else:
        safe_print_file(file)

@app.command(help="Compare plugin files and group identical host:port combos.")
def compare(
    paths: list[str] = typer.Argument(..., help="Files/dirs/globs to compare (e.g., '4_Critical/*.txt').")
):
    out: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            out.extend([f for f in pp.rglob("*.txt")])
        else:
            if any(ch in p for ch in ["*", "?", "["]):
                out.extend([Path(x) for x in map(str, Path().glob(p)) if str(x).endswith(".txt")])
            else:
                out.append(pp)
    files = [f for f in out if f.exists()]
    if not files:
        err("No plugin files found for comparison.")
        raise typer.Exit(1)
    _ = compare_filtered(files)

@app.command(help="Show a scan summary for a scan directory.")
def summary(
    scan_dir: Path = typer.Argument(..., exists=True, dir_okay=True, file_okay=False),
    top_ports: int = typer.Option(5, "--top-ports", "-n", min=1, help="How many top ports to show."),
):
    show_scan_summary(scan_dir, top_ports_n=top_ports)

@app.command(help="Wizard: seed exported plugin files from a .nessus scan using NessusPluginHosts.")
def wizard(
    nessus: Path = typer.Argument(..., exists=True, readable=True, help="Path to a .nessus file"),
    out_dir: Path = typer.Option(Path("./nessus_plugin_hosts"), "--out-dir", "-o", help="Export output directory"),
    repo_dir: Path = typer.Option(Path.home() / "NessusPluginHosts", "--repo-dir", help="Where to clone the helper repo"),
    review: bool = typer.Option(False, "--review", help="Launch interactive review after export"),
):
    # 1) Ensure repo present
    repo_url = "https://github.com/DefensiveOrigins/NessusPluginHosts"
    repo_path = clone_nessus_plugin_hosts(repo_url, repo_dir)

    # 2) Run export
    header("Exporting plugin host files")
    out_dir.mkdir(parents=True, exist_ok=True)
    helper = repo_path / "NessusPluginHosts.py"
    if not helper.exists():
        err(f"Helper script not found: {helper}")
        raise typer.Exit(1)
    cmd = [sys.executable, str(helper), "-f", str(nessus), "--list-plugins", "--export-plugin-hosts", str(out_dir)]
    run_command_with_progress(cmd, shell=False)

    ok(f"Export complete. Files written under: {out_dir.resolve()}")
    info("Next step:")
    info(f"  python mundane.py review --export-root {out_dir}")

    if review:
        args = types.SimpleNamespace(export_root=str(out_dir), no_tools=False)
        try:
            main(args)
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to shell.")

if __name__ == "__main__":

    # Optional: enable file logging via env var without changing terminal UX
    _log_file = os.environ.get("MUNDANE_LOG_FILE")
    if _log_file and isinstance(_LOG.handlers[0], logging.NullHandler):
        fh = logging.FileHandler(_log_file, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        _LOG.addHandler(fh)

    app()