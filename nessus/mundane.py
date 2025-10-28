#!/usr/bin/env python3
# --- import path shim (supports both `python mundane.py` and `python -m mundane`) ---
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from mundane_pkg import (
    # ops
    require_cmd, resolve_cmd, root_or_sudo_available,
    run_command_with_progress, clone_nessus_plugin_hosts,

    # parsing
    normalize_combos, parse_for_overview,
    parse_hosts_ports,
    parse_file_hosts_ports_detailed,

    # constants
    RESULTS_ROOT, PLUGIN_DETAILS_BASE,
    NSE_PROFILES,

    # ansi / labels
    C, header, ok, warn, err, info,
    fmt_action, fmt_reviewed, cyan_label, colorize_severity_label,

    # render:
    render_scan_table, render_severity_table, render_file_list_table,
    render_actions_footer, show_actions_help,
    show_reviewed_help, menu_pager, pretty_severity_label, list_files, default_page_size,

    # fs:
    list_dirs, read_text_lines, safe_print_file, build_results_paths,
    rename_review_complete, write_work_files,

    # tools:
    build_nmap_cmd, build_netexec_cmd,
    choose_tool, choose_netexec_protocol,
    custom_command_help, render_placeholders,
    command_review_menu, copy_to_clipboard,
    choose_nse_profile,

    # analysis
    compare_filtered, analyze_inclusions,
    natural_key, count_reviewed_in_scan
)

import re, random, shutil, tempfile, subprocess, ipaddress, types, math
from pathlib import Path
from collections import Counter
from typing import Any, Optional, Tuple, List, Dict, Callable

# === Required dependencies (no fallbacks) ===
import typer
from rich.console import Console
from rich.traceback import install as rich_tb_install
from rich.progress import Progress, SpinnerColumn, TextColumn as ProgTextColumn, TimeElapsedColumn
from rich.prompt import Confirm

# Create a console for the interactive flow
_console_global = Console()

# Install pretty tracebacks (no try/except; fail loudly if Rich is absent)
rich_tb_install(show_locals=False)

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

def _color_unreviewed(n: int) -> str:
    if n == 0: return f"{C.GREEN}{n}{C.RESET}"
    if n <= 10: return f"{C.YELLOW}{n}{C.RESET}"
    return f"{C.RED}{n}{C.RESET}"

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

# ====== Scan overview helpers ======
def show_scan_summary(scan_dir: Path, top_ports_n: int = 5):
    header(f"Scan Overview — {scan_dir.name}")

    severities = list_dirs(scan_dir)
    all_files = []
    for sev in severities:
        all_files.extend([f for f in list_files(sev) if f.suffix.lower() == ".txt"])

    total_files, reviewed_files = count_reviewed_in_scan(scan_dir)

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
            hosts, ports, combos, had_explicit, malformed = parse_for_overview(f)
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
            sig = normalize_combos(hosts, ports, combos, had_explicit)
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

# ========== REFACTORED: File viewing logic ==========
def handle_file_view(chosen: Path):
    """Unified file viewing handler (raw/grouped/hosts-only/copy)"""
    try:
        view_choice = input("\nView file? [R]aw / [G]rouped / [H]osts-only / [C] Copy / [N]one (default=N): ").strip().lower()
    except KeyboardInterrupt:
        return
    
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

# ========== REFACTORED: Tool execution flow ==========
def run_tool_workflow(chosen: Path, scan_dir: Path, sev_dir: Path, hosts: List[str], 
                      ports_str: str, args, use_sudo: bool) -> bool:
    """
    Unified tool execution workflow. Returns True if any tool was used.
    """
    sample_hosts = hosts
    if len(hosts) > 5:
        try:
            do_sample = yesno(f"There are {len(hosts)} hosts. Sample a subset?", default="n")
        except KeyboardInterrupt:
            return False
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
    
    # Get plugin details for Metasploit
    _pd_line = _plugin_details_line(chosen)
    try:
        plugin_url = _pd_line.split()[-1] if _pd_line else None
    except Exception:
        plugin_url = None

    while True:
        tool_choice = choose_tool()
        if tool_choice is None:
            break

        _tmp_dir, oabase = build_results_paths(scan_dir, sev_dir, chosen.name)
        results_dir = out_dir_static
        nxc_relay_path = None

        if tool_choice == "nmap":
            cmd, display_cmd, artifact_note = _build_nmap_workflow(
                tcp_ips, udp_ips, ports_str, use_sudo, oabase
            )
            if cmd is None:  # User interrupted
                break

        elif tool_choice == "netexec":
            result = _build_netexec_workflow(tcp_ips, oabase)
            if result is None:
                continue
            cmd, display_cmd, artifact_note, nxc_relay_path = result

        elif tool_choice == "metasploit":
            if plugin_url:
                from mundane_pkg import tools as _tools
                try:
                    _tools.interactive_msf_search(plugin_url)
                except Exception:
                    warn("Metasploit search failed; continuing to tool menu.")
            continue

        elif tool_choice == "custom":
            result = _build_custom_workflow(tcp_ips, udp_ips, tcp_sockets, ports_str, workdir, results_dir, oabase)
            if result is None:
                break
            cmd, display_cmd, artifact_note = result

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
    
    return tool_used

def _build_nmap_workflow(tcp_ips, udp_ips, ports_str, use_sudo, oabase):
    """Build nmap command workflow"""
    try:
        udp_ports = yesno("\nDo you want to perform UDP scanning instead of TCP?", default="n")
    except KeyboardInterrupt:
        return None, None, None

    try:
        nse_scripts, needs_udp = choose_nse_profile()
    except KeyboardInterrupt:
        return None, None, None

    try:
        extra = input("Enter additional NSE scripts (comma-separated, no spaces, or Enter to skip): ").strip()
    except KeyboardInterrupt:
        return None, None, None
    
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
    return cmd, cmd, f"Results base:  {oabase}  (nmap -oA)"

def _build_netexec_workflow(tcp_ips, oabase):
    """Build netexec command workflow"""
    protocol = choose_netexec_protocol()
    if not protocol:
        return None
    
    exec_bin = resolve_cmd(["nxc", "netexec"])
    if not exec_bin:
        warn("Neither 'nxc' nor 'netexec' was found in PATH.")
        info("Skipping run; returning to tool menu.")
        return None
    
    cmd, nxc_log, relay_path = build_netexec_cmd(exec_bin, protocol, tcp_ips, oabase)
    return cmd, cmd, f"NetExec log:   {nxc_log}", relay_path

def _build_custom_workflow(tcp_ips, udp_ips, tcp_sockets, ports_str, workdir, results_dir, oabase):
    """Build custom command workflow"""
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
        return None
    
    if not template:
        warn("No command entered.")
        return None
    
    rendered = render_placeholders(template, mapping)
    return rendered, rendered, f"OABASE path:   {oabase}"

# ========== REFACTORED: File processing workflow ==========
def process_single_file(chosen: Path, scan_dir: Path, sev_dir: Path, args, use_sudo: bool,
                       skipped_total: List[str], reviewed_total: List[str], 
                       completed_total: List[str]):
    """
    Unified file processing workflow - handles preview, view, tools, and completion marking.
    """
    lines = read_text_lines(chosen)
    tokens = [ln for ln in lines if ln.strip()]
    if not tokens:
        warn("File is empty; skipping.")
        skipped_total.append(chosen.name)
        return

    hosts, ports_str = parse_hosts_ports(tokens)
    header("Preview")
    info(f"File: {chosen.name}")
    _pd_line = _plugin_details_line(chosen)
    if _pd_line:
        info(_pd_line)
        try:
            m = re.search(r"(https?://[^\s)\]\}>,;]+)", _pd_line)
            plugin_url = m.group(1) if m else None
        except Exception:
            plugin_url = None

        if chosen.name.lower().endswith("-msf.txt") and plugin_url:
            from mundane_pkg import tools as _tools
            _tools.show_msf_available(plugin_url)
    
    info(f"Hosts parsed: {len(hosts)}")
    if hosts:
        info(f"Example host: {hosts[0]}")
    if ports_str:
        info(f"Ports detected: {ports_str}")

    # View file
    handle_file_view(chosen)

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
            pass
        return

    try:
        do_scan = yesno("\nRun a tool now?", default="n")
    except KeyboardInterrupt:
        return

    if not do_scan:
        try:
            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                newp = rename_review_complete(chosen)
                completed_total.append(newp.name if newp != chosen else chosen.name)
            else:
                reviewed_total.append(chosen.name)
            completion_decided = True
        except KeyboardInterrupt:
            pass
        return

    # Run tool workflow
    tool_used = run_tool_workflow(chosen, scan_dir, sev_dir, hosts, ports_str, args, use_sudo)

    if not completion_decided:
        try:
            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                newp = rename_review_complete(chosen)
                completed_total.append(newp.name if newp != chosen else chosen.name)
            else:
                reviewed_total.append(chosen.name)
        except KeyboardInterrupt:
            pass

# ========== REFACTORED: File list management ==========
def handle_file_list_actions(
    ans: str, 
    candidates: List[Path], 
    page_items: List[Path],
    display: List[Path],
    file_filter: str,
    reviewed_filter: str,
    group_filter: Optional[Tuple[int, set]],
    sort_mode: str,
    page_idx: int,
    total_pages: int,
    reviewed: List[Path],
    sev_map: Optional[Dict[Path, Path]] = None
) -> Tuple[Optional[str], str, str, Optional[Tuple[int, set]], str, int]:
    """
    Unified handler for file list actions (filter, sort, navigate, etc.)
    Returns: (action_type, file_filter, reviewed_filter, group_filter, sort_mode, page_idx)
    action_type can be: None (continue loop), "back", "file_selected", "help"
    """
    
    if ans in ("?", "help"):
        show_actions_help(
            group_applied=bool(group_filter),
            candidates_count=len(candidates),
            sort_mode=sort_mode,
            can_next=(page_idx + 1 < total_pages),
            can_prev=(page_idx > 0),
        )
        return "help", file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans in ("b", "back"):
        return "back", file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "n":
        if page_idx + 1 < total_pages:
            page_idx += 1
        else:
            warn("Already at last page.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "p":
        if page_idx > 0:
            page_idx -= 1
        else:
            warn("Already at first page.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "f":
        file_filter = input("Enter substring to filter by: ").strip()
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "c":
        file_filter = ""
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "o":
        sort_mode = "hosts" if sort_mode == "name" else "name"
        ok(f"Sorting by {'host count (desc)' if sort_mode=='hosts' else 'name (A↑Z)'}")
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "x" and group_filter:
        group_filter = None
        ok("Cleared group filter.")
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "r":
        header("Reviewed files (read-only)")
        print(f"Current filter: '{reviewed_filter or '*'}'")
        filtered_reviewed = [r for r in reviewed if (reviewed_filter.lower() in r.name.lower())]
        
        for i, f in enumerate(filtered_reviewed, 1):
            if sev_map:  # MSF mode with severity labels
                sev_label = pretty_severity_label(sev_map[f].name)
                sev_col = colorize_severity_label(sev_label)
                print(f"[{i}] {fmt_reviewed(f.name)}  — {sev_col}")
            else:
                print(f"[{i}] {fmt_reviewed(f.name)}")
        
        print(fmt_action("[?] Help  [F] Set filter  [C] Clear filter  [B] Back"))
        try:
            choice = input("Action or [B]ack: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        
        if choice in ("?", "help"):
            show_reviewed_help()
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        if choice == "f":
            reviewed_filter = input("Enter substring to filter by: ").strip()
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        if choice == "c":
            reviewed_filter = ""
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        if choice in ("b", "back"):
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        warn("Read-only view; no file selection here.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "m":
        if not candidates:
            warn("No files match the current filter.")
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        confirm_msg = (
            f"You are about to rename {len(candidates)} files with prefix 'REVIEW_COMPLETE-'.\n"
            "Type 'mark' to confirm, or anything else to cancel: "
        )
        confirm = input(f"{C.RED}{confirm_msg}{C.RESET}").strip().lower()
        if confirm != "mark":
            info("Canceled.")
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        
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
                progress.advance(task)
        ok(f"Summary: {renamed} renamed, {len(candidates)-renamed} skipped.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "h":
        if not candidates:
            warn("No files match the current filter.")
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
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
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if ans == "i":
        if not candidates:
            warn("No files match the current filter.")
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
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
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    # File selection logic
    if ans == "":
        if not page_items:
            warn("No files match the current page/filter.")
            return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
        return "file_selected", file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    if not ans.isdigit():
        warn("Please select a file by number, or use actions above.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    global_idx = int(ans) - 1
    if global_idx < 0 or global_idx >= len(display):
        warn("Invalid index.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx
    
    return "file_selected", file_filter, reviewed_filter, group_filter, sort_mode, page_idx

# ========== REFACTORED: Unified file list browser ==========
def browse_file_list(
    scan_dir: Path,
    sev_dir: Path,
    files_getter: Callable[[], List[Tuple[Path, Path]]],
    severity_label: str,
    args,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    is_msf_mode: bool = False
):
    """
    Unified file list browser that handles both normal severity and MSF virtual group.
    
    Args:
        files_getter: Function that returns list of (file, severity_dir) tuples
        severity_label: Display label for the severity
        is_msf_mode: If True, shows severity labels for each file in reviewed list
    """
    file_filter = ""
    reviewed_filter = ""
    group_filter = None
    sort_mode = "name"
    file_parse_cache = {}
    page_size = default_page_size()
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
        # Get files
        file_tuples = files_getter()
        sev_map = {f: sd for (f, sd) in file_tuples}
        files = [f for (f, _sd) in file_tuples if f.suffix.lower() == ".txt"]
        
        reviewed = [f for f in files if f.name.lower().startswith(
            ("review_complete", "review-complete", "review_complete-", "review-complete-"))]
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
            header(f"Severity: {severity_label}")
            status = f"Unreviewed files ({len(unreviewed)}). Current filter: '{file_filter or '*'}'"
            if group_filter:
                status += f" | Group filter: #{group_filter[0]} ({len(group_filter[1])})"
            status += f" | Sort: {'Host count ↓' if sort_mode=='hosts' else 'Name A↑Z'}"
            status += f" | Page: {page_idx+1}/{total_pages}"
            print(status)

            render_file_list_table(page_items, sort_mode, get_counts_for, row_offset=start)

            can_next = page_idx + 1 < total_pages
            can_prev = page_idx > 0
            render_actions_footer(
                group_applied=bool(group_filter),
                candidates_count=len(candidates),
                sort_mode=sort_mode,
                can_next=can_next,
                can_prev=can_prev,
            )

            ans = input("Choose a file number, or action: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to severity menu.")
            break

        # Pre-sort loading if switching to host count sort
        if ans == "o" and sort_mode == "name":
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

        # Handle actions
        action_result = handle_file_list_actions(
            ans, candidates, page_items, display, 
            file_filter, reviewed_filter, group_filter, 
            sort_mode, page_idx, total_pages, reviewed,
            sev_map if is_msf_mode else None
        )
        
        action_type, file_filter, reviewed_filter, group_filter, sort_mode, page_idx = action_result
        
        if action_type == "back":
            break
        elif action_type == "help":
            continue
        elif action_type == "file_selected":
            # Determine which file was selected
            if ans == "":
                chosen = page_items[0]
            else:
                global_idx = int(ans) - 1
                chosen = display[global_idx]
            
            # Get the correct severity dir for this file
            chosen_sev_dir = sev_map[chosen] if is_msf_mode else sev_dir
            
            # Process the file
            process_single_file(
                chosen, scan_dir, chosen_sev_dir, args, use_sudo,
                skipped_total, reviewed_total, completed_total
            )
        elif action_type is None:
            continue

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
        render_scan_table(scans)
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
            render_severity_table(severities, msf_summary=msf_summary)

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
                
                def files_getter():
                    files = [f for f in list_files(sev_dir) if f.suffix.lower() == ".txt"]
                    return [(f, sev_dir) for f in files]
                
                browse_file_list(
                    scan_dir, sev_dir, files_getter,
                    pretty_severity_label(sev_dir.name),
                    args, use_sudo, skipped_total, reviewed_total, completed_total,
                    is_msf_mode=False
                )

            # === Metasploit Module (virtual) ===
            else:
                def msf_files_getter():
                    msf_files = []
                    for sd in severities:
                        for f in list_files(sd):
                            if f.suffix.lower() == ".txt" and f.name.endswith("-MSF.txt"):
                                msf_files.append((f, sd))
                    return msf_files
                
                # Use the first severity dir as a placeholder (won't be used due to is_msf_mode=True)
                browse_file_list(
                    scan_dir, severities[0], msf_files_getter,
                    "Metasploit Module",
                    args, use_sudo, skipped_total, reviewed_total, completed_total,
                    is_msf_mode=True
                )

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
    app()