#!/usr/bin/env python3
# mundane.py
import sys, os, re, random, shutil, tempfile, subprocess, ipaddress, argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

# ========== Colors & helpers ==========
NO_COLOR = (os.environ.get("NO_COLOR") is not None) or (os.environ.get("TERM") == "dumb")
class C:
    RESET  = "" if NO_COLOR else "\033[0m"
    BOLD   = "" if NO_COLOR else "\033[1m"
    BLUE   = "" if NO_COLOR else "\033[34m"
    GREEN  = "" if NO_COLOR else "\033[32m"
    YELLOW = "" if NO_COLOR else "\033[33m"
    RED    = "" if NO_COLOR else "\033[31m"
    CYAN   = "" if NO_COLOR else "\033[36m"
    MAGENTA= "" if NO_COLOR else "\033[35m"

def header(msg): print(f"{C.BOLD}{C.BLUE}\n{msg}{C.RESET}")
def ok(msg):     print(f"{C.GREEN}{msg}{C.RESET}")
def warn(msg):   print(f"{C.YELLOW}{msg}{C.RESET}")
def err(msg):    print(f"{C.RED}{msg}{C.RESET}")
def info(msg):   print(msg)
def fmt_action(text): return f"{C.CYAN}>> {text}{C.RESET}"
def fmt_reviewed(text): return f"{C.MAGENTA}{text}{C.RESET}"
def cyan_label(s: str) -> str: return f"{C.CYAN}{s}{C.RESET}"

def require_cmd(name):
    if shutil.which(name) is None:
        err(f"Required command '{name}' not found on PATH.")
        sys.exit(1)

def resolve_cmd(candidates):
    """Return the first available binary from candidates, or None."""
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
        with path.open("rb") as f:
            data = f.read(max_bytes)
        try:
            print(data.decode("utf-8", errors="replace"))
        except Exception:
            print(data)
    except Exception as e:
        warn(f"Could not display file: {e}")

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
        # Bare IPv6 (no port)
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
    hosts = list(dict.fromkeys(hosts))  # preserve order, dedupe
    ports_str = ",".join(sorted(ports, key=lambda x: int(x))) if ports else ""
    return hosts, ports_str

def parse_file_hosts_ports_detailed(path: Path):
    """Return (hosts_order_preserved, ports_set, combos_map: host->set(ports), had_explicit_ports: bool)."""
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
    # Always write results
    cmd += ["-oA", str(oabase)]
    return cmd

def build_netexec_cmd(exec_bin: str, protocol: str, ips_file: Path, oabase: Path):
    """
    NetExec command builder.
    - Passes the targets file as a positional argument (no -iL).
    - Always logs to {oabase}.nxc.<protocol>.log
    - SMB adds --gen-relay-list and --shares, writing the relay list into the artifacts area.
    Returns: (cmd_list, log_path, relay_path_or_None)
    """
    log_path = f"{str(oabase)}.nxc.{protocol}.log"
    relay_path = None
    if protocol == "smb":
        # Write the relay list next to other run artifacts
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

def copy_to_clipboard(s: str) -> tuple:
    """Best-effort cross-platform clipboard.
    Returns (ok, detail_message)."""
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
    return False, 'No suitable clipboard tool found.'

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
    """Return (unreviewed_count, reviewed_count, total)."""
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
    """Convert '4_Critical' -> 'Critical'."""
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

def rename_review_complete(path: Path):
    name = path.name
    prefix = "REVIEW_COMPLETE-"
    if name.lower().startswith(("review_complete", "review-complete")):
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
NSE_PROFILES = [
    ("Crypto", ["ssl-enum-ciphers", "ssl-cert", "ssl-date"], False),
    ("SSH",    ["ssh2-enum-algos", "ssh-auth-methods"], False),
    ("SMB",    ["smb-security-mode", "smb2-security-mode"], False),
    ("SNMP",   ["snmp*"], True),            # requires UDP
    ("IPMI",   ["ipmi-version"], True),     # requires UDP
]

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
    out_dir = Path("scan_artifacts") / scan_dir.name / sev_label / stem
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    oabase = out_dir / f"run-{ts}"
    return out_dir, oabase

# ====== Compare hosts/ports across filtered files ======
def _normalize_combos(hosts, ports_set, combos_map, had_explicit):
    """
    Produce a canonical representation for comparison:
    - If explicit combos were present, use them.
    - Otherwise, assume each host pairs with the global ports_set.
    Returns sorted tuple of (host, sorted_ports_tuple).
    """
    if had_explicit and combos_map:
        items = []
        for h in hosts:
            ps = combos_map.get(h, set())
            items.append((h, tuple(sorted(ps, key=lambda x: int(x)))))
        return tuple(items)
    # No explicit combos -> assume all hosts share the global ports_set (possibly empty)
    assumed = tuple(sorted(
        (h, tuple(sorted(ports_set, key=lambda x: int(x))))
        for h in hosts
    ))
    return assumed

def compare_filtered(files):
    """
    Print a concise comparison report for the given plugin files.
    Returns: list[list[str]] groups, sorted by size DESC (each inner list is file names in that group).
    """
    if not files:
        warn("No files selected for comparison.")
        return []

    header("Filtered Files: Host/Port Comparison")
    info(f"Files compared: {len(files)}")

    # Parse all
    parsed = []
    for f in files:
        hosts, ports_set, combos, had_explicit = parse_file_hosts_ports_detailed(f)
        parsed.append((f, hosts, ports_set, combos, had_explicit))

    # Compute set-level intersections/unions
    all_host_sets = [set(h) for _, h, _, _, _ in parsed]
    all_port_sets = [set(p) for _, _, p, _, _ in parsed]
    host_intersection = set.intersection(*all_host_sets) if all_host_sets else set()
    host_union        = set.union(*all_host_sets) if all_host_sets else set()
    port_intersection = set.intersection(*all_port_sets) if all_port_sets else set()
    port_union        = set.union(*all_port_sets) if all_port_sets else set()

    # Canonical signatures (host-only, ports-only, and combos)
    host_sigs  = [tuple(sorted(h)) for _, h, _, _, _ in parsed]
    port_sigs  = [tuple(sorted(p, key=lambda x: int(x))) for _, _, p, _, _ in parsed]
    combo_sigs = [_normalize_combos(h, p, c, e) for _, h, p, c, e in parsed]

    same_hosts  = all(sig == host_sigs[0] for sig in host_sigs) if host_sigs else True
    same_ports  = all(sig == port_sigs[0] for sig in port_sigs) if port_sigs else True
    same_combos = all(sig == combo_sigs[0] for sig in combo_sigs) if combo_sigs else True

    # Summary
    if same_hosts and same_ports and same_combos:
        ok("All filtered files target the SAME hosts and ports (identical host:port combinations).")
    else:
        warn("Filtered files are NOT identical.")
        info(f"- Same hosts across all:  {same_hosts}")
        info(f"- Same ports across all:  {same_ports}")
        info(f"- Same host:port combos:  {same_combos}")

    # Show quick stats
    info(f"\nHosts: intersection={len(host_intersection)}  union={len(host_union)}")
    if host_intersection:
        info("  ⋂ Example: " + ", ".join(list(sorted(host_intersection))[:5]) + (" ..." if len(host_intersection) > 5 else ""))
    if host_union:
        info("  ⋃ Example: " + ", ".join(list(sorted(host_union))[:5]) + (" ..." if len(host_union) > 5 else ""))
    info(f"Ports: intersection={len(port_intersection)}  union={len(port_union)}")
    if port_union:
        info("  ⋃ Ports: " + ", ".join(sorted(port_union, key=lambda x: int(x))))

    # Group files by identical combo signature
    groups_dict = defaultdict(list)
    for (f, h, p, c, e), sig in zip(parsed, combo_sigs):
        groups_dict[sig].append(f.name)

    # Sort groups by size (desc). Restart numbering from 1 every run.
    groups_sorted = sorted(groups_dict.values(), key=lambda names: len(names), reverse=True)

    if len(groups_sorted) > 1:
        header("Groups (files with identical host:port combos)")
        for i, names in enumerate(groups_sorted, 1):
            info(f"[Group {i}] {len(names)} file(s)")
            for nm in names[:6]:
                info(f"  - {nm}")
            if len(names) > 6:
                info(f"  - ... (+{len(names)-6} more)")
    else:
        info("\nAll filtered files fall into a single identical group.")

    # Return groups as list of lists (sorted)
    return groups_sorted

# -------- Sorting helpers for file list --------
def natural_key(s: str):
    """Natural sort key: splits digits for A10 < A2 issues."""
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
    """
    Validate a token as host or host:port.
    Returns (valid, host, port_or_None). Port is a string if present.
    Valid forms:
      - hostname
      - IPv4
      - IPv6 (bare)
      - [IPv6]
      - hostname:port / IPv4:port / [IPv6]:port
    """
    tok = tok.strip()
    if not tok:
        return False, None, None

    # [IPv6] or [IPv6]:port
    if tok.startswith("["):
        m = re.match(r"^\[(.+?)\](?::(\d+))?$", tok)
        if m and _is_ipv6(m.group(1)):
            port = m.group(2)
            if port is None:
                return True, m.group(1), None
            if port.isdigit() and 1 <= int(port) <= 65535:
                return True, m.group(1), port
        return False, None, None

    # Bare IPv6 (no port)
    if tok.count(":") >= 2 and not re.search(r"]:\d+$", tok):
        return (_is_ipv6(tok), tok if _is_ipv6(tok) else None, None)

    # host[:port] (hostname or IPv4)
    if ":" in tok:
        h, p = tok.rsplit(":", 1)
        if p.isdigit() and 1 <= int(p) <= 65535 and (_is_hostname(h) or _is_ipv4(h)):
            return True, h, p
        return False, None, None

    # host without port
    if _is_hostname(tok) or _is_ipv4(tok) or _is_ipv6(tok):
        return True, tok, None

    return False, None, None

def _parse_for_overview(path: Path):
    """Parse a file for overview metrics only (strict). Returns:
       (hosts:list[str], ports:set[str], combos:dict[host]->set[port], had_explicit:bool, malformed_count:int)
    """
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
    """Compute and print scan-level overview (shown right after choosing a scan) with cyan labels."""
    header(f"Scan Overview — {scan_dir.name}")

    # Collect all TXT files across severities
    severities = list_dirs(scan_dir)
    all_files = []
    for sev in severities:
        all_files.extend([f for f in list_files(sev) if f.suffix.lower() == ".txt"])

    total_files, reviewed_files = _count_reviewed_in_scan(scan_dir)

    unique_hosts = set()
    ipv4_set = set()
    ipv6_set = set()
    ports_counter = Counter()  # per-file prevalence
    empties = 0
    malformed_total = 0
    combo_sig_counter = Counter()

    for f in all_files:
        hosts, ports, combos, had_explicit, malformed = _parse_for_overview(f)
        malformed_total += malformed
        if not hosts:
            empties += 1
        unique_hosts.update(hosts)
        # Track IP versions (hostnames are ignored for v4/v6 split)
        for h in hosts:
            try:
                ip = ipaddress.ip_address(h)
                if isinstance(ip, ipaddress.IPv4Address):
                    ipv4_set.add(h)
                elif isinstance(ip, ipaddress.IPv6Address):
                    ipv6_set.add(h)
            except Exception:
                pass
        # per-file port prevalence
        for p in ports:
            ports_counter[p] += 1
        # identical host:port cluster signature
        sig = _normalize_combos(hosts, ports, combos, had_explicit)
        combo_sig_counter[sig] += 1

    # Folder health (cyan labels)
    info(f"{cyan_label('Files:')} {total_files}  |  "
         f"{cyan_label('Reviewed:')} {reviewed_files}  |  "
         f"{cyan_label('Empty:')} {empties}  |  "
         f"{cyan_label('Malformed tokens:')} {malformed_total}")

    # Host coverage
    info(f"{cyan_label('Hosts:')} unique={len(unique_hosts)}  "
         f"({cyan_label('IPv4:')} {len(ipv4_set)} | {cyan_label('IPv6:')} {len(ipv6_set)})")
    if unique_hosts:
        sample = ", ".join(list(sorted(unique_hosts))[:5])
        info(f"  {cyan_label('Example:')} {sample}{' ...' if len(unique_hosts) > 5 else ''}")

    # Port landscape
    port_set = set(ports_counter.keys())
    info(f"{cyan_label('Ports:')} unique={len(port_set)}")
    if ports_counter:
        top_ports = ports_counter.most_common(top_ports_n)
        tp_str = ", ".join(f"{p} ({n} files)" for p, n in top_ports)
        info(f"  {cyan_label(f'Top {top_ports_n}:')} {tp_str}")

    # Duplicate/cluster insight
    multi_clusters = [c for c in combo_sig_counter.values() if c > 1]
    info(f"{cyan_label('Identical host:port groups across all files:')} {len(multi_clusters)}")
    if multi_clusters:
        sizes = sorted(multi_clusters, reverse=True)[:3]
        info("  " + cyan_label("Largest clusters:") + " " + ", ".join(f"{n} files" for n in sizes))

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
            return None if ans else "nmap"  # Enter defaults to nmap
        if ans.isdigit():
            i = int(ans)
            if i == 1: return "nmap"
            if i == 2: return "netexec"
            if i == 3: return "custom"
        warn("Invalid choice.")

NETEXEC_PROTOCOLS = ["mssql","smb","ftp","ldap","nfs","rdp","ssh","vnc","winrm","wmi"]

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
    # No hard require for nmap here — check per selected tool instead.
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
        for i, sdir in enumerate(scans, 1):
            print(f"[{i}] {sdir.name}")
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

        # --- show scan overview immediately after selecting scan ---
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

            for i, sd in enumerate(severities, 1):
                unrev, rev, tot = _count_severity_files(sd)
                label = pretty_severity_label(sd.name)
                print(f"[{i}] {label} — unreviewed: {_color_unreviewed(unrev)} | reviewed: {fmt_reviewed(rev)} | total: {tot}")
            print(fmt_action("[B] Back"))
            try:
                ans = input("Choose: ").strip().lower()
            except KeyboardInterrupt:
                warn("\nInterrupted — returning to scan menu.")
                break
            if ans in ("b", "back"):
                break
            if not ans.isdigit() or not (1 <= int(ans) <= len(severities)):
                warn("Invalid choice.")
                continue
            sev_dir = severities[int(ans)-1]

            # Per-severity file review
            file_filter = ""
            reviewed_filter = ""
            group_filter = None  # (group_index:int, names:set[str]) — resets whenever you enter a severity
            sort_mode = "name"   # "name" or "hosts"
            file_parse_cache = {}  # Path -> (host_count:int, ports_str:str) for this severity view

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

                # Apply substring filter and (optional) group filter
                candidates = [
                    u for u in unreviewed
                    if (file_filter.lower() in u.name.lower())
                    and (group_filter is None or u.name in group_filter[1])
                ]

                # Sort candidates for display
                if sort_mode == "hosts":
                    display = sorted(
                        candidates,
                        key=lambda p: (-get_counts_for(p)[0], natural_key(p.name))
                    )
                else:
                    display = sorted(candidates, key=lambda p: natural_key(p.name))

                # Filtering UI (unreviewed)
                try:
                    status = f"Unreviewed files ({len(unreviewed)}). Current filter: '{file_filter or '*'}'"
                    if group_filter:
                        status += f" | Group filter: #{group_filter[0]} ({len(group_filter[1])})"
                    status += f" | Sort: {'Host count ↓' if sort_mode=='hosts' else 'Name A→Z'}"
                    print(status)

                    actions = "[F] Set filter / [C] Clear filter / [R] View reviewed files / "
                    actions += f"[M] Mark ALL filtered as REVIEW_COMPLETE ({len(candidates)}) / "
                    actions += "[H] Compare hosts/ports in filtered files / "
                    actions += "[O] Toggle sort / "
                    if group_filter:
                        actions += "[X] Clear group filter / "
                    actions += "[B] Back / [Enter] Open first match"
                    print(fmt_action(actions))

                    for i, f in enumerate(display, 1):
                        if sort_mode == "hosts":
                            hc, _ps = get_counts_for(f)
                            print(f"[{i}] {f.name}  — hosts: {hc}")
                        else:
                            print(f"[{i}] {f.name}")
                    ans = input("Choose a file number, or action: ").strip().lower()
                except KeyboardInterrupt:
                    warn("\nInterrupted — returning to severity menu.")
                    break

                # --- Actions ---
                if ans in ("b", "back"):
                    break
                if ans == "f":
                    file_filter = input("Enter substring to filter by: ").strip()
                    continue
                if ans == "c":
                    file_filter = ""
                    continue
                if ans == "o":
                    sort_mode = "hosts" if sort_mode == "name" else "name"
                    ok(f"Sorting by {'host count (desc)' if sort_mode=='hosts' else 'name (A→Z)'}")
                    continue
                if ans == "x" and group_filter:
                    group_filter = None
                    ok("Cleared group filter.")
                    continue
                if ans == "r":
                    # Reviewed viewer
                    header("Reviewed files (read-only)")
                    print(f"Current filter: '{reviewed_filter or '*'}'")
                    print(fmt_action("[F] Set filter / [C] Clear filter / [B] Back"))
                    for i, f in enumerate([r for r in reviewed if (reviewed_filter.lower() in r.name.lower())], 1):
                        print(f"[{i}] {fmt_reviewed(f.name)}")
                    try:
                        choice = input("Action or [B]ack: ").strip().lower()
                    except KeyboardInterrupt:
                        warn("\nInterrupted — returning.")
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
                if ans == "m":
                    # Mark all filtered as REVIEW_COMPLETE
                    if not candidates:
                        warn("No files match the current filter.")
                        continue
                    confirm = input(f"You are about to rename {len(candidates)} files with prefix 'REVIEW_COMPLETE-'.\nType 'mark' to confirm, or anything else to cancel: ").strip().lower()
                    if confirm != "mark":
                        info("Canceled.")
                        continue
                    renamed = 0
                    for f in candidates:
                        newp = rename_review_complete(f)
                        if newp != f or newp.name.startswith("REVIEW_COMPLETE-"):
                            renamed += 1
                            completed_total.append(newp.name)
                    ok(f"Summary: {renamed} renamed, {len(candidates)-renamed} skipped.")
                    continue
                if ans == "h":
                    # Compare hosts/ports across filtered files (fresh each time; numbering restarts from 1)
                    if not candidates:
                        warn("No files match the current filter.")
                        continue
                    groups = compare_filtered(candidates)  # returns groups sorted by size DESC
                    # Immediate group selection with compact prompt showing only first 5 groups
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
                    continue

                # Default-select top item on Enter
                if ans == "":
                    if not display:
                        warn("No files match the current filter.")
                        continue
                    chosen = display[0]
                else:
                    if not ans.isdigit():
                        warn("Please select a file by number, or use actions above.")
                        continue
                    idx = int(ans) - 1
                    if idx < 0 or idx >= len(display):
                        warn("Invalid index.")
                        continue
                    chosen = display[idx]

                # Per-file workflow
                lines = read_text_lines(chosen)
                tokens = [ln for ln in lines if ln.strip()]
                if not tokens:
                    warn("File is empty; skipping.")
                    skipped_total.append(chosen.name)
                    continue

                # Parse hosts/ports
                hosts, ports_str = parse_hosts_ports(tokens)
                header("Preview")
                info(f"File: {chosen.name}")
                info(f"Hosts parsed: {len(hosts)}")
                if hosts:
                    info(f"Example host: {hosts[0]}")
                if ports_str:
                    info(f"Ports detected: {ports_str}")

                # Offer to view file
                try:
                    if yesno("\nWould you like to view the contents of the selected plugin file? (y/N):", default="n"):
                        safe_print_file(chosen)
                except KeyboardInterrupt:
                    continue

                # ============ NO-TOOLS MODE SHORT-CIRCUIT ============
                if args.no_tools:
                    info("(no-tools mode active — skipping tool selection)")
                    try:
                        if yesno("Mark this file as REVIEW_COMPLETE? (y/N):", default="n"):
                            newp = rename_review_complete(chosen)
                            completed_total.append(newp.name if newp != chosen else chosen.name)
                        else:
                            reviewed_total.append(chosen.name)
                    except KeyboardInterrupt:
                        continue
                    continue
                # =====================================================

                # Run a tool?
                try:
                    do_scan = yesno("\nRun a tool now? (y/N):", default="n")
                except KeyboardInterrupt:
                    continue

                if not do_scan:
                    try:
                        if yesno("Mark this file as REVIEW_COMPLETE? (y/N):", default="n"):
                            newp = rename_review_complete(chosen)
                            completed_total.append(newp.name if newp != chosen else chosen.name)
                        else:
                            reviewed_total.append(chosen.name)
                    except KeyboardInterrupt:
                        continue
                    continue

                # Sampling (applies to any tool)
                sample_hosts = hosts
                if len(hosts) > 5:
                    try:
                        do_sample = yesno(f"There are {len(hosts)} hosts. Sample a subset? (y/N):", default="n")
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

                # --- Prepare per-file context ONCE (persists across multiple commands) ---
                workdir = Path(tempfile.mkdtemp(prefix="nph_work_"))
                # Write both TCP and UDP lists so any tool/custom can reference them
                tcp_ips, udp_ips, tcp_sockets = write_work_files(workdir, sample_hosts, ports_str, udp=True)

                # results base dir stays the same; each run gets a fresh timestamped oabase
                out_dir_static = Path("scan_artifacts") / scan_dir.name / pretty_severity_label(sev_dir.name) / Path(chosen.name).stem
                out_dir_static.mkdir(parents=True, exist_ok=True)

                # ----- Tool loop: allow running multiple commands in the same context -----
                while True:
                    tool_choice = choose_tool()
                    if tool_choice is None:
                        break  # back to file menu

                    # Fresh timestamped oabase per run
                    _tmp_dir, oabase = build_results_paths(scan_dir, sev_dir, chosen.name)
                    results_dir = out_dir_static  # for clearer prints

                    nxc_relay_path = None  # reset per run

                    if tool_choice == "nmap":
                        # Nmap-specific options
                        try:
                            udp_ports = yesno("\nDo you want to perform UDP scanning instead of TCP? (y/N):", default="n")
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
                        # Custom command with placeholders
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
                        cmd = rendered  # string
                        artifact_note = f"OABASE path:   {oabase}"

                    else:
                        warn("Unknown tool selection.")
                        continue

                    # Command review
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
                            if isinstance(cmd, list):
                                subprocess.run(cmd, check=True)
                            else:
                                # custom string command
                                shell_exec = shutil.which("bash") or shutil.which("sh")
                                subprocess.run(cmd, shell=True, check=True, executable=shell_exec)
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

                    # Artifacts for this run
                    header("Artifacts")
                    info(f"Workspace:     {workdir}")
                    info(f" - Hosts:      {workdir / 'tcp_ips.list'}")
                    if ports_str:
                        info(f" - Host:Ports: {workdir / 'tcp_host_ports.list'}")
                    info(f" - {artifact_note}")
                    if nxc_relay_path:
                        info(f" - Relay targets: {nxc_relay_path}")
                    info(f" - Results dir:{results_dir}")

                    # Run another command in this same context?
                    try:
                        again = yesno("\nRun another command for this plugin file? (y/N):", default="n")
                    except KeyboardInterrupt:
                        break
                    if not again:
                        break  # exit tool loop

                # After leaving tool loop, optional rename
                try:
                    if yesno("Mark this file as REVIEW_COMPLETE? (y/N):", default="n"):
                        newp = rename_review_complete(chosen)
                        completed_total.append(newp.name if newp != chosen else chosen.name)
                    else:
                        reviewed_total.append(chosen.name)
                except KeyboardInterrupt:
                    continue

    # Session summary
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Review Nessus plugin host files and optionally run tools.")
    parser.add_argument("export_root", nargs="?", default="./nessus_plugin_hosts",
                        help="Root directory containing scan folders (default: ./nessus_plugin_hosts)")
    parser.add_argument("--no-tools", action="store_true",
                        help="Disable all tool prompts and execution for this session.")
    args = parser.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")
