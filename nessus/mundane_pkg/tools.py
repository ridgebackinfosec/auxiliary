from .ansi import header, warn, fmt_action, info, ok
from .constants import NETEXEC_PROTOCOLS, NSE_PROFILES
from pathlib import Path
import pyperclip

import os, sys, shutil, subprocess

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