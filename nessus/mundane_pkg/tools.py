from .ansi import header, warn, fmt_action, info, ok
from .constants import NETEXEC_PROTOCOLS, NSE_PROFILES
from pathlib import Path
import pyperclip
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

import os, sys, shutil, subprocess
import json

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
    print("[3] metasploit — search for modules")
    print("[4] Custom command (advanced)")
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
            if i == 3: return "metasploit"
            if i == 4: return "custom"
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

# ---------------------- Metasploit search helpers ----------------------
import re
from typing import List
try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"}
PAREN_RE = re.compile(r"\(([^)]+)\)")
MSF_AFTER_RE = re.compile(r"Metasploit[:\-\s]*\(?([^)]+)\)?", re.IGNORECASE)

def _fetch_html(url: str, timeout: int = 12) -> str:
    if not requests:
        raise RuntimeError("requests library is not available")
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.text

def _extract_candidates_from_text(text: str, soup=None) -> List[str]:
    """
    DOM-aware and text-based extractor for Metasploit candidate terms.
    Priority:
      1. If soup provided: find element(s) mentioning 'Metasploit' and inspect nearby siblings/children for parenthesized tokens.
      2. Use MSF_AFTER_RE to capture text immediately following "Metasploit (...)"
      3. Look for the first parenthesized token after the word 'metasploit' within a window.
      4. Legacy fallback: scan all parenthesized tokens across the page.
    Returns a de-duplicated list of cleaned candidate strings.
    """
    def clean_token(t: str) -> str:
        tt = re.sub(r"\\s+", " ", t).strip()
        tt = tt.strip(" \\n\\t\"'.:;")
        return tt

    # 0) If soup is provided, prefer DOM traversal (scan nodes that contain 'Metasploit')
    if soup is not None:
        for string_node in soup.find_all(string=re.compile(r"metasploit", re.I)):
            parent = string_node.parent
            # 0a: Check same parent element text after the match
            try:
                inner = parent.get_text(" ", strip=True)
                idx = inner.lower().find("metasploit")
                if idx != -1:
                    rest_inner = inner[idx: idx + 800]
                    m_par = re.search(r"\\(\\s*([^)]+?)\\s*\\)", rest_inner)
                    if m_par:
                        val = m_par.group(1).strip()
                        if val and not val.lower().startswith("http") and val.lower() != "metasploit":
                            return [clean_token(val)]
            except Exception:
                pass
            # 0b: Inspect next siblings for a parenthesized token
            try:
                for sib in parent.next_siblings:
                    stext = ""
                    if hasattr(sib, "get_text"):
                        stext = sib.get_text(" ", strip=True)
                    else:
                        stext = str(sib).strip()
                    m = re.search(r"\\(\\s*([^)]+?)\\s*\\)", stext)
                    if m:
                        val = m.group(1).strip()
                        if val and not val.lower().startswith("http") and val.lower() != "metasploit":
                            return [clean_token(val)]
            except Exception:
                pass

    # 1) Direct regex match (Metasploit ( ... ) style)
    m2 = MSF_AFTER_RE.search(text)
    if m2:
        val = m2.group(1).strip()
        if val and not val.lower().startswith("http") and val.lower() != "metasploit":
            return [clean_token(val)]

    # 2) First parenthesis AFTER the word "metasploit" in a text window
    idx = text.lower().find("metasploit")
    if idx != -1:
        window = text[idx: idx + 800]
        m_par = re.search(r"\\(\\s*([^)]+?)\\s*\\)", window)
        if m_par:
            val = m_par.group(1).strip()
            if val and not val.lower().startswith("http") and val.lower() != "metasploit":
                return [clean_token(val)]

    # 3) Legacy fallback: grab parenthesized fragments across the page
    candidates: List[str] = []
    for m in PAREN_RE.finditer(text):
        inner = m.group(1).strip()
        if len(inner) > 3 and not inner.lower().startswith("http"):
            candidates.append(inner)

    # Also include MSF_AFTER_RE bag if present and not already in candidates
    if 'm2' in locals() and m2:
        val = m2.group(1).strip()
        if val and val not in candidates:
            candidates.insert(0, val)

    # Clean, dedupe, and filter
    terms = list(dict.fromkeys(candidates))
    cleaned = []
    for t in terms:
        tt = clean_token(t)
        if len(tt) > 2 and tt.lower() != "metasploit":
            cleaned.append(tt)
    return cleaned
def _find_search_terms_from_html(html: str) -> List[str]:

    # --- Prefer structured page data when available (Next.js __NEXT_DATA__ JSON) ---
    try:
        # soup is available in callers; try to locate the __NEXT_DATA__ script tag with JSON that includes plugin metadata
        script = None
        if 'soup' in locals() and getattr(soup, "find", None):
            script = soup.find("script", {"id": "__NEXT_DATA__"})
        else:
            # fallback: search for the script by regex in raw html
            m = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html, flags=re.S)
            if m:
                script = type("S", (), {"string": m.group(1)})

        if script and getattr(script, "string", None):
            try:
                data = json.loads(script.string)
                # navigate to plugin metadata if present
                plugin = data.get("props", {}).get("pageProps", {}).get("plugin")
                if plugin and isinstance(plugin, dict):
                    # prefer explicit metasploit_name field
                    ms_name = plugin.get("metasploit_name")
                    if ms_name and isinstance(ms_name, str) and ms_name.strip():
                        return [ms_name.strip()]
                    # otherwise inspect attributes list for metasploit_name attribute
                    attrs = plugin.get("attributes") or plugin.get("attributes", [])
                    if isinstance(attrs, list):
                        for a in attrs:
                            try:
                                if a.get("attribute_name", "").lower() == "metasploit_name".lower():
                                    val = a.get("attribute_value")
                                    if val and isinstance(val, str) and val.strip():
                                        return [val.strip()]
                            except Exception:
                                continue
            except Exception:
                # JSON parse failed; safe to ignore and continue to legacy extraction
                pass
    except Exception:
        # Any error here should not break extraction; fall back to text-based methods
        pass
    # --- End structured-data preference ---
    if not BeautifulSoup:
        return []
    soup = BeautifulSoup(html, "html.parser")
    header_el = soup.find(
        lambda tag: tag.name in ["h1", "h2", "h3", "h4", "h5"]
        and "exploitable with" in tag.get_text(strip=True).lower()
    )
    terms: List[str] = []
    if header_el:
        nxt = header_el.find_next_sibling()
        if nxt:
            terms.extend(_extract_candidates_from_text(nxt.get_text(" ", strip=True), soup=soup))
        if not terms:
            terms.extend(_extract_candidates_from_text(header_el.parent.get_text(" ", strip=True), soup=soup))
    if not terms:
        ms_elems = soup.find_all(string=re.compile(r"\bMetasploit\b", re.I))
        for s in ms_elems:
            parent = s.parent
            if parent:
                terms.extend(_extract_candidates_from_text(parent.get_text(" ", strip=True), soup=soup))
                if not terms and parent.parent:
                    terms.extend(_extract_candidates_from_text(parent.parent.get_text(" ", strip=True)))
    if not terms:
        all_text = soup.get_text(" ", strip=True)
        for m in PAREN_RE.finditer(all_text):
            p = m.group(1).strip()
            if len(p) > 3 and re.search(r"[A-Za-z]", p):
                if "metasploit" in p.lower() or p[0].isupper():
                    terms.append(p)
        terms = list(dict.fromkeys(terms))
    cleaned = []
    for t in terms:
        tt = re.sub(r"\s+", " ", t).strip()
        tt = tt.strip(" \n\t\"'.,:;")
        if len(tt) > 2 and tt.lower() != "metasploit":
            cleaned.append(tt)
    return cleaned

def _build_one_liners(term: str) -> List[str]:
    if "'" in term:
        cmd = f'msfconsole -q -x "search {term}; exit"'
        cmd2 = f'msfconsole -q -x "search type:exploit {term}; exit"'
    else:
        cmd = f"msfconsole -q -x 'search {term}; exit'"
        cmd2 = f"msfconsole -q -x 'search type:exploit {term}; exit'"
    return [cmd, cmd2]

def show_msf_available(plugin_url: str) -> None:
    """Non-blocking informational notice shown after Plugin Details when file ends with '-MSF.txt'."""
    header("Metasploit module available!")
    info("A Metasploit module may be available for this finding. Use the search prompt before running tools.\n")

def interactive_msf_search(plugin_url: str) -> None:
    """Fetch plugin page, extract candidate terms, display one-liners, offer copy-to-clipboard."""
    # copy_to_clipboard is defined in this module; import local symbol if needed
    header("Metasploit module search")
    if not requests or not BeautifulSoup:
        warn("Required libraries (requests, beautifulsoup4) are not installed; cannot perform MSF search.")
        return
    # show a spinner/short progress bar while fetching the plugin page
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Fetching plugin page...", start=False)
            # start the task so spinner appears; total is not used (indeterminate)
            progress.start_task(task)
            html = _fetch_html(plugin_url)
    except Exception as exc:
        warn(f"Failed to fetch plugin page: {exc}")
        return

    terms = _find_search_terms_from_html(html)
    if not terms:
        warn("No candidate Metasploit search terms found on the page.")
        return

    info("Found candidate search term(s):")
    for i, t in enumerate(terms, 1):
        info(f" {i}. {t}")

    info("\nSuggested msfconsole one-liner(s):")
    one_liners = []
    for t in terms:
        one_liners.extend(_build_one_liners(t))

    for i, cmd in enumerate(one_liners, 1):
        info(f" {i}. {fmt_action(cmd)}")

    # Offer to copy one to clipboard
    try:
        from rich.prompt import Prompt
        ans = Prompt.ask("Copy which one-liner to clipboard? (number or [N]one)", default="N")
        if ans and ans.strip().lower() != "n":
            try:
                n = int(ans.strip())
                if 1 <= n <= len(one_liners):
                    try:
                        copy_to_clipboard(one_liners[n - 1])
                    except Exception:
                        try:
                            from .tools import copy_to_clipboard as _copy
                            _copy(one_liners[n - 1])
                        except Exception:
                            pass
                    ok("Copied to clipboard.")
            except Exception:
                warn("Invalid selection. No copy performed.")
    except Exception:
        pass

# ----------------------------------------------------------------------
# End of MSF helpers
# ----------------------------------------------------------------------