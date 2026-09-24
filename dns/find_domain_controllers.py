#!/usr/bin/env python3
"""
find_domain_controllers.py

Discover Windows Domain Controllers by:
  1) Determining a domain (from --domain, or auto-detect: resolv.conf 'search'
     on Linux, USERDNSDOMAIN / host FQDN on Windows)
  2) Querying SRV records: _ldap._tcp.dc._msdcs.<domain>  (uses nslookup or dig if available)
  3) Extracting DC hostnames from SRV output and resolving to IPs (stdlib 'socket')
  4) (Optional) Falling back to masscan against ports 389,636 over an in-scope list
  5) (Optional) Doing reverse DNS (PTR) for discovered IPs

Outputs (prefix 'dc' by default):
  - dc_hosts.txt    : DC hostnames (one per line)
  - dc_ips.txt      : unique IPs (one per line)
  - dc_map.txt      : "IP hostname" pairs (one per line)
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Dict, List, Optional

SRV_NAME_FMT = "_ldap._tcp.dc._msdcs.{domain}"

HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\.?")  # rough FQDN (non-capturing so findall returns full matches)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_search_domain_from_resolv(conf: Path = Path("/etc/resolv.conf")) -> Optional[str]:
    """Extract the search domain from /etc/resolv.conf.

    Args:
        conf: Path to resolv.conf file (default: /etc/resolv.conf)

    Returns:
        First search domain if found, None otherwise

    Note:
        Used to auto-detect the domain for SRV queries when --domain not specified.
    """
    try:
        text = conf.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("search"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].strip()
    return None


def detect_domain() -> Optional[str]:
    """Auto-detect the current DNS domain across Linux and Windows.

    Returns:
        First domain found, None otherwise.

    Note:
        Tries, in order:
          1. /etc/resolv.conf 'search' line (Linux).
          2. USERDNSDOMAIN environment variable (domain-joined Windows).
          3. The domain portion of socket.getfqdn() (either platform).
        Used when --domain is not supplied. Windows has no /etc/resolv.conf,
        so the env var and FQDN fallbacks keep the tool usable there.
    """
    dom = read_search_domain_from_resolv()
    if dom:
        return dom

    env_dom = os.environ.get("USERDNSDOMAIN")
    if env_dom and env_dom.strip():
        return env_dom.strip()

    try:
        fqdn = socket.getfqdn()
    except Exception:
        fqdn = ""
    if fqdn and "." in fqdn:
        return fqdn.split(".", 1)[1]

    return None


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    """Execute a command and capture output.

    Args:
        cmd: Command and arguments as a list

    Returns:
        CompletedProcess with stdout, stderr, and returncode
    """
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def lookup_srv_via_nslookup(domain: str) -> List[str]:
    """Query SRV records for Domain Controllers using nslookup.

    Args:
        domain: Domain name to query (e.g., "example.corp")

    Returns:
        List of output lines from nslookup, or empty list if no output

    Note:
        Queries _ldap._tcp.dc._msdcs.<domain> SRV record.
        Returns empty list if nslookup command not found.

        Deliberately ignores the process return code: Windows nslookup
        commonly exits non-zero on an otherwise successful query (e.g. when
        it can't reverse-resolve the configured DNS server it prints a
        cosmetic "*** Can't find server name for address ..." warning to
        stderr and returns non-zero), while still writing the SRV answer to
        stdout. We parse whatever stdout we got; parse_hosts_from_nslookup()
        filters to FQDNs ending in the target domain, so warning text can't
        produce false hosts.
    """
    if not shutil.which("nslookup"):
        return []
    q = SRV_NAME_FMT.format(domain=domain)
    cp = run(["nslookup", "-type=SRV", q])
    if not cp.stdout.strip():
        return []
    return cp.stdout.splitlines()


def lookup_srv_via_dig(domain: str) -> List[str]:
    if not shutil.which("dig"):
        return []
    q = SRV_NAME_FMT.format(domain=domain)
    cp = run(["dig", "+short", q, "SRV"])
    if cp.returncode != 0:
        return []
    return cp.stdout.splitlines()


def parse_hosts_from_nslookup(lines: List[str], domain: str) -> List[str]:
    hosts: List[str] = []
    dom = domain.lower().rstrip(".")
    for ln in lines:
        for m in HOST_RE.findall(ln):
            m2 = m.rstrip(".")
            low = m2.lower()
            # Keep names *within* the domain (dc01.example.com), but skip the
            # bare domain apex itself, which the regex also extracts from the
            # echoed SRV query name (_ldap._tcp.dc._msdcs.example.com).
            if low.endswith(dom) and low != dom:
                hosts.append(m2)
    seen = set()
    out: List[str] = []
    for h in hosts:
        key = h.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def parse_hosts_from_dig(lines: List[str]) -> List[str]:
    hosts: List[str] = []
    for ln in lines:
        parts = ln.strip().split()
        if len(parts) >= 4:
            tgt = parts[-1].rstrip(".")
            hosts.append(tgt)
    seen = set()
    out: List[str] = []
    for h in hosts:
        key = h.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def resolve_host_ips(host: str) -> List[str]:
    """Resolve a hostname to IPv4 addresses.

    Args:
        host: Hostname to resolve (e.g., "dc01.example.corp")

    Returns:
        List of unique IPv4 addresses for the host (deduplicated)

    Note:
        Uses socket.getaddrinfo() and filters to IPv4 only.
        Returns empty list if resolution fails.
    """
    ips: List[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            try:
                if ip_address(ip).version == 4:
                    ips.append(ip)
            except Exception:
                continue
    except Exception:
        pass
    seen = set()
    out: List[str] = []
    for i in ips:
        if i in seen:
            continue
        seen.add(i)
        out.append(i)
    return out


def reverse_ptr(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup (PTR record) for an IP address.

    Args:
        ip: IPv4 address to look up

    Returns:
        Hostname if PTR record exists, None otherwise

    Note:
        Uses socket.gethostbyaddr() which may be slow on networks with high latency.
    """
    try:
        name, _aliases, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".")
    except Exception:
        return None


def run_masscan(in_scope_file: Path, rate: int, ports: str) -> List[str]:
    """Run masscan to discover hosts with common DC ports open.

    Args:
        in_scope_file: Path to file containing target IPs/ranges
        rate: Scan rate (packets per second)
        ports: Comma-separated port list (default: "389,636")

    Returns:
        List of unique IPv4 addresses with specified ports open, sorted numerically

    Note:
        Fallback method when SRV queries fail. Requires masscan to be installed.
        Writes output to DC_masscan_output in current directory.
    """
    if not shutil.which("masscan"):
        return []
    out_path = Path("DC_masscan_output")
    cmd = ["masscan", "-p", ports, "--rate", str(rate), "-oG", str(out_path), "-iL", str(in_scope_file)]
    cp = run(cmd)
    if cp.returncode != 0:
        return []
    try:
        txt = out_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        txt = ""
    raw_ips = IP_RE.findall(txt)
    valid: List[str] = []
    for s in raw_ips:
        try:
            if ip_address(s).version == 4:
                valid.append(s)
        except Exception:
            pass
    uniq: List[str] = []
    seen = set()
    for ip in valid:
        if ip in seen:
            continue
        seen.add(ip)
        uniq.append(ip)
    uniq.sort(key=lambda s: tuple(int(o) for o in s.split(".")))
    return uniq


def load_nonempty_lines(path: Path) -> List[str]:
    """Load lines from a file, filtering out empty lines and comments.

    Args:
        path: Path to the file to read

    Returns:
        List of non-empty, non-comment lines (stripped of whitespace)

    Note:
        Lines starting with '#' are treated as comments and skipped.
        Returns empty list if file cannot be read.
    """
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    out: List[str] = []
    for ln in txt.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Discover Domain Controllers via SRV lookup; optional masscan fallback.")
    ap.add_argument("--domain", help="Domain to query (e.g., example.corp). If omitted, auto-detect: /etc/resolv.conf 'search' line on Linux, USERDNSDOMAIN or the host FQDN on Windows.")
    ap.add_argument("--output-prefix", default="dc", help="Prefix for output files (default: dc)")
    ap.add_argument("--no-reverse", action="store_true", help="Skip PTR lookups for discovered IPs.")
    ap.add_argument("--fallback-masscan", action="store_true", help="If SRV discovery finds nothing, run masscan against --in-scope.")
    ap.add_argument("--in-scope", type=Path, default=Path.home() / "in-scope", help="In-scope file for masscan fallback (default: ~/in-scope)")
    ap.add_argument("--rate", type=int, default=10000, help="Masscan rate (default: 10000)")
    ap.add_argument("--ports", default="389,636", help="Ports to scan with masscan (default: 389,636)")
    args = ap.parse_args(argv)

    domain = (args.domain or detect_domain() or "").strip().rstrip(".")
    if not domain:
        print("Could not determine domain (provide --domain, or ensure /etc/resolv.conf has a 'search' entry on Linux / USERDNSDOMAIN is set on Windows).", file=sys.stderr)
        return 2

    print(f"[+] Using domain: {domain}")
    srv_hosts: List[str] = []

    # Try nslookup first, fall back to dig
    ns_lines = lookup_srv_via_nslookup(domain)
    if ns_lines:
        srv_hosts = parse_hosts_from_nslookup(ns_lines, domain)

    if not srv_hosts:
        dig_lines = lookup_srv_via_dig(domain)
        if dig_lines:
            srv_hosts = parse_hosts_from_dig(dig_lines)

    # Resolve SRV hosts to IPs
    ips: List[str] = []
    if srv_hosts:
        print(f"[+] SRV returned {len(srv_hosts)} host(s). Resolving...")
        for h in srv_hosts:
            res = resolve_host_ips(h)
            if res:
                ips.extend(res)
        # dedupe while preserving order
        seen = set()
        ips = [i for i in ips if not (i in seen or seen.add(i))]

    # Fallback to masscan if requested and no IPs found
    if not ips and args.fallback_masscan:
        if not args.in_scope.exists():
            print(f"[!] In-scope file not found for masscan fallback: {args.in_scope}", file=sys.stderr)
        else:
            print("[*] No SRV DCs found; running masscan fallback...")
            ips = run_masscan(args.in_scope, rate=args.rate, ports=args.ports)
            if ips:
                print(f"[+] Masscan discovered {len(ips)} potential DC IP(s).")

    # Reverse PTR (optional)
    ptr_map: Dict[str, Optional[str]] = {}
    if ips and not args.no_reverse:
        print("[*] Performing reverse lookups...")
        for ip in ips:
            ptr_map[ip] = reverse_ptr(ip)
    else:
        ptr_map = {ip: None for ip in ips}

    # Write outputs
    prefix = args.output_prefix
    hosts_out = Path(f"{prefix}_hosts.txt")
    ips_out = Path(f"{prefix}_ips.txt")
    map_out = Path(f"{prefix}_map.txt")

    # Hostnames: prefer SRV hostnames first, else PTRs
    host_list: List[str] = []
    if srv_hosts:
        host_list = srv_hosts[:]
    else:
        for ip in ips:
            hn = ptr_map.get(ip)
            if hn:
                host_list.append(hn)

    # dedupe host_list case-insensitively
    seen = set()
    deduped_hosts: List[str] = []
    for h in host_list:
        if not h:
            continue
        key = h.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped_hosts.append(h)

    hosts_out.write_text("\n".join(deduped_hosts) + ("\n" if deduped_hosts else ""), encoding="utf-8")
    ips_out.write_text("\n".join(ips) + ("\n" if ips else ""), encoding="utf-8")
    with map_out.open("w", encoding="utf-8") as fh:
        for ip in ips:
            hn = ptr_map.get(ip) or ""
            fh.write(f"{ip} {hn}\n")

    print(f"[✓] Wrote hosts: {hosts_out} ({len(deduped_hosts)})")
    print(f"[✓] Wrote IPs:   {ips_out} ({len(ips)})")
    print(f"[✓] Wrote map:   {map_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
