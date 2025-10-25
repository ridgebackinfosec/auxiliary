from __future__ import annotations
import re, ipaddress
from pathlib import Path
from collections import defaultdict
from .logging_setup import log_timing

# ====== Scan overview helpers ======
_HNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')

def is_hostname(s: str) -> bool:
    return bool(_HNAME_RE.match(s)) and len(s) <= 253

def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

def is_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False

def is_valid_token(tok: str):
    tok = tok.strip()
    if not tok:
        return False, None, None

    if tok.startswith("["):
        m = re.match(r"^\[(.+?)\](?::(\d+))?$", tok)
        if m and is_ipv6(m.group(1)):
            port = m.group(2)
            if port is None:
                return True, m.group(1), None
            if port.isdigit() and 1 <= int(port) <= 65535:
                return True, m.group(1), port
        return False, None, None

    if tok.count(":") >= 2 and not re.search(r"]:\d+$", tok):
        return (is_ipv6(tok), tok if is_ipv6(tok) else None, None)

    if ":" in tok:
        h, p = tok.rsplit(":", 1)
        if p.isdigit() and 1 <= int(p) <= 65535 and (is_hostname(h) or is_ipv4(h)):
            return True, h, p
        return False, None, None

    if is_hostname(tok) or is_ipv4(tok) or is_ipv6(tok):
        return True, tok, None

    return False, None, None
@log_timing

@log_timing
def parse_for_overview(path: Path):
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
            valid, h, p = is_valid_token(tok)
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

# ====== Compare hosts/ports across filtered files ======
def normalize_combos(hosts, ports_set, combos_map, had_explicit):
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

# ====== Superset / coverage analysis across filtered files ======
def build_item_set(hosts, ports_set, combos_map, had_explicit):
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