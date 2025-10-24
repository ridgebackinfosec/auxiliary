
from __future__ import annotations
import re, ipaddress
from pathlib import Path
from collections import defaultdict
from typing import Dict, Set

_HNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')

def _is_hostname(s: str) -> bool:
    return bool(_HNAME_RE.match(s)) and len(s) <= 253

def _is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s); return True
    except Exception:
        return False

def _is_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s); return True
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
    hosts = []
    ports: Set[str] = set()
    combos: Dict[str, Set[str]] = defaultdict(set)
    malformed = 0
    text = path.read_text(encoding="utf-8", errors="ignore")
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln:
            continue
        for tok in re.split(r"[\s,]+", ln):
            valid, h, p = _is_valid_token(tok)
            if not valid:
                malformed += 1; continue
            hosts.append(h)
            if p:
                ports.add(p); combos[h].add(p)
    hosts = list(dict.fromkeys(hosts))
    had_explicit = any(combos[h] for h in combos)
    return hosts, ports, combos, had_explicit, malformed

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

def _build_item_set(hosts, ports_set, combos_map, had_explicit):
    items = set()
    if had_explicit and combos_map:
        for h in hosts:
            for p in sorted(combos_map.get(h, set()), key=lambda x: int(x)):
                items.add(f"{h}:{p}")
        return items
    for h in hosts:
        for p in sorted(ports_set, key=lambda x: int(x)):
            items.add(f"{h}:{p}")
    return items
