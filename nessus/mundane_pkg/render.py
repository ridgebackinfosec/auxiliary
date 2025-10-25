from __future__ import annotations
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box
from rich.text import Text
from pathlib import Path
import math, re, shutil

from .ansi import (
    C, header, ok, warn, err, info,
    fmt_action, fmt_reviewed, cyan_label, colorize_severity_label,
)

_console_global = Console()

# -------------------------------------------------------------------
# Rendering Helpers (Tables, Panels, Prompts)
# -------------------------------------------------------------------

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

def render_scan_table(scans):
    table = Table(title=None, box=box.SIMPLE, show_lines=False, pad_edge=False)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Scan")
    for i, sdir in enumerate(scans, 1):
        table.add_row(str(i), sdir.name)
    _console_global.print(table)

def render_severity_table(severities, msf_summary=None):
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

def render_file_list_table(display, sort_mode, get_counts_for, row_offset: int = 0):
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

def render_compare_tables(parsed, host_intersection, host_union, port_intersection, port_union, same_hosts, same_ports, same_combos, groups_sorted):
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


    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left_row1, right_row1)
    grid.add_row(left_row2, right_row2)
    _console_global.print(grid)

def _count_severity_files(d: Path):
    files = [f for f in list_files(d) if f.suffix.lower() == ".txt"]
    reviewed = [f for f in files if f.name.lower().startswith(("review_complete", "review-complete"))]
    reviewed += [f for f in files if f.name.lower().startswith(("review_complete-", "review-complete-"))]
    reviewed = list(dict.fromkeys(reviewed))
    unreviewed = [f for f in files if f not in reviewed]
    return len(unreviewed), len(reviewed), len(files)

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

def pretty_severity_label(name: str) -> str:
    m = re.match(r"^\d+_(.+)$", name)
    label = m.group(1) if m else name
    label = label.replace("_", " ").strip()
    return " ".join(w[:1].upper() + w[1:] for w in label.split())

def list_files(p: Path):
    return sorted([f for f in p.iterdir() if f.is_file()], key=lambda f: f.name)

def _default_page_size() -> int:
    try:
        h = shutil.get_terminal_size((80, 24)).lines
        return max(8, h - 10)
    except Exception:
        return 12


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

def _severity_style(label: str) -> str:
    l = label.strip().lower()
    if "critical" in l: return "red"
    if "high"     in l: return "yellow"
    if "medium"   in l: return "magenta"
    if "low"      in l: return "green"
    if "info"     in l: return "cyan"
    return "magenta"