from __future__ import annotations
from typing import Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.prompt import Confirm, Prompt
from typing import Iterable
from pathlib import Path
import math

from .ansi import (
    info, fmt_action, warn
)

from .fs import list_files, default_page_size, pretty_severity_label
from .logging_setup import log_timing

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
    ps = page_size or default_page_size()
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
            ans = ask_text("Action:", to_lower=True)
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
        unrev, rev, tot = count_severity_files(sd)
        label = pretty_severity_label(sd.name)
        table.add_row(
            str(i),
            rich_severity_cell(label),
            rich_unreviewed_cell(unrev, tot),
            rich_reviewed_cell(rev, tot),
            rich_total_cell(tot),
        )

    if msf_summary:
        idx, unrev, rev, tot = msf_summary
        table.add_row(
            str(idx),
            rich_severity_cell("Metasploit Module"),
            rich_unreviewed_cell(unrev, tot),
            rich_reviewed_cell(rev, tot),
            rich_total_cell(tot),
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
@log_timing

def render_actions_footer(*, group_applied: bool, candidates_count: int, sort_mode: str, can_next: bool, can_prev: bool):
    """Two-row, two-column action footer."""
    left_row1  = join_actions_texts([
        key_text("Enter", "Open first match"),
        key_text("B", "Back"),
        key_text("?", "Help"),
    ])
    right_row1 = join_actions_texts([
        key_text("F", "Set filter"),
        key_text("C", "Clear filter"),
        key_text("O", f"Toggle sort (now: {'Hosts' if sort_mode=='hosts' else 'Name'})"),
    ])
    left_row2  = join_actions_texts([
        key_text("R", "Reviewed files"),
        key_text("H", "Compare"),
        key_text("I", "Superset analysis"),
        key_text("M", f"Mark ALL filtered as REVIEW_COMPLETE ({candidates_count})"),
    ])
    right_items = [
        key_text("N", "Next page", enabled=can_next),
        key_text("P", "Prev page", enabled=can_prev),
    ]
    if group_applied:
        right_items.append(key_text("X", "Clear group"))
    right_row2 = join_actions_texts(right_items)

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left_row1, right_row1)
    grid.add_row(left_row2, right_row2)
    _console_global.print(grid)

def show_actions_help(*, group_applied: bool, candidates_count: int, sort_mode: str, can_next: bool, can_prev: bool):
    """Render a categorized help panel for main/MSF file lists."""
    t = Table.grid(padding=(0,1))
    t.add_row(Text("Navigation", style="bold"), key_text("Enter", "Open first match"),
              key_text("N", "Next page", enabled=can_next), key_text("P", "Prev page", enabled=can_prev), key_text("B", "Back"))
    t.add_row(Text("Filtering", style="bold"), key_text("F", "Set filter"), key_text("C", "Clear filter"))
    t.add_row(Text("Sorting", style="bold"), key_text("O", f"Toggle sort (now: {'Hosts' if sort_mode=='hosts' else 'Name'})"))
    t.add_row(Text("Bulk review", style="bold"), key_text("M", f"Mark ALL filtered as REVIEW_COMPLETE ({candidates_count})"))
    t.add_row(Text("Analysis", style="bold"),
              key_text("H", "Compare hosts/ports (identical)"),
              key_text("I", "Superset / coverage groups"))
    if group_applied:
        t.add_row(Text("Groups", style="bold"), key_text("X", "Clear group filter"))
    panel = Panel(t, title="Actions", border_style="cyan")
    _console_global.print(panel)

def show_reviewed_help():
    t = Table.grid(padding=(0,1))
    t.add_row(Text("Filtering", style="bold"), key_text("F", "Set filter"), key_text("C", "Clear filter"))
    t.add_row(Text("Exit", style="bold"), key_text("B", "Back"))
    panel = Panel(t, title="Reviewed Files — Actions", border_style="cyan")
    _console_global.print(panel)

def key_text(key: str, label: str, *, enabled: bool = True) -> Text:
    t = Text()
    t.append(f"[{key}] ", style="cyan")
    t.append(label, style=None if enabled else "dim")
    if not enabled:
        t.stylize("dim")
    return t

def join_actions_texts(items: list[Text]) -> Text:
    out = Text()
    for i, it in enumerate(items):
        if i:
            out.append(" / ", style="dim")
        out.append(it)
    return out

def count_severity_files(d: Path):
    files = [f for f in list_files(d) if f.suffix.lower() == ".txt"]
    reviewed = [f for f in files if f.name.lower().startswith(("review_complete", "review-complete"))]
    reviewed += [f for f in files if f.name.lower().startswith(("review_complete-", "review-complete-"))]
    reviewed = list(dict.fromkeys(reviewed))
    unreviewed = [f for f in files if f not in reviewed]
    return len(unreviewed), len(reviewed), len(files)

def rich_severity_cell(label: str) -> Any:
    t = Text(label)
    t.stylize("bold")
    t.stylize(severity_style(label))
    return t

def rich_unreviewed_cell(n: int, total: int) -> Any:
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

def rich_reviewed_cell(n: int, total: int) -> Any:
    pct = 0
    if total:
        pct = round((n / total) * 100)
    t = Text(f"{n} ({pct}%)")
    t.stylize("magenta")
    return t

def rich_total_cell(n: int) -> Any:
    t = Text(str(n))
    t.stylize("bold")
    return t

def severity_style(label: str) -> str:
    l = label.strip().lower()
    if "critical" in l: return "red"
    if "high"     in l: return "yellow"
    if "medium"   in l: return "magenta"
    if "low"      in l: return "green"
    if "info"     in l: return "cyan"
    return "magenta"

# === Unified prompt helpers (Rich) ===
def ask_confirm(message: str, default: bool | None = False) -> bool:
    """Unified yes/no confirmation using Rich. Mirrors previous yes/no semantics."""
    return bool(Confirm.ask(message, default=bool(default)))

def ask_text(message: str, default: str | None = None, to_lower: bool = False) -> str:
    """Unified text prompt using Rich. Returns stripped string; optionally lower-cased."""
    if default is None:
        ans = Prompt.ask(message, default="").strip()
    else:
        ans = Prompt.ask(message, default=default).strip()
    return ans.lower() if to_lower else ans

def ask_number_or_none(message: str, max_number: int, default_none_key: str = "N") -> int | None:
    """Prompt for an integer in [1, max_number] or None via a sentinel key.
    Example UI: "Copy which one-liner to clipboard? (number or [N]one) (N):"
    Returns an int (1..max_number) or None.
    """
    default_display = default_none_key.upper()
    suffix = f" (number or [{default_display}]one) ({default_display}):"
    while True:
        raw = Prompt.ask(message + suffix, default=default_display).strip()
        if not raw:
            return None
        if raw.upper() == default_none_key.upper():
            return None
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= max_number:
                return n
        _console_global.print(f"[yellow]Enter 1–{max_number} or {default_display}[/]")

def ask_key(message: str, valid_keys: Iterable[str], default: str | None = None) -> str:
    """Prompt for a single key from a set (case-insensitive). Returns normalized lower-case key."""
    norm = {k.lower() for k in valid_keys}
    default_disp = default if default is not None else None
    while True:
        ans = Prompt.ask(message, default=default_disp).strip()
        if not ans:
            if default is not None:
                return default.lower()
            continue
        key = ans.lower()
        if key in norm:
            return key
        _console_global.print(f"[yellow]Choose one of: {', '.join(sorted(norm))}[/]")
