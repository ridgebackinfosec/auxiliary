import re

from .logging_setup import log_timing
from .ansi import warn, header, info
from .parsing import parse_file_hosts_ports_detailed, build_item_set, normalize_combos
from .render import render_compare_tables
from .fs import list_dirs, list_files

from collections import defaultdict
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, TextColumn as ProgTextColumn, TimeElapsedColumn
from rich.console import Console
from rich.table import Table
from rich import box

_console_global = Console()

@log_timing
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
    combo_sigs = [normalize_combos(h, p, c, e) for _, h, p, c, e in parsed]

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

    render_compare_tables(
        parsed,
        host_intersection, host_union, port_intersection, port_union,
        same_hosts, same_ports, same_combos,
        groups_sorted
    )
    return groups_sorted

@log_timing
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
            item_sets[f] = build_item_set(hosts, ports_set, combos, had_explicit)
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

def natural_key(s: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', s)]

def count_reviewed_in_scan(scan_dir: Path):
    total_files = 0
    reviewed_files = 0
    for sev in list_dirs(scan_dir):
        files = [f for f in list_files(sev) if f.suffix.lower() == ".txt"]
        total_files += len(files)
        reviewed = [f for f in files if f.name.lower().startswith(("review_complete", "review-complete", "review_complete-", "review-complete-"))]
        reviewed = list(dict.fromkeys(reviewed))
        reviewed_files += len(reviewed)
    return total_files, reviewed_files
