from __future__ import annotations
import re, shutil
from pathlib import Path
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn as ProgTextColumn, TimeElapsedColumn
from rich.console import Console

from .constants import RESULTS_ROOT, REVIEW_PREFIX  # :contentReference[oaicite:0]{index=0}
from .ansi import warn, ok, err, header

_console_global = Console()

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
        with Progress(
            SpinnerColumn(style="cyan"),
            ProgTextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task("Reading file...", start=True)
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

def is_review_complete(path: Path) -> bool:
    return path.name.startswith(REVIEW_PREFIX)

def rename_review_complete(path: Path):
    name = path.name
    prefix = REVIEW_PREFIX
    if is_review_complete(path):
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

def build_results_paths(scan_dir: Path, sev_dir: Path, plugin_filename: str):
    stem = Path(plugin_filename).stem
    sev_label = pretty_severity_label(sev_dir.name)
    out_dir = RESULTS_ROOT / scan_dir.name / sev_label / stem
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    oabase = out_dir / f"run-{ts}"
    return out_dir, oabase

def pretty_severity_label(name: str) -> str:
    m = re.match(r"^\d+_(.+)$", name)
    label = m.group(1) if m else name
    label = label.replace("_", " ").strip()
    return " ".join(w[:1].upper() + w[1:] for w in label.split())

def list_files(p: Path):
    return sorted([f for f in p.iterdir() if f.is_file()], key=lambda f: f.name)

def default_page_size() -> int:
    try:
        h = shutil.get_terminal_size((80, 24)).lines
        return max(8, h - 10)
    except Exception:
        return 12