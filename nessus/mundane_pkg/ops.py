# Operational helpers: external commands, cloning, and shell checks (extracted; no behavior change)
from __future__ import annotations
from pathlib import Path
from typing import Optional
import os, shutil, subprocess, sys
from rich.progress import Progress, SpinnerColumn, TextColumn as ProgTextColumn, TimeElapsedColumn
from rich.console import Console

# --- in mundane_pkg/ops.py ---
from .ansi import header, ok, err, C

# Create a console for the interactive flow
_console_global = Console()

# ---------- Run tools with a Rich spinner ----------
def run_command_with_progress(cmd, *, shell: bool = False, executable: Optional[str] = None) -> int:
    disp = cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd)
    if len(disp) > 120:
        disp = disp[:117] + "..."


    # Delay spinner until after sudo password (if needed)
    try:
        def _cmd_starts_with_sudo(c):
            import os, re
            if isinstance(c, list):
                return len(c) > 0 and os.path.basename(str(c[0])) == "sudo"
            if isinstance(c, str):
                return bool(re.match(r'^\s*(?:\S*/)?sudo\b', c))
            return False

        if _cmd_starts_with_sudo(cmd):
            # Check if sudo is already validated (non-interactive); 0 => cached
            try:
                _chk = subprocess.run(["sudo", "-vn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                needs_pw = (_chk.returncode != 0)
            except Exception:
                needs_pw = True  # be conservative

            if needs_pw:
                print(f"{C.YELLOW}Waiting for sudo password...{C.RESET} (type it when prompted below)")
                # Prompt the user once, blocking, before launching the actual command.
                # This allows the spinner to only start after authentication is satisfied.
                try:
                    subprocess.run(["sudo", "-v"], check=True)
                except KeyboardInterrupt:
                    # Propagate so upstream code can handle graceful termination
                    raise
                except subprocess.CalledProcessError as _e:
                    # The user failed sudo; abort early with a useful message.
                    raise subprocess.CalledProcessError(_e.returncode, _e.cmd)
    except Exception:
        # Non-fatal: even if pre-validation fails, fallback to normal behavior.
        pass


    if isinstance(cmd, list):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    else:
        proc = subprocess.Popen(cmd, shell=True, executable=executable, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    try:
        with Progress(
            SpinnerColumn(style="cyan"),
            ProgTextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task(f"Running: {disp}", start=True)
            for line in iter(proc.stdout.readline, ""):
                print(line, end="")
                progress.refresh()
            proc.stdout.close()
            proc.wait()
            rc = proc.returncode
    except KeyboardInterrupt:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        finally:
            raise
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)
    return rc

# ---------- Wizard helpers ----------
def clone_nessus_plugin_hosts(repo_url: str, dest: Path) -> Path:
    """Clone NessusPluginHosts into dest if absent; returns the repo path."""
    if dest.exists() and (dest / "NessusPluginHosts.py").exists():
        ok(f"Repo already present: {dest}")
        return dest
    require_cmd("git")
    dest.parent.mkdir(parents=True, exist_ok=True)
    header("Cloning NessusPluginHosts")
    run_command_with_progress(["git", "clone", "--depth", "1", repo_url, str(dest)])
    ok(f"Cloned into {dest}")
    return dest

def root_or_sudo_available() -> bool:
    """Return True if we're root on *nix or 'sudo' is available on PATH."""
    try:
        if os.name != "nt" and os.geteuid() == 0:
            return True
    except AttributeError:
        # os.geteuid not present on Windows; fall back to sudo check
        pass
    return shutil.which("sudo") is not None

def require_cmd(name):
    if shutil.which(name) is None:
        err(f"Required command '{name}' not found on PATH.")
        sys.exit(1)

def resolve_cmd(candidates):
    for c in candidates:
        if shutil.which(c):
            return c
    return None
