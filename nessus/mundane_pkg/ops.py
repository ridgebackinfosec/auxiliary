# Operational helpers: external commands, cloning, and shell checks (extracted; no behavior change)
from __future__ import annotations
from pathlib import Path
from typing import Optional, Any, List
import os, re, shutil, subprocess, sys

# --- in mundane_pkg/ops.py ---
from .logging_setup import log_timing, _log_info, _log_error
from .ansi import header, ok, warn, err
from .constants import RESULTS_ROOT, REVIEW_PREFIX, PLUGIN_DETAILS_BASE, NETEXEC_PROTOCOLS, NSE_PROFILES

def require_cmd(name):
    if shutil.which(name) is None:
        err(f"Required command '{name}' not found on PATH.")
        sys.exit(1)

def resolve_cmd(candidates):
    for c in candidates:
        if shutil.which(c):
            return c
    return None

