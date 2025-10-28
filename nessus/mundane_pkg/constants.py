"""Centralized application constants and configuration.

This module contains all constants used throughout the mundane application,
including paths, URL templates, protocol lists, and NSE profiles for security
testing tools integration.
"""

import os
import re
from pathlib import Path


# ========== Application paths and prefixes ==========
RESULTS_ROOT: Path = Path(os.environ.get("NPH_RESULTS_ROOT", "scan_artifacts"))
"""Root directory for scan artifacts and results output."""

REVIEW_PREFIX: str = "REVIEW_COMPLETE-"
"""Prefix added to filenames that have been reviewed."""


# ========== Plugin details configuration ==========
PLUGIN_DETAILS_BASE: str = "https://www.tenable.com/plugins/nessus/"
"""Base URL for Tenable plugin detail pages."""


# ========== NetExec protocol support ==========
NETEXEC_PROTOCOLS: list[str] = [
    "mssql",
    "smb",
    "ftp",
    "ldap",
    "nfs",
    "rdp",
    "ssh",
    "vnc",
    "winrm",
    "wmi",
]
"""Supported protocols for NetExec/CrackMapExec tool integration."""


# ========== NSE (Nmap Scripting Engine) profiles ==========
NSE_PROFILES: list[tuple[str, list[str], bool]] = [
    ("Crypto", ["ssl-enum-ciphers", "ssl-cert", "ssl-date"], False),
    ("SSH", ["ssh2-enum-algos", "ssh-auth-methods"], False),
    ("SMB", ["smb-security-mode", "smb2-security-mode"], False),
    ("SNMP", ["snmp*"], True),
    ("IPMI", ["ipmi-version"], True),
]
"""NSE profile definitions: (name, script_list, is_wildcard)."""


# ========== Validation patterns ==========
HNAME_RE: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
"""Regex pattern for validating hostname format."""
