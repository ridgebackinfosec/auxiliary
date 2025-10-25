import os
from pathlib import Path

# ========== Centralized constants ==========
RESULTS_ROOT: Path = Path(os.environ.get("NPH_RESULTS_ROOT", "scan_artifacts"))
REVIEW_PREFIX: str = "REVIEW_COMPLETE-"

# ---------- Plugin details link helpers ----------
PLUGIN_DETAILS_BASE = "https://www.tenable.com/plugins/nessus/"

NETEXEC_PROTOCOLS = ["mssql","smb","ftp","ldap","nfs","rdp","ssh","vnc","winrm","wmi"]

# === NSE Profiles (single-selection) ===
NSE_PROFILES = [
    ("Crypto", ["ssl-enum-ciphers", "ssl-cert", "ssl-date"], False),
    ("SSH",    ["ssh2-enum-algos", "ssh-auth-methods"], False),
    ("SMB",    ["smb-security-mode", "smb2-security-mode"], False),
    ("SNMP",   ["snmp*"], True),
    ("IPMI",   ["ipmi-version"], True),
]
