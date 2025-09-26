# mundane.py

A small TUI helper to **review Nessus plugin host files** quickly and (optionally) kick off focused checks with **nmap** or **NetExec**. Includes a one-step **wizard** to seed the export structure directly from a `.nessus` file.

---

## Requirements

- Python 3.8+
- Install Python deps:
  ```bash
  pip install -r requirements.txt
  ```
  (uses: `rich`, `typer`, `pyperclip`, `colorama`)
- Optional external tools (only if you choose to run them):
  - `git` (required for `wizard`)
  - `nmap`
  - `nxc` or `netexec`
- Unix-like shell recommended. On Linux, clipboard copy may require one of: `xclip`, `wl-copy`, or `xsel`.

---

## Quick Start

### 1) Seed exports from a `.nessus` (wizard)
This clones **NessusPluginHosts** and exports plugin hostlists into `./nessus_plugin_hosts`:

```bash
python mundane.py wizard path/to/scan.nessus
# immediately start reviewing after export:
python mundane.py wizard path/to/scan.nessus --review
# customize clone/output locations:
python mundane.py wizard scan.nessus --repo-dir ./vendor/NessusPluginHosts --out-dir ./nessus_plugin_hosts
```

### 2) Review exports interactively
```bash
python mundane.py review --export-root ./nessus_plugin_hosts
```

---

## What You Can Do

- **Browse scans & severities** with clean Rich tables.
- **Preview files** before acting (shows **Plugin Details** link like `https://www.tenable.com/plugins/nessus/<ID>`).
- **Paged views** for long outputs with familiar controls: **[N]**ext, **[P]**rev, **[B]**ack (single-page views auto-return).
- **Grouped view** (`host:port,port`) or raw file view.
- **Copy to clipboard** from file view (**[C] Copy**) or the command review dialog.
- **Run tools** against current hosts:
  - `nmap` (choose NSE profiles; SNMP/IPMI auto-switch to UDP)
  - `netexec`/`nxc` (SMB relay list generation included)
  - **Custom commands** with placeholders (see below)
- **Compare files**: find identical host:port combo groups across filtered files.
- **Bulk mark** filtered files as `REVIEW_COMPLETE-...` with confirmation.
- **Scan overview** (auto after selecting a scan): totals, empty/malformed counts, IPv4/IPv6 split, top ports, identical groups.
- **Progress indicators** while cloning, exporting, parsing, grouping, bulk-marking, and running tools.

---

## Commands

```bash
# Wizard: seed exported plugin files from a .nessus scan (then optionally review)
python mundane.py wizard <scan.nessus> [--repo-dir DIR] [--out-dir DIR] [--review]

# Interactive review (main workflow)
python mundane.py review --export-root ./nessus_plugin_hosts [--no-tools]

# Summarize a scan directory
python mundane.py summary ./nessus_plugin_hosts/<ScanName> [--top-ports 10]

# Compare/group identical host:port combos across files
python mundane.py compare 4_Critical/*.txt

# Quick file preview
python mundane.py view nessus_plugin_hosts/<Scan>/<Severity>/<Plugin>.txt [--grouped]
```

### Custom command placeholders
When running a custom command, you can use these tokens (expanded at runtime):

- `{TCP_IPS}` – file containing hosts (one per line)
- `{UDP_IPS}` – same as above, used when needed by UDP
- `{TCP_HOST_PORTS}` – file with `host:port1,port2,...`
- `{PORTS}` – comma-separated ports string (if detected)
- `{WORKDIR}` – temp working directory for the run
- `{RESULTS_DIR}` – persistent results directory for the plugin
- `{OABASE}` – base path prefix for output artifacts (e.g., `nmap -oA {OABASE}`)

**Examples**
```bash
httpx -l {TCP_IPS} -silent -o {OABASE}.urls.txt
nuclei -l {OABASE}.urls.txt -o {OABASE}.nuclei.txt
cat {TCP_IPS} | xargs -I{} sh -c 'echo {}; nmap -Pn -p {PORTS} {}'
```

---

## Tips

- Colors can be disabled by setting `NO_COLOR=1` or using a dumb terminal (`TERM=dumb`).
- Not running as root and no `sudo` available may limit UDP/NSE behavior—mundane will warn you.
- Clipboard: if headless Linux lacks a clipboard utility, copy prompts will print content for manual copy.

---

## Directory Layout (after wizard)

```
nessus_plugin_hosts/
  <ScanName>/
    4_Critical/
      193421_Apache_2.4.x___2.4.54_Authentication_Bypass.txt
      ...
    3_High/
    2_Medium/
    1_Low/
    0_Info/
scan_artifacts/
  <ScanName>/<Severity>/<PluginBase>/run-YYYYmmdd-HHMMSS.*
```

---

## License

This tool orchestrates local utilities and uses data produced by
[DefensiveOrigins/NessusPluginHosts](https://github.com/DefensiveOrigins/NessusPluginHosts).
Respect each dependency’s license and your environment’s usage policies.
