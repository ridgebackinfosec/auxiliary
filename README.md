# auxiliary

## mundane.py — Nessus findings triage + nmap helper

**Purpose:** make reviewing Nessus plugin “host/port” files fast and less clicky, with one-shot nmap commands and tidy output artifacts.

**Pre-req:** Leverages the output from NessusPluginHosts.py (https://github.com/DefensiveOrigins/NessusPluginHosts).

`python NessusPluginHosts/NessusPluginHosts.py -f [scan_name].nessus --list-plugins --export-plugin-hosts ./nessus_plugin_hosts`

### What it does (high-level)

* **Walks your export tree**: `nessus_plugin_hosts/<scan>/<severity>/*.txt`
* **Pretty severity menu** with live counts
  `Critical — unreviewed: N | reviewed: M | total: T`
* **Filterable file list** (substring match) with:

  * **\[Enter] = open first match** (saves keystrokes)
  * **\[M] Mark ALL filtered** → prefixes files with `REVIEW_COMPLETE-`
  * **\[R] View reviewed files** (read-only)
  * **\[H] Compare hosts/ports** across all *filtered* files to spot duplicates
* **Preview**: shows file name, host count, sample host, and any detected ports
* **Optional file view**: print contents safely (guards huge files)
* **Sampling**: if many hosts, sample K at random for a quick probe
* **Scan mode**:

  * TCP or UDP (prompted)
  * **NSE Profile (single-selection)**: Crypto / SSH / SMB / SNMP / IPMI

    * **SNMP or IPMI auto-switches to UDP**
  * Extra NSE scripts can be appended (comma-separated)
* **Command review** before running:
  `[1] Run now | [2] Copy to clipboard | [3] Cancel`
* **Always writes `-oA` artifacts** under:
  `scan_artifacts/<scan>/<Severity>/<file_stem>/run-YYYYmmdd-HHMMSS.{nmap,gnmap,xml}`
* **Workspace files** for transparency:
  `tcp_ips.list`, `udp_ips.list` (if used), `tcp_host_ports.list`
* **Session summary**: reviewed/complete/skipped counts at the end
* **No external Python deps** (uses stdlib + `nmap` on PATH). Honors `NO_COLOR` or dumb terminals.

### Expected input layout

```
nessus_plugin_hosts/
  ScanA/
    4_Critical/
      153583_Apache_...txt
      ...
    3_High/
      ...
  ScanB/
    ...
```

Run with an explicit root if different:

```bash
python3 mundane.py /path/to/nessus_plugin_hosts
```

---

### Sample executions

#### 1) Severity selection + filtering (Enter opens first match)

```text
Select a scan
[1] ScanA
[2] ScanB
>> [X] Exit
Choose: 1

Scan: ScanA — choose severity
[1] Critical — unreviewed: 25 | reviewed: 17 | total: 42
[2] High     — unreviewed: 74 | reviewed: 2  | total: 76
[3] Medium   — unreviewed: 127| reviewed: 1  | total: 128
[4] Low      — unreviewed: 14 | reviewed: 0  | total: 14
[5] Info     — unreviewed: 254| reviewed: 0  | total: 254
>> [B] Back
Choose: 1

Severity: 4_Critical
Unreviewed files (25). Current filter: 'apache'
>> [F] Set filter / [C] Clear filter / [R] View reviewed files /
>> [M] Mark ALL filtered as REVIEW_COMPLETE (7) /
>> [H] Compare hosts/ports in filtered files /
>> [B] Back / [Enter] Open first match
[1] 153583_Apache_2.4.49_Multiple_Vulnerabilities.txt
[2] 153584_Apache_2.4.49_Multiple_Vulnerabilities.txt
[3] 158900_Apache_2.4.x_2.4.53_Multiple_Vulnerabilities.txt
...
Choose a file number, or action: ⏎
```

#### 2) Preview + optional file view

```text
Preview
File: 153583_Apache_2.4.49_Multiple_Vulnerabilities.txt
Hosts parsed: 37
Example host: 10.20.30.40
Ports detected: 80,443

Would you like to view the contents of the selected plugin file? (y/N):
```

#### 3) One-profile NSE selection (SNMP/IPMI forces UDP automatically)

```text
Do you want to perform UDP scanning instead of TCP? (y/N): n

NSE Profiles
[1] Crypto (ssl-enum-ciphers, ssl-cert, ssl-date)
[2] SSH    (ssh2-enum-algos, ssh-auth-methods)
[3] SMB    (smb-security-mode, smb2-security-mode)
[4] SNMP   (snmp*)
[5] IPMI   (ipmi-version)
>> [N] None (no NSE profile)
>> [B] Back
Choose: 4
Including: snmp*
SNMP/IPMI selected — switching to UDP scan.

Enter additional NSE scripts (comma-separated, no spaces, or Enter to skip):
```

#### 4) Command review + artifacts path (`-oA` auto-set)

```text
Output directory will be:
scan_artifacts/ScanA/Critical/153583_Apache_2.4.49_Multiple_Vulnerabilities/run-20250815-1304

Command Review
sudo nmap -A --script=snmp* -iL /tmp/nph_work_ad32/udp_ips.list -sU -p 161,162 \
  -oA scan_artifacts/ScanA/Critical/153583_Apache_2.4.49_Multiple_Vulnerabilities/run-20250815-1304
>> [1] Run now
>> [2] Copy command to clipboard (don’t run)
>> [3] Cancel
Choose: 1
```

#### 5) Artifacts + optional rename to REVIEW\_COMPLETE

```text
Artifacts
Workspace: /tmp/nph_work_ad32
 - Hosts:         /tmp/nph_work_ad32/tcp_ips.list
 - UDP hosts:     /tmp/nph_work_ad32/udp_ips.list
 - Results:       scan_artifacts/ScanA/Critical/153583_Apache_2.4.49_Multiple_Vulnerabilities/
                  ├─ run-20250815-1304.nmap
                  ├─ run-20250815-1304.gnmap
                  └─ run-20250815-1304.xml

Mark this file as REVIEW_COMPLETE? (y/N):
```

#### 6) Compare hosts/ports across filtered files

```text
Severity: 4_Critical
Unreviewed files (25). Current filter: 'apache'
>> [F] ... / [M] ... (7) / [H] Compare hosts/ports in filtered files / [B] ... / [Enter] ...
[1] 153583_Apache_...txt
[2] 153584_Apache_...txt
[3] 158900_Apache_...txt
...
Choose a file number, or action: h

Filtered Files: Host/Port Comparison
Files compared: 7
All filtered files target the SAME hosts and ports (identical host:port combinations).

Hosts: intersection=37  union=37
Ports: intersection=2   union=2
Press Enter to return to the file list...
```

#### 7) Mark all filtered files as reviewed (batch rename)

```text
Choose a file number, or action: m
You are about to rename 7 files with prefix 'REVIEW_COMPLETE-'.
Type 'mark' to confirm, or anything else to cancel: mark

Renamed: 7  Skipped: 0
```

---

### Requirements

* Python 3.8+
* `nmap` available on PATH (and `sudo` for certain scan types on Unix)
* Optional: clipboard tool (`pbcopy`, `clip`, `xclip`/`wl-copy`/`xsel`) for “Copy command” action

> Tip: set `NO_COLOR=1` or use a dumb terminal to disable ANSI colors.

---

### Quick start

```bash
git clone https://github.com/ridgebackinfosec/auxiliary.git
cd auxiliary
python3 mundane.py                # assumes ./nessus_plugin_hosts
# or
python3 mundane.py /path/to/nessus_plugin_hosts
```
