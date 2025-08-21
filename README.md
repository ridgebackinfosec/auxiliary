# auxiliary

## mundane.py

Small TUI helper to **review Nessus plugin host files** quickly and (optionally) kick off focused checks with **nmap** or **NetExec**—all with **zero Python deps**.

**Goal:** make it fast to review Nessus “host/port” plugin files and launch sensible `nmap` runs with saved artifacts.

---

### Requirements

* Python 3.8+
* The exported Nessus files via [NessusPluginHosts.py](https://github.com/DefensiveOrigins/NessusPluginHosts).
  
`python NessusPluginHosts.py -f scan.nessus --list-plugins --export-plugin-hosts ./nessus_plugin_hosts`

### Safety & Options

* External commands are executed only after a **Run / Copy / Cancel** review step.
* If a binary is missing, the script warns and skips the run.
* `--no-tools` guarantees a review-only session. (no tool execution during review process)

### Highlights

* **Scan overview (auto)** after choosing a scan:

  * Files: total, reviewed, empty, malformed tokens
  * Hosts: unique count + IPv4/IPv6 split (with sample)
  * Ports: unique + **Top 5** most prevalent
  * Duplicates: count of identical host\:port clusters, top cluster sizes
    *(section labels render in **cyan** in ANSI-capable terminals)*
* **Severity browser** with substring filtering, host-count sort, reviewed view.
* **Compare & group** (\[H]) filtered files by identical host\:port combinations; pick a group to filter (shows only first 5 group shortcuts for long lists).
* **Open-first-on-Enter** — press Enter to open the first filtered match.
* **Mark-all-filtered** — bulk mark current filtered set as `REVIEW_COMPLETE-...`.
* **Tools (optional)** per file (run one or many in the same context):

  * **nmap** (TCP/UDP, single-select **NSE profiles**; auto-switch to UDP for SNMP/IPMI)
  * **NetExec** (**protocol select**: mssql, smb, ftp, ldap, nfs, rdp, ssh, vnc, winrm, wmi)
  * **Custom command** with placeholders:
    `{TCP_IPS} {UDP_IPS} {TCP_HOST_PORTS} {PORTS} {WORKDIR} {RESULTS_DIR} {OABASE}`
* **Artifacts** are organized under `scan_artifacts/<scan>/<severity>/<plugin>/`

  * nmap: `-oA run-<ts>` triple
  * NetExec: `run-<ts>.nxc.<proto>.log`
  * **SMB relay list**: `run-<ts>.SMB_Signing_not_required_targets.txt`
  * Temp helpers per run: `tcp_ips.list`, `udp_ips.list`, `tcp_host_ports.list`

### Quick start

```bash
# 1) Put your exported plugin host files here:
./nessus_plugin_hosts/<ScanName>/<Severity>/*.txt

# 2) Run
python3 mundane.py

# Optional: point to a different root
python3 mundane.py /path/to/nessus_plugin_hosts

# Optional: disable all tool prompts (review-only)
python3 mundane.py --no-tools
```

> **No Python packages required.** Optional external binaries if you want to execute tools:
>
> * `nmap` (with NSE scripts)
> * `nxc` or `netexec` (detected automatically)

### Typical flow

1. **Select a scan** → see the **Scan Overview** (cyan-labeled stats).
2. **Choose a severity** → filter/sort unreviewed files.
3. Press **Enter** to open the top match, or type a number to open a file.
4. **Optionally** run a tool (nmap / NetExec / custom). You can run multiple commands in the same context.
5. **Mark** the file as `REVIEW_COMPLETE` (or leave it reviewed but not renamed).

### Tool notes

* **nmap**

  * TCP by default; select profile (Crypto/SSH/SMB/SNMP/IPMI).
  * Picking SNMP/IPMI or adding `snmp*`/`ipmi-version` auto-enables **UDP**.
  * Always writes `-oA` to the run’s artifact base.

* **NetExec**

  * Choose the **protocol** first.
  * **SMB template** uses positional targets and writes the **relay list** into the run’s artifact folder:

    ```
    nxc smb <tcp_ips.list> --gen-relay-list run-<ts>.SMB_Signing_not_required_targets.txt --shares --log run-<ts>.nxc.smb.log
    ```
  * Other protocols write a per-run `.log` alongside artifacts.

* **Custom command**

  * Use placeholders to reference the current context:

    * `{TCP_IPS}`, `{UDP_IPS}`, `{TCP_HOST_PORTS}`, `{PORTS}`
    * `{WORKDIR}`, `{RESULTS_DIR}`, `{OABASE}`

### Keyboard hints

* **Enter**: open first filtered file
* **F/C**: set/clear filter
* **O**: toggle sort (Name ↔ Host count)
* **R**: view reviewed files
* **M**: mark all filtered as reviewed
* **H**: compare filtered files, then select a **group** (e.g., `g1…g5`) to filter
