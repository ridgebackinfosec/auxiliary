# auxiliary

## mundane.py — quick triage for Nessus plugin files + one-shot nmap

**Goal:** make it fast to review Nessus “host/port” plugin files and launch sensible `nmap` runs with saved artifacts.

### What it does

* Walks your export tree: `nessus_plugin_hosts/<scan>/<severity>/*.txt`
* Shows a clean **severity menu** with live counts
* Lets you **filter** the file list and open the first match with **Enter**
* Can **batch-mark** filtered files as `REVIEW_COMPLETE-…`
* **Compares hosts/ports** across filtered files and groups identical sets
  (pick a group like `g1`, `g2`…; only the first 5 are shown, “etc.” after that)
* Builds an `nmap` command for the selected file (TCP or UDP) with **NSE profiles**
* **Always saves results** with `-oA` under `scan_artifacts/...`

No external Python deps. Uses only stdlib + `nmap` on your PATH.

### Requirements

* Python 3.8+
* `nmap` installed (and `sudo` for some scan types on Unix)
* The export files from [NessusPluginHosts.py](https://github.com/DefensiveOrigins/NessusPluginHosts).
  
`python NessusPluginHosts.py -f scan.nessus --list-plugins --export-plugin-hosts ./nessus_plugin_hosts`

### Typical flow

1. Pick a **scan**, then a **severity**
2. Type a **substring filter** (e.g., `apache`) and press **Enter** to open the first match
3. (Optional) **\[H]** to compare the filtered files → pick `g1`/`g2`… to focus on a group
4. Decide TCP vs UDP, choose an **NSE profile** (single select), and add any extra scripts

   * **SNMP**/**IPMI** profiles auto-switch to **UDP**
5. Review the generated command, **Run** or **Copy**, and optionally mark the file as reviewed

![mundane-demo](https://github.com/user-attachments/assets/f1bb7835-70cb-4efe-a8a6-1938255445db)

### Keys you’ll use

* **\[F]** Set substring filter  **\[C]** Clear filter
* **\[R]** View reviewed files (read-only)
* **\[M]** Mark **ALL filtered** files as `REVIEW_COMPLETE-…`
* **\[H]** Compare hosts/ports (groups sorted by size; prompt shows `g1–g5 | etc.`)
* **\[O]** Toggle sort: **Name A→Z** ↔ **Host count ↓**
* **\[X]** Clear active group filter
* **\[Enter]** Open first match  **\[B]** Back

> Group filters are **not persistent**: they reset when you change severity or re-run **\[H]**.

### NSE profiles (single-select)

* **Crypto:** `ssl-enum-ciphers, ssl-cert, ssl-date`
* **SSH:** `ssh2-enum-algos, ssh-auth-methods`
* **SMB:** `smb-security-mode, smb2-security-mode`
* **SNMP:** `snmp*` *(forces UDP)*
* **IPMI:** `ipmi-version` *(forces UDP)*
* Plus optional extra scripts (comma-separated, no spaces)

### Example command review

```text
Command Review
sudo nmap -A --script=snmp* -iL /tmp/nph_work_abcd/udp_ips.list -sU -p 161 \
  -oA scan_artifacts/ScanA/Critical/153583_Apache_2.4.49_Multiple_Vulnerabilities/run-20250819-1042

[1] Run now  |  [2] Copy command  |  [3] Cancel
```

Artifacts are saved as:
`scan_artifacts/<scan>/<Severity>/<plugin>/run-YYYYmmdd-HHMMSS.{nmap,gnmap,xml}`

### Tips

* Press **Enter** often: it opens the first result after filtering—fastest path forward.
* Use **\[H]** early to discover duplicates and **\[M]** to batch-mark them done.
* Sorting by **Host count** helps you tackle the noisiest files first.

That’s it—run it from the repo root and follow the prompts.
