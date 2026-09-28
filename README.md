![auxiliary banner](auxiliary-banner.png)

# Ridgeback InfoSec — auxiliary scripts/tools

Collection of small Python3 utilities used for reconnaissance, list processing, and local tooling. **Most tools are stdlib-only** (no pip packages required); the exception is `webtech_fingerprint` (web/), which needs `requests`, `beautifulsoup4`, and `playwright` — see the `web/` section below.

Tested with Python 3.8+.

---

## Installation

### Using pipx (recommended)
Install the tools as CLI commands using pipx:
```bash
pipx install git+https://github.com/ridgebackinfosec/auxiliary.git
```

### Using pip
Install globally or in a virtual environment:
```bash
pip install git+https://github.com/ridgebackinfosec/auxiliary.git
```

### Development install
For local development with editable installation:
```bash
git clone https://github.com/ridgebackinfosec/auxiliary.git
cd auxiliary
pip install -e .
```

### Manual usage (without installation)
Clone the repository and run scripts directly with Python:
```bash
git clone https://github.com/ridgebackinfosec/auxiliary.git
cd auxiliary
python3 dns/find_domain_controllers.py --help
```

---

## Usage

After installation via pipx or pip, you can use the tools in two ways:

### Unified CLI
Use the `auxiliary` command with subcommands:
```bash
auxiliary <tool> [args...]
auxiliary --list              # Show all available tools
auxiliary --help              # Show help information
auxiliary <tool> --help       # Show help for a specific tool
```

### Individual commands
Each tool is also available as a standalone command with the `aux-` prefix:
```bash
aux-find-dc --domain example.corp
aux-reverse-dns --input ips.txt --output hostnames.txt
aux-extract-ips --input ~/chaos --output ~/order
aux-masscan masscan_output --output targets
aux-gobuster gobuster.txt http://example.com urls.txt
aux-webtech https://target.example.com
aux-split-lines --input targets --lines 1000
aux-split-creds --glob 'creds-*.txt' --dedupe-users
aux-iptables --ranges-file ranges.txt --apply
aux-nessus-rules --input out-of-scope.txt --apply
aux-reverse-ssh diagram
```

---

## Folder summary & quick examples

### `dns/`
Tools for reverse lookups and Domain Controller discovery.

- **reverse_dns** — Perform reverse DNS lookups and/or produce hostnames lists (two modes: `hostnames` or `ip-map`).
  Examples:
  ```bash
  # Using installed command
  aux-reverse-dns --mode hostnames --input ip_list.txt --output dns_results.txt
  auxiliary reverse-dns --mode ip-map --input in-scope --output resolved_ips.txt

  # Using script directly (no installation)
  python3 dns/reverse_dns.py --mode hostnames --input ip_list.txt --output dns_results.txt
  ```

- **find_domain_controllers** — Discover Windows DCs via SRV lookup (`_ldap._tcp.dc._msdcs.<domain>`), resolve hostnames → IPs, optional masscan fallback and PTR lookups.
  Examples:
  ```bash
  # Using installed command
  aux-find-dc --domain example.corp
  sudo auxiliary find-dc --domain example.corp --fallback-masscan --in-scope ~/in-scope

  # Using script directly (no installation)
  python3 dns/find_domain_controllers.py
  sudo python3 dns/find_domain_controllers.py --domain example.corp --fallback-masscan
  ```

---

### `network/`
Helpers to extract and normalize IP/target lists from scan output.

- **chaos_ip_extract** — Extract valid IPv4s from `~/chaos`, dedupe and numeric-sort into `~/order` (defaults).
  Examples:
  ```bash
  # Using installed command
  aux-extract-ips
  auxiliary extract-ips --input /path/to/chaos.txt --output /tmp/order.txt

  # Using script directly (no installation)
  python3 network/chaos_ip_extract.py
  python3 network/chaos_ip_extract.py --input /path/to/chaos.txt --output /tmp/order.txt
  ```

- **masscan_to_targets** — Extract IPv4 tokens from masscan/scan output, validate octets, dedupe and numeric sort (writes `targets` by default).
  Examples:
  ```bash
  # Using installed command
  aux-masscan masscan_output --output targets
  cat masscan_output | auxiliary masscan - --no-validate --output targets

  # Using script directly (no installation)
  python3 network/masscan_to_targets.py masscan_output --output targets
  cat masscan_output | python3 network/masscan_to_targets.py - --no-validate --output targets
  ```

---

### `web/`
Web recon helpers.

- **gobuster_to_eyewitness** — Convert Gobuster output paths into full URLs (for EyeWitness or similar). Supports stdin and optional dedupe.
  Examples:
  ```bash
  # Using installed command
  aux-gobuster gobuster_output.txt http://example.com urls_for_eyewitness.txt
  cat gobuster_output.txt | auxiliary gobuster - http://example.com urls.txt --dedupe

  # Using script directly (no installation)
  python3 web/gobuster_to_eyewitness.py gobuster_output.txt http://example.com urls_for_eyewitness.txt
  cat gobuster_output.txt | python3 web/gobuster_to_eyewitness.py - http://example.com urls.txt --dedupe
  ```

- **webtech_fingerprint** — Wappalyzer-style technology/version fingerprinting tool for web app pentests. Loads each target in a headless browser via Playwright, identifies third-party JS/CSS libraries and versions (plus `Server`/`X-Powered-By` headers and `<meta name="generator">`), and cross-checks each against endoflife.date and, where available, the GitHub releases/security-advisories API. By default only `webtech_fingerprint_results.zip` is left in the output directory (per-host `.json`/`.txt` and a full transcript are bundled inside it, then the loose copies are deleted) — pass `--no-zip` to keep the loose files instead, or extract the zip to get them after the fact. Requires one-time setup beyond `pip install`:
  ```bash
  pip install -r requirements.txt
  playwright install chromium
  ```
  If this was installed via `pipx`, the `playwright` command above won't be on `PATH` (pipx only exposes this package's own commands, not a dependency's). Use this instead — it works under `pip`, `pip -e`, and `pipx` installs alike:
  ```bash
  aux-webtech --install-browser
  ```
  Examples:
  ```bash
  # Using installed command
  aux-webtech https://target.example.com
  aux-webtech -f targets.txt -o results/
  auxiliary webtech https://target.example.com --no-eol
  aux-webtech https://target.example.com --proxy http://127.0.0.1:8080

  # Using script directly (no installation)
  python3 web/webtech_fingerprint.py https://target.example.com
  python3 web/webtech_fingerprint.py -f targets.txt -o results/
  ```
  Offline/network-isolated workflow: component detection needs no external network (only the endoflife.date/GitHub enrichment step does, and it already fails soft rather than crashing). Inside a locked-down network, run with `--no-eol --no-repo-check` to skip the doomed-to-fail lookups and their timeouts entirely, producing a zip with accurate version data but no EOL/support status. Once you have connectivity again (e.g. after scp'ing the zip to another machine), run `--enrich` against it to fill in exactly the lookups that were missing or previously unreachable, without re-crawling the target:
  ```bash
  # Inside the isolated network
  aux-webtech https://target.example.com --no-eol --no-repo-check -o results/

  # On a machine with internet access
  aux-webtech --enrich results/webtech_fingerprint_results.zip -o results/
  ```
  Note: a WAF/CDN bot-challenge (e.g. Cloudflare Turnstile) can prevent the real page from ever being reached, producing a misleadingly clean "0 libraries detected" for the challenge page instead. This tool applies best-effort anti-detection browser hardening and prints an explicit `WARNING` (plus `"challenge_page"` in the saved JSON) when a known challenge signature is detected — treat those results as unverified.

  To inspect this tool's own traffic (e.g. in Burp), use `--proxy http://127.0.0.1:8080` rather than `HTTP_PROXY`/`HTTPS_PROXY` environment variables — Playwright's browser doesn't automatically honor those the way `requests`-based tools do, so setting only the env vars will silently NOT route the browser's navigation through your proxy.

---

### `firewall/`
Manage iptables OUTPUT DROP rules safely.

- **apply_iptables_blocks** — Add DROP rules for IP addresses, CIDR ranges, and IP ranges using a unified targets file. Automatically detects target types (IP ranges with `-` use iprange module, others use `-d` flag). Dry-run by default, with `--apply` to actually run. Creates timestamped backups and can save persistent rules via `iptables-save`. Includes `--restore` flag to restore from backups. Automatically prompts to create `/etc/iptables` directory if it doesn't exist. **Be careful** — applying rules requires root/sudo.
  Examples:
  ```bash
  # Using installed command (dry-run - preview changes)
  aux-iptables --targets-file all-blocks.txt

  # Apply from file
  sudo auxiliary iptables --targets-file all-blocks.txt --apply

  # Apply from CLI arguments
  sudo aux-iptables --ip 172.0.0.0-172.255.255.255 --ip 10.21.10.31 --apply

  # Mixed: file + CLI
  sudo aux-iptables --targets-file blocks.txt --ip 192.168.1.0/24 --apply

  # Restore from backup (interactive)
  sudo aux-iptables --restore

  # Using script directly (no installation)
  python3 firewall/apply_iptables_blocks.py --targets-file all-blocks.txt
  sudo python3 firewall/apply_iptables_blocks.py --targets-file blocks.txt --apply
  sudo python3 firewall/apply_iptables_blocks.py --restore
  ```

  Target file format (automatically detects each type):
  ```
  # IP ranges (uses iprange module)
  172.0.0.0-172.255.255.255
  192.0.0.0-192.255.255.255

  # Single IPs
  10.21.10.31
  10.20.74.19

  # CIDR ranges
  192.168.1.0/24
  10.0.0.0/8
  ```

---

### `files/`
Small file utilities for splitting and credential processing.

- **split_lines** — Split a file into N-line chunks (GNU `split`-style numeric suffixes).
  Examples:
  ```bash
  # Using installed command
  aux-split-lines --input targets --outdir target_batches --prefix targets_batch_ --lines 1000
  auxiliary split-lines --input targets --lines 500 --suffix .txt

  # Using script directly (no installation)
  python3 files/split_lines.py --input targets --outdir target_batches --prefix targets_batch_ --lines 1000
  ```

- **split_creds** — Split `user:pass[:...]` dumps into separate user and password lists; supports dedupe, sorting, stripping quotes/whitespace, and ignoring lines without delimiter.
  Examples:
  ```bash
  # Using installed command
  aux-split-creds
  auxiliary split-creds --glob "unique-creds-*.txt" --users users.txt --passwords pws.txt --dedupe-users --strip --sort users

  # Using script directly (no installation)
  python3 files/split_creds.py
  python3 files/split_creds.py --glob "unique-creds-*.txt" --dedupe-users --strip --sort users
  ```

---

### `nessus/`
Nessus configuration and management utilities.

- **add_out_of_scope** — Add out-of-scope IP addresses and CIDR ranges to the nessusd.rules file. Automatically inserts "reject" entries before the "default accept" line, creates timestamped backups, and prevents duplicates. **Be careful** — modifying nessusd.rules requires root/sudo.
  Examples:
  ```bash
  # Using installed command (dry-run by default)
  aux-nessus-rules --input out-of-scope.txt
  auxiliary nessus-rules --ip 10.10.11.34 --ip 192.168.1.0/24 --apply
  sudo aux-nessus-rules --input out-of-scope.txt --apply

  # Using script directly (no installation)
  python3 nessus/add_out_of_scope.py --input out-of-scope.txt
  sudo python3 nessus/add_out_of_scope.py --input out-of-scope.txt --apply
  ```

---

### `pivot/`
Reverse SSH tunnel with a SOCKS pivot mode, for **authorized engagements only**.

- **reverse_ssh_tunnel** — Set up, establish, and test a reverse SSH tunnel across three
  systems and run tools through it via proxychains.

  **The three systems**
  - **Operator host** — you; already has SSH to the redirector. Orchestrates.
  - **Remote redirector** — internet-facing; the SSH server + SOCKS proxy live here.
  - **Internal sender** — inside the target network; outbound-only; the SSH client.

  An internal machine dials **out** to the redirector, opening a SOCKS proxy on the
  redirector; tools pointed at that proxy tunnel **back** through the internal machine
  into the target network. The keypair is generated on the internal sender, so the
  **private key never crosses the network** — only the public key is transferred.

  Visualize it: `auxiliary reverse-ssh diagram` (prints Mermaid; add `--sequence` for the
  setup steps). Paste the output into GitHub or https://mermaid.live.

  **End-to-end flow** (run each command on the noted system):
  ```bash
  # 1. [internal sender] make a keypair (private key stays here)
  auxiliary reverse-ssh keygen --name reverse_tunnel

  # 2. [remote redirector] listen for the public key (HMAC-authenticated)
  auxiliary reverse-ssh recv-key --port 4444 --secret CHANGEME

  # 3. [internal sender] send the public key, then COMPARE the printed fingerprints
  auxiliary reverse-ssh send-key --host REDIRECTOR --port 4444 --secret CHANGEME

  # 4. [remote redirector] install it into authorized_keys (re-verify fingerprint)
  auxiliary reverse-ssh install-key --from /tmp/reverse_tunnel.pub

  # 5. [internal sender] open the reverse SSH + SOCKS pivot (127.0.0.1:9050 on the remote)
  #    tunnel/verify auto-use ~/.ssh/<name> from keygen (any working directory); pass -i to
  #    override, or --ssh-host ALIAS to use ssh-agent/~/.ssh/config. If no key is found they
  #    error with a keygen hint rather than failing later with "Permission denied".
  auxiliary reverse-ssh tunnel --socks --user USER --host REDIRECTOR

  # 6. verify from both ends (verify uses a throwaway remote port, so it is safe to
  #    run whether or not the tunnel from step 5 is already up)
  auxiliary reverse-ssh verify --user USER --host REDIRECTOR   # [internal sender]
  auxiliary reverse-ssh check                                  # [remote redirector]

  # 7. point proxychains at the pivot, then run your tools through it
  #    In /etc/proxychains.conf (or proxychains4.conf) under [ProxyList]:
  #        socks5 127.0.0.1 9050          # lowercase 'socks5', NOT socks4
  proxychains nmap -sT -Pn TARGET        # on the remote, or after `ssh -L 9050:...`
  ```

  **Windows internal sender:** the subcommands and flags are identical; only the invocation
  prefix differs — after a pip/pipx install use `aux-reverse-ssh ...` (or
  `auxiliary reverse-ssh ...`), or when running from source use
  `python pivot\reverse_ssh_tunnel.py ...` (note the backslash path). It relies on the Win32
  OpenSSH client — if `ssh` is missing, enable the *OpenSSH Client* optional feature.
  `send-key`/`recv-key` are pure-Python, so **no `nc` is required** on either side.

  **Fallbacks & options:** every remote subcommand supports `--print` to emit the equivalent
  shell one-liner (paste it over your existing SSH if the repo isn't installed on the
  redirector). Transfer protection is layered: fingerprint comparison is always on,
  `--secret` adds HMAC authentication, and `--tls` encrypts the transfer. Use
  `tunnel --print-only` to preview the ssh command and `tunnel --config-entry` to emit a
  `~/.ssh/config` block. Run `preflight` on the redirector for sshd guidance (notably: keep
  the SOCKS proxy on loopback and do **not** set `GatewayPorts yes`).

  ```bash
  # Using script directly (no installation)
  python3 pivot/reverse_ssh_tunnel.py --help
  ```

---

### Mundane (Nessus Review Tool) — MIGRATED

The **Mundane** Nessus plugin-host review and verification tool has been moved to its own dedicated repository:

**→ https://github.com/ridgebackinfosec/mundane**

For Nessus vulnerability review workflows, please use the standalone Mundane repository.

---

## Notes & recommendations

- All tools use the Python standard library only (stdlib), with one exception: `webtech_fingerprint` (web/) requires `requests`, `beautifulsoup4`, and `playwright` (`pip install -r requirements.txt` then `aux-webtech --install-browser`, which downloads Playwright's Chromium browser correctly regardless of whether you installed via `pip` or `pipx`).
- Firewall tools will require root (`sudo`) when using `--apply` or saving persistent iptables rules.
- Examples are intentionally explicit so you can copy/paste; tweak paths/options per your workflow.
