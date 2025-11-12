# Ridgeback InfoSec — auxiliary scripts/tools

Collection of small Python3 utilities used for reconnaissance, list processing, and local tooling. **All tools are stdlib-only** (no pip packages required).

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
aux-split-lines --input targets --lines 1000
aux-split-creds --glob 'creds-*.txt' --dedupe-users
aux-iptables --ranges-file ranges.txt --apply
aux-nessus-rules --input out-of-scope.txt --apply
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

---

### `firewall/`
Manage iptables OUTPUT DROP rules safely.

- **apply_iptables_blocks** — Add DROP rules for IP ranges and/or single IPs; dry-run by default, with `--apply` to actually run. Creates a timestamped backup before changes and can save persistent rules via `iptables-save`. Includes `--restore` flag to restore from backups. Automatically prompts to create `/etc/iptables` directory if it doesn't exist. **Be careful** — applying rules requires root/sudo.
  Examples:
  ```bash
  # Using installed command (dry-run)
  aux-iptables --ranges-file cleaned_ip_ranges.txt --ip 1.2.3.4

  # Apply rules
  sudo auxiliary iptables --ranges-file cleaned_ip_ranges.txt --ips-file block_ips.txt --apply
  sudo aux-iptables --ranges-file cleaned_ip_ranges.txt --apply --yes

  # Restore from backup (interactive)
  sudo aux-iptables --restore

  # Using script directly (no installation)
  python3 firewall/apply_iptables_blocks.py --ranges-file cleaned_ip_ranges.txt --ip 1.2.3.4
  sudo python3 firewall/apply_iptables_blocks.py --ranges-file cleaned_ip_ranges.txt --apply
  sudo python3 firewall/apply_iptables_blocks.py --restore
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

### Mundane (Nessus Review Tool) — MIGRATED

The **Mundane** Nessus plugin-host review and verification tool has been moved to its own dedicated repository:

**→ https://github.com/ridgebackinfosec/mundane**

For Nessus vulnerability review workflows, please use the standalone Mundane repository.

---

## Notes & recommendations

- All tools use Python standard library only (stdlib). No external dependencies required.
- Firewall tools will require root (`sudo`) when using `--apply` or saving persistent iptables rules.
- Examples are intentionally explicit so you can copy/paste; tweak paths/options per your workflow.
