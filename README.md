# Ridgeback InfoSec — auxiliary scripts/tools

Collection of small, zero-dependency Python3 utilities used for reconnaissance, list processing, and local tooling. Each folder contains single-file tools intended to be runnable directly with `python3 <path/to/script>.py`. These are minimal: no pip packages required (stdlib only).

Tested with Python 3.8+. Use `python3` (or `python`) to run.

---

## Folder summary & quick examples

### `dns/`  
Tools for reverse lookups and Domain Controller discovery.

- `dns/reverse_dns.py` — Perform reverse DNS lookups and/or produce hostnames lists (two modes: `hostnames` or `ip-map`).  
  Example:
  ```bash
  # produce deduped, sorted hostnames from ip_list.txt
  python3 dns/reverse_dns.py --mode hostnames --input ip_list.txt --output dns_results.txt

  # produce "IP (hostname)" mappings preserving input order
  python3 dns/reverse_dns.py --mode ip-map --input in-scope --output resolved_ips.txt
  ```

- `dns/find_domain_controllers.py` — Discover Windows DCs via SRV lookup (`_ldap._tcp.dc._msdcs.<domain>`), resolve hostnames → IPs, optional masscan fallback and PTR lookups.  
  Example:
  ```bash
  # auto-detect domain from /etc/resolv.conf 'search', do SRV lookup then resolve
  python3 dns/find_domain_controllers.py

  # explicitly set domain and run masscan fallback if SRV returns nothing
  sudo python3 dns/find_domain_controllers.py --domain example.corp --fallback-masscan --in-scope ~/in-scope --rate 10000
  ```

---

### `network/`  
Helpers to extract and normalize IP/target lists from scan output.

- `network/chaos_ip_extract.py` — Extract valid IPv4s from `~/chaos`, dedupe and numeric-sort into `~/order` (defaults).  
  Example:
  ```bash
  # defaults: input ~/chaos -> output ~/order
  python3 network/chaos_ip_extract.py

  # custom files
  python3 network/chaos_ip_extract.py --input /path/to/chaos.txt --output /tmp/order.txt
  ```

- `network/masscan_to_targets.py` — Extract IPv4 tokens from masscan/scan output, validate octets, dedupe and numeric sort (writes `targets` by default).  
  Example:
  ```bash
  # read masscan_output file and write ./targets
  python3 network/masscan_to_targets.py masscan_output --output targets

  # from stdin, permissive (no octet validation)
  cat masscan_output | python3 network/masscan_to_targets.py - --no-validate --output targets
  ```

---

### `web/`  
Web recon helpers.

- `web/gobuster_to_eyewitness.py` — Convert Gobuster output paths into full URLs (for EyeWitness or similar). Supports stdin and optional dedupe.  
  Example:
  ```bash
  # convert a gobuster output file to full URLs for http://example.com
  python3 web/gobuster_to_eyewitness.py gobuster_output.txt http://example.com urls_for_eyewitness.txt

  # read from stdin and dedupe
  cat gobuster_output.txt | python3 web/gobuster_to_eyewitness.py - http://example.com urls.txt --dedupe
  ```

---

### `firewall/`  
Manage iptables OUTPUT DROP rules safely.

- `firewall/apply_iptables_blocks.py` — Add DROP rules for IP ranges and/or single IPs; dry-run by default, with `--apply` to actually run. Creates a timestamped backup before changes and can save persistent rules via `iptables-save`. **Be careful** — applying rules requires root/sudo.  
  Example:
  ```bash
  # show planned rules (dry-run)
  python3 firewall/apply_iptables_blocks.py --ranges-file cleaned_ip_ranges.txt --ip 1.2.3.4

  # apply rules and save (interactive confirmation)
  sudo python3 firewall/apply_iptables_blocks.py --ranges-file cleaned_ip_ranges.txt --ips-file block_ips.txt --apply

  # apply non-interactively (dangerous)
  sudo python3 firewall/apply_iptables_blocks.py --ranges-file cleaned_ip_ranges.txt --apply --yes
  ```

---

### `files/`  
Small file utilities for splitting and credential processing.

- `files/split_lines.py` — Split a file into N-line chunks (GNU `split`-style numeric suffixes).  
  Example:
  ```bash
  # split `targets` into batches of 1000 lines into target_batches/targets_batch_01.txt, etc.
  python3 files/split_lines.py --input targets --outdir target_batches --prefix targets_batch_ --lines 1000
  ```

- `files/split_creds.py` — Split `user:pass[:...]` dumps into separate user and password lists; supports dedupe, sorting, stripping quotes/whitespace, and ignoring lines without delimiter.  
  Example:
  ```bash
  # default behavior: preserve order, allow duplicates
  python3 files/split_creds.py

  # dedupe usernames, strip surrounding quotes and whitespace, and sort users
  python3 files/split_creds.py --glob "unique-creds-*.txt" --users users.txt --passwords pws.txt --dedupe-users --strip --sort users
  ```

---

### `nessus/`  
Nessus / vulnerability review tooling.

- `nessus/mundane.py` — Nessus plugin-host review and verification helper.

---

## Notes & recommendations
- All tools are standard-Python only (stdlib). Run with `python3`/`python` (3.8+ recommended).
- Firewall tools will require root (`sudo`) when using `--apply` or saving persistent iptables rules.
- Examples are intentionally explicit so you can copy/paste; tweak paths/options per your workflow.