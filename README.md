![auxiliary banner](auxiliary-banner.png)

# Ridgeback InfoSec — auxiliary scripts/tools

Collection of small Python 3 utilities used for reconnaissance, list
processing, and local tooling. **Most tools are stdlib-only** (no pip packages
required); the exception is `webtech_fingerprint` (web/), which needs
`requests`, `beautifulsoup4`, and `playwright` — see [`web/`](web/README.md).

Tested with Python 3.8+.

---

## Installation

### Using pipx (recommended)
```bash
pipx install git+https://github.com/ridgebackinfosec/auxiliary.git
```

### Using pip
```bash
pip install git+https://github.com/ridgebackinfosec/auxiliary.git
```

### Development install (editable)
```bash
git clone https://github.com/ridgebackinfosec/auxiliary.git
cd auxiliary
pip install -e .
```

### Manual usage (without installation)
```bash
git clone https://github.com/ridgebackinfosec/auxiliary.git
cd auxiliary
python3 dns/find_domain_controllers.py --help
```

---

## Usage

After installation you can use the tools two ways.

**Unified CLI** — the `auxiliary` command with subcommands:
```bash
auxiliary <tool> [args...]
auxiliary --list              # show all available tools
auxiliary --help              # show help information
auxiliary <tool> --help       # help for a specific tool
```

**Individual commands** — each tool is also a standalone `aux-` command:
```bash
aux-find-dc --domain example.corp
aux-reverse-dns --input ips.txt --output hostnames.txt
aux-extract-ips --input ~/chaos --output ~/order
aux-masscan masscan_output --output targets
aux-gobuster gobuster.txt http://example.com urls.txt
aux-webtech https://target.example.com
aux-split-lines --input targets --lines 1000
aux-split-creds --glob 'creds-*.txt' --dedupe-users
aux-iptables --targets-file all-blocks.txt --apply
aux-nessus-rules --input out-of-scope.txt --apply
aux-reverse-ssh diagram
```

Each tool is also runnable directly as `python3 <folder>/<script>.py`
(see the Manual usage section).

---

## Tool catalog

Each folder has a README with full options, examples, and caveats. One
representative example is shown here per tool.

### [`dns/`](dns/README.md) — reverse lookups & DC discovery
- **reverse_dns** — reverse DNS lookups producing hostname lists or `IP (hostname)` maps.
  `aux-reverse-dns --mode hostnames --input ip_list.txt --output dns_results.txt`
- **find_domain_controllers** — discover Windows DCs via SRV lookup, with optional masscan fallback and PTR.
  `aux-find-dc --domain example.corp`

### [`network/`](network/README.md) — extract & normalize IP lists
- **chaos_ip_extract** — extract, dedupe, and numeric-sort IPv4s from a file.
  `aux-extract-ips --input /path/to/chaos.txt --output /tmp/order.txt`
- **masscan_to_targets** — extract validated IPv4 tokens from masscan output into a deduped, sorted list.
  `aux-masscan masscan_output --output targets`

### [`web/`](web/README.md) — web recon helpers
- **gobuster_to_eyewitness** — convert Gobuster paths into full URLs (for EyeWitness or similar).
  `aux-gobuster gobuster_output.txt http://example.com urls.txt --dedupe`
- **webtech_fingerprint** — Wappalyzer-style tech/version fingerprinter (headless browser + EOL/advisory cross-check). *Requires extra setup — see [`web/`](web/README.md).*
  `aux-webtech https://target.example.com`

### [`files/`](files/README.md) — splitting & credential processing
- **split_lines** — split a file into N-line chunks with numeric suffixes.
  `aux-split-lines --input targets --lines 1000`
- **split_creds** — split `user:pass` dumps into separate user and password lists.
  `aux-split-creds --glob 'creds-*.txt' --dedupe-users`

### [`firewall/`](firewall/README.md) — iptables OUTPUT DROP rules
- **apply_iptables_blocks** — add DROP rules for IPs, CIDRs, and IP ranges. Dry-run by default; `--apply` needs root. ⚠️
  `sudo aux-iptables --targets-file all-blocks.txt --apply`

### [`nessus/`](nessus/README.md) — Nessus configuration
- **add_out_of_scope** — add out-of-scope IPs/CIDRs as reject rules in `nessusd.rules`. Dry-run by default; `--apply` needs root. ⚠️
  `sudo aux-nessus-rules --input out-of-scope.txt --apply`

### [`pivot/`](pivot/README.md) — reverse SSH SOCKS pivot
- **reverse_ssh_tunnel** — set up, establish, and test a reverse SSH tunnel with a SOCKS pivot across three systems. **Authorized engagements only.**
  `aux-reverse-ssh diagram`

---

## Notes & recommendations

- All tools use the Python standard library only, with one exception:
  `webtech_fingerprint` (web/) requires `requests`, `beautifulsoup4`, and
  `playwright` — see [`web/`](web/README.md) for setup
  (`pip install -r requirements.txt` then `aux-webtech --install-browser`).
- The **firewall** and **nessus** tools are dry-run by default and need root
  (`sudo`) when using `--apply` or saving persistent rules.
- The **pivot** tool is for authorized penetration-testing engagements only.
- Examples are intentionally explicit so you can copy/paste; tweak
  paths/options per your workflow.
