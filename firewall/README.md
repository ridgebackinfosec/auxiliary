# `firewall/` — manage iptables OUTPUT DROP rules safely

One stdlib-only tool. Runs as `aux-iptables`, `auxiliary iptables`, or the
script directly. Append `--help` for the full option list.

> **Be careful** — applying rules or saving persistent rules requires
> root/sudo. The tool is **dry-run by default**; nothing changes until you
> pass `--apply`.

---

## apply_iptables_blocks — `aux-iptables` / `auxiliary iptables`

Add OUTPUT DROP rules for IP addresses, CIDR ranges, and IP ranges from a
unified targets file and/or repeated `--ip` flags. Target types are detected
automatically: IP ranges (containing `-`) use the `iprange` module; single IPs
and CIDRs use iptables' `-d` flag.

It creates timestamped backups before modifying rules, prevents nothing from
being applied in dry-run, can persist rules via `iptables-save`, and offers
`--restore` to roll back from a backup. If `/etc/iptables` is missing it
prompts to create it.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --targets-file` | — | File of targets (IPs, CIDRs, and/or IP ranges), one per line |
| `--ip` | — | A single IP / CIDR / IP range to block (repeatable) |
| `--apply` | off (dry-run) | Actually apply the rules |
| `--restore` | off | Restore iptables rules from a backup (requires root) |
| `--yes` | off | Assume "yes" to confirmation (dangerous) |
| `--no-backup` | off | Skip the timestamped backup before modifying |
| `--no-save` | off | Don't write persistent rules after applying |
| `--save-path` | `/etc/iptables/rules.v4` | Where `iptables-save` writes |

### Examples

```bash
# Dry-run (preview changes)
aux-iptables --targets-file all-blocks.txt

# Apply from a file
sudo auxiliary iptables --targets-file all-blocks.txt --apply

# Apply from CLI arguments
sudo aux-iptables --ip 172.0.0.0-172.255.255.255 --ip 10.21.10.31 --apply

# Mixed: file + CLI
sudo aux-iptables --targets-file blocks.txt --ip 192.168.1.0/24 --apply

# Restore from a backup (interactive)
sudo aux-iptables --restore

# script directly (no installation)
python3 firewall/apply_iptables_blocks.py --targets-file all-blocks.txt
sudo python3 firewall/apply_iptables_blocks.py --targets-file blocks.txt --apply
```

### Target file format

Each line's type is detected automatically:

```
# IP ranges (use the iprange module)
172.0.0.0-172.255.255.255
192.0.0.0-192.255.255.255

# Single IPs
10.21.10.31
10.20.74.19

# CIDR ranges
192.168.1.0/24
10.0.0.0/8
```
