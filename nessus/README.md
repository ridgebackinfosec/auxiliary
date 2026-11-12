# `nessus/` — Nessus configuration utilities

One stdlib-only tool. Runs as `aux-nessus-rules`, `auxiliary nessus-rules`, or
the script directly. Append `--help` for the full option list.

> **Be careful** — modifying `nessusd.rules` requires root/sudo. The tool is
> **dry-run by default**; nothing changes until you pass `--apply`.

---

## add_out_of_scope — `aux-nessus-rules` / `auxiliary nessus-rules`

Add out-of-scope IP addresses and CIDR ranges to the `nessusd.rules` file to
exclude them from scanning. Reject entries are inserted just before the
`default accept` line; timestamped backups are created and duplicates are
prevented.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | — | File of IPs/CIDR ranges to reject, one per line |
| `--ip` | — | A single IP / CIDR range to reject (repeatable) |
| `--rules-file` | `/opt/nessus/etc/nessus/nessusd.rules` | Path to the rules file |
| `--apply` | off (dry-run) | Apply changes |

### Examples

```bash
# Dry-run by default
aux-nessus-rules --input out-of-scope.txt
auxiliary nessus-rules --ip 10.10.11.34 --ip 192.168.1.0/24 --apply
sudo aux-nessus-rules --input out-of-scope.txt --apply

# script directly (no installation)
python3 nessus/add_out_of_scope.py --input out-of-scope.txt
sudo python3 nessus/add_out_of_scope.py --input out-of-scope.txt --apply
```
