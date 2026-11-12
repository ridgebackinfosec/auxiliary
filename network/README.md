# `network/` — extract & normalize IP/target lists

Two stdlib-only helpers for turning scan output into clean target lists.

Each tool runs as `aux-<name>`, `auxiliary <name>`, or the script directly.
Append `--help` for the full option list.

---

## chaos_ip_extract — `aux-extract-ips` / `auxiliary extract-ips`

Extract valid IPv4 addresses from an input file, deduplicate, numeric-sort, and
write them out. Only dotted-decimal IPv4 (`0.0.0.0`–`255.255.255.255`) is
matched; the count and final list are printed to stdout.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | `~/chaos` | Input file to scan for IPs |
| `-o, --output` | `~/order` | Output file for sorted, unique IPs |

### Examples

```bash
aux-extract-ips
auxiliary extract-ips --input /path/to/chaos.txt --output /tmp/order.txt

# script directly (no installation)
python3 network/chaos_ip_extract.py --input /path/to/chaos.txt --output /tmp/order.txt
```

---

## masscan_to_targets — `aux-masscan` / `auxiliary masscan`

Extract IPv4 tokens from masscan/scan output, validate octets, dedupe, and
numeric-sort. Roughly equivalent to
`grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' masscan_output | sort -u > targets`,
but with octet validation on by default.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `input` (positional) | `masscan_output` | Input file, or `-` for stdin |
| `-o, --output` | `./targets` | Output file path |
| `--no-validate` | off | Skip octet validation (permissive, like raw grep) |
| `--keep-order` | off | Keep first-seen order instead of sorting (still dedupes) |

### Examples

```bash
aux-masscan masscan_output --output targets
cat masscan_output | auxiliary masscan - --no-validate --output targets

# script directly (no installation)
python3 network/masscan_to_targets.py masscan_output --output targets
cat masscan_output | python3 network/masscan_to_targets.py - --no-validate --output targets
```
