# `dns/` — reverse lookups & Domain Controller discovery

Two stdlib-only tools for DNS reconnaissance.

Each tool is runnable three ways: `aux-<name>`, `auxiliary <name>`, or the
script directly (`python3 dns/<file>.py`). Examples below show the installed
command; append `--help` to any of them for the full option list.

---

## reverse_dns — `aux-reverse-dns` / `auxiliary reverse-dns`

Perform reverse DNS (PTR) lookups on a list of IPs. Two output modes:

- **`hostnames`** (default) — hostnames only, deduped and sorted. Alias
  hostnames are included unless `--no-aliases` is given.
- **`ip-map`** — `IP (hostname)` lines, preserving input order.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | `ip_list.txt` | Input file of IP addresses |
| `-o, --output` | `dns_results.txt` | Output file |
| `--mode {hostnames,ip-map}` | `hostnames` | Output mode |
| `--no-aliases` | off | Ignore alias hostnames (hostnames mode only) |

### Examples

```bash
aux-reverse-dns --mode hostnames --input ip_list.txt --output dns_results.txt
auxiliary reverse-dns --mode ip-map --input in-scope --output resolved_ips.txt

# script directly (no installation)
python3 dns/reverse_dns.py --mode hostnames --input ip_list.txt --output dns_results.txt
```

---

## find_domain_controllers — `aux-find-dc` / `auxiliary find-dc`

Discover Windows Domain Controllers by:

1. Determining a domain — from `--domain`, or auto-detected (the
   `/etc/resolv.conf` `search` line on Linux; `USERDNSDOMAIN` or the host FQDN
   on Windows).
2. Querying SRV records `_ldap._tcp.dc._msdcs.<domain>` (uses `nslookup` or
   `dig` if available).
3. Extracting DC hostnames and resolving them to IPs via the stdlib `socket`.
4. *(Optional)* Falling back to masscan against ports `389,636` over an
   in-scope list when SRV discovery finds nothing.
5. *(Optional)* Reverse DNS (PTR) for the discovered IPs.

Outputs (prefix `dc` by default): `dc_hosts.txt` (hostnames), `dc_ips.txt`
(unique IPs), `dc_map.txt` (`IP hostname` pairs).

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | auto-detect | Domain to query (e.g. `example.corp`) |
| `--output-prefix` | `dc` | Prefix for the output files |
| `--no-reverse` | off | Skip PTR lookups for discovered IPs |
| `--fallback-masscan` | off | Run masscan against `--in-scope` if SRV finds nothing |
| `--in-scope` | `~/in-scope` | In-scope file for the masscan fallback |
| `--rate` | `10000` | Masscan rate |
| `--ports` | `389,636` | Ports to scan with masscan |

### Examples

```bash
aux-find-dc --domain example.corp
sudo auxiliary find-dc --domain example.corp --fallback-masscan --in-scope ~/in-scope

# script directly (no installation)
python3 dns/find_domain_controllers.py
sudo python3 dns/find_domain_controllers.py --domain example.corp --fallback-masscan
```

> The masscan fallback needs `masscan` on `PATH` and typically root/sudo.
