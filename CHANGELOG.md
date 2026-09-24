# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.9] - 2026-09-24

### Fixed
- `dns/find_domain_controllers.py` now discovers Domain Controllers on Windows.
  Windows `nslookup` exits non-zero even on a successful query (e.g. the cosmetic
  "can't find server name for address" warning when the DNS server has no PTR),
  so its valid SRV output was being discarded; the output is now parsed regardless
  of exit code, gating on empty output instead.
- Fixed a `HOST_RE` capturing-group bug that caused `parse_hosts_from_nslookup()`
  to extract nothing — the tool had been silently relying on the `dig` fallback,
  which is absent on Windows. The regex group is now non-capturing.
- The bare domain apex is no longer mistaken for a DC hostname when it appears in
  the echoed SRV query name.

### Added
- Cross-platform domain auto-detection in `dns/find_domain_controllers.py`:
  `/etc/resolv.conf` on Linux, `USERDNSDOMAIN` or the host FQDN on Windows, so
  `--domain` is now optional on Windows.

## [1.5.8] - 2026-09-17

### Changed
- Added a project banner to the README.

## [1.5.7] - 2026-09-02

### Added
- Next.js detection in `web/webtech_fingerprint.py`.

## [1.5.6] - 2026-07-28

### Changed
- Surface the `-r` / `cf_clearance` workaround in the bot-challenge warning.

## [1.5.5] - 2026-07-28

### Fixed
- `-r` now replays the captured HTTP method/body and scopes headers correctly,
  unblocking sub-resource loading.

## [1.5.4] - 2026-07-27

### Added
- `--proxy` support for `web/webtech_fingerprint.py`.

## [1.5.3] - 2026-07-27

### Changed
- Hardened `webtech-fingerprint` against Cloudflare bot-challenge pages
  (challenge detection plus extended wait).

## [1.5.2] - 2026-07-27

### Fixed
- Playwright browser install under pipx; improved error hints.

## [1.5.1] - 2026-07-16

### Added
- Offline-enrichment workflow for `webtech-fingerprint` (`--enrich`).

## [1.5.0] - 2026-07-15

### Added
- Integrated `web/webtech_fingerprint.py` into the unified CLI.

## [1.4.4] - 2025-11-11

### Changed
- Simplified iptables input with auto-detection.

## [1.4.3] - 2025-11-11

### Added
- `--restore` flag and automatic backup-directory handling for the iptables tool.

## [1.4.2] - 2025-11-11

### Changed
- Renamed the pipx package.

## [1.4.1] - 2025-11-11

### Fixed
- iptables bug in `firewall/apply_iptables_blocks.py`.

## [1.4.0] - 2025-11-05

### Added
- `nessus` module to automate adding out-of-scope systems to `nessusd.rules`.

## [1.3.1] - 2025-11-05

### Changed
- pipx packaging.

## [1.2.0] - 2025-10-31

### Changed
- Migrated away from the Mundane/Nessus wizard; documentation cleanup.

## [1.1.1] - 2025-10-29

### Changed
- Tool-registry extraction.

## [1.1.0] - 2025-10-28

### Changed
- Added type hints, docstrings, and PEP 8 compliance to the nessus modules.

## [1.0.0] - 2025-09-26

### Added
- Initial tagged release: one-step `.nessus` seeding wizard via NessusPluginHosts
  clone and export.
