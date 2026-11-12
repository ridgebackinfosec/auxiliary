# `web/` — web recon helpers

Two tools. `gobuster_to_eyewitness` is stdlib-only; `webtech_fingerprint`
requires `requests`, `beautifulsoup4`, and `playwright` (see **Setup** below).
Each runs as `aux-<name>`, `auxiliary <name>`, or the script directly; append
`--help` for the full option list.

---

## gobuster_to_eyewitness — `aux-gobuster` / `auxiliary gobuster`

Convert Gobuster directory/listing output into a newline-separated list of full
URLs suitable for EyeWitness or similar. It extracts the first meaningful token
per line (e.g. `/admin (Status: 200)` → `http://example.com/admin`); tokens
that already look like full URLs are kept and normalized. Duplicates are
preserved by default — pass `--dedupe` to remove them (preserving order).

### Arguments

| Argument | Description |
|----------|-------------|
| `gobuster_file` (positional) | Gobuster output file, or `-` for stdin |
| `base_url` (positional) | Base URL, e.g. `http://example.com` |
| `output_file` (positional) | Where to write the resulting URLs |
| `--dedupe` | Remove duplicate URLs (keep first occurrence) |

### Examples

```bash
aux-gobuster gobuster_output.txt http://example.com urls_for_eyewitness.txt
cat gobuster_output.txt | auxiliary gobuster - http://example.com urls.txt --dedupe

# script directly (no installation)
python3 web/gobuster_to_eyewitness.py gobuster_output.txt http://example.com urls.txt
```

---

## webtech_fingerprint — `aux-webtech` / `auxiliary webtech`

Wappalyzer-style technology/version fingerprinting for web-app pentests. It
loads each target in a headless browser via Playwright, identifies third-party
JS/CSS libraries and versions (plus `Server`/`X-Powered-By` headers and
`<meta name="generator">`), and cross-checks each against endoflife.date and,
where available, the GitHub releases/security-advisories API.

By default only `webtech_fingerprint_results.zip` is left in the output
directory (per-host `.json`/`.txt` and a full transcript are bundled inside it,
then the loose copies are deleted). Pass `--no-zip` to keep the loose files
instead, or extract the zip afterward.

### Setup (one-time, beyond `pip install`)

```bash
pip install -r requirements.txt
playwright install chromium
```

If installed via **pipx**, the `playwright` command above won't be on `PATH`
(pipx only exposes this package's own commands, not a dependency's). Use this
instead — it works under `pip`, `pip -e`, and `pipx` alike:

```bash
aux-webtech --install-browser
```

### Options

| Flag | Description |
|------|-------------|
| `url` (positional) | A single target URL |
| `-f, --targets-file` | Text file with one target URL per line (blank lines and `#` comments skipped) |
| `-r, --request-file` | Crawl as a logged-in user from a captured request — a Burp "Copy as Python-Requests" script or "Copy as curl-command" export (real cookies + headers, so post-login components are detected). Replaces `url`; not combinable with `-f` |
| `--enrich ZIP` | Re-attempt only the EOL/GitHub lookups that didn't complete (or were skipped) on an earlier run's zip, without re-crawling. Replaces `url`; not combinable with `-f`/`-r` |
| `-o, --outdir` | Directory for the per-host `.json`/`.txt` files (default: current dir) |
| `--json` | Explicit JSON output path (single-URL mode only) |
| `--no-txt` | Don't write the per-host `.txt` report (JSON still written) |
| `--no-eol` | Skip the endoflife.date support/EOL lookup |
| `--no-repo-check` | Skip source-repo detection and the GitHub release/advisory lookup |
| `--no-zip` | Don't bundle output into `webtech_fingerprint_results.zip` |
| `--proxy` | Route all traffic (browser + fetches) through this proxy, e.g. `http://127.0.0.1:8080` |
| `--timeout MS` | Max ms to wait for a target's initial page load (default `25000`; `0` = wait indefinitely) |
| `-t, --threads N` | Targets to scan at once on a `-f` run (default `5`) |
| `--match TECH` | Highlight hosts running a technology (repeatable, comma-separated) |
| `--match-only` | Drop non-matching hosts from the feed and skip writing their files |
| `--resume` | Continue an interrupted `-f` run from its progress file |
| `--no-color` | Disable colorized output |
| `--install-browser` | Install Playwright's Chromium correctly under pip/pipx |

### Examples

```bash
aux-webtech https://target.example.com
aux-webtech -f targets.txt -o results/
auxiliary webtech https://target.example.com --no-eol
aux-webtech https://target.example.com --proxy http://127.0.0.1:8080
aux-webtech https://target.example.com --timeout 60000
aux-webtech -f targets.txt -o results/ --resume
aux-webtech -f targets.txt -o results/ --threads 10            # scan 10 at once (-t 10)
aux-webtech -f targets.txt -o results/ --match php,apache      # triage: who runs PHP/Apache?
aux-webtech -f targets.txt -o results/ --match wordpress --match-only

# script directly (no installation)
python3 web/webtech_fingerprint.py https://target.example.com
python3 web/webtech_fingerprint.py -f targets.txt -o results/
```

### Authenticated crawl (`-r`)

To pick up components that only render once logged in, capture an authenticated
request in Burp (**Copy as Python-Requests**) or as a curl command, save it to a
file, and pass it with `-r`. The tool replays its real cookies and headers
instead of crawling anonymously. `-r` replaces the `url` argument and can't be
combined with `-f`.

### Offline / network-isolated workflow

Component detection needs no external network — only the endoflife.date/GitHub
enrichment step does (and it already fails soft rather than crashing). Inside a
locked-down network, run with `--no-eol --no-repo-check` to skip the
doomed-to-fail lookups and their timeouts entirely, producing a zip with
accurate version data but no EOL/support status. Once you have connectivity
again (e.g. after scp'ing the zip elsewhere), run `--enrich` against it to fill
in exactly the lookups that were missing, without re-crawling:

```bash
# Inside the isolated network
aux-webtech https://target.example.com --no-eol --no-repo-check -o results/

# On a machine with internet access
aux-webtech --enrich results/webtech_fingerprint_results.zip -o results/
```

### Concurrency & the compact feed

A `-f/--targets-file` run scans **5 targets at once by default**; change this
with `--threads N` (short `-t`). Each worker thread drives its own headless
browser, so `N` is roughly the peak browser count — raise it for a large scope
on a beefy host, lower it or use `1` to go easy on memory or a fragile target.
This only applies to `-f`; single-URL/`-r`/`--enrich` are always one target.

With more than one target in flight, the full per-target reports would
interleave into noise, so the screen shows a compact one-line-per-host feed
printed as each host finishes (out of order):

```
[ 1/20] done  https://web01.corp.local   PHP 8.1.2, nginx 1.18.0
[ 3/20] FAIL  https://web03.corp.local   timeout
[ 2/20] done  https://web02.corp.local   no components detected
```

The full reports aren't lost — they're still written to the per-host
`.json`/`.txt` files and into the saved transcript. `--threads 1` keeps the
original inline full-report output. These markers are colorized on an
interactive terminal (auto-disabled off a TTY, when `NO_COLOR` is set, or with
`--no-color`; the saved transcript is always plain text).

### Resume after Ctrl-C

Press `Ctrl-C` once to stop gracefully — it stops launching new targets, lets
the in-flight ones finish and save, then stops (a second `Ctrl-C` force-quits,
leaving the saved progress for `--resume`). An interrupted run (graceful stop or
crash) leaves a `webtech_fingerprint_progress.json` plus the loose per-host
files in the output directory instead of the usual single zip; re-run the same
command with `--resume` to skip finished targets, crawl only what's left, and
bundle everything into one final zip:

```bash
aux-webtech -f targets.txt -o results/            # Ctrl-C partway through...
aux-webtech -f targets.txt -o results/ --resume   # ...continues where it left off
```

### Technology sweep (`--match`)

To sweep a scope for a specific technology — e.g. "which hosts run PHP?" to find
where to patch a fresh advisory — add `--match TECH`. It's a case-insensitive
substring match on the detected tech name across libraries, server components,
and cookie fingerprints; after the run it prints a
`=== MATCHED: <tech> (N hosts) ===` list of matching hosts with their detected
version (or `version unknown` for a presence-only hit such as a `PHPSESSID`
cookie). `--match` is repeatable and comma-separated
(`--match php,apache --match jquery`). Add `--match-only` to drop non-matching
hosts from the feed and skip writing their files entirely.

```bash
aux-webtech -f scope.txt -o results/ --match php             # list every host running PHP
aux-webtech -f scope.txt -o results/ --match php --match-only # ...and only those hosts
```

> **Note:** server-component matches (e.g. the `PHP/8.1.2` in an `X-Powered-By`
> header) depend on the endoflife lookup, so don't combine a server-tech match
> with `--no-eol`.

### Caveats

- **WAF/CDN bot-challenge** (e.g. Cloudflare Turnstile) can prevent the real
  page from ever being reached, producing a misleadingly clean "0 libraries
  detected" for the challenge page. The tool applies best-effort anti-detection
  hardening and prints an explicit `WARNING` (plus `"challenge_page"` in the
  saved JSON) when a known challenge signature is detected — treat those results
  as unverified.
- **Proxy env vars don't work.** To inspect this tool's own traffic (e.g. in
  Burp), use `--proxy http://127.0.0.1:8080` rather than
  `HTTP_PROXY`/`HTTPS_PROXY` — Playwright's browser doesn't honor those env
  vars the way `requests`-based tools do, so setting only the env vars will
  silently NOT route the browser's navigation through your proxy.
- **`--timeout` only bounds the initial navigation** (the `load` event); the
  fixed post-load settle wait and the resource/EOL fetch timeouts are
  unaffected.
