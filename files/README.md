# `files/` — splitting & credential processing

Two stdlib-only file utilities. Each runs as `aux-<name>`, `auxiliary <name>`,
or the script directly. Append `--help` for the full option list.

---

## split_lines — `aux-split-lines` / `auxiliary split-lines`

Split a text file into fixed-size line batches with numeric suffixes and a
custom prefix/suffix — similar to
`split -l 1000 -d --numeric-suffixes=1 --additional-suffix=.txt`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | `targets` | Input file, or `-` for stdin |
| `-o, --outdir` | `target_batches` | Output directory |
| `-p, --prefix` | `targets_batch_` | Output filename prefix |
| `--suffix` | `.txt` | Output filename suffix |
| `-n, --lines` | `1000` | Lines per output file |
| `-s, --start` | `1` | Starting numeric suffix |
| `-w, --width` | `2` | Zero-pad width for the numeric suffix |

### Examples

```bash
aux-split-lines --input targets --outdir target_batches --prefix targets_batch_ --lines 1000
auxiliary split-lines --input targets --lines 500 --suffix .txt

# read from stdin, script directly (no installation)
cat targets | python3 files/split_lines.py -i - -o target_batches -p targets_batch_
```

---

## split_creds — `aux-split-creds` / `auxiliary split-creds`

Split `user:pass[:...]` dumps into separate username and password lists.
Default behavior preserves order and duplicates and splits on the first
delimiter (`:`). Input files are gathered by glob.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--glob` | `unique-creds-*.txt` | Glob matching the input credential files |
| `--users` | `pitchfork_users` | Output file for usernames |
| `--passwords` | `pitchfork_passwords` | Output file for passwords |
| `--delimiter` | `:` | Delimiter splitting user from password |
| `--dedupe-users` | off | Drop duplicate usernames (keep first) |
| `--dedupe-passwords` | off | Drop duplicate passwords (keep first) |
| `--sort {none,users,passwords,both}` | `none` | Sort selected output(s) |
| `--ignore-no-delim` | off | Skip lines with no delimiter (vs. empty password) |
| `--strip` | off | Strip surrounding whitespace and quotes from fields |

### Examples

```bash
aux-split-creds
auxiliary split-creds --glob "unique-creds-*.txt" --users users.txt --passwords pws.txt --dedupe-users --strip --sort users

# script directly (no installation)
python3 files/split_creds.py --glob "unique-creds-*.txt" --dedupe-users --strip --sort users
```
