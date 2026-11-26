# Troubleshooting

Start with the built-in diagnostics:

```bash
python main.py status
python main.py rules --json
pytest -q
```

`status` reports the detected platform, database path and counts, live-mode
availability and the effective rule settings.

---

## Installation and startup

### `ModuleNotFoundError: No module named 'flask'` (or `Evtx`)

The virtual environment is not active or dependencies are missing.

```bash
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -c "import flask, Evtx; print('ok')"
```

### `python: command not found`

Use `python3` on systems that do not alias `python`, or install Python 3.10+.

### `TypeError` involving `X | Y` annotations

The code requires Python **3.10+**. Check `python --version` inside the venv.

### `minisiem: command not found` after `pip install -e .`

The editable install did not complete or the venv is not active. You can always
run `python main.py ...` from the repository root.

---

## Offline analysis

### `error: provide --file and/or --directory`

Pass at least one input:

```bash
python main.py offline --directory sample_logs
python main.py offline --file sample_logs/linux/auth.log
```

### `error: no readable log files found`

- Confirm the path exists and is a file or directory.
- Directory discovery only picks known extensions (`.log`, `.txt`, `.evtx`,
  `.xml`, `.csv`, `.json`, `.jsonl`, `.ndjson`, `.out`, `.err`) and known names
  (`auth.log`, `secure`, `messages`, `syslog`, etc.).
- Use `--file` to force a specific file with an unusual name.
- Check permissions with `ls -l`.

### A file is skipped with `File is empty`

The file contains only whitespace. This is reported as an error, not a crash.

### Wrong format detected

Force it:

```bash
python main.py offline --file my.log --format auth
python main.py offline --file access.log --format nginx_access
```

Combined access logs are ambiguous; Nginx access is auto-selected only when the
filename contains `nginx`. CSV detection deliberately refuses JSON/XML-looking
content. JSON detection requires `EventID`/`event_id` keys.

### Fewer events than expected

- The parser only creates events for lines it recognizes. For example, the SSH
  parser ignores non-sshd lines; use `--format auth` for a mixed auth log.
- Blank lines are skipped.
- Malformed lines are skipped and counted in the summary under processing
  messages.
- Cross-format duplicates are not merged (see below).

### Events appear duplicated across Windows formats

This is expected with the current fingerprint design. The fingerprint includes
the log format and raw message, so the same logical event exported as XML, CSV,
JSON and EVTX is stored as separate records. Analyze one export per event source
when you need exact counts.

### No alerts on logs that look malicious

Check, in order:

1. Are events actually parsed? The summary shows `Events parsed`.
2. Do the events carry the fields the rule needs?
   - SSH brute force needs `auth_result == "failure"` and a valid source IP.
   - Port scan needs `destination_port`; auth logs do not have it.
   - Web attacks need a web format or HTTP status/path fields.
   - Windows rules need `os_source == "windows"` or a `windows_*` format.
3. Are events inside the time window? Threshold rules use the densest window
   (for example 10 failures in 300 seconds), not the whole file.
4. Is the rule enabled? `python main.py rules --json`.
5. Are the thresholds too high? Inspect the effective config.
6. Is the IP allowlisted? `suspicious_ip.allowlist` suppresses suspicious-IP
   findings, including denylist findings for that IP.

---

## EVTX parsing

### `python-evtx is not installed`

```bash
pip install python-evtx
```

### `Could not parse EVTX file ...`

- Confirm the file is a real EVTX container, not a renamed XML/JSON file.
- Confirm the file is not truncated or corrupted.
- Some records may be unreadable; the parser skips them and continues.
- Verify the fixture with:

```bash
python -c "from Evtx.Evtx import Evtx; \
  f=Evtx('sample_logs/windows/new-user-security.evtx'); \
  print(len(list(f.records())))"
```

### EVTX works on Linux/WSL but not live

EVTX is an offline format. Windows host logs are not captured live from WSL; use
`offline --file`. Live mode only monitors Linux logs visible in the WSL
filesystem.

---

## Live monitoring

### `Live Linux monitoring is unavailable here`

You are on native Windows or macOS. Use offline analysis. On WSL, confirm the
platform detector reports WSL (see `status`).

### `No known log sources were found`

Provide a source explicitly:

```bash
python main.py live --source /var/log/auth.log
```

### `none of the discovered log sources are readable`

On Debian/Ubuntu:

```bash
sudo usermod -aG adm "$USER"
# log out and back in, then verify
groups
```

Alternatively run with appropriate privileges for the files you need. The tool
does not attempt to escalate privileges.

### No new events appear

- By default, live mode starts at the end of each file. Use `--from-beginning`
  to read existing content.
- Confirm the file is actually being appended to.
- Check that the parser selected for the source is appropriate; the source table
  prints the parser name.
- Increase verbosity with `-v` to print each parsed event.

### Events stop after log rotation

The collector detects an inode change or a size shrink and restarts from offset
0. If a rotation replaces the path with a file that is not readable, fix
permissions. If you use a custom log path, keep passing it via `--source`.

---

## Dashboard

### `Address already in use`

Choose another port:

```bash
python main.py dashboard --port 8081
```

### Upload returns 413

Uploads are limited to 100 MB. Split large files or analyze them from the CLI
with `offline`.

### Upload is rejected as an unsupported type

Allowed extensions: `.log`, `.txt`, `.evtx`, `.xml`, `.csv`, `.json`, `.jsonl`,
`.ndjson`, `.out`, `.err`. Rename only if the content truly matches the format.

### `TemplateNotFound` or missing CSS

Run from the repository root, or install the package with `pip install -e .` so
package data is available. The dashboard expects its templates under
`siem/dashboard/templates/`.

### Dashboard exposed on the network

Do not bind to `0.0.0.0` on an untrusted network. There is no authentication. Use
localhost or place it behind an authenticating reverse proxy with TLS.

---

## Database

### `database is locked`

- Another process may be writing for a long time. SQLite allows one writer.
- The connection uses a 30-second timeout and WAL mode, but heavy concurrent
  writes can still conflict.
- Close long-running dashboard/live sessions before bulk imports.
- Check for stale `-wal`/`-shm` files only after all processes have stopped.

### I want a clean database

Use a new path or remove the database when no process is using it:

```bash
python main.py --db /tmp/fresh.db offline --directory sample_logs
```

The default `data/minisiem.db` is gitignored.

### Alerts do not reappear after resolving

That is intentional. Deduplication only suppresses `NEW`/`INVESTIGATING` alerts.
After `RESOLVED` or `FALSE_POSITIVE`, a matching pattern can create a new alert.

---

## Reports

### Report path

`report` writes to `reports/output/minisiem_report_<timestamp>.html` relative to
the current directory by default. Pass `--output` to choose a path.

### Report is empty

The report reflects the database you pass with `--db`. If you analyzed into
`/tmp/demo.db`, generate the report with the same `--db`.

---

## Tests

### Tests fail on a fresh clone

- Ensure the virtual environment is active and `requirements-dev.txt` is
  installed.
- Confirm `sample_logs/windows/new-user-security.evtx` exists.
- Run `pytest -q` from the repository root.
- The suite uses temporary databases, so a corrupt `data/minisiem.db` should not
  matter.

### EVTX tests fail

Install `python-evtx`; the EVTX test is skipped or errors if the dependency or
fixture is missing. Confirm the fixture path.

---

## Timestamps and time zones

- Syslog timestamps without a year infer the current year, rolling back one year
  if the date would be in the future.
- Naive timestamps are treated as UTC.
- Apache/Nginx offsets are preserved and converted to ISO-8601.
- Windows `SystemTime` values with 7-digit fractions are truncated to
  microseconds and normalized to UTC.
- If your logs are in local time and you care about precise ordering, normalize
  them before ingestion or adjust the source format.

---

## Performance

- Offline analysis is batch-oriented and holds parsed events in memory. For very
  large files, split them by day or host.
- SQLite is usually the bottleneck for bulk inserts; WAL and batch inserts help.
- Live mode trims its buffer to the largest rule window plus a margin, so memory
  does not grow without bound.
- Use `--limit` on `alerts` and dashboard pagination for large databases.

---

## Getting more detail

- Add `-v` for verbose CLI logging.
- Check `logs/minisiem.log` (created by CLI runs).
- Inspect a specific alert's evidence in the dashboard or with
  `python main.py alerts --json`.
- Use `python main.py rules --json` to confirm the effective configuration.
