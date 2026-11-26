# Log Analyzer & Mini SIEM

A cross-platform, educational **log analyzer and mini SIEM** written in Python.
It ingests Linux and Windows logs, normalizes them into a common event schema,
applies transparent detection rules, scores findings heuristically, stores
events and alerts in SQLite, and exposes them through a CLI, a Flask dashboard
and a standalone HTML report.

Author: **Debonmoy Pal** · Version **1.0.0** · License **MIT**

> This is a learning and triage tool, not a production-grade SIEM. Severity is a
> qualitative heuristic, not a statistically validated probability of
> compromise. It never blocks, firewalls or modifies the monitored system.

---

## Table of contents

1. [What it does](#what-it-does)
2. [What it is not](#what-it-is-not)
3. [Features](#features)
4. [Architecture](#architecture)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Quick start](#quick-start)
8. [CLI reference](#cli-reference)
9. [Dashboard](#dashboard)
10. [Supported log formats](#supported-log-formats)
11. [Detection rules](#detection-rules)
12. [Risk scoring and severity](#risk-scoring-and-severity)
13. [Alert lifecycle and deduplication](#alert-lifecycle-and-deduplication)
14. [Database schema](#database-schema)
15. [Configuration](#configuration)
16. [Security design](#security-design)
17. [Testing](#testing)
18. [Project structure](#project-structure)
19. [Sample data](#sample-data)
20. [Cross-platform notes](#cross-platform-notes)
21. [Limitations and false positives](#limitations-and-false-positives)
22. [Troubleshooting](#troubleshooting)
23. [Educational walkthrough](#educational-walkthrough)
24. [Future improvements](#future-improvements)
25. [Contributing](#contributing)
26. [Attribution](#attribution)
27. [License](#license)
28. [Author](#author)

---

## What it does

- Parses **Linux** authentication/SSH, Apache, Nginx and generic syslog-style
  logs, including firewall key-value records.
- Parses **Windows** event logs in **EVTX**, XML, CSV and JSON/NDJSON formats.
- Normalizes every record into one `Event` model (timestamp, host, user, IPs,
  ports, event code, HTTP fields, raw message, extras).
- Runs six independent detection rule families and produces explained alerts.
- Scores alerts from `INFO` to `CRITICAL` using transparent heuristics.
- Persists events, alerts, analysis sessions and alert status history in SQLite.
- Provides an `argparse` CLI, a local Flask dashboard and a self-contained HTML
  report.
- Supports **live monitoring of Linux/WSL logs** (tail-like polling with log
  rotation handling).
- Deduplicates ingested events by fingerprint and correlates repeat alerts.

## What it is not

- Not a replacement for Splunk, Elastic Security, Wazuh, Sentinel or a real SOC.
- Not an intrusion prevention system: it does not block traffic or change hosts.
- Not a malware scanner and not a packet capture tool.
- Not a source of ground truth: every alert requires analyst verification.
- Not multi-tenant and not hardened for exposure to untrusted networks.

## Features

| Area | Capability |
| --- | --- |
| Parsing | Linux auth/SSH, Apache access/error, Nginx access/error, generic/firewall, Windows EVTX/XML/CSV/JSON |
| Detection | SSH brute force, success after failures, port scan, suspicious IP, web attacks, Windows Security events |
| Analysis | Event normalization, field validation, fingerprint dedup, densest-window counting |
| Risk | Severity escalation with explicit rationale |
| Storage | SQLite with WAL, indexes, parameterized queries, sessions and status history |
| Interfaces | CLI tables/JSON, Flask dashboard, standalone HTML report |
| Live mode | Linux/WSL tailing, rotation/truncation detection, permission checks |
| Safety | Upload validation, path traversal protection, no shell execution, no blocking actions |
| Quality | 54 automated tests across parsers, detection, database, platform, security and integration |

## Architecture

```
                       +----------------------+
  log files / EVTX --->|  Collectors          |<--- live Linux log tail
                       |  File / LinuxLive    |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |  Parser registry     |
                       |  auto-detect format  |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |  EventNormalizer     |
                       |  validate + hash     |
                       +----------+-----------+
                                  |
              +-------------------+-------------------+
              |                                       |
              v                                       v
   +----------------------+                +----------------------+
   |  SQLite (events)     |                |  DetectionEngine     |
   |  dedup by fingerprint|                |  6 rule families     |
   +----------------------+                +----------+-----------+
                                                     |
                                                     v
                                          +----------------------+
                                          |  RiskEngine          |
                                          |  severity + rationale|
                                          +----------+-----------+
                                                     |
                                                     v
                                          +----------------------+
                                          |  AlertManager        |
                                          |  dedup/correlate     |
                                          +----------+-----------+
                                                     |
                          +--------------------------+--------------------------+
                          |                          |                          |
                          v                          v                          v
                       CLI                     Dashboard                  HTML report
```

Key design choices:

- **Parsers only parse.** They never decide what is malicious.
- **Rules only detect.** They read normalized events and rule configuration.
- **Risk scoring is separate.** Detection and severity can be tuned independently.
- **Storage is a thin layer.** Every query is parameterized; grouping and ordering
  values are allow-listed.
- **One pipeline is shared** by offline CLI analysis, dashboard uploads and live
  monitoring (`siem/pipeline.py`).

## Requirements

- Python **3.10+** (developed and verified on Python **3.14.4**)
- pip and venv
- Flask 3.x, Jinja2 3.x, python-evtx 0.7.4+
- SQLite (bundled with Python)
- Optional: a Linux or WSL environment for live monitoring

## Installation

```bash
git clone <your-repository-url>
cd miniSIEM

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt  # runtime + pytest
```

Optional editable install (adds a `minisiem` command):

```bash
pip install -e .
minisiem --version
```

Without installation, run everything through `main.py`.

## Quick start

```bash
# 1. Version and environment
python main.py --version
python main.py status

# 2. Analyze the bundled sample logs
python main.py --db data/minisiem.db offline --directory sample_logs

# 3. Inspect the most serious alerts
python main.py --db data/minisiem.db alerts --severity CRITICAL

# 4. Generate a standalone HTML report
python main.py --db data/minisiem.db report

# 5. Start the local dashboard
python main.py --db data/minisiem.db dashboard --port 8080
# open http://127.0.0.1:8080/

# 6. Live monitor Linux/WSL logs for 60 seconds
python main.py --db data/minisiem.db live --duration 60
```

Expected sample result (default rules):

```
Events parsed      : 99
New events stored  : 99
Duplicates dropped : 0
Findings           : 26
Alerts generated   : 26
```

## CLI reference

Global options may appear before or after the subcommand:

```bash
python main.py [--db PATH] [-v] <command> [options]
```

| Command | Purpose | Common options |
| --- | --- | --- |
| `offline` | Analyze files/directories once | `--file PATH` (repeatable), `--directory DIR` (repeatable), `--format FMT`, `--no-recursive` |
| `live` | Tail Linux/WSL log sources | `--source PATH`, `--from-beginning`, `--interval SEC`, `--duration SEC`, `--max-events N` |
| `alerts` | List stored alerts | `--severity`, `--category`, `--ip`, `--status`, `--limit`, `--json` |
| `report` | Write a standalone HTML report | `--output PATH`, `--title TEXT`, `--events N` |
| `status` | Show platform, DB and rule status | `-v` |
| `rules` | Show effective rule configuration | `--json` |
| `dashboard` | Start the Flask dashboard | `--host`, `--port`, `--debug` |

Examples:

```bash
python main.py offline --file sample_logs/windows/new-user-security.evtx
python main.py offline --directory sample_logs --format auto
python main.py alerts --status NEW --json
python main.py report --output /tmp/report.html
python main.py rules --json > effective-rules.json
python main.py dashboard --host 127.0.0.1 --port 8080
```

`--db` precedence: explicit CLI value, then `MINISIEM_DB`, then
`data/minisiem.db`.

## Dashboard

The dashboard is intentionally local-only by default.

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Overview: counters, severity/category breakdown, recent alerts |
| `/analytics` | GET | Aggregations: top IPs/users, formats, event codes, failure timeline |
| `/events` | GET | Paginated event explorer with filters (IP, user, format, OS, code, search, date) |
| `/alerts` | GET | Paginated alert explorer with filters |
| `/alerts/<id>` | GET | Alert detail: evidence, explanation, recommendations, status form |
| `/alerts/<id>/status` | POST | Update alert status and add a note |
| `/import` | GET/POST | Upload logs (multipart) and analyze them |
| `/api/overview` | GET | Overview counters as JSON |
| `/health` | GET | Liveness plus event/alert counts |

Notes:

- Uploads are limited to **100 MB** and to known log extensions. Filenames are
  reduced to a safe basename and joined inside a temporary directory that is
  deleted after analysis.
- There is **no authentication**. Binding to a non-local host prints a warning;
  do not expose it to an untrusted network.
- `MINISIEM_SECRET_KEY` can pin Flask's session secret; otherwise a random key
  is generated at startup.

## Supported log formats

Auto-detection uses the filename and a sample of the content. `--format` forces a
specific parser.

| Format name | Aliases | Source | Key fields extracted |
| --- | --- | --- | --- |
| `auth` | `linux_auth`, `auth.log`, `secure` | Linux `auth.log` / `secure` | timestamp, host, program, PID, user, source IP/port, auth result, sudo/su, user/group changes |
| `ssh` | - | SSH-focused logs | timestamp, host, user, source IP/port, success/failure, disconnect events |
| `apache_access` | `apache` | Apache combined access | timestamp, client IP, user, method, path, status, user agent, referer |
| `apache_error` | - | Apache error | timestamp, level, client IP/port, message |
| `nginx_access` | `nginx` | Nginx combined access | same as Apache access |
| `nginx_error` | - | Nginx error | timestamp, level, client IP, method, path, message |
| `windows_xml` | `xml` | Windows Event XML | System metadata, EventID, time, host, channel, EventData |
| `windows_csv` | `csv` | Windows Event CSV export | flexible header matching for EventID/time/host/user/IP |
| `windows_json` | `json`, `jsonl`, `ndjson` | Windows Event JSON / NDJSON | nested `System`/`EventData`, flat keys, arrays, wrapped `Events` |
| `evtx` | `windows_evtx` | Binary EVTX (offline, any OS) | records converted to XML then normalized |
| `generic` | - | Anything else | timestamp if present, host, program, raw message, firewall `SRC/DST/SPT/DPT` |

Format detection caveats:

- Combined access logs are ambiguous. Nginx access is selected when the filename
  contains `nginx`; otherwise use `--format nginx_access` explicitly.
- CSV detection refuses JSON/XML-looking input, and JSON detection requires
  event-like keys (`EventID`/`event_id`).
- A broken or empty file yields a per-file error, not a crash.

## Detection rules

Rules are configured in `config/detection_rules.json` and deep-merged over
built-in defaults. Disable a rule with `"enabled": false`.

| Rule ID | Category | Fires when | Defaults |
| --- | --- | --- | --- |
| `ssh_brute_force` | `brute_force` | Failed Linux SSH/auth attempts from one source IP, counted in the densest window | 10 failures / 300 s, base HIGH |
| `success_after_failures` | `authentication_anomaly` | A successful Linux login is preceded by failures from the same IP within the window | 5 failures / 600 s, base HIGH |
| `port_scan` | `network_scan` | One source contacts many distinct destination ports (requires destination-port data) | 10 distinct ports, at least 5 events/failures, 300 s, base MEDIUM |
| `suspicious_ip` | `suspicious_ip` | Source IP is on the local denylist, or produces many failures | 20 failures / 600 s, base MEDIUM; allowlist `127.0.0.1`, `::1` |
| `web_attack_*` | `web_attack` | Request path/message matches SQLi, XSS, traversal or sensitive-file patterns (raw and URL-decoded) | One alert per category+IP |
| `web_auth_failures` | `web_attack` | Many HTTP 401/403 responses to one IP | 20 / 300 s, MEDIUM |
| `windows_failed_logon` | `windows_auth` | Event 4625 failures grouped by source IP or user | 5 / 600 s, base MEDIUM (escalates at 2x) |
| `windows_account_lockout` | `windows_account` | Any 4740 | HIGH |
| `windows_audit_cleared` | `windows_audit` | Any 1102 | CRITICAL |
| `windows_account_created` | `windows_account` | Any 4720 | MEDIUM |
| `windows_group_membership_change` | `windows_account` | Any 4728 / 4732 | MEDIUM |
| `windows_explicit_credentials` | `windows_auth` | Any 4648 | MEDIUM |
| `windows_special_privileges` | `windows_privilege` | Any 4672 | LOW |
| `windows_service_installed` | `windows_persistence` | Any 4697 | MEDIUM |
| `windows_suspicious_process` | `windows_process` | Event 4688 creates a known dual-use binary (PowerShell, WMIC, certutil, mshta, rundll32, regsvr32, psexec, bitsadmin, etc.) | INFO |
| `windows_remote_logon` | `windows_auth` | Event 4624 logon type 10 (RDP), or type 3 from a public IP | MEDIUM |
| `windows_success_after_failures` | `windows_auth` | Event 4624 after repeated 4625 from the same IP | 5 / 600 s, HIGH |

Important semantics:

- Counting uses the **densest window** of event timestamps, not "first to last".
- `port_scan` only fires when events actually carry destination ports. It does
  not pretend that authentication logs contain network-scan evidence.
- Windows rules require `os_source == "windows"` or a `windows_*` format.
- Patterns are matched against both the raw request and URL-decoded variants.
- Every alert includes an explanation and recommended investigation steps.

See [docs/detection-rules.md](docs/detection-rules.md) for per-rule detail,
tuning guidance and false-positive notes.

## Risk scoring and severity

`RiskEngine` (`siem/analysis/risk_engine.py`) assigns the final severity:

- SSH brute force: +1 level at 2x the failure threshold, +2 at 3x, and +1 more
  when 3+ distinct usernames are targeted (capped at CRITICAL).
- Success-after-failures: at least HIGH.
- Audit log cleared: always CRITICAL.
- Account lockout: at least HIGH.
- Port scan: +1 level at 50+ distinct ports.
- Web attack: +1 level at 10+ matching requests.
- Denylisted IP: rationale is recorded (severity already bumped by the rule).

Every explanation ends with a reminder that severity is a **heuristic risk
indicator, not a statistically validated probability**.

## Alert lifecycle and deduplication

- Each finding receives a `dedup_key` such as `ssh_brute_force:203.0.113.50`.
- If an alert with the same key is **NEW** or **INVESTIGATING**, no duplicate is
  created; if the new finding has a higher event count, the existing alert's
  count is updated.
- If the existing alert is **RESOLVED** or **FALSE_POSITIVE**, a new alert may be
  created for the same pattern.
- Status values: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`.
- Every status change is recorded in `alert_status_history` with an optional note.

## Database schema

SQLite file (default `data/minisiem.db`) with WAL enabled:

| Table | Purpose |
| --- | --- |
| `events` | Normalized events; `fingerprint` is UNIQUE for dedup |
| `alerts` | Alerts with severity, explanation, evidence (JSON), recommendations, dedup key |
| `analysis_sessions` | One row per offline/live/dashboard analysis run |
| `alert_status_history` | Audit trail of alert status transitions |

Indexes cover timestamps, source IPs, usernames, formats, OS source, event codes,
sessions, severity, category, status and dedup keys.

Event fingerprints hash the format, source file, timestamp, source IP, username,
event code and raw message. **The same logical event exported in two different
formats is intentionally treated as two records**, because the raw message and
format differ; this is documented as a limitation rather than hidden.

## Configuration

Environment variables:

| Variable | Meaning | Default |
| --- | --- | --- |
| `MINISIEM_DB` | SQLite database path | `data/minisiem.db` |
| `MINISIEM_RULES` | Detection rule JSON path | `config/detection_rules.json` |
| `MINISIEM_SECRET_KEY` | Flask session secret | random per start |

Rule file shape:

```json
{
  "version": 1,
  "rules": {
    "ssh_brute_force": {
      "enabled": true,
      "severity": "HIGH",
      "threshold": 10,
      "window_seconds": 300,
      "username_escalation_count": 3
    },
    "web_attack": {
      "enabled": true,
      "severity": "HIGH",
      "auth_failure_threshold": 20,
      "window_seconds": 300,
      "patterns": {
        "sql_injection": ["(?i)(\\bunion\\b[^\\n]{0,40}\\bselect\\b)"]
      }
    }
  }
}
```

A missing, malformed or partial file is merged with defaults; a broken file never
crashes the tool.

## Security design

- All SQL uses parameters. Dynamic table/column/order values are allow-listed.
- Uploaded filenames are reduced to a basename; `safe_join` blocks traversal.
- Uploads are restricted to known log extensions and a 100 MB size limit.
- Uploaded files are written to a temporary directory and removed afterwards.
- Paths are resolved with `strict=True` and checked for readability.
- No `shell=True`, no `eval`, no execution of log content.
- HTML output uses Jinja2 autoescaping.
- Application logs do not contain raw log lines or secrets.
- The tool is read-only with respect to monitored systems: no blocking actions.
- Dashboard binds to `127.0.0.1` by default and has no authentication, so it must
  not be exposed publicly.

## Testing

```bash
pytest -q
```

Current suite: **54 tests**, covering:

| File | Focus |
| --- | --- |
| `tests/test_parsers.py` | Linux auth/SSH, Apache, Nginx, generic/firewall, Windows XML/CSV/JSON/EVTX, malformed and empty input |
| `tests/test_detection.py` | Brute force, success-after-failure, port scan, suspicious IP, web attacks, Windows rules, risk engine, alert dedup |
| `tests/test_database.py` | Insert/dedup, filters, counts, alert persistence/status, sessions, stats |
| `tests/test_platform.py` | Windows/Linux/WSL/macOS detection and live-mode restrictions |
| `tests/test_security.py` | Upload names, traversal, extensions, size, SQL-injection-safe queries |
| `tests/test_analysis.py` | Normalization, field validation, fingerprints |
| `tests/test_integration.py` | End-to-end pipeline, CLI, dashboard routes/upload, report, live collector rotation |

Tests use temporary databases and do not modify the project database.

## Project structure

```
miniSIEM/
├── main.py                      # CLI entry point
├── config/
│   └── detection_rules.json     # detection thresholds and patterns
├── siem/
│   ├── config.py                # defaults, env overrides, rule loading
│   ├── models.py                # Event and Alert models
│   ├── pipeline.py              # shared analyze/process pipeline
│   ├── analysis/                # normalization and risk scoring
│   ├── alerts/                  # alert lifecycle and dedup
│   ├── cli/                     # argparse commands
│   ├── collectors/              # file and live Linux collectors
│   ├── dashboard/               # Flask app, routes, templates, CSS
│   ├── database/                # schema.sql and DBManager
│   ├── detection/               # rules and detection engine
│   ├── parsers/                 # all format parsers and registry
│   ├── reports/                 # standalone HTML report
│   └── utils/                   # platform, files, logging
├── sample_logs/                 # synthetic Linux/Windows samples + EVTX
├── tests/                       # pytest suite
├── docs/                        # architecture, rules, troubleshooting, walkthrough
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
└── LICENSE
```

## Sample data

See [sample_logs/README.md](sample_logs/README.md) for a per-file description,
expected alerts and EVTX attribution. All addresses are documentation ranges;
most files are synthetic.

## Cross-platform notes

| Platform | Offline analysis | Live Linux monitoring | EVTX parsing |
| --- | --- | --- | --- |
| Linux | Yes | Yes | Yes |
| WSL2 (Ubuntu) | Yes | Yes (Linux logs only) | Yes |
| Native Windows | Yes | No (use offline) | Yes |
| macOS | Yes | No (use offline) | Yes |

Inside WSL, Windows host EVTX files are **not** captured live; import them in
offline mode. This limitation is surfaced by the platform detector and the
`status`/`live` commands.

Runtime verification was performed on WSL2 Ubuntu 26.04 with Python 3.14.4.
Windows and macOS behavior is covered by simulated unit tests; it was not run on
real Windows/macOS hardware during development.

## Limitations and false positives

- Detections are heuristic and context-free; legitimate administration,
  vulnerability scanners and mistyped passwords can trigger alerts.
- Offline analysis loads a batch into memory; it is not a distributed stream
  processor.
- There is no cross-host or cross-time correlation beyond per-rule windows.
- Live mode only monitors logs visible from the local Linux/WSL filesystem.
- Cross-format duplicate events are not merged (see fingerprint note above).
- Syslog timestamps without a year are inferred, and timezone handling assumes
  UTC for naive values.
- Generic parsing only extracts a limited set of fields.
- The dashboard has no authentication, RBAC or TLS termination.
- No threat-intelligence feeds, GeoIP, packet capture or automatic response.
- The Windows suspicious-process rule is name-based and easily evaded.

## Troubleshooting

Quick checks:

```bash
python main.py status
python main.py rules
pytest -q
```

Common issues and fixes are documented in
[docs/troubleshooting.md](docs/troubleshooting.md), including permissions for
live logs, missing `python-evtx`, empty files, thresholds that do not fire,
database locks, dashboard ports and WSL limitations.

## Educational walkthrough

A step-by-step explanation of how a raw log line becomes a triaged alert, with
exercises and verification commands, is in
[docs/educational-walkthrough.md](docs/educational-walkthrough.md). It is the
recommended starting point for learning how a SIEM pipeline works.

## Future improvements

- Cross-format event correlation and entity timelines.
- Sigma rule import/export.
- Threat-intelligence and GeoIP enrichment.
- Pluggable database backend and streaming ingestion for very large files.
- Dashboard authentication, RBAC and TLS guidance.
- Windows remote event collection (WinRM or EVTX forwarding).
- Additional parsers: journald, Zeek, Suricata, cloud audit logs.

## Contributing

1. Fork the repository and create a focused branch.
2. Keep the existing package layout and coding style.
3. Add tests for new parsers, rules or behavior changes.
4. Run `pytest -q` before opening a pull request.
5. Do not commit databases, logs, secrets or real customer data.
6. Describe detection changes with positive, negative and boundary cases.

Bug reports are most useful when they include the platform, Python version, the
command run, and a minimal sanitized log sample.

## Attribution

- EVTX test fixture: [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)
  (MIT License). See `sample_logs/README.md`.
- Built with Flask, Jinja2 and python-evtx.

## License

MIT License. See [LICENSE](LICENSE).

Copyright (c) 2026 Debonmoy Pal.

## Author

**Debonmoy Pal**

This project was built as a practical, educational exploration of log analysis,
detection engineering and mini-SIEM architecture. It is intended for learning,
lab use and small-scale triage, not for production security operations without
further hardening and review.
