# Development log

Author: Debonmoy Pal
Date: 2026-11-26
Environment: WSL2 Ubuntu 26.04, Python 3.14.4, git 2.53.0

This log records what was built, the decisions behind it, the defects found, and
the verification performed. It is intentionally honest about what was and was
not run on real hardware.

---

## 1. Environment and setup

- Inspected the host: WSL2 Ubuntu 26.04, Python 3.14.4, git 2.53.0, internet
  access available, sufficient disk space, initially empty project directory.
- Created `.venv` and installed:
  - Flask 3.1.3
  - Jinja2 3.1.6
  - python-evtx 0.8.1
  - pytest 9.2.0
- Confirmed EVTX parsing works on Linux/WSL, which is a core cross-platform goal.

## 2. Foundation

- Chose a `siem/` package layout (instead of a flat set of folders) so imports are
  explicit and testable. The CLI remains a single `main.py` entry point.
- Implemented `siem/config.py` with layered configuration:
  - built-in defaults,
  - JSON rule file,
  - environment overrides (`MINISIEM_DB`, `MINISIEM_RULES`).
- Implemented `Event` and `Alert` dataclasses with timestamp conversion and
  SHA-256 fingerprints.
- Implemented `siem/database/schema.sql` and `DBManager`:
  - events, alerts, analysis sessions, alert status history,
  - WAL mode, indexes, parameterized queries,
  - `INSERT OR IGNORE` dedup on fingerprint,
  - allow-listed grouping columns and alert order clauses.
- Added platform detection with explicit WSL awareness and a hard rule that live
  monitoring is Linux-only.
- Added file validation (strict path resolution, supported extensions, upload
  basename sanitization, `safe_join`, size checks) and logging.

## 3. Parsers

Implemented and verified:

- Linux `auth.log`/`secure` (sshd, PAM, sudo, su, user/group changes).
- SSH-focused view.
- Apache access (combined) and error.
- Nginx access (combined) and error.
- Generic syslog/fallback with firewall `SRC/DST/SPT/DPT` extraction.
- Windows XML, CSV, JSON/NDJSON, and binary EVTX (via python-evtx, converted to
  XML and normalized).
- Parser registry with conservative auto-detection and format aliases.

Design choice: parsers only extract fields. They do not decide what is malicious.

## 4. Detection, risk and alerts

Implemented six rule families:

- SSH brute force and success-after-failures.
- Port scan (only when destination ports exist).
- Suspicious IP (denylist and failure frequency, allowlist).
- Web attacks (SQLi, XSS, traversal, sensitive files, 401/403 bursts).
- Windows Security events (4624/4625/4634/4648/4672/4688/4697/4720/4728/4732/
  4740/1102 families).
- Detection engine that isolates rule failures.

Added `RiskEngine` with explicit escalation and an explicit disclaimer that
severity is heuristic. Added `AlertManager` with dedup keys and open-alert
correlation, plus status history.

## 5. Interfaces

- CLI: `offline`, `live`, `alerts`, `report`, `status`, `rules`, `dashboard`.
  Supports `--db` before or after the subcommand, colored tables when stdout is a
  TTY, and JSON output for alerts/rules.
- Flask dashboard: overview, analytics, event explorer, alert explorer, alert
  detail, status updates, upload/import, overview API, health endpoint, 404/413
  handlers.
- Standalone HTML report generated from SQLite with Jinja2 autoescaping.
- Live collector: source discovery, permission reporting, tail-like polling,
  rotation/truncation handling, bounded buffer in the CLI.

## 6. Sample data

- Wrote synthetic Linux samples for auth, Apache, Nginx and firewall logs.
- Wrote synthetic Windows XML, CSV and JSON samples.
- Downloaded a public EVTX fixture from `omerbenamram/evtx` (MIT) to verify real
  binary parsing on Linux/WSL. Attribution is recorded in
  `sample_logs/README.md`.
- Adjusted the auth sample timestamps to be sequential within 12 seconds so the
  default brute-force window triggers predictably.

## 7. Defects found and fixed

| Defect | Fix |
| --- | --- |
| sshd regex missed the "for user X" form | Accept optional `invalid user`/`user` prefixes |
| PAM program regex captured parentheses | Normalize `pam_unix(service:auth)` to the service name |
| CSV parser could claim JSON/XML input | Guard on extension and leading `{`/`[`/`<` |
| CSV header lookup lost original names | Keep both normalized and original header maps |
| Windows field extraction mishandled `-`/empty values | Case-insensitive empty check with fallback |
| Group-change mapping was ambiguous | Use MemberName/MemberSid and GroupName/TargetUserName |
| `.env` web pattern required a trailing dot or end | Allow path/query/whitespace boundary |
| Test asserted an HTML-escaped `&` | Assert unescaped substrings instead |
| Risk engine hardcoded the username escalation count | Read `username_escalation_count` from config |

## 8. Tests

Built a pytest suite covering:

- parsers (all formats, malformed/empty input),
- detection rules (positive, negative, boundary, Windows),
- risk engine,
- database persistence, filters, dedup, sessions, stats,
- platform simulation (Windows/Linux/WSL/macOS),
- security (upload names, traversal, extensions, size, SQL-injection-safe input),
- normalization and fingerprints,
- integration (pipeline, CLI, dashboard routes/upload, report, live rotation).

Final result:

```
54 passed
```

Tests use temporary databases and never modify `data/minisiem.db`.

## 9. Verification performed

Commands and observed results:

```bash
python -m pytest -q
# 54 passed

python main.py --db /tmp/minisiem_demo.db offline --directory sample_logs
# Events parsed: 99, new events stored: 99, findings: 26, alerts: 26

python main.py --db /tmp/minisiem_demo.db alerts --severity CRITICAL
# SSH brute force from 203.0.113.50 (CRITICAL)
# Windows audit log cleared on DC01 (CRITICAL)

python main.py --db /tmp/minisiem_demo.db report
# HTML report generated

python main.py status
# WSL detected, live monitoring available, database and rule summary

# Dashboard via Flask test client:
# /, /analytics, /events, /alerts, /import, /api/overview, /health -> 200
# alert detail -> 200, status update -> redirect, 404 -> 404
# multipart upload -> 200 with analysis result

# EVTX:
# new-user-security.evtx -> 4 events (4720/4728/4732 family)
```

## 10. Packaging and documentation

- Added `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `.gitignore`,
  MIT `LICENSE`.
- Added a comprehensive `README.md`, `docs/architecture.md`,
  `docs/detection-rules.md`, `docs/troubleshooting.md`, and
  `docs/educational-walkthrough.md`.
- Added `sample_logs/README.md` with EVTX attribution.
- Reconciled `DEVELOPMENT_PLAN.md` with actual completion.

## 11. Known limitations

- Heuristic detection; legitimate administration and scanners can trigger alerts.
- No cross-host correlation, threat intelligence, GeoIP or automatic response.
- Offline analysis is batch/in-memory, not a distributed stream processor.
- Cross-format duplicate events are not merged (fingerprint includes format and
  raw message).
- Live mode monitors only Linux/WSL logs visible locally; Windows host EVTX is
  not captured live from WSL.
- Dashboard has no authentication, RBAC or TLS.
- Windows/macOS behavior was verified with simulated platform tests, not real
  hardware.
- The Windows suspicious-process rule is name-based and easy to evade.

## 12. Possible future work

- Cross-format event correlation and entity timelines.
- Sigma rule import/export.
- Threat-intelligence and GeoIP enrichment.
- Pluggable database backend.
- Authentication and RBAC for the dashboard.
- Streaming/chunked ingestion for very large files.
- Windows remote event collection (WinRM/EVTX forwarding).
- More parsers (journald, Zeek, Suricata, cloud audit logs).

## 13. Final status

The project is complete for its stated scope: parsers, detection, risk, alerts,
SQLite persistence, CLI, dashboard, HTML report, live Linux monitoring, tests,
sample data and documentation. All 54 tests pass, and end-to-end verification
was performed on WSL2 Ubuntu 26.04 with Python 3.14.4.
