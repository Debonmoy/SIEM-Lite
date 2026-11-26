# Development Plan — Log Analyzer & Mini SIEM

Author: Debonmoy Pal
Primary environment: WSL2 (Ubuntu 26.04), Python 3.14.4

Legend: `[ ]` not started · `[~]` in progress · `[x]` completed and verified

---

## PHASE 1 — Project foundation and architecture

- [x] T1.1 Inspect environment (Python, WSL, git, disk, internet).
- [x] T1.2 Create virtual environment and install deps (flask, python-evtx, pytest).
- [x] T1.3 Create package layout (`siem/`), project metadata, `.gitignore`, `LICENSE`.
- [x] T1.4 Define normalized `Event` and `Alert` models (`siem/models.py`).
- [x] T1.5 Central configuration loader (`siem/config.py`, `config/detection_rules.json`).
- [x] T1.6 Utility modules: platform detector, file validator, logger.
- [x] T1.7 SQLite schema + `DBManager` with parameterized queries and indexes.
- [x] T1.8 Verify DB init/insert/query with a smoke test.

## PHASE 2 — Cross-platform detection and configuration

- [x] T2.1 Platform detection (Windows / Linux / WSL / macOS) with capability flags.
- [x] T2.2 Live-mode availability rules (disable on native Windows).
- [x] T2.3 Load/validate JSON detection rule configuration with defaults.

## PHASE 3 — Log collection

- [x] T3.1 `BaseCollector` interface.
- [x] T3.2 `FileCollector` (single file, multiple files, recursive dir, encodings, errors).
- [x] T3.3 `LinuxLiveCollector` (tail -like follow, rotation, permission checks).

## PHASE 4 — Linux log parsing

- [x] T4.1 `BaseParser` + shared timestamp/field helpers.
- [x] T4.2 Auth parser (auth.log / secure).
- [x] T4.3 SSH parser.
- [x] T4.4 Apache access + error parsers.
- [x] T4.5 Nginx access + error parsers.
- [x] T4.6 Generic fallback parser.
- [x] T4.7 Format registry with automatic detection.
- [x] T4.8 Verify parsing on synthetic logs.

## PHASE 5 — Windows EVTX and event parsing

- [x] T5.1 EVTX parser (python-evtx, offline on any OS).
- [x] T5.2 Windows XML parser.
- [x] T5.3 Windows CSV parser.
- [x] T5.4 Windows JSON parser.
- [x] T5.5 Normalize Windows events into common schema.
- [x] T5.6 Verify with synthetic XML/CSV/JSON and a public EVTX fixture (attribution in `sample_logs/README.md`).

## PHASE 6 — Event normalization

- [x] T6.1 `EventNormalizer` (timestamps, IP/port validation, OS tagging, fingerprints).
- [x] T6.2 Deduplicate events by fingerprint during ingestion.

## PHASE 7 — Threat detection engine

- [x] T7.1 `BaseRule` + `DetectionEngine` orchestration.
- [x] T7.2 SSH brute-force rule (configurable threshold/window).
- [x] T7.3 Success-after-failures rule.
- [x] T7.4 Port-scan rule (distinct ports, failed connections).
- [x] T7.5 Suspicious-IP rule (denylist, frequency, private/public classification).
- [x] T7.6 Web attack rule (SQLi, XSS, traversal, sensitive files, 401/403 bursts).
- [x] T7.7 Windows security event rules (4624/4625/4634/4648/4672/4688/4697/4720/4728/4732/4740/1102).
- [x] T7.8 Rule enable/disable + config wiring.

## PHASE 8 — Risk assessment

- [x] T8.1 `RiskEngine` severity assignment from rule + count + window + context.
- [x] T8.2 Explanation + recommended investigation steps.

## PHASE 9 — Alert management

- [x] T9.1 `AlertManager` (generate, store, dedup/correlate, status updates).
- [x] T9.2 Filtering/search (severity, category, IP, status).

## PHASE 10 — SQLite database integration

- [x] T10.1 Events, alerts, analysis sessions tables + indexes.
- [x] T10.2 Event ingestion with duplicate prevention.
- [x] T10.3 Alert persistence and retrieval helpers.

## PHASE 11 — CLI interface

- [x] T11.1 `main.py` + argparse subcommands (`offline`, `live`, `alerts`, `report`, `status`, `dashboard`, `rules`).
- [x] T11.2 Tables, severity coloring, progress feedback.
- [x] T11.3 End-to-end offline pipeline command.

## PHASE 12 — HTML dashboard

- [x] T12.1 Flask app + routes (overview, analytics, events, alerts, import).
- [x] T12.2 Templates + static CSS (real DB data only).
- [x] T12.3 Safe uploads (size limit, extension validation, no path traversal).
- [x] T12.4 Alert status management from UI.

## PHASE 13 — HTML report generation

- [x] T13.1 Standalone HTML report from DB (Jinja2).
- [x] T13.2 CLI `report` command.

## PHASE 14 — Live Linux monitoring

- [x] T14.1 Discover available log sources + permission checks.
- [x] T14.2 Tail/follow with rotation handling.
- [x] T14.3 Real-time parse + detect + persist.
- [x] T14.4 Graceful behavior on Windows / WSL messaging.

## PHASE 15 — Security hardening

- [x] T15.1 Path validation, upload validation, no shell execution.
- [x] T15.2 Parameterized SQL, secret-safe logging.
- [x] T15.3 No auto-firewall/blocking actions.

## PHASE 16 — Unit and integration testing

- [x] T16.1 Parser tests (Linux, Apache, Nginx, Windows XML/CSV/JSON/EVTX, malformed, empty).
- [x] T16.2 Detection tests (brute force, success-after-fail, port scan, suspicious IP, web, Windows).
- [x] T16.3 Database tests (insert, dedup, retrieval, status).
- [x] T16.4 Cross-platform tests (Windows/Linux/WSL detection, live restrictions).
- [x] T16.5 Integration test (import → parse → detect → store → retrieve).
- [x] T16.6 Full suite green.

## PHASE 17 — Cross-platform compatibility testing

- [x] T17.1 Linux/WSL runtime verification (this environment).
- [x] T17.2 Windows/macOS behavior verified via simulated platform unit tests (documented as not run on real hardware).

## PHASE 18 — Documentation and GitHub preparation

- [x] T18.1 README.md (all required sections).
- [x] T18.2 docs/ (architecture, detection rules, troubleshooting).
- [x] T18.3 DEVELOPMENT_LOG.md, requirements.txt, pyproject.toml.
- [x] T18.4 Sample logs (Linux + Windows synthetic).
- [x] T18.5 Final audit + educational walkthrough.

---

## Verification gates

Each task is marked complete only after its code runs and the relevant test(s) pass.
The final gate is `pytest -q` returning all green plus a live CLI smoke run.

## Final verification (2026-11-26)

- `python -m pytest -q` -> **54 passed**.
- Offline analysis of `sample_logs` -> **99 events, 26 alerts**, including
  CRITICAL SSH brute force and CRITICAL Windows audit-log clearing.
- CLI `status`, `rules --json`, `alerts`, `report` verified.
- Dashboard routes and multipart upload verified with Flask's test client.
- Live collector verified with a temporary file, including append and rotation.
- Real EVTX fixture parsed successfully on Linux/WSL.
- Windows/macOS behavior covered by simulated platform tests (not real hardware).
- Final audit and educational walkthrough completed in
  `docs/educational-walkthrough.md`.
