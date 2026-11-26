# Architecture

This document explains how the Mini SIEM is structured, how data flows through
it, and where to extend it. It describes the implementation in this repository,
not an idealized enterprise SIEM.

## Design goals

1. **Clarity over cleverness.** Every stage should be readable and explainable.
2. **One normalized event model.** Parsers differ; everything downstream does not.
3. **Separation of concerns.** Parsing, detection, scoring, storage and presentation
   are independent.
4. **Safe failure.** One bad line, file or rule must not crash a run.
5. **Cross-platform.** Offline analysis works anywhere Python runs; live mode is
   explicitly limited to Linux/WSL.
6. **No side effects on monitored systems.** Read-only analysis, no blocking.

## Layered view

```
+-------------------------------------------------------------+
| Presentation: CLI, Flask dashboard, HTML report             |
+-------------------------------------------------------------+
| Orchestration: AnalysisPipeline, AlertManager, DetectionEngine |
+-------------------------------------------------------------+
| Domain: Event, Alert, Finding, RiskEngine, rules            |
+-------------------------------------------------------------+
| Ingestion: Collectors, ParserRegistry, parsers              |
+-------------------------------------------------------------+
| Infrastructure: config, DBManager/SQLite, logging, platform |
+-------------------------------------------------------------+
```

Dependencies point downward. For example, parsers do not import the dashboard,
and detection rules do not write to the database.

## Component responsibilities

| Component | Files | Responsibility |
| --- | --- | --- |
| Configuration | `siem/config.py`, `config/detection_rules.json` | Defaults, env overrides, deep-merged rules |
| Models | `siem/models.py` | `Event`, `Alert`, timestamp conversion, fingerprints |
| Collectors | `siem/collectors/` | Discover/read files; tail Linux logs |
| Parsers | `siem/parsers/` | Convert native records to `Event` |
| Registry | `siem/parsers/registry.py` | Parser selection and auto-detection |
| Normalizer | `siem/analysis/event_normalizer.py` | Validate fields, normalize timestamps, dedup batch |
| Detection | `siem/detection/` | Independent rules producing `Finding` objects |
| Risk | `siem/analysis/risk_engine.py` | Final severity and rationale |
| Alerts | `siem/alerts/alert_manager.py` | Build, deduplicate and persist alerts |
| Pipeline | `siem/pipeline.py` | Shared offline/live/dashboard flow |
| Storage | `siem/database/` | Schema and parameterized queries |
| Interfaces | `siem/cli/`, `siem/dashboard/`, `siem/reports/` | CLI, web UI, HTML report |
| Utilities | `siem/utils/` | Platform detection, file validation, logging |

## Data model

`Event` is the contract between parsing and detection:

- Identity/traceability: `timestamp`, `source_file`, `source_type`, `os_source`,
  `log_format`, `session_id`, `fingerprint`, `ingested_at`.
- Network: `source_ip`, `destination_ip`, `source_port`, `destination_port`.
- Identity: `host`, `username`, `service`.
- Semantics: `event_type`, `event_code`, `auth_result`.
- HTTP: `http_method`, `http_status`, `request_path`, `user_agent`.
- Raw: `raw_message`, `extra` (parser-specific data such as Windows `EventData`).

Missing values are `None`; parsers do not invent data.

`Finding` is the contract between detection and alerting: rule id, category,
severity, title, description, explanation, source IP/user, event count, evidence,
recommended actions, dedup key and context used for risk scoring.

`Alert` is the persisted form, adding an alert id, status, timestamps and session.

## Offline analysis flow

1. CLI builds a `FileCollector` from `--file`/`--directory` inputs.
2. The collector validates paths and discovers supported files.
3. `AnalysisPipeline.analyze_paths` starts an analysis session.
4. `ParserRegistry` selects a parser per file (explicit `--format` or auto).
5. Each parser returns a `ParseResult` with events and per-file errors.
6. `EventNormalizer` validates fields, computes timestamps and fingerprints, and
   removes duplicates inside the batch.
7. `DBManager.insert_events` inserts with `INSERT OR IGNORE` on the unique
   fingerprint.
8. `DetectionEngine` runs each enabled rule over the normalized batch.
9. `RiskEngine` scores each finding.
10. `AlertManager` suppresses duplicates against open alerts and inserts new ones.
11. The session row is updated with counts and errors.
12. CLI prints a summary; the dashboard/report read the same database.

## Live monitoring flow

1. `LinuxLiveCollector.discover_sources` checks known Linux paths plus
   `--source` extras for existence and readability.
2. The parser for each source is detected once and cached.
3. `poll` tracks inode and byte offset per file:
   - first poll starts at EOF unless `--from-beginning`;
   - new bytes are buffered and split on newlines;
   - an inode change or size shrink is treated as rotation/truncation and reading
     restarts from offset 0.
4. New lines are parsed into events with `source_type="live"`.
5. The CLI keeps a rolling in-memory buffer, trims it to the largest configured
   detection window plus a margin, and flushes every ~2 seconds or 200 events.
6. The shared pipeline normalizes, stores, detects and alerts.
7. Session counts are refreshed periodically and at shutdown.

Live mode is intentionally not a daemon: it runs in the foreground, prints alerts
as they occur, and stops on Ctrl+C, `--duration` or `--max-events`.

## Dashboard flow

- `create_app` opens one `DBManager`, loads rules and the parser registry, and
  registers routes.
- GET pages read from SQLite; filters are translated into parameterized queries.
- `/import` saves validated uploads to a temporary directory, runs the same
  pipeline, then deletes the directory in a `finally` block.
- Alert status changes update the alert and append to `alert_status_history`.
- The app is a development server bound to localhost by default.

## Storage and concurrency

- SQLite is opened with `check_same_thread=False` and guarded by an `RLock`.
- WAL mode allows concurrent readers with a writer.
- A 30-second busy timeout reduces transient `database is locked` errors.
- Events are inserted in batches with `executemany`.
- Fingerprints are SHA-256 over selected normalized fields and are UNIQUE.
- Alerts are deduplicated by `dedup_key` among `NEW`/`INVESTIGATING` alerts.

## Error handling

| Failure | Behavior |
| --- | --- |
| Unreadable file | Recorded in `ParseResult.errors`; other files continue |
| Empty file | Explicit error message; no crash |
| Malformed line/record | Skipped, counted, message capped at 50 per file |
| Broken EVTX record | Skipped with an error; other records continue |
| Rule raises an exception | Logged; other rules continue |
| Invalid config JSON | Falls back to defaults |
| Invalid CLI input | Error to stderr, non-zero exit code |
| Invalid upload | Flash/validation error; no partial file left behind |
| Missing alert id | HTTP 404 |
| Oversized upload | HTTP 413 with a clear message |

## Security boundaries

- Untrusted input: log content, uploaded filenames, query parameters.
- Controls: parameterized SQL, allow-listed dynamic identifiers, upload basename
  sanitization, `safe_join`, extension allow-list, size limit, Jinja2 autoescape,
  strict path resolution, no shell execution.
- The dashboard has no authentication and must stay on localhost or behind a
  trusted reverse proxy.
- The tool never acts on the monitored host (no firewall changes, no blocking).

## Extension points

### Add a log format

1. Implement a `BaseParser` subclass in `siem/parsers/`.
2. Implement `can_parse`, `parse_line` (or override `parse_file` for
   container/row-oriented formats).
3. Register it in `ParserRegistry` and add aliases in `FORMAT_ALIASES`.
4. Add the extension to `SUPPORTED_EXTENSIONS` if it is new.
5. Add parser tests and a sample file.

### Add a detection rule

1. Subclass `BaseRule`, set `rule_id`, `category`, `default_severity`.
2. Implement `evaluate(events) -> list[Finding]`.
3. Add defaults to `DEFAULT_RULES` and to `config/detection_rules.json`.
4. Instantiate it in `DetectionEngine._build_rules`.
5. Add risk escalation logic if needed.
6. Add tests for positive, negative and boundary cases.

### Change scoring

Edit `RiskEngine.assess`. Keep explanations explicit; avoid implying certainty.

## Trade-offs

- Batch-in-memory detection is simple and fast for moderate files but not
  horizontally scalable.
- SQLite avoids operational dependencies but limits concurrent writers.
- Heuristic rules are explainable but noisy compared with behavioral baselines.
- Format auto-detection favors safety (conservative markers) over magic.
- Live mode supports Linux logs only because Windows event logs require Windows
  APIs or remote collection.

## Testing strategy

- Unit tests for parsers, normalization, rules, scoring, database and security.
- Platform tests simulate `sys.platform` and WSL detection.
- Integration tests exercise the full pipeline, CLI, dashboard routes/upload,
  report generation and live collector rotation.
- The suite uses temporary databases and never touches the project database.
