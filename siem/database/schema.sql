-- Mini SIEM SQLite schema
-- All writes go through parameterized queries in db_manager.py.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint       TEXT NOT NULL UNIQUE,
    timestamp         TEXT,
    timestamp_epoch   REAL,
    ingested_at       TEXT NOT NULL,
    source_file       TEXT,
    source_type       TEXT DEFAULT 'file',
    os_source         TEXT DEFAULT 'unknown',
    log_format        TEXT DEFAULT 'generic',
    host              TEXT,
    username          TEXT,
    source_ip         TEXT,
    destination_ip    TEXT,
    source_port       INTEGER,
    destination_port  INTEGER,
    event_type        TEXT,
    event_code        TEXT,
    service           TEXT,
    auth_result       TEXT,
    http_method       TEXT,
    http_status       INTEGER,
    request_path      TEXT,
    user_agent        TEXT,
    raw_message       TEXT,
    extra             TEXT,
    session_id        TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_epoch      ON events(timestamp_epoch);
CREATE INDEX IF NOT EXISTS idx_events_source_ip  ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_username   ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_format     ON events(log_format);
CREATE INDEX IF NOT EXISTS idx_events_os         ON events(os_source);
CREATE INDEX IF NOT EXISTS idx_events_code       ON events(event_code);
CREATE INDEX IF NOT EXISTS idx_events_session    ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_auth       ON events(auth_result);

CREATE TABLE IF NOT EXISTS alerts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id             TEXT NOT NULL UNIQUE,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    rule_id              TEXT,
    category             TEXT,
    severity             TEXT,
    title                TEXT,
    description          TEXT,
    source_ip            TEXT,
    username             TEXT,
    event_count          INTEGER DEFAULT 0,
    status               TEXT DEFAULT 'NEW',
    explanation          TEXT,
    evidence             TEXT,
    recommended_actions  TEXT,
    dedup_key            TEXT,
    session_id           TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_category   ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip  ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created    ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup      ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alerts_session    ON alerts(session_id);

CREATE TABLE IF NOT EXISTS analysis_sessions (
    session_id          TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL,
    mode                TEXT NOT NULL,
    source_description  TEXT,
    files               TEXT,
    event_count         INTEGER DEFAULT 0,
    alert_count         INTEGER DEFAULT 0,
    errors              TEXT
);

CREATE TABLE IF NOT EXISTS alert_status_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    TEXT NOT NULL,
    old_status  TEXT,
    new_status  TEXT NOT NULL,
    changed_at  TEXT NOT NULL,
    note        TEXT
);

CREATE INDEX IF NOT EXISTS idx_status_history_alert ON alert_status_history(alert_id);
