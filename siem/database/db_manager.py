"""SQLite persistence layer.

A thin abstraction so a different database could be swapped in later. Every
query uses parameters; no user input is interpolated into SQL.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

from .. import config
from ..models import Alert, Event, utc_now_iso

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

EVENT_COLUMNS = [
    "fingerprint",
    "timestamp",
    "timestamp_epoch",
    "ingested_at",
    "source_file",
    "source_type",
    "os_source",
    "log_format",
    "host",
    "username",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "event_type",
    "event_code",
    "service",
    "auth_result",
    "http_method",
    "http_status",
    "request_path",
    "user_agent",
    "raw_message",
    "extra",
    "session_id",
]


class DBManager:
    """Thread-safe wrapper around a single SQLite database file."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(config.get_db_path(db_path))
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._connect()

    def _connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=30
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        with self._lock:
            assert self._conn is not None
            self._conn.executescript(schema)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> "DBManager":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ events
    def insert_events(self, events: Iterable[Event], session_id: str | None = None) -> int:
        """Insert events, skipping duplicates by fingerprint. Returns inserted count."""
        rows: list[tuple] = []
        for event in events:
            event.ensure_derived()
            if session_id and not event.session_id:
                event.session_id = session_id
            data = event.to_row()
            rows.append(tuple(data.get(col) for col in EVENT_COLUMNS))
        if not rows:
            return 0
        placeholders = ", ".join("?" for _ in EVENT_COLUMNS)
        columns = ", ".join(EVENT_COLUMNS)
        sql = f"INSERT OR IGNORE INTO events ({columns}) VALUES ({placeholders})"
        with self._lock:
            assert self._conn is not None
            before = self._conn.total_changes
            self._conn.executemany(sql, rows)
            self._conn.commit()
            return self._conn.total_changes - before

    def get_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_ip: str | None = None,
        username: str | None = None,
        log_format: str | None = None,
        os_source: str | None = None,
        event_code: str | None = None,
        search: str | None = None,
        start_epoch: float | None = None,
        end_epoch: float | None = None,
        session_id: str | None = None,
    ) -> list[Event]:
        clauses: list[str] = []
        params: list[Any] = []
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if username:
            clauses.append("username = ?")
            params.append(username)
        if log_format:
            clauses.append("log_format = ?")
            params.append(log_format)
        if os_source:
            clauses.append("os_source = ?")
            params.append(os_source)
        if event_code:
            clauses.append("event_code = ?")
            params.append(str(event_code))
        if search:
            clauses.append("(raw_message LIKE ? OR request_path LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])
        if start_epoch is not None:
            clauses.append("timestamp_epoch >= ?")
            params.append(start_epoch)
        if end_epoch is not None:
            clauses.append("timestamp_epoch <= ?")
            params.append(end_epoch)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM events{where} "
            "ORDER BY timestamp_epoch DESC, id DESC LIMIT ? OFFSET ?"
        )
        params.extend([int(limit), int(offset)])
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(sql, params).fetchall()
        return [Event.from_row(row) for row in rows]

    def count_events(self, session_id: str | None = None) -> int:
        sql = "SELECT COUNT(*) AS c FROM events"
        params: list[Any] = []
        if session_id:
            sql += " WHERE session_id = ?"
            params.append(session_id)
        with self._lock:
            assert self._conn is not None
            return int(self._conn.execute(sql, params).fetchone()["c"])

    def count_events_filtered(
        self,
        *,
        source_ip: str | None = None,
        username: str | None = None,
        log_format: str | None = None,
        os_source: str | None = None,
        event_code: str | None = None,
        search: str | None = None,
        start_epoch: float | None = None,
        end_epoch: float | None = None,
        session_id: str | None = None,
    ) -> int:
        clauses: list[str] = []
        params: list[Any] = []
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if username:
            clauses.append("username = ?")
            params.append(username)
        if log_format:
            clauses.append("log_format = ?")
            params.append(log_format)
        if os_source:
            clauses.append("os_source = ?")
            params.append(os_source)
        if event_code:
            clauses.append("event_code = ?")
            params.append(str(event_code))
        if search:
            clauses.append("(raw_message LIKE ? OR request_path LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])
        if start_epoch is not None:
            clauses.append("timestamp_epoch >= ?")
            params.append(start_epoch)
        if end_epoch is not None:
            clauses.append("timestamp_epoch <= ?")
            params.append(end_epoch)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            assert self._conn is not None
            return int(
                self._conn.execute(
                    f"SELECT COUNT(*) AS c FROM events{where}", params
                ).fetchone()["c"]
            )

    def get_event_by_id(self, event_id: int) -> Event | None:
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        return Event.from_row(row) if row else None

    # ------------------------------------------------------------------ alerts
    def insert_alert(self, alert: Alert) -> bool:
        """Insert an alert. Returns False if the alert_id already exists."""
        data = alert.to_row()
        columns = list(data.keys())
        placeholders = ", ".join("?" for _ in columns)
        sql = (
            f"INSERT OR IGNORE INTO alerts ({', '.join(columns)}) "
            f"VALUES ({placeholders})"
        )
        with self._lock:
            assert self._conn is not None
            cursor = self._conn.execute(sql, [data[c] for c in columns])
            self._conn.commit()
            return cursor.rowcount > 0

    def get_alerts(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        severity: str | None = None,
        category: str | None = None,
        source_ip: str | None = None,
        status: str | None = None,
        session_id: str | None = None,
        search: str | None = None,
        order: str = "created_at DESC",
    ) -> list[Alert]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if category:
            clauses.append("category = ?")
            params.append(category)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if search:
            clauses.append("(title LIKE ? OR description LIKE ? OR source_ip LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_order = order if order in {
            "created_at DESC", "created_at ASC",
            "severity DESC", "severity ASC", "event_count DESC",
        } else "created_at DESC"
        sql = f"SELECT * FROM alerts{where} ORDER BY {safe_order} LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(sql, params).fetchall()
        return [Alert.from_row(row) for row in rows]

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        return Alert.from_row(row) if row else None

    def find_open_alert_by_dedup(self, dedup_key: str) -> Alert | None:
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE dedup_key = ? "
                "AND status IN ('NEW','INVESTIGATING') "
                "ORDER BY created_at DESC LIMIT 1",
                (dedup_key,),
            ).fetchone()
        return Alert.from_row(row) if row else None

    def update_alert_progress(self, alert_id: str, event_count: int) -> bool:
        """Update the correlated event count of an existing open alert."""
        with self._lock:
            assert self._conn is not None
            cursor = self._conn.execute(
                "UPDATE alerts SET event_count = ?, updated_at = ? WHERE alert_id = ?",
                (int(event_count), utc_now_iso(), alert_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def update_alert_status(
        self, alert_id: str, status: str, note: str | None = None
    ) -> bool:
        status = status.upper()
        if status not in config.ALERT_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        now = utc_now_iso()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if not row:
                return False
            old = row["status"]
            self._conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
                (status, now, alert_id),
            )
            self._conn.execute(
                "INSERT INTO alert_status_history "
                "(alert_id, old_status, new_status, changed_at, note) "
                "VALUES (?, ?, ?, ?, ?)",
                (alert_id, old, status, now, note),
            )
            self._conn.commit()
            return True

    def count_alerts(self, session_id: str | None = None) -> int:
        sql = "SELECT COUNT(*) AS c FROM alerts"
        params: list[Any] = []
        if session_id:
            sql += " WHERE session_id = ?"
            params.append(session_id)
        with self._lock:
            assert self._conn is not None
            return int(self._conn.execute(sql, params).fetchone()["c"])

    def count_alerts_filtered(
        self,
        *,
        severity: str | None = None,
        category: str | None = None,
        source_ip: str | None = None,
        status: str | None = None,
        session_id: str | None = None,
        search: str | None = None,
    ) -> int:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if category:
            clauses.append("category = ?")
            params.append(category)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if search:
            clauses.append("(title LIKE ? OR description LIKE ? OR source_ip LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            assert self._conn is not None
            return int(
                self._conn.execute(
                    f"SELECT COUNT(*) AS c FROM alerts{where}", params
                ).fetchone()["c"]
            )

    # --------------------------------------------------------------- sessions
    def create_session(
        self,
        session_id: str,
        mode: str,
        source_description: str,
        files: list[str] | None = None,
    ) -> None:
        with self._lock:
            assert self._conn is not None
            self._conn.execute(
                "INSERT OR REPLACE INTO analysis_sessions "
                "(session_id, created_at, mode, source_description, files, "
                "event_count, alert_count, errors) VALUES (?, ?, ?, ?, ?, 0, 0, ?)",
                (
                    session_id,
                    utc_now_iso(),
                    mode,
                    source_description,
                    json.dumps(files or []),
                    json.dumps([]),
                ),
            )
            self._conn.commit()

    def update_session(
        self,
        session_id: str,
        *,
        event_count: int | None = None,
        alert_count: int | None = None,
        errors: list[str] | None = None,
    ) -> None:
        fields: list[str] = []
        params: list[Any] = []
        if event_count is not None:
            fields.append("event_count = ?")
            params.append(event_count)
        if alert_count is not None:
            fields.append("alert_count = ?")
            params.append(alert_count)
        if errors is not None:
            fields.append("errors = ?")
            params.append(json.dumps(errors))
        if not fields:
            return
        params.append(session_id)
        with self._lock:
            assert self._conn is not None
            self._conn.execute(
                f"UPDATE analysis_sessions SET {', '.join(fields)} WHERE session_id = ?",
                params,
            )
            self._conn.commit()

    def get_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                "SELECT * FROM analysis_sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            for key in ("files", "errors"):
                try:
                    item[key] = json.loads(item.get(key) or "[]")
                except (ValueError, TypeError):
                    item[key] = []
            result.append(item)
        return result

    # ------------------------------------------------------------------- stats
    def overview_stats(self) -> dict[str, Any]:
        with self._lock:
            assert self._conn is not None
            c = self._conn

            def scalar(sql: str, params: tuple = ()) -> int:
                return int(c.execute(sql, params).fetchone()[0] or 0)

            total_events = scalar("SELECT COUNT(*) FROM events")
            total_alerts = scalar("SELECT COUNT(*) FROM alerts")
            critical = scalar("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
            high = scalar("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
            unique_ips = scalar(
                "SELECT COUNT(DISTINCT source_ip) FROM events "
                "WHERE source_ip IS NOT NULL AND source_ip != ''"
            )
            failed_logins = scalar(
                "SELECT COUNT(*) FROM events WHERE auth_result = 'failure'"
            )
            success_logins = scalar(
                "SELECT COUNT(*) FROM events WHERE auth_result = 'success'"
            )
            open_alerts = scalar(
                "SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"
            )
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical,
            "high_alerts": high,
            "unique_ips": unique_ips,
            "failed_logins": failed_logins,
            "success_logins": success_logins,
            "open_alerts": open_alerts,
        }

    def group_counts(self, table: str, column: str, limit: int = 20) -> list[dict]:
        allowed = {
            ("alerts", "severity"),
            ("alerts", "category"),
            ("alerts", "status"),
            ("events", "source_ip"),
            ("events", "username"),
            ("events", "event_code"),
            ("events", "log_format"),
            ("events", "os_source"),
            ("events", "source_type"),
        }
        if (table, column) not in allowed:
            raise ValueError("Unsupported grouping")
        sql = (
            f"SELECT {column} AS label, COUNT(*) AS count FROM {table} "
            f"WHERE {column} IS NOT NULL AND {column} != '' "
            f"GROUP BY {column} ORDER BY count DESC LIMIT ?"
        )
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(sql, (limit,)).fetchall()
        return [{"label": row["label"], "count": row["count"]} for row in rows]

    def failed_logins_over_time(self, limit: int = 50) -> list[dict]:
        sql = (
            "SELECT strftime('%Y-%m-%d %H:00', timestamp_epoch, 'unixepoch') AS bucket, "
            "COUNT(*) AS count FROM events WHERE auth_result = 'failure' "
            "AND timestamp_epoch IS NOT NULL "
            "GROUP BY bucket ORDER BY bucket DESC LIMIT ?"
        )
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(sql, (limit,)).fetchall()
        return [{"label": r["bucket"], "count": r["count"]} for r in reversed(rows)]

    def search_alerts_by_ip(self, ip: str, limit: int = 200) -> list[Alert]:
        return self.get_alerts(source_ip=ip, limit=limit)

    def distinct_values(self, column: str, table: str = "events") -> list[str]:
        allowed = {
            "log_format", "os_source", "event_code", "username", "source_ip"
        }
        if column not in allowed:
            raise ValueError("Unsupported column")
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                f"SELECT DISTINCT {column} FROM {table} "
                f"WHERE {column} IS NOT NULL AND {column} != '' "
                f"ORDER BY {column}"
            ).fetchall()
        return [row[0] for row in rows]
