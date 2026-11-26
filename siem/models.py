"""Normalized data models shared across collectors, parsers and detection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value)


@dataclass
class Event:
    """A single normalized security event.

    Every parser converts its native log record into this schema. Missing data
    is represented as ``None`` (never fabricated).
    """

    timestamp: Optional[str] = None
    source_file: Optional[str] = None
    source_type: str = "file"  # "file" | "live"
    os_source: str = "unknown"  # "linux" | "windows" | "unknown"
    log_format: str = "generic"
    host: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    event_type: Optional[str] = None
    event_code: Optional[str] = None
    service: Optional[str] = None
    auth_result: Optional[str] = None  # "success" | "failure" | None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    request_path: Optional[str] = None
    user_agent: Optional[str] = None
    raw_message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    # Populated at persistence time.
    timestamp_epoch: Optional[float] = None
    ingested_at: Optional[str] = None
    session_id: Optional[str] = None
    fingerprint: Optional[str] = None

    def compute_fingerprint(self) -> str:
        """Stable hash used to prevent duplicate ingestion."""
        parts = [
            _normalize_value(self.log_format),
            _normalize_value(self.source_file),
            _normalize_value(self.timestamp),
            _normalize_value(self.source_ip),
            _normalize_value(self.username),
            _normalize_value(self.event_code),
            _normalize_value(self.raw_message),
        ]
        digest = hashlib.sha256("|".join(parts).encode("utf-8", "replace"))
        return digest.hexdigest()

    def ensure_derived(self) -> "Event":
        """Fill in fingerprint, epoch and ingestion time if missing."""
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        if self.timestamp_epoch is None:
            self.timestamp_epoch = iso_to_epoch(self.timestamp)
        if not self.ingested_at:
            self.ingested_at = utc_now_iso()
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_row(self) -> dict[str, Any]:
        data = self.to_dict()
        data["extra"] = json.dumps(self.extra or {}, default=str)
        return data

    @classmethod
    def from_row(cls, row: Any) -> "Event":
        extra_raw = row["extra"] if "extra" in row.keys() else None
        try:
            extra = json.loads(extra_raw) if extra_raw else {}
        except (ValueError, TypeError):
            extra = {}
        return cls(
            timestamp=row["timestamp"],
            source_file=row["source_file"],
            source_type=row["source_type"] or "file",
            os_source=row["os_source"] or "unknown",
            log_format=row["log_format"] or "generic",
            host=row["host"],
            username=row["username"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            event_type=row["event_type"],
            event_code=row["event_code"],
            service=row["service"],
            auth_result=row["auth_result"],
            http_method=row["http_method"],
            http_status=row["http_status"],
            request_path=row["request_path"],
            user_agent=row["user_agent"],
            raw_message=row["raw_message"] or "",
            extra=extra,
            timestamp_epoch=row["timestamp_epoch"],
            ingested_at=row["ingested_at"],
            session_id=row["session_id"],
            fingerprint=row["fingerprint"],
        )


@dataclass
class Alert:
    """A detection result requiring analyst attention."""

    alert_id: str
    created_at: str
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    event_count: int = 0
    source_ip: Optional[str] = None
    username: Optional[str] = None
    status: str = "NEW"
    explanation: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    dedup_key: str = ""
    session_id: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_row(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at or self.created_at,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "username": self.username,
            "event_count": self.event_count,
            "status": self.status,
            "explanation": self.explanation,
            "evidence": json.dumps(self.evidence, default=str),
            "recommended_actions": json.dumps(self.recommended_actions, default=str),
            "dedup_key": self.dedup_key,
            "session_id": self.session_id,
        }

    @classmethod
    def from_row(cls, row: Any) -> "Alert":
        def _load(value: Any) -> Any:
            if not value:
                return [] if value in (None, "") else value
            try:
                return json.loads(value)
            except (ValueError, TypeError):
                return []

        return cls(
            alert_id=row["alert_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            rule_id=row["rule_id"],
            category=row["category"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            event_count=row["event_count"] or 0,
            source_ip=row["source_ip"],
            username=row["username"],
            status=row["status"] or "NEW",
            explanation=row["explanation"] or "",
            evidence=_load(row["evidence"]),
            recommended_actions=_load(row["recommended_actions"]),
            dedup_key=row["dedup_key"] or "",
            session_id=row["session_id"],
        )


def iso_to_epoch(value: Optional[str]) -> Optional[float]:
    """Best-effort conversion of an ISO timestamp to a POSIX epoch."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()
