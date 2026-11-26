"""Detection rule primitives shared by all rule modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..models import Event

SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_LEVELS.index(severity.upper())
    except ValueError:
        return 0


def bump_severity(severity: str, levels: int = 1) -> str:
    idx = min(len(SEVERITY_LEVELS) - 1, severity_rank(severity) + levels)
    return SEVERITY_LEVELS[idx]


def event_to_evidence(event: Event, raw_limit: int = 500) -> dict[str, Any]:
    """Compact, investigation-friendly representation of an event."""
    return {
        "timestamp": event.timestamp,
        "log_format": event.log_format,
        "event_type": event.event_type,
        "event_code": event.event_code,
        "source_ip": event.source_ip,
        "username": event.username,
        "auth_result": event.auth_result,
        "http_method": event.http_method,
        "http_status": event.http_status,
        "request_path": event.request_path,
        "raw_message": (event.raw_message or "")[:raw_limit],
    }


def events_to_evidence(events: list[Event], limit: int = 20) -> list[dict[str, Any]]:
    selected = events[-limit:] if len(events) > limit else events
    return [event_to_evidence(event) for event in selected]


def events_with_epoch(events: list[Event]) -> list[Event]:
    return sorted(
        [e for e in events if e.timestamp_epoch is not None],
        key=lambda e: e.timestamp_epoch,
    )


def densest_window(events: list[Event], window_seconds: int) -> list[Event]:
    """Return the densest time window (list of events) of the given length."""
    ordered = events_with_epoch(events)
    if not ordered:
        return []
    best: list[Event] = []
    start = 0
    for end in range(len(ordered)):
        while (
            ordered[end].timestamp_epoch - ordered[start].timestamp_epoch
            > window_seconds
        ):
            start += 1
        current = ordered[start : end + 1]
        if len(current) > len(best):
            best = current
    return best


@dataclass
class Finding:
    """A raw detection result before risk scoring and persistence."""

    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    explanation: str = ""
    source_ip: str | None = None
    username: str | None = None
    event_count: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    dedup_key: str = ""
    context: dict[str, Any] = field(default_factory=dict)


class BaseRule(ABC):
    rule_id: str = "base"
    category: str = "general"
    default_severity: str = "MEDIUM"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    @property
    def severity(self) -> str:
        return str(self.config.get("severity", self.default_severity)).upper()

    @abstractmethod
    def evaluate(self, events: list[Event]) -> list[Finding]:
        """Inspect events and return findings."""
