"""Event normalization and batch de-duplication."""

from __future__ import annotations

from ..models import Event, iso_to_epoch
from ..parsers.common import normalize_ip, parse_windows_time

LINUX_FORMATS = {"auth", "ssh"}


def _valid_port(value: int | None) -> int | None:
    if value is None:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _valid_status(value: int | None) -> int | None:
    if value is None:
        return None
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


class EventNormalizer:
    """Ensures every event conforms to the shared schema before persistence."""

    def normalize(self, event: Event) -> Event:
        event.source_ip = normalize_ip(event.source_ip)
        event.destination_ip = normalize_ip(event.destination_ip)
        event.source_port = _valid_port(event.source_port)
        event.destination_port = _valid_port(event.destination_port)
        event.http_status = _valid_status(event.http_status)

        if event.username is not None:
            text = str(event.username).strip()
            event.username = text or None

        if event.timestamp:
            normalized_time = parse_windows_time(event.timestamp)
            if normalized_time:
                event.timestamp = normalized_time
        event.timestamp_epoch = iso_to_epoch(event.timestamp)

        if event.log_format.startswith("windows") or event.os_source == "windows":
            event.os_source = "windows"
        elif event.log_format in LINUX_FORMATS:
            event.os_source = "linux"

        if event.source_type not in {"file", "live"}:
            event.source_type = "file"

        event.ensure_derived()
        return event

    def normalize_many(self, events: list[Event]) -> tuple[list[Event], int]:
        """Normalize and drop duplicate fingerprints within the batch."""
        normalized: list[Event] = []
        seen: set[str] = set()
        duplicates = 0
        for event in events:
            self.normalize(event)
            fingerprint = event.fingerprint or event.compute_fingerprint()
            if fingerprint in seen:
                duplicates += 1
                continue
            seen.add(fingerprint)
            normalized.append(event)
        return normalized, duplicates
