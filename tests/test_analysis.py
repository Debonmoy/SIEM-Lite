"""Event normalization tests."""

from __future__ import annotations

from siem.analysis.event_normalizer import EventNormalizer
from siem.models import Event


def test_normalizer_validates_fields():
    event = Event(
        timestamp="2024-01-15T10:00:00Z",
        source_ip=" 1.2.3.4 ",
        destination_ip="not-an-ip",
        source_port=70000,
        destination_port=443,
        http_status=999,
        username="  root ",
        log_format="ssh",
    )
    normalized = EventNormalizer().normalize(event)
    assert normalized.source_ip == "1.2.3.4"
    assert normalized.destination_ip is None
    assert normalized.source_port is None
    assert normalized.destination_port == 443
    assert normalized.http_status is None
    assert normalized.username == "root"
    assert normalized.os_source == "linux"
    assert normalized.timestamp_epoch is not None
    assert normalized.fingerprint


def test_normalizer_deduplicates_batch():
    events = [
        Event(timestamp="2024-01-15T10:00:00+00:00", raw_message="same", log_format="ssh"),
        Event(timestamp="2024-01-15T10:00:00+00:00", raw_message="same", log_format="ssh"),
        Event(timestamp="2024-01-15T10:00:01+00:00", raw_message="different", log_format="ssh"),
    ]
    normalized, duplicates = EventNormalizer().normalize_many(events)
    assert duplicates == 1
    assert len(normalized) == 2


def test_fingerprint_stable():
    first = Event(timestamp="2024-01-15T10:00:00+00:00", raw_message="x", log_format="ssh")
    second = Event(timestamp="2024-01-15T10:00:00+00:00", raw_message="x", log_format="ssh")
    assert first.compute_fingerprint() == second.compute_fingerprint()
