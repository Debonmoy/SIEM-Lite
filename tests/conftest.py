"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from siem.config import load_rules
from siem.database.db_manager import DBManager
from siem.models import Event

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_dir() -> Path:
    return ROOT / "sample_logs"


@pytest.fixture
def tmp_db(tmp_path: Path) -> DBManager:
    db = DBManager(tmp_path / "test.db")
    yield db
    db.close()


@pytest.fixture
def rules() -> dict:
    return load_rules()


@pytest.fixture
def make_event():
    def _make(timestamp: str = "2024-01-15T10:00:00+00:00", **kwargs) -> Event:
        event = Event(timestamp=timestamp, **kwargs)
        event.ensure_derived()
        return event

    return _make
