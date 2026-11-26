"""Collector interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class BaseCollector(ABC):
    """A collector discovers log sources and exposes them as file paths."""

    def __init__(self) -> None:
        self.errors: list[str] = []

    @abstractmethod
    def collect(self) -> list[Path]:
        """Return the list of readable log file paths."""
