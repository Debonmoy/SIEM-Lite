"""Base parser interface and file parsing driver."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Event

MAX_ERROR_MESSAGES = 50
ENCODINGS = ("utf-8", "utf-8-sig", "latin-1")


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    lines_read: int = 0
    lines_skipped: int = 0
    parser_name: str = ""
    source_file: str = ""


class BaseParser(ABC):
    """All parsers convert native records into normalized :class:`Event`s."""

    name: str = "base"
    log_format: str = "generic"
    os_source: str = "unknown"
    extensions: set[str] = set()

    @abstractmethod
    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        """Return True if this parser can likely handle the given sample."""

    @abstractmethod
    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        """Parse one logical record; return None when the line is not relevant."""

    def parse_file(self, path: str | Path) -> ParseResult:
        path = Path(path)
        result = ParseResult(parser_name=self.name, source_file=str(path))
        try:
            text = self.read_text(path)
        except OSError as exc:
            result.errors.append(f"Could not read {path}: {exc}")
            return result

        if not text.strip():
            result.errors.append(f"File is empty: {path}")
            return result

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            result.lines_read += 1
            try:
                event = self.parse_line(line, str(path))
            except Exception as exc:  # noqa: BLE001 - malformed input must not crash
                result.lines_skipped += 1
                if len(result.errors) < MAX_ERROR_MESSAGES:
                    snippet = line[:120]
                    result.errors.append(
                        f"{path}:{line_number}: parse error ({exc}): {snippet}"
                    )
                continue
            if event is None:
                continue
            event.source_file = event.source_file or str(path)
            result.events.append(event)
        return result

    @staticmethod
    def read_text(path: str | Path) -> str:
        """Read a text file trying a few common encodings."""
        path = Path(path)
        last_error: Exception | None = None
        for encoding in ENCODINGS:
            try:
                with path.open("r", encoding=encoding, errors="strict") as handle:
                    return handle.read()
            except UnicodeDecodeError as exc:
                last_error = exc
                continue
            except OSError:
                raise
        # Final fallback: replace undecodable bytes rather than crash.
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError as exc:
            raise exc from last_error
