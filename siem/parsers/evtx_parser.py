"""Windows EVTX parser using python-evtx (works offline on Linux/WSL/macOS)."""

from __future__ import annotations

from pathlib import Path

from ..models import Event
from .base_parser import BaseParser, ParseResult
from .windows_xml_parser import events_from_xml_text


class EvtxParser(BaseParser):
    name = "evtx"
    log_format = "windows_evtx"
    os_source = "windows"
    extensions = {".evtx"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        return (filename or "").lower().endswith(".evtx")

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        return None  # binary container; parsed record-by-record in parse_file

    def parse_file(self, path: str | Path) -> ParseResult:
        path = Path(path)
        result = ParseResult(parser_name=self.name, source_file=str(path))
        try:
            from Evtx.Evtx import Evtx  # type: ignore
        except ImportError:
            result.errors.append(
                "python-evtx is not installed; install it with 'pip install python-evtx'"
            )
            return result

        if not path.is_file():
            result.errors.append(f"EVTX file not found: {path}")
            return result

        try:
            with Evtx(str(path)) as log:
                for record in log.records():
                    try:
                        xml_text = record.xml()
                    except Exception as exc:  # noqa: BLE001
                        if len(result.errors) < 50:
                            result.errors.append(f"Unreadable EVTX record: {exc}")
                        continue
                    events, errors = events_from_xml_text(xml_text, str(path))
                    for event in events:
                        event.log_format = self.log_format
                    result.events.extend(events)
                    result.errors.extend(errors[: max(0, 50 - len(result.errors))])
                    result.lines_read += 1
        except Exception as exc:  # noqa: BLE001 - malformed file must not crash
            result.errors.append(f"Could not parse EVTX file {path}: {exc}")
        if not result.events and not result.errors:
            result.errors.append(f"No events found in EVTX file: {path}")
        return result
