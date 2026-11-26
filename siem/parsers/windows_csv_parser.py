"""Windows Event Log CSV export parser."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from ..models import Event
from .base_parser import BaseParser, ParseResult
from .common import parse_windows_time
from .windows_common import build_windows_event

_CODE_KEYS = ["eventid", "eventcode", "event_id", "eventcodeid"]
_TIME_KEYS = ["timecreated", "timecreatedutc", "timegenerated", "timestamp", "datetime", "dateandtime"]
_HOST_KEYS = ["computer", "computername", "hostname", "host"]
_PROVIDER_KEYS = ["provider", "providername", "source", "sourcename"]
_CHANNEL_KEYS = ["channel", "logname"]
_LEVEL_KEYS = ["level", "leveldisplayname"]
_RECORD_KEYS = ["eventrecordid", "recordid"]


def _norm_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _lookup(row: dict[str, str], keys: list[str]) -> str | None:
    for key in keys:
        if key in row and str(row[key]).strip():
            return str(row[key]).strip()
    return None


class WindowsCsvParser(BaseParser):
    name = "windows_csv"
    log_format = "windows_csv"
    os_source = "windows"
    extensions = {".csv"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if lowered.endswith((".json", ".jsonl", ".ndjson", ".xml", ".evtx")):
            return False
        if lowered.endswith(".csv"):
            return True
        first_line = next((ln for ln in sample.splitlines() if ln.strip()), "")
        if not first_line or first_line.lstrip().startswith(("{", "[", "<")):
            return False
        has_delim = first_line.count(",") >= 2 or "\t" in first_line or ";" in first_line
        normalized = _norm_header(first_line)
        return has_delim and ("eventid" in normalized or "timecreated" in normalized)

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        return None  # CSV parsing is row-oriented; see parse_file

    def parse_file(self, path: str | Path) -> ParseResult:
        path = Path(path)
        result = ParseResult(parser_name=self.name, source_file=str(path))
        try:
            text = self.read_text(path)
        except OSError as exc:
            result.errors.append(f"Could not read {path}: {exc}")
            return result
        lines = text.splitlines()
        if not lines:
            result.errors.append(f"File is empty: {path}")
            return result

        delimiter = ","
        header_line = next((ln for ln in lines if ln.strip()), "")
        if header_line.count("\t") > header_line.count(","):
            delimiter = "\t"
        elif header_line.count(";") > header_line.count(","):
            delimiter = ";"

        reader = csv.reader(lines, delimiter=delimiter)
        try:
            header = next(reader)
        except StopIteration:
            result.errors.append(f"CSV has no header: {path}")
            return result
        normalized_header = [_norm_header(h) for h in header]
        result.lines_read = 1

        for row_number, row in enumerate(reader, start=2):
            if not any(cell.strip() for cell in row):
                continue
            result.lines_read += 1
            try:
                count = min(len(normalized_header), len(row))
                norm_map = {normalized_header[i]: row[i] for i in range(count)}
                orig_map = {header[i]: row[i] for i in range(count)}
                raw = delimiter.join(row)
                event = self._row_to_event(norm_map, orig_map, raw, str(path))
                if event:
                    result.events.append(event)
            except Exception as exc:  # noqa: BLE001
                result.lines_skipped += 1
                if len(result.errors) < 50:
                    result.errors.append(f"{path}:{row_number}: {exc}")
        return result

    @staticmethod
    def _row_to_event(
        row: dict[str, str], original: dict[str, str], raw: str, source_file: str
    ) -> Event | None:
        code = _lookup(row, _CODE_KEYS)
        time_value = _lookup(row, _TIME_KEYS)
        if not code and not time_value:
            return None
        timestamp = parse_windows_time(time_value) if time_value else None
        data = {key: value for key, value in original.items() if value not in (None, "")}
        return build_windows_event(
            event_code=code,
            timestamp=timestamp,
            host=_lookup(row, _HOST_KEYS),
            provider=_lookup(row, _PROVIDER_KEYS),
            data=data,
            raw_message=raw,
            source_file=source_file,
            channel=_lookup(row, _CHANNEL_KEYS),
            level=_lookup(row, _LEVEL_KEYS),
            record_id=_lookup(row, _RECORD_KEYS),
            log_format="windows_csv",
        )
