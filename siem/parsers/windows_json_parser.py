"""Windows Event Log JSON / NDJSON export parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Event
from .base_parser import BaseParser, ParseResult
from .common import parse_windows_time
from .windows_common import build_windows_event

_CODE_KEYS = ["eventid", "event_id", "eventid_qualifiers", "id"]
_TIME_KEYS = ["timecreated", "timecreated_utc", "timegenerated", "timestamp", "@timestamp", "time"]
_HOST_KEYS = ["computer", "computername", "hostname", "host"]
_PROVIDER_KEYS = ["provider", "providername", "source", "sourcename"]
_CHANNEL_KEYS = ["channel", "logname"]
_LEVEL_KEYS = ["level", "leveldisplayname"]
_RECORD_KEYS = ["eventrecordid", "recordid"]
_SKIP_FROM_DATA = set(_CODE_KEYS + _TIME_KEYS + _HOST_KEYS + _PROVIDER_KEYS + _CHANNEL_KEYS + _LEVEL_KEYS + _RECORD_KEYS)


def _case_map(obj: dict[str, Any]) -> dict[str, Any]:
    return {str(k).lower(): v for k, v in obj.items()}


def _lookup(mapping: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, "", "-"):
            return mapping[key]
    return None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        for inner in ("SystemTime", "systemTime", "Name", "Value", "value"):
            if inner in value:
                return _as_text(value[inner])
        return None
    text = str(value).strip()
    return text or None


def _flatten_event_data(obj: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    event_data = (
        obj.get("EventData") or obj.get("event_data") or obj.get("eventdata") or {}
    )
    if isinstance(event_data, dict):
        data.update(event_data)
    elif isinstance(event_data, list):
        for item in event_data:
            if isinstance(item, dict):
                name = item.get("Name") or item.get("name") or item.get("Key")
                value = item.get("Value") or item.get("value")
                if name:
                    data[str(name)] = value
    # Include flat top-level fields that are not structural metadata.
    for key, value in obj.items():
        if isinstance(value, (str, int, float, bool)) and str(key).lower() not in _SKIP_FROM_DATA:
            data.setdefault(key, value)
    return data


def event_from_json_object(obj: Any, source_file: str | None = None) -> Event | None:
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("Event"), dict):
        obj = obj["Event"]

    system = obj.get("System") if isinstance(obj.get("System"), dict) else {}
    sys_map = _case_map(system)
    top_map = _case_map(obj)

    code = _lookup(sys_map, ["eventid"]) or _lookup(top_map, _CODE_KEYS)
    time_value = _lookup(sys_map, ["timecreated"]) or _lookup(top_map, _TIME_KEYS)
    if isinstance(time_value, dict):
        time_value = time_value.get("SystemTime") or time_value.get("systemTime")
    host = _as_text(_lookup(sys_map, ["computer"])) or _as_text(_lookup(top_map, _HOST_KEYS))
    provider = _as_text(_lookup(sys_map, ["provider"])) or _as_text(_lookup(top_map, _PROVIDER_KEYS))
    channel = _as_text(_lookup(sys_map, ["channel"])) or _as_text(_lookup(top_map, _CHANNEL_KEYS))
    level = _as_text(_lookup(sys_map, ["level"])) or _as_text(_lookup(top_map, _LEVEL_KEYS))
    record_id = _as_text(_lookup(sys_map, ["eventrecordid"])) or _as_text(_lookup(top_map, _RECORD_KEYS))

    if code is None and time_value is None:
        return None

    timestamp = parse_windows_time(_as_text(time_value)) if time_value else None
    data = _flatten_event_data(obj)
    return build_windows_event(
        event_code=code,
        timestamp=timestamp,
        host=host,
        provider=provider,
        data=data,
        raw_message=json.dumps(obj, default=str),
        source_file=source_file,
        channel=channel,
        level=level,
        record_id=record_id,
        log_format="windows_json",
    )


class WindowsJsonParser(BaseParser):
    name = "windows_json"
    log_format = "windows_json"
    os_source = "windows"
    extensions = {".json", ".jsonl", ".ndjson"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if lowered.endswith((".jsonl", ".ndjson")):
            return True
        text = sample.lstrip()
        if not text.startswith(("{", "[")):
            return False
        lowered_sample = text[:4000].lower()
        return "eventid" in lowered_sample or "event_id" in lowered_sample

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        line = line.strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        return event_from_json_object(obj, source_file)

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

        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None

        if document is not None:
            objects: list[Any]
            if isinstance(document, list):
                objects = document
            elif isinstance(document, dict):
                for key in ("Events", "events", "records", "Records"):
                    if isinstance(document.get(key), list):
                        objects = document[key]
                        break
                else:
                    objects = [document]
            else:
                objects = []
            for obj in objects:
                event = event_from_json_object(obj, str(path))
                if event:
                    result.events.append(event)
            result.lines_read = len(objects)
            if not result.events and not result.errors:
                result.errors.append("No Windows events found in JSON input")
            return result

        # Fall back to newline-delimited JSON.
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            result.lines_read += 1
            try:
                obj = json.loads(line)
                event = event_from_json_object(obj, str(path))
                if event:
                    result.events.append(event)
            except json.JSONDecodeError as exc:
                result.lines_skipped += 1
                if len(result.errors) < 50:
                    result.errors.append(f"{path}:{line_number}: invalid JSON ({exc})")
        return result
