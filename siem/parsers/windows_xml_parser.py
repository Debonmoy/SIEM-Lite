"""Windows Event Log XML parser (exported ``<Event>`` documents)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Event
from .base_parser import BaseParser, ParseResult
from .common import localname, parse_windows_time
from .windows_common import build_windows_event


def _collect_event_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for elem in root.iter():
        tag = localname(elem.tag)
        if tag not in {"Data", "Binary"}:
            continue
        name = elem.get("Name") or elem.get("name")
        text = (elem.text or "").strip()
        if not name:
            continue
        if name in data and text and text not in data[name]:
            data[name] = f"{data[name]}; {text}"
        elif name not in data:
            data[name] = text
    return data


def event_from_xml_element(elem: ET.Element, source_file: str | None = None) -> Event | None:
    if localname(elem.tag) != "Event":
        return None

    event_code = None
    timestamp = None
    host = None
    provider = None
    channel = None
    level = None
    record_id = None

    for child in elem:
        tag = localname(child.tag)
        if tag == "System":
            for item in child:
                item_tag = localname(item.tag)
                if item_tag == "Provider":
                    provider = item.get("Name")
                elif item_tag == "EventID":
                    event_code = (item.text or "").strip() or None
                elif item_tag == "TimeCreated":
                    timestamp = parse_windows_time(item.get("SystemTime"))
                elif item_tag == "Computer":
                    host = (item.text or "").strip() or None
                elif item_tag == "Channel":
                    channel = (item.text or "").strip() or None
                elif item_tag == "Level":
                    level = (item.text or "").strip() or None
                elif item_tag == "EventRecordID":
                    record_id = (item.text or "").strip() or None

    data = _collect_event_data(elem)
    try:
        raw = ET.tostring(elem, encoding="unicode")
    except (TypeError, ValueError):
        raw = ""
    return build_windows_event(
        event_code=event_code,
        timestamp=timestamp,
        host=host,
        provider=provider,
        data=data,
        raw_message=raw,
        source_file=source_file,
        channel=channel,
        level=level,
        record_id=record_id,
        log_format="windows_xml",
    )


def events_from_xml_text(
    xml_text: str, source_file: str | None = None
) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    errors: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Support concatenated <Event> documents without a wrapping root.
        if xml_text.count("<Event") > 1:
            try:
                root = ET.fromstring(f"<Events>{xml_text}</Events>")
            except ET.ParseError as exc:
                return events, [f"Invalid XML: {exc}"]
        else:
            try:
                root = ET.fromstring(xml_text)
            except ET.ParseError as exc:
                return events, [f"Invalid XML: {exc}"]

    if localname(root.tag) == "Event":
        elements = [root]
    else:
        elements = [el for el in root.iter() if localname(el.tag) == "Event"]

    if not elements:
        errors.append("No <Event> elements found in XML input")
        return events, errors

    for element in elements:
        try:
            event = event_from_xml_element(element, source_file)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Failed to parse event element: {exc}")
            continue
        if event is not None:
            events.append(event)
    return events, errors


class WindowsXmlParser(BaseParser):
    name = "windows_xml"
    log_format = "windows_xml"
    os_source = "windows"
    extensions = {".xml"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        text = sample.lstrip()[:4000]
        if not text.startswith("<"):
            return False
        return "<Event" in text and ("EventID" in text or "SystemTime" in text)

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        events, _errors = events_from_xml_text(line, source_file)
        return events[0] if events else None

    def parse_file(self, path: str | Path) -> ParseResult:
        path = Path(path)
        result = ParseResult(parser_name=self.name, source_file=str(path))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.errors.append(f"Could not read {path}: {exc}")
            return result
        if not text.strip():
            result.errors.append(f"File is empty: {path}")
            return result
        events, errors = events_from_xml_text(text, str(path))
        result.events = events
        result.errors.extend(errors)
        result.lines_read = len(events)
        return result
