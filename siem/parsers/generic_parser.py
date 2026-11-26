"""Generic fallback parser for arbitrary text logs."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Event
from .base_parser import BaseParser
from .common import (
    extract_program,
    normalize_ip,
    parse_syslog_timestamp,
    parse_windows_time,
    split_syslog_line,
    to_int,
)

_ISO_AT_START = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_KV_SRC = re.compile(r"\bSRC=(?P<ip>[0-9a-fA-F:.]+)", re.IGNORECASE)
_KV_DST = re.compile(r"\bDST=(?P<ip>[0-9a-fA-F:.]+)", re.IGNORECASE)
_KV_SPT = re.compile(r"\bSPT=(?P<port>\d+)", re.IGNORECASE)
_KV_DPT = re.compile(r"\bDPT=(?P<port>\d+)", re.IGNORECASE)
_DENY_TOKENS = ("BLOCK", "DENY", "DENIED", "DROP", "REJECT")


class GenericParser(BaseParser):
    """Last-resort parser: keeps the raw message, extracts a timestamp if any."""

    name = "generic"
    log_format = "generic"
    os_source = "unknown"

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        return True

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        if not line.strip():
            return None
        raw_ts, host, rest = split_syslog_line(line)
        timestamp = None
        host_value = host
        service = None
        message = line

        if raw_ts:
            timestamp = parse_syslog_timestamp(raw_ts) or parse_windows_time(raw_ts)
            program, _pid, msg = extract_program(rest)
            service = program
            message = msg if program else rest
        else:
            match = _ISO_AT_START.match(line)
            if match:
                timestamp = parse_windows_time(match.group("ts"))
                message = line[match.end():].strip()

        event = Event(
            timestamp=timestamp,
            source_file=source_file,
            os_source=self.os_source,
            log_format=self.log_format,
            host=host_value,
            service=service,
            event_type="generic",
            raw_message=line,
            extra={"message": message} if message != line else {},
        )

        # Extract firewall/netfilter key-value fields when present.
        src = _KV_SRC.search(line)
        dst = _KV_DST.search(line)
        spt = _KV_SPT.search(line)
        dpt = _KV_DPT.search(line)
        if src or dst or dpt:
            event.event_type = "firewall_event"
            if src:
                event.source_ip = normalize_ip(src.group("ip"))
            if dst:
                event.destination_ip = normalize_ip(dst.group("ip"))
            if spt:
                event.source_port = to_int(spt.group("port"))
            if dpt:
                event.destination_port = to_int(dpt.group("port"))
            upper = line.upper()
            if any(token in upper for token in _DENY_TOKENS):
                event.auth_result = "failure"
            event.extra["firewall"] = True
        return event
