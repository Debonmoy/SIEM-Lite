"""Apache access and error log parsers."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Event
from .base_parser import BaseParser
from .common import normalize_ip, parse_apache_timestamp, parse_combined_access_line, to_int

_APACHE_ERROR = re.compile(
    r"^\[(?P<time>[^\]]+)\]\s+\[(?P<level>[a-zA-Z]+)\]"
    r"(?:\s+\[pid\s+\d+\])?"
    r"(?:\s+\[client\s+(?P<ip>[^\]:]+)(?::(?P<port>\d+))?\])?"
    r"\s*(?P<msg>.*)$"
)


def _parse_apache_error_time(text: str) -> str | None:
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(text.strip(), fmt).replace(
                tzinfo=timezone.utc
            ).isoformat()
        except ValueError:
            continue
    return None


class ApacheAccessParser(BaseParser):
    name = "apache_access"
    log_format = "apache_access"
    os_source = "unknown"
    extensions = {".log", ".txt"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if "apache" in lowered or "httpd" in lowered:
            return True
        first_lines = [ln for ln in sample.splitlines() if ln.strip()][:5]
        return any(parse_combined_access_line(ln) for ln in first_lines)

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        data = parse_combined_access_line(line)
        if not data:
            return None
        username = data.get("user")
        if username == "-":
            username = None
        return Event(
            timestamp=parse_apache_timestamp(data.get("time", "")),
            source_file=source_file,
            os_source=self.os_source,
            log_format=self.log_format,
            username=username,
            source_ip=normalize_ip(data.get("ip")),
            event_type="http_request",
            http_method=data.get("method"),
            http_status=data.get("status"),
            request_path=data.get("path"),
            user_agent=data.get("ua"),
            raw_message=line,
            extra={"server": "apache", "referer": data.get("referer")},
        )


class ApacheErrorParser(BaseParser):
    name = "apache_error"
    log_format = "apache_error"
    os_source = "unknown"
    extensions = {".log", ".txt"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if ("apache" in lowered or "httpd" in lowered) and "error" in lowered:
            return True
        first_lines = [ln for ln in sample.splitlines() if ln.strip()][:5]
        return any(_APACHE_ERROR.match(ln) and "[client" in ln for ln in first_lines)

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        match = _APACHE_ERROR.match(line)
        if not match:
            return None
        data = match.groupdict()
        return Event(
            timestamp=_parse_apache_error_time(data["time"]),
            source_file=source_file,
            os_source=self.os_source,
            log_format=self.log_format,
            source_ip=normalize_ip(data.get("ip")),
            source_port=to_int(data.get("port")),
            event_type="http_error",
            raw_message=line,
            extra={
                "server": "apache",
                "level": data.get("level"),
                "message": data.get("msg"),
            },
        )
