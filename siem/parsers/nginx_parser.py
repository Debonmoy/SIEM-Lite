"""Nginx access and error log parsers."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Event
from .base_parser import BaseParser
from .common import normalize_ip, parse_apache_timestamp, parse_combined_access_line, to_int

_NGINX_ERROR = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>[a-zA-Z]+)\]\s+"
    r"(?:\d+#\d+:\s+)?(?:\*\d+\s+)?(?P<msg>.*)$"
)
_NGINX_CLIENT = re.compile(r"client:\s*(?P<ip>[^,\s]+)")
_NGINX_REQUEST = re.compile(
    r'request:\s*"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"'
)


def _parse_nginx_error_time(text: str) -> str | None:
    try:
        return datetime.strptime(text.strip(), "%Y/%m/%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        ).isoformat()
    except ValueError:
        return None


class NginxAccessParser(BaseParser):
    name = "nginx_access"
    log_format = "nginx_access"
    os_source = "unknown"
    extensions = {".log", ".txt"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if "nginx" in lowered:
            return True
        return False

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
            extra={"server": "nginx", "referer": data.get("referer")},
        )


class NginxErrorParser(BaseParser):
    name = "nginx_error"
    log_format = "nginx_error"
    os_source = "unknown"
    extensions = {".log", ".txt"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if "nginx" in lowered and "error" in lowered:
            return True
        first_lines = [ln for ln in sample.splitlines() if ln.strip()][:5]
        return any(
            _NGINX_ERROR.match(ln) and "client:" in ln for ln in first_lines
        )

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        match = _NGINX_ERROR.match(line)
        if not match:
            return None
        data = match.groupdict()
        client = _NGINX_CLIENT.search(line)
        request = _NGINX_REQUEST.search(line)
        extra = {
            "server": "nginx",
            "level": data.get("level"),
            "message": data.get("msg"),
        }
        if request:
            extra["request_method"] = request.group("method")
        return Event(
            timestamp=_parse_nginx_error_time(data["time"]),
            source_file=source_file,
            os_source=self.os_source,
            log_format=self.log_format,
            source_ip=normalize_ip(client.group("ip")) if client else None,
            event_type="http_error",
            http_method=request.group("method") if request else None,
            request_path=request.group("path") if request else None,
            raw_message=line,
            extra=extra,
        )
