"""Shared parsing helpers: timestamps, IP/port normalisation, access logs."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$"
)
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.+)$"
)
_SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.+)$"
)
_PROGRAM = re.compile(
    r"^(?P<prog>[A-Za-z0-9_.\-/]+(?:\([^)]*\))?)"
    r"(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_syslog_timestamp(text: str, now: datetime | None = None) -> Optional[str]:
    """Parse ``Mon DD HH:MM:SS`` syslog timestamps (year inferred)."""
    match = _SYSLOG_TS.match(text.strip())
    if not match:
        return None
    month = MONTHS.get(match.group("mon"))
    if not month:
        return None
    now = now or datetime.now(timezone.utc)
    try:
        dt = datetime(
            now.year, month, int(match.group("day")),
            int(match.group("h")), int(match.group("m")), int(match.group("s")),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    # If the parsed date is in the future, assume it belongs to last year.
    if dt - now > timedelta(days=1):
        try:
            dt = dt.replace(year=now.year - 1)
        except ValueError:
            pass
    return dt.isoformat()


def parse_apache_timestamp(text: str) -> Optional[str]:
    """Parse ``10/Oct/2000:13:55:36 -0700`` style timestamps."""
    text = text.strip()
    try:
        dt = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return dt.isoformat()


def parse_windows_time(value: str | None) -> Optional[str]:
    """Parse Windows ``SystemTime`` values (7-digit fractional seconds, Z)."""
    if not value:
        return None
    text = value.strip()
    match = re.match(
        r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<frac>\d+))?"
        r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$",
        text,
    )
    if match:
        frac = (match.group("frac") or "0")[:6].ljust(6, "0")
        tz = match.group("tz") or "Z"
        if tz == "Z":
            tz = "+00:00"
        elif re.fullmatch(r"[+-]\d{4}", tz):
            tz = f"{tz[:3]}:{tz[3:]}"
        iso = f"{match.group('base')}.{frac}{tz}"
        try:
            dt = datetime.fromisoformat(iso)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    # Fallback: plain ISO without fractional part.
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def split_syslog_line(line: str) -> tuple[Optional[str], Optional[str], str]:
    """Split a syslog line into (raw_timestamp, host, remainder)."""
    match = _SYSLOG_LINE.match(line)
    if match:
        return match.group("ts"), match.group("host"), match.group("rest")
    match = _ISO_PREFIX.match(line)
    if match:
        return match.group("ts"), match.group("host"), match.group("rest")
    return None, None, line


def extract_program(rest: str) -> tuple[Optional[str], Optional[str], str]:
    """Extract ``program[pid]: message`` from the remainder of a syslog line."""
    match = _PROGRAM.match(rest)
    if match:
        return match.group("prog"), match.group("pid"), match.group("msg")
    return None, None, rest


def normalize_ip(value: str | None) -> Optional[str]:
    """Validate and normalise an IP address; return ``None`` if not valid."""
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    if not text or text in {"-", "unknown", "N/A"}:
        return None
    # Strip an IPv4-mapped IPv6 prefix while preserving a usable address.
    if text.lower().startswith("::ffff:") and "." in text:
        text = text[7:]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_private_ip(value: str | None) -> Optional[bool]:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return None


def to_int(value: str | int | None) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def parse_combined_access_line(line: str) -> Optional[dict]:
    """Parse an Apache/Nginx 'combined' access log line."""
    match = _ACCESS.match(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = to_int(data.get("status"))
    data["size"] = to_int(data.get("size"))
    return data


def localname(tag: str) -> str:
    """Strip an XML namespace from a tag name."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag
