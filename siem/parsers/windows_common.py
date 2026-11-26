"""Shared Windows event normalization used by XML, CSV, JSON and EVTX parsers."""

from __future__ import annotations

from typing import Any

from ..models import Event
from .common import normalize_ip, to_int

WINDOWS_EVENT_TYPES = {
    "4624": "logon_success",
    "4625": "logon_failure",
    "4634": "logoff",
    "4648": "explicit_credentials",
    "4672": "special_privileges",
    "4688": "process_creation",
    "4697": "service_installation",
    "4720": "account_created",
    "4728": "group_member_added_global",
    "4732": "group_member_added_local",
    "4740": "account_locked",
    "1102": "audit_log_cleared",
}

AUTH_RESULT_BY_CODE = {"4624": "success", "4625": "failure"}

_USERNAME_KEYS = [
    "TargetUserName",
    "SubjectUserName",
    "UserName",
    "AccountName",
    "SamAccountName",
    "user",
]
_IP_KEYS = [
    "IpAddress",
    "SourceNetworkAddress",
    "Address",
    "ClientAddress",
    "SourceIp",
    "source_ip",
]
_PORT_KEYS = ["IpPort", "SourcePort", "source_port"]
_DEST_IP_KEYS = ["DestinationAddress", "DestAddress"]
_PATH_KEYS = ["NewProcessName", "ProcessName", "ObjectName", "Image"]

_IGNORED = {"", "-", "n/a", "none", "null", "unknown"}


def normalize_event_code(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(int(float(text)))
    except (ValueError, TypeError):
        return text


def pick(data: dict[str, Any], keys: list[str]) -> str | None:
    """Return the first meaningful value for any of ``keys``."""
    for key in keys:
        if key not in data:
            continue
        value = data[key]
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value is None:
            continue
        text = str(value).strip()
        if text.lower() in _IGNORED:
            continue
        return text
    return None


def build_windows_event(
    *,
    event_code: Any,
    timestamp: str | None,
    host: str | None,
    provider: str | None,
    data: dict[str, Any],
    raw_message: str,
    source_file: str | None,
    channel: str | None = None,
    level: str | None = None,
    record_id: str | None = None,
    log_format: str = "windows_event",
) -> Event:
    code = normalize_event_code(event_code)
    event_type = WINDOWS_EVENT_TYPES.get(code or "", "windows_event")
    username = pick(data, _USERNAME_KEYS)
    source_ip = normalize_ip(pick(data, _IP_KEYS))
    source_port = to_int(pick(data, _PORT_KEYS))
    destination_ip = normalize_ip(pick(data, _DEST_IP_KEYS))
    request_path = None
    if code in {"4688", "4697", "1102"}:
        request_path = pick(data, _PATH_KEYS)

    return Event(
        timestamp=timestamp,
        source_file=source_file,
        os_source="windows",
        log_format=log_format,
        host=host,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        event_type=event_type,
        event_code=code,
        service=provider,
        auth_result=AUTH_RESULT_BY_CODE.get(code or ""),
        request_path=request_path,
        raw_message=raw_message,
        extra={
            "event_data": data,
            "channel": channel,
            "level": level,
            "record_id": record_id,
            "provider": provider,
        },
    )
