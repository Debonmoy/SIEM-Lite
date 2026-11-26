"""Linux authentication log parser (auth.log / secure)."""

from __future__ import annotations

import re

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

_SSHD_PATTERNS: list[tuple[re.Pattern, str, str | None]] = [
    (
        re.compile(
            r"Failed\s+\S+\s+for\s+(?:invalid\s+user\s+|user\s+)?(?P<user>\S+)\s+"
            r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
        ),
        "ssh_login_failed",
        "failure",
    ),
    (
        re.compile(
            r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+"
            r"port\s+(?P<port>\d+)"
        ),
        "ssh_login_success",
        "success",
    ),
    (
        re.compile(r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"),
        "ssh_invalid_user",
        "failure",
    ),
    (
        re.compile(
            r"maximum\s+authentication\s+attempts\s+exceeded\s+for\s+"
            r"(?:invalid\s+user\s+|user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
        ),
        "ssh_auth_attempts_exceeded",
        "failure",
    ),
    (
        re.compile(
            r"error:\s*PAM:\s*Authentication\s+failure\s+for\s+"
            r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
        ),
        "ssh_login_failed",
        "failure",
    ),
    (
        re.compile(
            r"Connection\s+closed\s+by\s+authenticating\s+user\s+"
            r"(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
        ),
        "ssh_connection_closed",
        None,
    ),
    (
        re.compile(
            r"Disconnected\s+from\s+(?:authenticating\s+|invalid\s+)?user\s+"
            r"(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
        ),
        "ssh_disconnect",
        None,
    ),
    (
        re.compile(r"Received\s+disconnect\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"),
        "ssh_disconnect",
        None,
    ),
    (
        re.compile(r"Connection\s+(?:closed|reset)\s+by\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"),
        "ssh_connection_closed",
        None,
    ),
]

_PAM_SSHD_FAIL = re.compile(
    r"pam_unix\(sshd:auth\):\s*authentication\s+failure", re.IGNORECASE
)
_PAM_RHOST = re.compile(r"rhost=(?P<ip>\S+)")
_PAM_USER = re.compile(r"\buser=(?P<user>\S+)")

_SUDO_CMD = re.compile(
    r"^(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S*)\s*;\s*)?"
    r"(?:PWD=(?P<pwd>\S*)\s*;\s*)?(?:USER=(?P<target>\S*)\s*;\s*)?"
    r"(?:COMMAND=(?P<cmd>.*))?$"
)
_SUDO_FAIL = re.compile(r"pam_unix\(sudo:auth\):\s*authentication\s+failure", re.I)
_SU_FAIL = re.compile(r"pam_unix\(su:auth\):\s*authentication\s+failure", re.I)
_SU_SUCCESS = re.compile(r"Successful\s+su\s+for\s+(?P<target>\S+)\s+by\s+(?P<user>\S+)")

_NEW_USER = re.compile(r"new\s+user:\s*name=(?P<user>[^,\s]+)")
_DEL_USER = re.compile(r"delete\s+user\s+'(?P<user>[^']+)'")
_NEW_GROUP = re.compile(r"new\s+group:\s*name=(?P<group>[^,\s]+)")
_ADD_TO_GROUP = re.compile(
    r"add\s+'(?P<user>[^']+)'\s+to\s+group\s+'(?P<group>[^']+)'"
)
_SESSION_NEW = re.compile(r"New\s+session\s+\S+\s+of\s+user\s+(?P<user>\S+)")

_AUTH_PROGRAMS = (
    "sshd",
    "sudo",
    "su",
    "systemd-logind",
    "login",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "gdm-password",
    "polkitd",
)


def parse_sshd_message(message: str) -> dict | None:
    """Extract fields from an sshd message; shared with the SSH parser."""
    for pattern, event_type, auth_result in _SSHD_PATTERNS:
        match = pattern.search(message)
        if match:
            groups = match.groupdict()
            return {
                "event_type": event_type,
                "auth_result": auth_result,
                "username": groups.get("user"),
                "source_ip": normalize_ip(groups.get("ip")),
                "source_port": to_int(groups.get("port")),
            }
    if _PAM_SSHD_FAIL.search(message):
        rhost = _PAM_RHOST.search(message)
        user = _PAM_USER.search(message)
        return {
            "event_type": "ssh_login_failed",
            "auth_result": "failure",
            "username": user.group("user") if user else None,
            "source_ip": normalize_ip(rhost.group("ip")) if rhost else None,
            "source_port": None,
        }
    return None


class AuthParser(BaseParser):
    name = "auth"
    log_format = "auth"
    os_source = "linux"
    extensions = {".log", ".txt"}

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if lowered.endswith(("auth.log", "secure", "auth.log.1")):
            return True
        sample_lower = sample.lower()
        markers = (
            "sshd[",
            "sshd:",
            "pam_unix",
            "sudo:",
            "su:",
            "authentication failure",
            "invalid user",
        )
        return any(marker in sample_lower for marker in markers)

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        raw_ts, host, rest = split_syslog_line(line)
        if raw_ts is None and host is None:
            return None
        program, pid, message = extract_program(rest)
        timestamp = parse_syslog_timestamp(raw_ts) if raw_ts else None
        if timestamp is None and raw_ts:
            timestamp = parse_windows_time(raw_ts)

        service = program.lower() if program else None
        event = Event(
            timestamp=timestamp,
            source_file=source_file,
            os_source=self.os_source,
            log_format=self.log_format,
            host=host,
            service=service,
            raw_message=line,
            event_type="auth_event",
        )
        if pid:
            event.extra["pid"] = pid

        msg = message or ""

        if service and service.startswith("pam_unix"):
            pam_service = re.match(r"pam_unix\((?P<svc>[^:)]+)", service)
            svc = pam_service.group("svc") if pam_service else service
            event.service = svc
            if "authentication failure" in msg.lower():
                user = _PAM_USER.search(msg)
                rhost = _PAM_RHOST.search(msg)
                event.auth_result = "failure"
                event.username = user.group("user") if user else None
                event.source_ip = normalize_ip(rhost.group("ip")) if rhost else None
                if svc == "sshd":
                    event.event_type = "ssh_login_failed"
                elif svc == "sudo":
                    event.event_type = "sudo_auth_failed"
                elif svc == "su":
                    event.event_type = "su_auth_failed"
                else:
                    event.event_type = "auth_failure"
                return event
            event.event_type = "auth_event"
            return event

        if service and service.startswith("sshd"):
            fields = parse_sshd_message(msg)
            if fields:
                event.event_type = fields["event_type"]
                event.auth_result = fields["auth_result"]
                event.username = fields["username"]
                event.source_ip = fields["source_ip"]
                event.source_port = fields["source_port"]
            else:
                event.event_type = "ssh_event"
            return event

        if service == "sudo" or "sudo:" in msg:
            fail = _SUDO_FAIL.search(msg)
            if fail:
                user = _PAM_USER.search(msg)
                event.event_type = "sudo_auth_failed"
                event.auth_result = "failure"
                event.username = user.group("user") if user else None
                return event
            match = _SUDO_CMD.search(msg)
            if match:
                event.event_type = "sudo_command"
                event.username = match.group("user")
                event.extra["target_user"] = match.group("target")
                event.extra["command"] = match.group("cmd")
                event.extra["tty"] = match.group("tty")
                return event
            event.event_type = "sudo_event"
            return event

        if service == "su" or _SU_FAIL.search(msg):
            if _SU_FAIL.search(msg):
                user = _PAM_USER.search(msg)
                event.event_type = "su_auth_failed"
                event.auth_result = "failure"
                event.username = user.group("user") if user else None
                return event
            match = _SU_SUCCESS.search(msg)
            if match:
                event.event_type = "su_success"
                event.auth_result = "success"
                event.username = match.group("user")
                event.extra["target_user"] = match.group("target")
                return event
            event.event_type = "su_event"
            return event

        for pattern, event_type in (
            (_NEW_USER, "user_created"),
            (_DEL_USER, "user_deleted"),
            (_ADD_TO_GROUP, "group_membership_change"),
        ):
            match = pattern.search(msg)
            if match:
                event.event_type = event_type
                event.username = match.groupdict().get("user")
                if "group" in match.groupdict():
                    event.extra["group"] = match.group("group")
                return event

        match = _NEW_GROUP.search(msg)
        if match:
            event.event_type = "group_created"
            event.extra["group"] = match.group("group")
            return event

        match = _SESSION_NEW.search(msg)
        if match:
            event.event_type = "session_new"
            event.username = match.group("user")
            return event

        if service in _AUTH_PROGRAMS:
            event.event_type = "auth_event"
            return event
        # Not an authentication-related line; let other parsers try.
        return None
