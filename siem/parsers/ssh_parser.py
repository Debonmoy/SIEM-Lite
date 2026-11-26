"""SSH authentication log parser (sshd-specific view)."""

from __future__ import annotations

from ..models import Event
from .auth_parser import AuthParser, parse_sshd_message
from .common import extract_program, parse_syslog_timestamp, split_syslog_line


class SSHParser(AuthParser):
    """Parses only sshd records.

    ``AuthParser`` already understands sshd; this parser exposes an
    SSH-focused view used when a file is explicitly an SSH log.
    """

    name = "ssh"
    log_format = "ssh"
    os_source = "linux"

    def can_parse(self, sample: str, filename: str | None = None) -> bool:
        lowered = (filename or "").lower()
        if "ssh" in lowered and "auth" not in lowered:
            return True
        sample_lower = sample.lower()
        if "sshd" not in sample_lower:
            return False
        # A full auth log also contains sudo/pam/useradd records; leave those
        # to AuthParser instead of hijacking the file as an SSH-only log.
        auth_markers = ("pam_unix", "sudo:", "useradd", "usermod", "su:")
        return not any(marker in sample_lower for marker in auth_markers)

    def parse_line(self, line: str, source_file: str | None = None) -> Event | None:
        raw_ts, host, rest = split_syslog_line(line)
        if raw_ts is None and host is None:
            return None
        program, pid, message = extract_program(rest)
        if not program or not program.lower().startswith("sshd"):
            return None
        fields = parse_sshd_message(message or "")
        if not fields:
            return None
        event = Event(
            timestamp=parse_syslog_timestamp(raw_ts) if raw_ts else None,
            source_file=source_file,
            os_source=self.os_source,
            log_format=self.log_format,
            host=host,
            service="sshd",
            event_type=fields["event_type"],
            auth_result=fields["auth_result"],
            username=fields["username"],
            source_ip=fields["source_ip"],
            source_port=fields["source_port"],
            raw_message=line,
        )
        if pid:
            event.extra["pid"] = pid
        return event
