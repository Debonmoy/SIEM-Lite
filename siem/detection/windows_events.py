"""Windows Security event detection rules."""

from __future__ import annotations

import bisect
import os

from ..models import Event
from ..parsers.common import is_private_ip
from .base_rule import (
    BaseRule,
    Finding,
    bump_severity,
    densest_window,
    events_to_evidence,
    events_with_epoch,
)

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "wmic.exe",
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "psexec.exe",
    "psexesvc.exe",
    "bitsadmin.exe",
    "cscript.exe",
    "wscript.exe",
    "nltest.exe",
    "vssadmin.exe",
    "bcdedit.exe",
    "schtasks.exe",
}

_EMPTY = {"", "-", "n/a", "none", "null"}


def _is_empty(value: object) -> bool:
    if value is None:
        return True
    return str(value).strip().lower() in _EMPTY


def _is_windows(event: Event) -> bool:
    return event.os_source == "windows" or (event.log_format or "").startswith("windows")


def _data(event: Event) -> dict:
    data = event.extra.get("event_data") if event.extra else None
    return data if isinstance(data, dict) else {}


def _field(event: Event, *keys: str) -> str | None:
    data = _data(event)
    for key in keys:
        value = data.get(key)
        if not _is_empty(value):
            return str(value).strip()
    lowered = {str(k).lower(): v for k, v in data.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if not _is_empty(value):
            return str(value).strip()
    return None


class WindowsSecurityRule(BaseRule):
    rule_id = "windows_security"
    category = "windows_security"
    default_severity = "MEDIUM"

    def _sev(self, code: str, default: str = "MEDIUM") -> str:
        mapping = self.config.get("rule_severities", {}) or {}
        return str(mapping.get(code, default)).upper()

    def evaluate(self, events: list[Event]) -> list[Finding]:
        windows_events = [e for e in events if _is_windows(e)]
        if not windows_events:
            return []
        findings: list[Finding] = []
        findings.extend(self._failed_logons(windows_events))
        findings.extend(self._lockouts(windows_events))
        findings.extend(self._audit_cleared(windows_events))
        findings.extend(self._account_created(windows_events))
        findings.extend(self._group_changes(windows_events))
        findings.extend(self._explicit_credentials(windows_events))
        findings.extend(self._special_privileges(windows_events))
        findings.extend(self._service_installations(windows_events))
        findings.extend(self._suspicious_processes(windows_events))
        findings.extend(self._remote_logons(windows_events))
        findings.extend(self._success_after_failures(windows_events))
        return findings

    def _failed_logons(self, events: list[Event]) -> list[Finding]:
        threshold = int(self.config.get("failed_logon_threshold", 5))
        window = int(self.config.get("window_seconds", 600))
        if threshold <= 0:
            return []
        by_key: dict[str, list[Event]] = {}
        for event in events:
            if event.event_code == "4625":
                key = event.source_ip or event.username or "unknown"
                by_key.setdefault(key, []).append(event)
        findings: list[Finding] = []
        for key, group in by_key.items():
            window_events = densest_window(group, window)
            if len(window_events) < threshold:
                continue
            severity = self._sev("4625", "MEDIUM")
            if len(window_events) >= threshold * 2:
                severity = bump_severity(severity, 1)
            findings.append(
                Finding(
                    rule_id="windows_failed_logon",
                    category="windows_auth",
                    severity=severity,
                    title=f"Repeated Windows failed logons ({key})",
                    description=(
                        f"{len(window_events)} Windows failed logon events (4625) "
                        f"for {key} within {window} seconds (threshold {threshold})."
                    ),
                    explanation=(
                        "Repeated failed Windows logons may indicate password "
                        "guessing, a stale credential, or a locked account. "
                        "Context determines whether this is malicious."
                    ),
                    source_ip=window_events[-1].source_ip,
                    username=window_events[-1].username,
                    event_count=len(window_events),
                    evidence=events_to_evidence(window_events),
                    recommended_actions=[
                        "Identify the source host/account and confirm whether it is expected.",
                        "Check for a subsequent successful logon (4624) from the same source.",
                        "Review account lockout (4740) events.",
                        "Reset credentials if the activity is unauthorized.",
                    ],
                    dedup_key=f"windows_failed_logon:{key}",
                    context={
                        "event_code": "4625",
                        "failures": len(window_events),
                        "threshold": threshold,
                        "window_seconds": window,
                    },
                )
            )
        return findings

    def _lockouts(self, events: list[Event]) -> list[Finding]:
        groups: dict[str, list[Event]] = {}
        for event in events:
            if event.event_code == "4740":
                key = event.username or event.host or "unknown"
                groups.setdefault(key, []).append(event)
        findings = []
        for key, group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_account_lockout",
                    category="windows_account",
                    severity=self._sev("4740", "HIGH"),
                    title=f"Windows account locked out: {key}",
                    description=f"{len(group)} account lockout event(s) for {key}.",
                    explanation=(
                        "Account lockouts can result from brute-force attempts or "
                        "from a user repeatedly entering a wrong password."
                    ),
                    source_ip=group[-1].source_ip,
                    username=group[-1].username,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Contact the account owner to confirm the failed attempts.",
                        "Check for failed logons (4625) preceding the lockout.",
                        "If malicious, reset the password and review source hosts.",
                    ],
                    dedup_key=f"windows_account_lockout:{key}",
                    context={"event_code": "4740"},
                )
            )
        return findings

    def _audit_cleared(self, events: list[Event]) -> list[Finding]:
        groups: dict[str, list[Event]] = {}
        for event in events:
            if event.event_code == "1102":
                groups.setdefault(event.host or "unknown", []).append(event)
        findings = []
        for host, group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_audit_cleared",
                    category="windows_audit",
                    severity=self._sev("1102", "CRITICAL"),
                    title=f"Windows audit log cleared on {host}",
                    description=(
                        f"The Security audit log was cleared {len(group)} time(s) "
                        f"on {host}. This can indicate defense evasion."
                    ),
                    explanation=(
                        "Clearing the audit log destroys evidence. It is a strong "
                        "indicator that warrants immediate investigation, though it "
                        "can occasionally be done by authorized maintenance."
                    ),
                    source_ip=group[-1].source_ip,
                    username=group[-1].username,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Determine who cleared the log and whether it was authorized.",
                        "Preserve remaining logs and forward them to a central system.",
                        "Review activity immediately before the log was cleared.",
                        "Check other hosts for similar audit-clearing events.",
                    ],
                    dedup_key=f"windows_audit_cleared:{host}",
                    context={"event_code": "1102"},
                )
            )
        return findings

    def _account_created(self, events: list[Event]) -> list[Finding]:
        groups: dict[str, list[Event]] = {}
        for event in events:
            if event.event_code == "4720":
                groups.setdefault(event.username or "unknown", []).append(event)
        findings = []
        for user, group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_account_created",
                    category="windows_account",
                    severity=self._sev("4720", "MEDIUM"),
                    title=f"Windows user account created: {user}",
                    description=f"User account '{user}' was created ({len(group)} event(s)).",
                    explanation=(
                        "New accounts are legitimate in many workflows but are also "
                        "used by attackers for persistence. Verify authorization."
                    ),
                    source_ip=group[-1].source_ip,
                    username=user,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Confirm the account creation was authorized.",
                        "Review the account's group memberships and logon activity.",
                        "Disable and remove the account if it was not authorized.",
                    ],
                    dedup_key=f"windows_account_created:{user}",
                    context={"event_code": "4720"},
                )
            )
        return findings

    def _group_changes(self, events: list[Event]) -> list[Finding]:
        groups: dict[tuple[str, str], list[Event]] = {}
        for event in events:
            if event.event_code in {"4728", "4732"}:
                member = _field(event, "MemberName", "MemberSid") or "unknown"
                group_name = _field(event, "GroupName", "TargetUserName") or "unknown"
                groups.setdefault((member, group_name), []).append(event)
        findings = []
        for (member, group_name), group in groups.items():
            code = group[-1].event_code or "4728"
            findings.append(
                Finding(
                    rule_id="windows_group_membership_change",
                    category="windows_account",
                    severity=self._sev(code, "MEDIUM"),
                    title=f"{member} added to {group_name}",
                    description=(
                        f"Member '{member}' was added to group '{group_name}' "
                        f"({len(group)} event(s), event {code})."
                    ),
                    explanation=(
                        "Security group changes can grant elevated privileges and "
                        "are a common persistence technique. Verify authorization."
                    ),
                    source_ip=group[-1].source_ip,
                    username=member,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Verify the group change was authorized.",
                        "Review the actor account and the new member's activity.",
                        "Revert the membership if it was not authorized.",
                    ],
                    dedup_key=f"windows_group_membership:{group_name}:{member}",
                    context={"event_code": code, "group": group_name, "member": member},
                )
            )
        return findings

    def _explicit_credentials(self, events: list[Event]) -> list[Finding]:
        groups: dict[tuple[str, str], list[Event]] = {}
        for event in events:
            if event.event_code == "4648":
                key = (event.username or "unknown", event.source_ip or "unknown")
                groups.setdefault(key, []).append(event)
        findings = []
        for (user, ip), group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_explicit_credentials",
                    category="windows_auth",
                    severity=self._sev("4648", "MEDIUM"),
                    title=f"Logon with explicit credentials by {user}",
                    description=(
                        f"{len(group)} event(s) show explicit credential use by "
                        f"'{user}' from {ip}."
                    ),
                    explanation=(
                        "Explicit credential logons are normal for administration "
                        "but can indicate lateral movement when unexpected."
                    ),
                    source_ip=None if ip == "unknown" else ip,
                    username=None if user == "unknown" else user,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Confirm the explicit credential use was expected.",
                        "Identify the target host and service.",
                        "Investigate further if the account should not perform this action.",
                    ],
                    dedup_key=f"windows_explicit_credentials:{user}:{ip}",
                    context={"event_code": "4648"},
                )
            )
        return findings

    def _special_privileges(self, events: list[Event]) -> list[Finding]:
        groups: dict[str, list[Event]] = {}
        for event in events:
            if event.event_code == "4672":
                groups.setdefault(event.username or "unknown", []).append(event)
        findings = []
        for user, group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_special_privileges",
                    category="windows_privilege",
                    severity=self._sev("4672", "LOW"),
                    title=f"Special privileges assigned to {user}",
                    description=(
                        f"{len(group)} event(s) show special privileges assigned "
                        f"to '{user}'."
                    ),
                    explanation=(
                        "Administrative logons routinely receive special privileges. "
                        "Treat this as context; investigate if the account or host is "
                        "unexpected."
                    ),
                    source_ip=group[-1].source_ip,
                    username=None if user == "unknown" else user,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Confirm the account is authorized for administrative access.",
                        "Correlate with logon events from unusual sources.",
                    ],
                    dedup_key=f"windows_special_privileges:{user}",
                    context={"event_code": "4672"},
                )
            )
        return findings

    def _service_installations(self, events: list[Event]) -> list[Finding]:
        groups: dict[tuple[str, str], list[Event]] = {}
        for event in events:
            if event.event_code == "4697":
                service = _field(event, "ServiceName", "ImagePath") or "unknown"
                groups.setdefault((event.host or "unknown", service), []).append(event)
        findings = []
        for (host, service), group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_service_installed",
                    category="windows_persistence",
                    severity=self._sev("4697", "MEDIUM"),
                    title=f"Service installed on {host}: {service}",
                    description=f"Service '{service}' was installed on {host} ({len(group)} event(s)).",
                    explanation=(
                        "Service installation is a common persistence mechanism. "
                        "Verify the service is legitimate and expected."
                    ),
                    source_ip=group[-1].source_ip,
                    username=group[-1].username,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Verify the service binary path and signer.",
                        "Confirm the installation was authorized.",
                        "Remove the service if it is malicious.",
                    ],
                    dedup_key=f"windows_service_installed:{host}:{service}",
                    context={"event_code": "4697", "service": service},
                )
            )
        return findings

    def _suspicious_processes(self, events: list[Event]) -> list[Finding]:
        groups: dict[tuple[str, str], list[Event]] = {}
        for event in events:
            if event.event_code != "4688":
                continue
            process = _field(event, "NewProcessName", "Image", "ProcessName")
            if not process:
                continue
            basename = os.path.basename(process.replace("\\", "/")).lower()
            if basename not in SUSPICIOUS_PROCESSES:
                continue
            groups.setdefault((event.host or "unknown", basename), []).append(event)
        findings = []
        for (host, process), group in groups.items():
            findings.append(
                Finding(
                    rule_id="windows_suspicious_process",
                    category="windows_process",
                    severity=self._sev("4688", "INFO"),
                    title=f"Potentially risky process on {host}: {process}",
                    description=(
                        f"Process '{process}' was created {len(group)} time(s) on "
                        f"{host}. It is commonly used for administration and by "
                        f"attackers."
                    ),
                    explanation=(
                        "This process name is frequently associated with scripting "
                        "or lateral movement but is also used legitimately. Review "
                        "the command line and parent process."
                    ),
                    source_ip=group[-1].source_ip,
                    username=group[-1].username,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Review the process command line and parent process.",
                        "Confirm the process activity was expected on this host.",
                        "Investigate further if the command line is obfuscated or suspicious.",
                    ],
                    dedup_key=f"windows_suspicious_process:{host}:{process}",
                    context={"event_code": "4688", "process": process},
                )
            )
        return findings

    def _remote_logons(self, events: list[Event]) -> list[Finding]:
        groups: dict[tuple[str, str, str], list[Event]] = {}
        for event in events:
            if event.event_code != "4624":
                continue
            logon_type = _field(event, "LogonType")
            if logon_type not in {"3", "10"}:
                continue
            if logon_type == "3" and is_private_ip(event.source_ip) is not False:
                continue
            key = (
                event.username or "unknown",
                event.source_ip or "unknown",
                logon_type,
            )
            groups.setdefault(key, []).append(event)
        findings = []
        for (user, ip, logon_type), group in groups.items():
            kind = "RDP/remote interactive" if logon_type == "10" else "network"
            findings.append(
                Finding(
                    rule_id="windows_remote_logon",
                    category="windows_auth",
                    severity=self._sev("4624", "MEDIUM"),
                    title=f"Remote Windows logon by {user} from {ip}",
                    description=(
                        f"{len(group)} successful {kind} logon(s) (type {logon_type}) "
                        f"by '{user}' from {ip}."
                    ),
                    explanation=(
                        "Remote logons from external addresses can be legitimate "
                        "but deserve review, especially for privileged accounts."
                    ),
                    source_ip=None if ip == "unknown" else ip,
                    username=None if user == "unknown" else user,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=[
                        "Confirm the remote logon was expected.",
                        "Review the account's subsequent activity.",
                        "Restrict remote access if it is not required.",
                    ],
                    dedup_key=f"windows_remote_logon:{user}:{ip}:{logon_type}",
                    context={"event_code": "4624", "logon_type": logon_type},
                )
            )
        return findings

    def _success_after_failures(self, events: list[Event]) -> list[Finding]:
        threshold = int(self.config.get("failed_logon_threshold", 5))
        window = int(self.config.get("window_seconds", 600))
        if threshold <= 0:
            return []
        failures_by_ip: dict[str, list[Event]] = {}
        for event in events:
            if event.event_code == "4625" and event.source_ip:
                failures_by_ip.setdefault(event.source_ip, []).append(event)
        findings = []
        for success in events:
            if success.event_code != "4624" or not success.source_ip:
                continue
            failures = events_with_epoch(failures_by_ip.get(success.source_ip, []))
            if not failures or success.timestamp_epoch is None:
                continue
            epochs = [e.timestamp_epoch for e in failures]
            right = bisect.bisect_right(epochs, success.timestamp_epoch)
            left = bisect.bisect_left(epochs, success.timestamp_epoch - window)
            matched = failures[left:right]
            if len(matched) < threshold:
                continue
            findings.append(
                Finding(
                    rule_id="windows_success_after_failures",
                    category="windows_auth",
                    severity="HIGH",
                    title=(
                        f"Windows logon success after {len(matched)} failures from "
                        f"{success.source_ip}"
                    ),
                    description=(
                        f"{len(matched)} failed logons (4625) from "
                        f"{success.source_ip} preceded a successful logon (4624) "
                        f"for '{success.username or 'unknown'}' within {window} seconds."
                    ),
                    explanation=(
                        "A success after repeated failures may indicate a successful "
                        "password-guessing attempt. Verify with the account owner."
                    ),
                    source_ip=success.source_ip,
                    username=success.username,
                    event_count=len(matched) + 1,
                    evidence=events_to_evidence(matched[-20:] + [success], limit=21),
                    recommended_actions=[
                        "Verify the successful logon with the account owner.",
                        "Review actions performed after the logon.",
                        "Reset credentials if the activity is unauthorized.",
                    ],
                    dedup_key=f"windows_success_after_failures:{success.source_ip}",
                    context={
                        "event_code": "4624",
                        "failures": len(matched),
                        "threshold": threshold,
                        "window_seconds": window,
                    },
                )
            )
        return findings
