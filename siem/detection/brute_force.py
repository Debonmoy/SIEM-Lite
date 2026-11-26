"""SSH brute-force and successful-login-after-failures detection."""

from __future__ import annotations

import bisect

from ..models import Event
from .base_rule import BaseRule, Finding, densest_window, events_to_evidence, events_with_epoch

LINUX_AUTH_FORMATS = {"auth", "ssh"}


def _linux_failures(events: list[Event]) -> list[Event]:
    return [
        e
        for e in events
        if e.log_format in LINUX_AUTH_FORMATS
        and e.auth_result == "failure"
        and e.source_ip
    ]


def _linux_successes(events: list[Event]) -> list[Event]:
    return [
        e
        for e in events
        if e.log_format in LINUX_AUTH_FORMATS
        and e.auth_result == "success"
        and e.source_ip
    ]


class SSHBruteForceRule(BaseRule):
    rule_id = "ssh_brute_force"
    category = "brute_force"
    default_severity = "HIGH"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        threshold = int(self.config.get("threshold", 10))
        window = int(self.config.get("window_seconds", 300))
        if threshold <= 0:
            return []

        by_ip: dict[str, list[Event]] = {}
        for event in _linux_failures(events):
            by_ip.setdefault(event.source_ip, []).append(event)

        findings: list[Finding] = []
        for ip, group in by_ip.items():
            window_events = densest_window(group, window)
            if len(window_events) < threshold:
                continue
            usernames = {e.username for e in window_events if e.username}
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    title=f"Possible SSH brute-force from {ip}",
                    description=(
                        f"{len(window_events)} failed SSH authentications from {ip} "
                        f"within {window} seconds (threshold {threshold})."
                    ),
                    explanation=(
                        "Repeated failed authentication attempts may indicate a "
                        "password-guessing attack. This is a detection indicator, "
                        "not proof of compromise."
                    ),
                    source_ip=ip,
                    username=next(iter(usernames)) if len(usernames) == 1 else None,
                    event_count=len(window_events),
                    evidence=events_to_evidence(window_events),
                    recommended_actions=[
                        "Review successful logins from this IP around the same time.",
                        "Confirm the targeted accounts are legitimate and use strong passwords/keys.",
                        "Consider blocking the source IP at the firewall after verification.",
                        "Check for other activity from this IP in the event timeline.",
                    ],
                    dedup_key=f"ssh_brute_force:{ip}",
                    context={
                        "failures": len(window_events),
                        "threshold": threshold,
                        "window_seconds": window,
                        "distinct_usernames": len(usernames),
                    },
                )
            )
        return findings


class SuccessAfterFailuresRule(BaseRule):
    rule_id = "success_after_failures"
    category = "authentication_anomaly"
    default_severity = "HIGH"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        threshold = int(self.config.get("failure_threshold", 5))
        window = int(self.config.get("window_seconds", 600))
        if threshold <= 0:
            return []

        failures_by_ip: dict[str, list[Event]] = {}
        for event in _linux_failures(events):
            failures_by_ip.setdefault(event.source_ip, []).append(event)

        findings: list[Finding] = []
        for success in _linux_successes(events):
            failures = events_with_epoch(failures_by_ip.get(success.source_ip, []))
            if not failures:
                continue
            epochs = [e.timestamp_epoch for e in failures]
            if success.timestamp_epoch is None:
                continue
            right = bisect.bisect_right(epochs, success.timestamp_epoch)
            left = bisect.bisect_left(epochs, success.timestamp_epoch - window)
            matched = failures[left:right]
            if len(matched) < threshold:
                continue
            evidence = matched[-20:] + [success]
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    title=(
                        f"Successful login after {len(matched)} failures from "
                        f"{success.source_ip}"
                    ),
                    description=(
                        f"{len(matched)} failed authentications from "
                        f"{success.source_ip} were followed by a successful login "
                        f"for '{success.username or 'unknown'}' within {window} seconds."
                    ),
                    explanation=(
                        "A success following many failures is suspicious and may "
                        "indicate a successful password-guessing attempt. It can "
                        "also be a legitimate user who mistyped a password, so "
                        "verification is required."
                    ),
                    source_ip=success.source_ip,
                    username=success.username,
                    event_count=len(matched) + 1,
                    evidence=events_to_evidence(evidence, limit=21),
                    recommended_actions=[
                        "Verify with the account owner whether the login was legitimate.",
                        "Check what actions the account performed after logging in.",
                        "If unexpected, reset the account credentials and revoke sessions.",
                        "Review the source IP reputation and block if malicious.",
                    ],
                    dedup_key=f"success_after_failures:{success.source_ip}",
                    context={
                        "failures": len(matched),
                        "threshold": threshold,
                        "window_seconds": window,
                        "success_username": success.username,
                    },
                )
            )
        return findings
