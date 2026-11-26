"""Suspicious IP detection: denylist matches and failure frequency."""

from __future__ import annotations

from ..models import Event
from ..parsers.common import is_private_ip
from .base_rule import BaseRule, Finding, densest_window, events_to_evidence, bump_severity


class SuspiciousIPRule(BaseRule):
    rule_id = "suspicious_ip"
    category = "suspicious_ip"
    default_severity = "MEDIUM"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        denylist = {str(ip) for ip in self.config.get("denylist", [])}
        allowlist = {str(ip) for ip in self.config.get("allowlist", [])}
        failure_threshold = int(self.config.get("failure_threshold", 20))
        window = int(self.config.get("window_seconds", 600))

        findings: list[Finding] = []

        events_by_ip: dict[str, list[Event]] = {}
        failures_by_ip: dict[str, list[Event]] = {}
        for event in events:
            if not event.source_ip or event.source_ip in allowlist:
                continue
            events_by_ip.setdefault(event.source_ip, []).append(event)
            if event.auth_result == "failure":
                failures_by_ip.setdefault(event.source_ip, []).append(event)

        for ip, group in events_by_ip.items():
            if ip in denylist:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=bump_severity(self.severity, 1),
                        title=f"Denylisted IP observed: {ip}",
                        description=f"{ip} appears in {len(group)} events and matches the local denylist.",
                        explanation=(
                            "The IP is on the configured local IOC denylist. "
                            "Presence is an indicator that requires investigation."
                        ),
                        source_ip=ip,
                        event_count=len(group),
                        evidence=events_to_evidence(group),
                        recommended_actions=[
                            "Review all activity from this IP.",
                            "Confirm the denylist entry is still relevant.",
                            "Block the IP at the perimeter if activity is malicious.",
                        ],
                        dedup_key=f"suspicious_ip_denylist:{ip}",
                        context={"denylist": True},
                    )
                )

        if failure_threshold > 0:
            for ip, group in failures_by_ip.items():
                window_events = densest_window(group, window)
                if len(window_events) < failure_threshold:
                    continue
                private = is_private_ip(ip)
                classification = (
                    "private/internal" if private else "public/external"
                ) if private is not None else "unknown scope"
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=self.severity,
                        title=f"High failure volume from {ip}",
                        description=(
                            f"{len(window_events)} failed events from {ip} within "
                            f"{window} seconds ({classification} address)."
                        ),
                        explanation=(
                            "A high volume of failures from one address can "
                            "indicate malicious activity or a misconfigured client. "
                            "Private addresses are not automatically malicious."
                        ),
                        source_ip=ip,
                        event_count=len(window_events),
                        evidence=events_to_evidence(window_events),
                        recommended_actions=[
                            "Determine whether this is an internal or external host.",
                            "Correlate with authentication and firewall events.",
                            "Investigate the host if activity is unexpected.",
                        ],
                        dedup_key=f"suspicious_ip_frequency:{ip}",
                        context={
                            "failures": len(window_events),
                            "threshold": failure_threshold,
                            "window_seconds": window,
                            "private_ip": private,
                        },
                    )
                )
        return findings
