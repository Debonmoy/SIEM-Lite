"""Port scanning detection based on destination-port evidence.

This rule only fires when events actually carry destination ports (for example
firewall/netfilter logs or network security events). It deliberately does not
claim to detect port scans from authentication logs, which contain no
destination-port information.
"""

from __future__ import annotations

from ..models import Event
from .base_rule import BaseRule, Finding, densest_window, events_to_evidence


class PortScanRule(BaseRule):
    rule_id = "port_scan"
    category = "network_scan"
    default_severity = "MEDIUM"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        distinct_threshold = int(self.config.get("distinct_port_threshold", 10))
        failed_threshold = int(self.config.get("failed_threshold", 5))
        window = int(self.config.get("window_seconds", 300))
        if distinct_threshold <= 0:
            return []

        by_ip: dict[str, list[Event]] = {}
        for event in events:
            if event.source_ip and event.destination_port is not None:
                by_ip.setdefault(event.source_ip, []).append(event)

        findings: list[Finding] = []
        for ip, group in by_ip.items():
            window_events = densest_window(group, window)
            if not window_events:
                continue
            ports = {e.destination_port for e in window_events if e.destination_port}
            if len(ports) < distinct_threshold:
                continue
            failed = [
                e
                for e in window_events
                if e.auth_result == "failure"
                or (e.event_type and any(
                    token in e.event_type.lower()
                    for token in ("deny", "denied", "drop", "block", "reject")
                ))
            ]
            if len(window_events) < failed_threshold and len(failed) < failed_threshold:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    title=f"Possible port scan from {ip}",
                    description=(
                        f"{ip} contacted {len(ports)} distinct destination ports "
                        f"in {len(window_events)} events within {window} seconds."
                    ),
                    explanation=(
                        "Connections to many distinct destination ports can "
                        "indicate reconnaissance or a port scan. Verify against "
                        "authorized vulnerability scanning activity."
                    ),
                    source_ip=ip,
                    event_count=len(window_events),
                    evidence=events_to_evidence(window_events),
                    recommended_actions=[
                        "Confirm whether the source IP belongs to an authorized scanner.",
                        "Review firewall logs for denied connection bursts.",
                        "Check whether any contacted service is unexpectedly exposed.",
                        "Consider rate-limiting or blocking the source if unauthorized.",
                    ],
                    dedup_key=f"port_scan:{ip}",
                    context={
                        "distinct_ports": len(ports),
                        "events": len(window_events),
                        "window_seconds": window,
                    },
                )
            )
        return findings
