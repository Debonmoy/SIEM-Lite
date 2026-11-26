"""Risk assessment: assigns final severity and explanation to findings.

Severity is a qualitative heuristic based on rule, occurrence count, time
window and event context. It is explicitly NOT a statistically validated
probability of compromise.
"""

from __future__ import annotations

from typing import Any

from ..config import load_rules
from ..detection.base_rule import (
    SEVERITY_LEVELS,
    Finding,
    bump_severity,
    severity_rank,
)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


class RiskEngine:
    def __init__(self, rules_config: dict[str, Any] | None = None):
        self.config = rules_config or load_rules()

    def assess(self, finding: Finding) -> tuple[str, str]:
        severity = finding.severity.upper()
        if severity not in SEVERITY_LEVELS:
            severity = "MEDIUM"
        reasons: list[str] = []
        context = finding.context or {}
        rule = finding.rule_id

        if rule == "ssh_brute_force":
            threshold = int(context.get("threshold", 10) or 10)
            failures = int(context.get("failures", 0))
            if threshold and failures >= threshold * 3:
                new = bump_severity(severity, 2)
                reasons.append(
                    f"volume is {failures} failures (>=3x threshold {threshold})"
                )
                severity = new
            elif threshold and failures >= threshold * 2:
                severity = bump_severity(severity, 1)
                reasons.append(
                    f"volume is {failures} failures (>=2x threshold {threshold})"
                )
            distinct = int(context.get("distinct_usernames", 0))
            ssh_config = self.config.get("rules", {}).get("ssh_brute_force", {})
            distinct_threshold = int(
                ssh_config.get("username_escalation_count", 3) or 3
            )
            if distinct_threshold > 0 and distinct >= distinct_threshold:
                severity = bump_severity(severity, 1)
                reasons.append(f"{distinct} distinct usernames targeted")

        elif rule in {"success_after_failures", "windows_success_after_failures"}:
            severity = max_severity(severity, "HIGH")
            reasons.append("successful authentication followed prior failures")

        elif rule == "windows_audit_cleared":
            severity = "CRITICAL"
            reasons.append("audit log clearing is a high-impact defense-evasion event")

        elif rule == "windows_account_lockout":
            severity = max_severity(severity, "HIGH")

        elif rule == "port_scan":
            ports = int(context.get("distinct_ports", 0))
            if ports >= 50:
                severity = bump_severity(severity, 1)
                reasons.append(f"{ports} distinct destination ports contacted")

        elif rule.startswith("web_attack") and rule != "web_auth_failures":
            matches = int(context.get("matches", 0))
            if matches >= 10:
                severity = bump_severity(severity, 1)
                reasons.append(f"{matches} matching requests observed")

        elif rule == "suspicious_ip" and context.get("denylist"):
            reasons.append("IP matches the local denylist")

        severity = max_severity(severity, finding.severity.upper())

        explanation = finding.explanation.strip()
        if reasons:
            explanation = (
                f"{explanation} Risk rationale: {'; '.join(reasons)}."
            ).strip()
        explanation = (
            f"{explanation} Severity is a heuristic risk indicator, not a "
            "statistically validated probability."
        ).strip()
        return severity, explanation
