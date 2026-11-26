"""Detection engine: orchestrates independent detection rules."""

from __future__ import annotations

from typing import Any

from ..config import load_rules
from ..models import Event
from ..utils.logger import get_logger
from .base_rule import BaseRule, Finding
from .brute_force import SSHBruteForceRule, SuccessAfterFailuresRule
from .port_scan import PortScanRule
from .suspicious_ip import SuspiciousIPRule
from .web_attacks import WebAttackRule
from .windows_events import WindowsSecurityRule

logger = get_logger("detection")


class DetectionEngine:
    def __init__(self, rules_config: dict[str, Any] | None = None):
        self.config = rules_config or load_rules()
        self.rules: list[BaseRule] = self._build_rules()

    def _build_rules(self) -> list[BaseRule]:
        cfg = self.config.get("rules", {})
        candidates: list[BaseRule] = [
            SSHBruteForceRule(cfg.get("ssh_brute_force")),
            SuccessAfterFailuresRule(cfg.get("success_after_failures")),
            PortScanRule(cfg.get("port_scan")),
            SuspiciousIPRule(cfg.get("suspicious_ip")),
            WebAttackRule(cfg.get("web_attack")),
            WindowsSecurityRule(cfg.get("windows_security")),
        ]
        return [rule for rule in candidates if rule.enabled]

    def run(self, events: list[Event]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            try:
                findings.extend(rule.evaluate(events))
            except Exception as exc:  # noqa: BLE001 - one rule must not break others
                logger.warning("Detection rule '%s' failed: %s", rule.rule_id, exc)
        return findings

    def rule_ids(self) -> list[str]:
        return [rule.rule_id for rule in self.rules]
