"""Alert lifecycle management with simple deduplication/correlation."""

from __future__ import annotations

import uuid
from typing import Any

from ..analysis.risk_engine import RiskEngine
from ..config import load_rules
from ..database.db_manager import DBManager
from ..detection.base_rule import Finding
from ..models import Alert, utc_now_iso
from ..utils.logger import get_logger

logger = get_logger("alerts")


def new_alert_id() -> str:
    return f"ALT-{uuid.uuid4().hex[:12]}"


class AlertManager:
    def __init__(
        self,
        db: DBManager,
        rules_config: dict[str, Any] | None = None,
    ):
        self.db = db
        self.config = rules_config or load_rules()
        self.risk = RiskEngine(self.config)

    def build_alert(self, finding: Finding, session_id: str | None = None) -> Alert:
        severity, explanation = self.risk.assess(finding)
        return Alert(
            alert_id=new_alert_id(),
            created_at=utc_now_iso(),
            updated_at=utc_now_iso(),
            rule_id=finding.rule_id,
            category=finding.category,
            severity=severity,
            title=finding.title,
            description=finding.description,
            event_count=finding.event_count,
            source_ip=finding.source_ip,
            username=finding.username,
            status="NEW",
            explanation=explanation,
            evidence=finding.evidence,
            recommended_actions=finding.recommended_actions,
            dedup_key=finding.dedup_key or f"{finding.rule_id}:{finding.source_ip or 'global'}",
            session_id=session_id,
        )

    def process_findings(
        self, findings: list[Finding], session_id: str | None = None
    ) -> list[Alert]:
        created: list[Alert] = []
        for finding in findings:
            try:
                alert = self.build_alert(finding, session_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to build alert for %s: %s", finding.rule_id, exc)
                continue

            existing = self.db.find_open_alert_by_dedup(alert.dedup_key)
            if existing is not None:
                # Correlate with the open alert instead of creating duplicates.
                if alert.event_count > existing.event_count:
                    self.db.update_alert_progress(
                        existing.alert_id, alert.event_count
                    )
                continue

            if self.db.insert_alert(alert):
                created.append(alert)
        return created

    # Convenience read/update helpers used by CLI and dashboard.
    def list_alerts(self, **filters: Any) -> list[Alert]:
        return self.db.get_alerts(**filters)

    def get_alert(self, alert_id: str) -> Alert | None:
        return self.db.get_alert(alert_id)

    def set_status(self, alert_id: str, status: str, note: str | None = None) -> bool:
        return self.db.update_alert_status(alert_id, status, note)

    def stats(self) -> dict[str, Any]:
        return self.db.overview_stats()
