"""End-to-end analysis pipeline shared by CLI, dashboard and live monitoring."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .alerts.alert_manager import AlertManager
from .analysis.event_normalizer import EventNormalizer
from .config import load_rules
from .database.db_manager import DBManager
from .detection.detection_engine import DetectionEngine
from .detection.base_rule import Finding
from .models import Alert, Event
from .parsers.registry import ParserRegistry
from .utils.logger import get_logger

logger = get_logger("pipeline")


@dataclass
class AnalysisResult:
    session_id: str
    mode: str
    files: list[str] = field(default_factory=list)
    events_parsed: int = 0
    events_inserted: int = 0
    duplicates_dropped: int = 0
    findings: list[Finding] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def alert_count(self) -> int:
        return len(self.alerts)


class AnalysisPipeline:
    def __init__(
        self,
        db: DBManager | None = None,
        rules_config: dict[str, Any] | None = None,
    ):
        self.db = db or DBManager()
        self.rules_config = rules_config or load_rules()
        self.registry = ParserRegistry()
        self.normalizer = EventNormalizer()
        self.engine = DetectionEngine(self.rules_config)
        self.alert_manager = AlertManager(self.db, self.rules_config)

    def start_session(
        self, mode: str, description: str, files: list[str] | None = None
    ) -> str:
        session_id = uuid.uuid4().hex[:12]
        self.db.create_session(session_id, mode, description, files or [])
        return session_id

    def analyze_paths(
        self,
        paths: Iterable[str | Path],
        *,
        fmt: str | None = None,
        mode: str = "offline",
        description: str | None = None,
        progress: Callable[[str, int, int], None] | None = None,
    ) -> AnalysisResult:
        path_list = [Path(p) for p in paths]
        description = description or f"{len(path_list)} file(s)"
        session_id = self.start_session(
            mode, description, [str(p) for p in path_list]
        )
        result = AnalysisResult(
            session_id=session_id,
            mode=mode,
            files=[str(p) for p in path_list],
        )

        parsed_events: list[Event] = []
        total = len(path_list)
        for index, path in enumerate(path_list, start=1):
            if progress:
                try:
                    progress(str(path), index, total)
                except Exception:  # noqa: BLE001 - progress UI must not break analysis
                    pass
            try:
                parse_result = self.registry.parse_file(path, fmt)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"{path}: {exc}")
                continue
            parsed_events.extend(parse_result.events)
            for error in parse_result.errors:
                result.errors.append(error)
            logger.info(
                "Parsed %s with %s: %d events, %d errors",
                path,
                parse_result.parser_name,
                len(parse_result.events),
                len(parse_result.errors),
            )

        result.events_parsed = len(parsed_events)
        normalized, duplicates = self.normalizer.normalize_many(parsed_events)
        result.duplicates_dropped = duplicates
        result.events_inserted = self.db.insert_events(normalized, session_id)

        result.findings = self.engine.run(normalized)
        result.alerts = self.alert_manager.process_findings(result.findings, session_id)

        self.db.update_session(
            session_id,
            event_count=result.events_parsed,
            alert_count=result.alert_count,
            errors=result.errors,
        )
        return result

    def process_events(
        self,
        events: list[Event],
        session_id: str | None = None,
        *,
        mode: str = "live",
    ) -> tuple[int, list[Alert]]:
        """Normalize, persist and analyze a batch of events (used by live mode)."""
        if not events:
            return 0, []
        normalized, _duplicates = self.normalizer.normalize_many(events)
        inserted = self.db.insert_events(normalized, session_id)
        findings = self.engine.run(normalized)
        alerts = self.alert_manager.process_findings(findings, session_id)
        if session_id:
            self.db.update_session(
                session_id,
                event_count=self.db.count_events(session_id),
                alert_count=self.db.count_alerts(session_id),
            )
        return inserted, alerts

    def close(self) -> None:
        self.db.close()
