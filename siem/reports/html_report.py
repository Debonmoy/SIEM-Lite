"""Standalone HTML report generation from the SQLite database."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..database.db_manager import DBManager
from ..models import utc_now_iso

TEMPLATE_DIR = Path(__file__).with_name("templates")


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _with_max(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return items


def generate_report(
    db: DBManager,
    output_path: str | Path,
    title: str = "Log Analyzer & Mini SIEM — Security Report",
    event_limit: int = 100,
    alert_limit: int = 500,
) -> Path:
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    context = {
        "title": title,
        "generated_at": utc_now_iso(),
        "overview": db.overview_stats(),
        "severity": db.group_counts("alerts", "severity"),
        "category": db.group_counts("alerts", "category"),
        "status": db.group_counts("alerts", "status"),
        "top_ips": db.group_counts("events", "source_ip", limit=10),
        "top_users": db.group_counts("events", "username", limit=10),
        "event_ids": db.group_counts("events", "event_code", limit=15),
        "formats": db.group_counts("events", "log_format", limit=15),
        "alerts": db.get_alerts(limit=alert_limit),
        "events": db.get_events(limit=event_limit),
        "sessions": db.get_sessions(limit=10),
    }

    template = _env().get_template("report.html")
    html = template.render(**context)
    output.write_text(html, encoding="utf-8")
    return output


def default_report_path(directory: str | Path | None = None) -> Path:
    base = Path(directory) if directory else Path.cwd() / "reports" / "output"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return base / f"minisiem_report_{stamp}.html"
