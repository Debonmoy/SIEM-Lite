"""Flask routes for the optional HTML dashboard."""

from __future__ import annotations

import math
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import (
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from .. import config
from ..database.db_manager import DBManager
from ..pipeline import AnalysisPipeline
from ..utils.file_validator import (
    ValidationError,
    check_upload_size,
    safe_join,
    validate_upload_extension,
    validate_upload_name,
)

PER_PAGE = 50


def _db() -> DBManager:
    from flask import current_app

    return current_app.config["DB"]


def _epoch(value: str | None, end_of_day: bool = False) -> float | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    dt = dt.replace(tzinfo=timezone.utc)
    if end_of_day:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt.timestamp()


def _filters(args: Any) -> dict[str, str]:
    keys = [
        "source_ip", "username", "log_format", "os_source", "event_code",
        "search", "severity", "category", "status", "start", "end",
    ]
    return {key: args.get(key, "").strip() for key in keys if args.get(key, "").strip()}


def _page(args: Any) -> int:
    try:
        return max(1, int(args.get("page", 1)))
    except (TypeError, ValueError):
        return 1


def register_routes(app) -> None:
    db = app.config["DB"]

    @app.template_filter("sev_class")
    def sev_class(severity: str) -> str:
        return f"sev-{str(severity).upper()}"

    @app.template_filter("short")
    def short(value: Any, length: int = 160) -> str:
        text = "" if value is None else str(value)
        return text if len(text) <= length else text[: length - 1] + "…"

    @app.route("/")
    def index():
        stats = db.overview_stats()
        return render_template(
            "overview.html",
            stats=stats,
            severity=db.group_counts("alerts", "severity"),
            categories=db.group_counts("alerts", "category"),
            statuses=db.group_counts("alerts", "status"),
            top_ips=db.group_counts("events", "source_ip", limit=8),
            top_users=db.group_counts("events", "username", limit=8),
            formats=db.group_counts("events", "log_format", limit=8),
            source_types=db.group_counts("events", "source_type", limit=5),
            failed_time=db.failed_logins_over_time(limit=24),
            recent_alerts=db.get_alerts(limit=8),
            sessions=db.get_sessions(limit=6),
        )

    @app.route("/analytics")
    def analytics():
        return render_template(
            "analytics.html",
            stats=db.overview_stats(),
            severity=db.group_counts("alerts", "severity"),
            categories=db.group_counts("alerts", "category"),
            statuses=db.group_counts("alerts", "status"),
            top_ips=db.group_counts("events", "source_ip", limit=15),
            top_users=db.group_counts("events", "username", limit=15),
            event_ids=db.group_counts("events", "event_code", limit=20),
            formats=db.group_counts("events", "log_format", limit=20),
            os_sources=db.group_counts("events", "os_source", limit=10),
            failed_time=db.failed_logins_over_time(limit=48),
        )

    @app.route("/events")
    def events_view():
        filters = _filters(request.args)
        page = _page(request.args)
        start = _epoch(filters.get("start"))
        end = _epoch(filters.get("end"), end_of_day=True)
        query = {
            "source_ip": filters.get("source_ip") or None,
            "username": filters.get("username") or None,
            "log_format": filters.get("log_format") or None,
            "os_source": filters.get("os_source") or None,
            "event_code": filters.get("event_code") or None,
            "search": filters.get("search") or None,
            "start_epoch": start,
            "end_epoch": end,
        }
        total = db.count_events_filtered(**query)
        rows = db.get_events(limit=PER_PAGE, offset=(page - 1) * PER_PAGE, **query)
        pages = max(1, math.ceil(total / PER_PAGE))
        return render_template(
            "events.html",
            events=rows,
            total=total,
            page=page,
            pages=pages,
            filters=filters,
            formats=db.distinct_values("log_format"),
            os_sources=db.distinct_values("os_source"),
            event_codes=db.distinct_values("event_code"),
        )

    @app.route("/alerts")
    def alerts_view():
        filters = _filters(request.args)
        page = _page(request.args)
        query = {
            "severity": filters.get("severity") or None,
            "category": filters.get("category") or None,
            "source_ip": filters.get("source_ip") or None,
            "status": filters.get("status") or None,
            "search": filters.get("search") or None,
        }
        total = db.count_alerts_filtered(**query)
        rows = db.get_alerts(limit=PER_PAGE, offset=(page - 1) * PER_PAGE, **query)
        pages = max(1, math.ceil(total / PER_PAGE))
        return render_template(
            "alerts.html",
            alerts=rows,
            total=total,
            page=page,
            pages=pages,
            filters=filters,
            severities=config.SEVERITY_ORDER,
            statuses=config.ALERT_STATUSES,
            categories=[item["label"] for item in db.group_counts("alerts", "category")],
        )

    @app.route("/alerts/<alert_id>")
    def alert_detail(alert_id: str):
        alert = db.get_alert(alert_id)
        if alert is None:
            abort(404)
        return render_template(
            "alert_detail.html",
            alert=alert,
            statuses=config.ALERT_STATUSES,
        )

    @app.route("/alerts/<alert_id>/status", methods=["POST"])
    def update_alert_status(alert_id: str):
        status = (request.form.get("status") or "").strip().upper()
        note = (request.form.get("note") or "").strip() or None
        if status not in config.ALERT_STATUSES:
            flash(f"Invalid status: {status}", "error")
        elif not db.update_alert_status(alert_id, status, note):
            flash("Alert not found", "error")
        else:
            flash(f"Alert {alert_id} marked as {status}", "success")
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.route("/import", methods=["GET", "POST"])
    def import_logs():
        result = None
        errors: list[str] = []
        if request.method == "POST":
            uploads = [f for f in request.files.getlist("files") if f and f.filename]
            fmt = (request.form.get("format") or "auto").strip()
            if not uploads:
                errors.append("Select at least one file to analyze.")
            else:
                temp_dir = Path(tempfile.mkdtemp(prefix="minisiem_upload_"))
                saved: list[Path] = []
                try:
                    for index, storage in enumerate(uploads):
                        try:
                            name = validate_upload_name(storage.filename)
                            validate_upload_extension(name)
                            storage.stream.seek(0, 2)
                            size = storage.stream.tell()
                            storage.stream.seek(0)
                            check_upload_size(size)
                        except ValidationError as exc:
                            errors.append(f"{storage.filename}: {exc}")
                            continue
                        target = safe_join(temp_dir, name)
                        if target.exists():
                            target = target.with_name(
                                f"{target.stem}_{index}{target.suffix}"
                            )
                        storage.save(str(target))
                        saved.append(target)

                    if saved:
                        pipeline = AnalysisPipeline(
                            db=db, rules_config=app.config["RULES"]
                        )
                        try:
                            result = pipeline.analyze_paths(
                                saved,
                                fmt=None if fmt == "auto" else fmt,
                                mode="offline",
                                description=f"Dashboard upload ({len(saved)} file(s))",
                            )
                            errors.extend(result.errors)
                        except ValueError as exc:
                            errors.append(str(exc))
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)
        return render_template(
            "import.html",
            result=result,
            errors=errors,
            formats=app.config["REGISTRY"].available_formats,
            sessions=db.get_sessions(limit=8),
        )

    @app.route("/api/overview")
    def api_overview():
        return jsonify(db.overview_stats())

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "events": db.count_events(), "alerts": db.count_alerts()})

    @app.errorhandler(413)
    def too_large(_error):
        flash(
            f"Upload rejected: exceeds {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
            "error",
        )
        return (
            render_template(
                "import.html",
                result=None,
                errors=["Upload exceeds the configured size limit."],
                formats=app.config["REGISTRY"].available_formats,
                sessions=db.get_sessions(limit=8),
            ),
            413,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="Page not found"), 404
