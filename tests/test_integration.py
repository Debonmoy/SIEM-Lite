"""Integration tests: pipeline, CLI, dashboard, report, live collector."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

from siem.cli import commands
from siem.cli.commands import main
from siem.collectors.linux_live_collector import LinuxLiveCollector
from siem.dashboard.app import create_app
from siem.database.db_manager import DBManager
from siem.models import Event
from siem.pipeline import AnalysisPipeline
from siem.reports.html_report import generate_report
from siem.utils.platform_detector import PlatformInfo


def _sample_files(sample_dir: Path) -> list[Path]:
    return [
        sample_dir / "linux" / "auth.log",
        sample_dir / "linux" / "apache_access.log",
        sample_dir / "linux" / "firewall.log",
        sample_dir / "windows" / "security_events.json",
        sample_dir / "windows" / "new-user-security.evtx",
    ]


def test_pipeline_end_to_end(tmp_db, sample_dir):
    pipeline = AnalysisPipeline(tmp_db)
    result = pipeline.analyze_paths(_sample_files(sample_dir))
    assert result.events_parsed > 0
    assert result.events_inserted > 0
    assert result.errors == []
    rule_ids = {alert.rule_id for alert in result.alerts}
    assert "ssh_brute_force" in rule_ids
    assert "success_after_failures" in rule_ids
    assert "port_scan" in rule_ids
    assert "web_attack_sql_injection" in rule_ids
    assert "windows_audit_cleared" in rule_ids
    assert tmp_db.count_events() == result.events_inserted
    assert tmp_db.count_alerts() == result.alert_count

    # Re-running the same files must not duplicate events or open alerts.
    second = pipeline.analyze_paths(_sample_files(sample_dir))
    assert second.events_inserted == 0
    assert second.alerts == []


def test_cli_offline_alerts_and_report(tmp_path, sample_dir, capsys):
    db_path = tmp_path / "cli.db"
    code = main(["--db", str(db_path), "offline", "--file", str(sample_dir / "linux" / "auth.log")])
    assert code == 0
    output = capsys.readouterr().out
    assert "Analysis summary" in output
    assert "Alerts generated" in output

    code = main(["alerts", "--db", str(db_path), "--json"])
    assert code == 0
    alerts = json.loads(capsys.readouterr().out)
    assert isinstance(alerts, list) and alerts

    report_path = tmp_path / "report.html"
    code = main(["report", "--db", str(db_path), "--output", str(report_path)])
    assert code == 0
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Log Analyzer" in content
    assert "Security analytics" in content


def test_cli_status_and_rules(tmp_path, capsys):
    db_path = tmp_path / "status.db"
    assert main(["--db", str(db_path), "status"]) == 0
    assert "Environment" in capsys.readouterr().out
    assert main(["--db", str(db_path), "rules", "--json"]) == 0
    rules = json.loads(capsys.readouterr().out)
    assert "ssh_brute_force" in rules["rules"]


def test_dashboard_routes_and_upload(tmp_path, sample_dir):
    db_path = tmp_path / "dash.db"
    db = DBManager(db_path)
    AnalysisPipeline(db).analyze_paths([sample_dir / "linux" / "auth.log"])
    db.close()

    app = create_app(db_path)
    app.config["TESTING"] = True
    client = app.test_client()

    for url in ["/", "/analytics", "/events", "/alerts", "/import", "/api/overview", "/health"]:
        assert client.get(url).status_code == 200

    alerts_page = client.get("/alerts")
    assert b"Alert explorer" in alerts_page.data

    upload = {
        "format": "auto",
        "files": (
            io.BytesIO(
                b"Jan 15 10:00:00 h sshd[1]: Failed password for root "
                b"from 192.0.2.44 port 1 ssh2\n"
            ),
            "upload_auth.log",
        ),
    }
    response = client.post(
        "/import", data=upload, content_type="multipart/form-data", follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Analysis result" in response.data

    assert client.get("/alerts/DOES-NOT-EXIST").status_code == 404


def test_dashboard_alert_status(tmp_path, sample_dir):
    db_path = tmp_path / "dash2.db"
    db = DBManager(db_path)
    result = AnalysisPipeline(db).analyze_paths([sample_dir / "linux" / "auth.log"])
    alert_id = result.alerts[0].alert_id
    db.close()

    app = create_app(db_path)
    app.config["TESTING"] = True
    client = app.test_client()
    detail = client.get(f"/alerts/{alert_id}")
    assert detail.status_code == 200
    response = client.post(
        f"/alerts/{alert_id}/status",
        data={"status": "INVESTIGATING", "note": "checking"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"marked as INVESTIGATING" in response.data


def test_html_report(tmp_db, sample_dir):
    AnalysisPipeline(tmp_db).analyze_paths([sample_dir / "linux" / "auth.log"])
    output = generate_report(tmp_db, Path(tmp_db.db_path).parent / "report.html")
    assert output.exists()
    content = output.read_text(encoding="utf-8")
    assert "Security analytics" in content
    assert "Alerts (" in content


def test_live_collector_poll_and_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jan 15 10:00:00 h sshd[1]: Failed password for root from 192.0.2.44 port 1 ssh2\n",
        encoding="utf-8",
    )
    collector = LinuxLiveCollector(extra_paths=[str(log)], from_beginning=True)
    sources = [s for s in collector.discover_sources() if s.path == log]
    assert sources and sources[0].readable

    events = [e for e in collector.poll(sources) if e.source_file == str(log)]
    assert len(events) == 1
    assert events[0].source_type == "live"

    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            "Jan 15 10:00:05 h sshd[1]: Accepted password for root from 192.0.2.44 port 2 ssh2\n"
        )
    events = [e for e in collector.poll(sources) if e.source_file == str(log)]
    assert len(events) == 1
    assert events[0].auth_result == "success"

    rotated = tmp_path / "rotated.log"
    rotated.write_text(
        "Jan 15 10:00:10 h sshd[1]: Failed password for admin from 198.51.100.9 port 3 ssh2\n",
        encoding="utf-8",
    )
    os.replace(rotated, log)
    events = [e for e in collector.poll(sources) if e.source_file == str(log)]
    assert len(events) == 1
    assert events[0].source_ip == "198.51.100.9"


def test_live_cli_without_verbose_flag(tmp_path, monkeypatch, capsys):
    """Regression: --verbose uses SUPPRESS, so live mode must not assume it exists."""
    fake_event = Event(
        timestamp="2024-01-15T10:00:00+00:00",
        source_file="/tmp/fake.log",
        source_type="live",
        os_source="linux",
        log_format="ssh",
        username="root",
        source_ip="203.0.113.9",
        auth_result="failure",
        event_type="ssh_login_failed",
        raw_message="Failed password for root from 203.0.113.9 port 22 ssh2",
    ).ensure_derived()

    class FakeCollector:
        def __init__(self, *args, **kwargs):
            self.poll_interval = 0.01
            self.sources = [
                SimpleNamespace(
                    path=Path("/tmp/fake.log"),
                    readable=True,
                    parser_name="ssh",
                    reason=None,
                )
            ]

        def discover_sources(self):
            return self.sources

        def poll(self, sources=None):
            return [fake_event]

    monkeypatch.setattr(commands, "LinuxLiveCollector", FakeCollector)
    monkeypatch.setattr(
        commands,
        "detect_platform",
        lambda: PlatformInfo(
            system="linux",
            is_windows=False,
            is_linux=True,
            is_macos=False,
            is_wsl=True,
            supports_live_monitoring=True,
            live_unavailable_reason=None,
            description="WSL (test)",
        ),
    )

    db_path = tmp_path / "live.db"
    code = commands.main(
        [
            "--db",
            str(db_path),
            "live",
            "--source",
            "/tmp/fake.log",
            "--max-events",
            "1",
            "--interval",
            "0.01",
        ]
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "Command failed" not in output
    assert "Live session summary" in output
    assert "New events stored : 1" in output
    assert "Duplicates skipped: 0" in output

    db = DBManager(db_path)
    try:
        assert db.count_events() == 1
    finally:
        db.close()
