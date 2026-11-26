"""Database persistence tests."""

from __future__ import annotations

from siem.alerts.alert_manager import AlertManager
from siem.detection.base_rule import Finding
from siem.models import Alert, utc_now_iso


def test_event_insert_and_dedup(tmp_db, make_event):
    event = make_event(
        "2024-01-15T10:00:00+00:00",
        source_ip="1.2.3.4",
        username="root",
        auth_result="failure",
        raw_message="Failed password",
        log_format="ssh",
    )
    assert tmp_db.insert_events([event]) == 1
    assert tmp_db.insert_events([event]) == 0
    assert tmp_db.count_events() == 1


def test_event_filters(tmp_db, make_event):
    tmp_db.insert_events(
        [
            make_event("2024-01-15T10:00:00+00:00", source_ip="1.2.3.4", username="root", log_format="ssh", raw_message="alpha"),
            make_event("2024-01-16T10:00:00+00:00", source_ip="5.6.7.8", username="bob", log_format="apache_access", raw_message="beta"),
            make_event("2024-01-17T10:00:00+00:00", source_ip="1.2.3.4", username="alice", log_format="auth", raw_message="gamma", event_code="4625", os_source="windows"),
        ]
    )
    assert len(tmp_db.get_events(source_ip="1.2.3.4")) == 2
    assert len(tmp_db.get_events(username="bob")) == 1
    assert len(tmp_db.get_events(log_format="ssh")) == 1
    assert len(tmp_db.get_events(search="beta")) == 1
    assert len(tmp_db.get_events(event_code="4625")) == 1
    assert len(tmp_db.get_events(os_source="windows")) == 1
    assert tmp_db.count_events_filtered(source_ip="1.2.3.4") == 2
    start = 1705312800  # 2024-01-15T10:00:00Z
    assert len(tmp_db.get_events(start_epoch=start, end_epoch=start + 1)) == 1


def test_alert_persistence_and_filters(tmp_db):
    alert = Alert(
        alert_id="ALT-TEST1",
        created_at=utc_now_iso(),
        rule_id="ssh_brute_force",
        category="brute_force",
        severity="HIGH",
        title="Brute force",
        description="desc",
        source_ip="1.2.3.4",
        username="root",
        event_count=10,
        evidence=[{"raw_message": "x"}],
        recommended_actions=["step"],
        dedup_key="ssh_brute_force:1.2.3.4",
    )
    assert tmp_db.insert_alert(alert)
    assert not tmp_db.insert_alert(alert)
    assert tmp_db.count_alerts() == 1
    assert tmp_db.get_alert("ALT-TEST1").severity == "HIGH"
    assert len(tmp_db.get_alerts(severity="HIGH")) == 1
    assert len(tmp_db.get_alerts(category="brute_force")) == 1
    assert len(tmp_db.get_alerts(source_ip="1.2.3.4")) == 1
    assert len(tmp_db.get_alerts(status="NEW")) == 1
    assert tmp_db.count_alerts_filtered(severity="HIGH") == 1
    assert tmp_db.find_open_alert_by_dedup("ssh_brute_force:1.2.3.4") is not None


def test_alert_status_update(tmp_db):
    alert = Alert(
        alert_id="ALT-TEST2",
        created_at=utc_now_iso(),
        rule_id="r",
        category="c",
        severity="MEDIUM",
        title="t",
        description="d",
    )
    tmp_db.insert_alert(alert)
    assert tmp_db.update_alert_status("ALT-TEST2", "INVESTIGATING", "note")
    assert tmp_db.get_alert("ALT-TEST2").status == "INVESTIGATING"
    try:
        tmp_db.update_alert_status("ALT-TEST2", "BOGUS")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid status should raise")


def test_sessions_and_stats(tmp_db, make_event):
    tmp_db.create_session("sess1", "offline", "test", ["a.log"])
    tmp_db.update_session("sess1", event_count=2, alert_count=1, errors=["e"])
    sessions = tmp_db.get_sessions()
    assert sessions[0]["session_id"] == "sess1"
    assert sessions[0]["event_count"] == 2
    assert sessions[0]["errors"] == ["e"]

    tmp_db.insert_events(
        [
            make_event("2024-01-15T10:00:00+00:00", source_ip="1.2.3.4", username="root", auth_result="failure", log_format="ssh"),
            make_event("2024-01-15T10:01:00+00:00", source_ip="1.2.3.4", username="root", auth_result="success", log_format="ssh"),
        ],
        session_id="sess1",
    )
    stats = tmp_db.overview_stats()
    assert stats["total_events"] == 2
    assert stats["failed_logins"] == 1
    assert stats["success_logins"] == 1
    assert stats["unique_ips"] == 1
    assert tmp_db.group_counts("events", "source_ip")[0]["label"] == "1.2.3.4"


def test_alert_manager_integration(tmp_db):
    manager = AlertManager(tmp_db)
    finding = Finding(
        rule_id="web_attack_sql_injection",
        category="web_attack",
        severity="HIGH",
        title="SQLi",
        description="d",
        source_ip="1.2.3.4",
        event_count=1,
        dedup_key="web_attack_sql_injection:1.2.3.4",
    )
    created = manager.process_findings([finding], session_id="sess1")
    assert len(created) == 1
    stored = tmp_db.get_alert(created[0].alert_id)
    assert stored.category == "web_attack"
    assert stored.session_id == "sess1"
    assert stored.explanation
