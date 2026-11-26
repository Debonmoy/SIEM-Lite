"""Detection rule, risk engine and alert manager tests."""

from __future__ import annotations

from siem.alerts.alert_manager import AlertManager
from siem.analysis.risk_engine import RiskEngine
from siem.detection.base_rule import Finding
from siem.detection.brute_force import SSHBruteForceRule, SuccessAfterFailuresRule
from siem.detection.port_scan import PortScanRule
from siem.detection.suspicious_ip import SuspiciousIPRule
from siem.detection.web_attacks import WebAttackRule
from siem.detection.windows_events import WindowsSecurityRule


def _ssh_failure(make_event, ts, ip="1.2.3.4", user="root"):
    return make_event(
        ts,
        log_format="ssh",
        os_source="linux",
        auth_result="failure",
        source_ip=ip,
        username=user,
        event_type="ssh_login_failed",
        raw_message="Failed password",
    )


def test_ssh_brute_force(make_event, rules):
    events = [
        _ssh_failure(make_event, f"2024-01-15T10:00:{i:02d}+00:00") for i in range(10)
    ]
    rule = SSHBruteForceRule(rules["rules"]["ssh_brute_force"])
    findings = rule.evaluate(events)
    assert len(findings) == 1
    assert findings[0].source_ip == "1.2.3.4"
    assert findings[0].event_count == 10
    assert findings[0].severity == "HIGH"


def test_ssh_brute_force_below_threshold(make_event, rules):
    events = [
        _ssh_failure(make_event, f"2024-01-15T10:00:{i:02d}+00:00") for i in range(9)
    ]
    assert SSHBruteForceRule(rules["rules"]["ssh_brute_force"]).evaluate(events) == []


def test_success_after_failures(make_event, rules):
    events = [
        _ssh_failure(make_event, f"2024-01-15T10:00:{i:02d}+00:00") for i in range(5)
    ]
    events.append(
        make_event(
            "2024-01-15T10:01:00+00:00",
            log_format="ssh",
            os_source="linux",
            auth_result="success",
            source_ip="1.2.3.4",
            username="root",
            event_type="ssh_login_success",
        )
    )
    findings = SuccessAfterFailuresRule(rules["rules"]["success_after_failures"]).evaluate(events)
    assert len(findings) == 1
    assert findings[0].event_count == 6
    assert findings[0].username == "root"


def test_port_scan(make_event, rules):
    events = [
        make_event(
            f"2024-01-15T10:00:{i:02d}+00:00",
            source_ip="9.9.9.9",
            destination_ip="10.0.0.1",
            destination_port=20 + i,
            event_type="firewall_event",
            auth_result="failure",
            log_format="generic",
        )
        for i in range(12)
    ]
    findings = PortScanRule(rules["rules"]["port_scan"]).evaluate(events)
    assert len(findings) == 1
    assert findings[0].context["distinct_ports"] == 12


def test_port_scan_requires_destination_ports(make_event, rules):
    events = [
        _ssh_failure(make_event, f"2024-01-15T10:00:{i:02d}+00:00") for i in range(20)
    ]
    assert PortScanRule(rules["rules"]["port_scan"]).evaluate(events) == []


def test_suspicious_ip_denylist_and_frequency(make_event):
    config = {
        "enabled": True,
        "severity": "MEDIUM",
        "failure_threshold": 20,
        "window_seconds": 600,
        "denylist": ["6.6.6.6"],
        "allowlist": ["127.0.0.1"],
    }
    events = [
        make_event(
            f"2024-01-15T10:00:{i:02d}+00:00",
            auth_result="failure",
            source_ip="6.6.6.6",
            log_format="ssh",
        )
        for i in range(20)
    ]
    findings = SuspiciousIPRule(config).evaluate(events)
    rules_ids = {finding.rule_id for finding in findings}
    assert "suspicious_ip" in rules_ids
    assert any(f.context.get("denylist") for f in findings)
    assert any(f.context.get("private_ip") is False for f in findings)


def test_suspicious_ip_allowlist_suppresses(make_event):
    config = {
        "enabled": True,
        "severity": "MEDIUM",
        "failure_threshold": 5,
        "window_seconds": 600,
        "denylist": ["127.0.0.1"],
        "allowlist": ["127.0.0.1"],
    }
    events = [
        make_event(
            f"2024-01-15T10:00:{i:02d}+00:00",
            auth_result="failure",
            source_ip="127.0.0.1",
            log_format="ssh",
        )
        for i in range(10)
    ]
    assert SuspiciousIPRule(config).evaluate(events) == []


def _web_event(make_event, ts, path, status=200, ip="1.2.3.4"):
    return make_event(
        ts,
        log_format="apache_access",
        os_source="unknown",
        source_ip=ip,
        http_method="GET",
        http_status=status,
        request_path=path,
        raw_message=f"GET {path} HTTP/1.1",
        event_type="http_request",
    )


def test_web_attack_indicators(make_event, rules):
    events = [
        _web_event(make_event, "2024-01-15T10:00:00+00:00", "/p?id=1 UNION SELECT password"),
        _web_event(make_event, "2024-01-15T10:00:01+00:00", "/?q=<script>alert(1)</script>"),
        _web_event(make_event, "2024-01-15T10:00:02+00:00", "/../../etc/passwd"),
        _web_event(make_event, "2024-01-15T10:00:03+00:00", "/.env"),
    ]
    findings = WebAttackRule(rules["rules"]["web_attack"]).evaluate(events)
    categories = {f.rule_id for f in findings}
    assert "web_attack_sql_injection" in categories
    assert "web_attack_xss" in categories
    assert "web_attack_directory_traversal" in categories
    assert "web_attack_sensitive_files" in categories


def test_web_auth_failure_burst(make_event, rules):
    events = [
        _web_event(
            make_event,
            f"2024-01-15T10:00:{i:02d}+00:00",
            "/admin",
            status=403,
            ip="2.2.2.2",
        )
        for i in range(20)
    ]
    findings = WebAttackRule(rules["rules"]["web_attack"]).evaluate(events)
    assert any(f.rule_id == "web_auth_failures" for f in findings)


def _win(make_event, code, ts, data=None, ip=None, user=None):
    return make_event(
        ts,
        os_source="windows",
        log_format="windows_json",
        event_code=str(code),
        source_ip=ip,
        username=user,
        event_type=f"event_{code}",
        extra={"event_data": data or {}},
    )


def test_windows_security_rules(make_event, rules):
    config = rules["rules"]["windows_security"]
    events = []
    for i in range(5):
        events.append(
            _win(
                make_event,
                "4625",
                f"2024-01-15T10:00:{i:02d}+00:00",
                {"TargetUserName": "administrator", "IpAddress": "203.0.113.5", "LogonType": "3"},
                ip="203.0.113.5",
                user="administrator",
            )
        )
    events.append(
        _win(
            make_event,
            "4624",
            "2024-01-15T10:01:00+00:00",
            {"TargetUserName": "administrator", "IpAddress": "203.0.113.5", "LogonType": "10"},
            ip="203.0.113.5",
            user="administrator",
        )
    )
    events += [
        _win(make_event, "4740", "2024-01-15T10:02:00+00:00", {"TargetUserName": "svc"}, user="svc"),
        _win(make_event, "1102", "2024-01-15T10:03:00+00:00", {"SubjectUserName": "attacker"}, user="attacker"),
        _win(make_event, "4720", "2024-01-15T10:04:00+00:00", {"TargetUserName": "evil"}, user="evil"),
        _win(make_event, "4728", "2024-01-15T10:05:00+00:00", {"MemberName": "evil", "TargetUserName": "Domain Admins"}, user="evil"),
        _win(make_event, "4648", "2024-01-15T10:06:00+00:00", {"SubjectUserName": "evil", "IpAddress": "203.0.113.5"}, ip="203.0.113.5", user="evil"),
        _win(make_event, "4672", "2024-01-15T10:07:00+00:00", {"SubjectUserName": "evil"}, user="evil"),
        _win(make_event, "4697", "2024-01-15T10:08:00+00:00", {"ServiceName": "EvilSvc"}, user="evil"),
        _win(
            make_event,
            "4688",
            "2024-01-15T10:09:00+00:00",
            {"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            user="evil",
        ),
    ]
    findings = WindowsSecurityRule(config).evaluate(events)
    ids = {f.rule_id for f in findings}
    expected = {
        "windows_failed_logon",
        "windows_account_lockout",
        "windows_audit_cleared",
        "windows_account_created",
        "windows_group_membership_change",
        "windows_explicit_credentials",
        "windows_special_privileges",
        "windows_service_installed",
        "windows_suspicious_process",
        "windows_remote_logon",
        "windows_success_after_failures",
    }
    assert expected <= ids


def test_risk_engine_escalates_brute_force():
    risk = RiskEngine()
    finding = Finding(
        rule_id="ssh_brute_force",
        category="brute_force",
        severity="HIGH",
        title="t",
        description="d",
        explanation="e",
        context={"threshold": 10, "failures": 30, "distinct_usernames": 5},
    )
    severity, explanation = risk.assess(finding)
    assert severity == "CRITICAL"
    assert "heuristic risk indicator" in explanation


def test_risk_engine_audit_cleared_critical():
    finding = Finding(
        rule_id="windows_audit_cleared",
        category="windows_audit",
        severity="HIGH",
        title="t",
        description="d",
    )
    severity, _ = RiskEngine().assess(finding)
    assert severity == "CRITICAL"


def test_alert_manager_dedup_and_status(tmp_db, make_event):
    manager = AlertManager(tmp_db)
    finding = Finding(
        rule_id="ssh_brute_force",
        category="brute_force",
        severity="HIGH",
        title="Brute force",
        description="many failures",
        source_ip="1.2.3.4",
        event_count=10,
        dedup_key="ssh_brute_force:1.2.3.4",
        evidence=[],
        recommended_actions=["investigate"],
    )
    first = manager.process_findings([finding])
    second = manager.process_findings([finding])
    assert len(first) == 1
    assert second == []
    assert tmp_db.count_alerts() == 1

    alert = first[0]
    assert manager.set_status(alert.alert_id, "INVESTIGATING", "looking")
    updated = manager.get_alert(alert.alert_id)
    assert updated.status == "INVESTIGATING"

    # Resolved alerts no longer suppress a new alert for the same pattern.
    manager.set_status(alert.alert_id, "RESOLVED")
    third = manager.process_findings([finding])
    assert len(third) == 1
    assert tmp_db.count_alerts() == 2
