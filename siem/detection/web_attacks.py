"""Web attack indicator detection for Apache/Nginx logs."""

from __future__ import annotations

import re
from urllib.parse import unquote, unquote_plus

from ..models import Event
from .base_rule import BaseRule, Finding, densest_window, events_to_evidence

WEB_FORMATS = {"apache_access", "apache_error", "nginx_access", "nginx_error"}

DEFAULT_PATTERNS = {
    "sql_injection": [
        r"(?i)(\bunion\b[^\n]{0,40}\bselect\b)",
        r"(?i)(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)('\s*or\s*'1'\s*=\s*'1)",
        r"(?i)(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\()",
        r"(?i)(information_schema|xp_cmdshell)",
    ],
    "xss": [
        r"(?i)(<script[^>]*>)",
        r"(?i)(javascript\s*:)",
        r"(?i)(on(error|load|mouseover|click)\s*=)",
        r"(?i)(<img[^>]+src\s*=)",
    ],
    "directory_traversal": [
        r"(\.\./){1,}",
        r"(\.\.\\){1,}",
        r"(?i)(%2e%2e%2f|%2e%2e/|%252e%252e)",
        r"(?i)(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
    ],
    "sensitive_files": [
        r"(?i)((^|/)\.env([./?\s]|$)|/wp-config\.php|/config\.php|/\.git/|/\.htaccess)",
        r"(?i)(phpmyadmin|/admin/config|/server-status)",
        r"(?i)(id_rsa|authorized_keys|\.aws/credentials)",
    ],
}

CATEGORY_SEVERITY = {
    "sql_injection": "HIGH",
    "directory_traversal": "HIGH",
    "xss": "MEDIUM",
    "sensitive_files": "MEDIUM",
}

CATEGORY_LABEL = {
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting",
    "directory_traversal": "Directory traversal",
    "sensitive_files": "Sensitive file discovery",
}

RECOMMENDED = {
    "sql_injection": [
        "Inspect the full request and application response.",
        "Verify input validation and parameterized queries on the endpoint.",
        "Check database logs for unusual queries if the request succeeded.",
    ],
    "xss": [
        "Check whether the payload is reflected in responses.",
        "Verify output encoding and Content-Security-Policy.",
        "Review the client IP for other attack attempts.",
    ],
    "directory_traversal": [
        "Confirm the web server did not serve files outside the web root.",
        "Review web server error logs for successful traversal responses.",
        "Ensure path normalization and access controls are enforced.",
    ],
    "sensitive_files": [
        "Verify the requested sensitive file is not publicly accessible.",
        "Review access logs for a 2xx response to this request.",
        "Remove or protect exposed configuration/secret files.",
    ],
}


def _compile_patterns(config: dict) -> dict[str, list[re.Pattern]]:
    source = config.get("patterns") or DEFAULT_PATTERNS
    compiled: dict[str, list[re.Pattern]] = {}
    for category, patterns in source.items():
        items: list[re.Pattern] = []
        for pattern in patterns:
            try:
                items.append(re.compile(pattern))
            except re.error:
                continue
        if items:
            compiled[category] = items
    return compiled


class WebAttackRule(BaseRule):
    rule_id = "web_attack"
    category = "web_attack"
    default_severity = "HIGH"

    def evaluate(self, events: list[Event]) -> list[Finding]:
        patterns = _compile_patterns(self.config)
        auth_failure_threshold = int(self.config.get("auth_failure_threshold", 20))
        window = int(self.config.get("window_seconds", 300))

        web_events = [
            e
            for e in events
            if e.log_format in WEB_FORMATS
            or e.event_type in {"http_request", "http_error"}
            or e.http_status is not None
        ]

        matches: dict[tuple[str, str], list[Event]] = {}
        for event in web_events:
            haystack_raw = f"{event.request_path or ''} {event.raw_message or ''}"
            haystack_decoded = f"{unquote(haystack_raw)} {unquote_plus(haystack_raw)}"
            for category, compiled in patterns.items():
                if any(p.search(haystack_raw) or p.search(haystack_decoded) for p in compiled):
                    key = (category, event.source_ip or "unknown")
                    matches.setdefault(key, []).append(event)

        findings: list[Finding] = []
        for (category, ip), group in matches.items():
            severity = CATEGORY_SEVERITY.get(category, self.severity)
            label = CATEGORY_LABEL.get(category, category)
            findings.append(
                Finding(
                    rule_id=f"web_attack_{category}",
                    category="web_attack",
                    severity=severity,
                    title=f"{label} indicators from {ip}",
                    description=(
                        f"{len(group)} request(s) from {ip} matched {label} "
                        f"indicators in web server logs."
                    ),
                    explanation=(
                        "Request content matches known attack patterns. This is an "
                        "indicator; confirm whether the request was blocked and "
                        "whether the application is vulnerable."
                    ),
                    source_ip=None if ip == "unknown" else ip,
                    event_count=len(group),
                    evidence=events_to_evidence(group),
                    recommended_actions=RECOMMENDED.get(
                        category, ["Review the request and server response."]
                    ),
                    dedup_key=f"web_attack_{category}:{ip}",
                    context={"pattern_category": category, "matches": len(group)},
                )
            )

        if auth_failure_threshold > 0:
            denied: dict[str, list[Event]] = {}
            for event in web_events:
                if event.http_status in (401, 403) and event.source_ip:
                    denied.setdefault(event.source_ip, []).append(event)
            for ip, group in denied.items():
                window_events = densest_window(group, window)
                if len(window_events) < auth_failure_threshold:
                    continue
                findings.append(
                    Finding(
                        rule_id="web_auth_failures",
                        category="web_attack",
                        severity="MEDIUM",
                        title=f"Repeated HTTP 401/403 responses to {ip}",
                        description=(
                            f"{len(window_events)} HTTP 401/403 responses to {ip} "
                            f"within {window} seconds."
                        ),
                        explanation=(
                            "Repeated authorization failures may indicate access "
                            "attempts against protected resources, brute forcing, "
                            "or a misconfigured client."
                        ),
                        source_ip=ip,
                        event_count=len(window_events),
                        evidence=events_to_evidence(window_events),
                        recommended_actions=[
                            "Review which protected paths are being requested.",
                            "Check for any successful (2xx) requests from this IP.",
                            "Consider rate-limiting repeated unauthorized requests.",
                        ],
                        dedup_key=f"web_auth_failures:{ip}",
                        context={
                            "responses": len(window_events),
                            "threshold": auth_failure_threshold,
                            "window_seconds": window,
                        },
                    )
                )
        return findings
