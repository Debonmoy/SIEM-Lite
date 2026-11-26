"""Central configuration for the Mini SIEM application.

Configuration is layered:
1. Built-in defaults (defined here).
2. JSON rule file (``config/detection_rules.json`` by default).
3. Environment overrides (``MINISIEM_DB``, ``MINISIEM_RULES``).

The rule engine is intentionally independent from the parsers: parsers only
produce normalized events, and detection reads rule configuration from here.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

APP_NAME = "Log Analyzer & Mini SIEM"
APP_SHORT_NAME = "miniSIEM"
APP_VERSION = "1.0.0"
AUTHOR = "Debonmoy Pal"

# Repository root = parent of the ``siem`` package directory.
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_RULES_PATH = DEFAULT_CONFIG_DIR / "detection_rules.json"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "minisiem.db"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports" / "output"
LOG_DIR = PROJECT_ROOT / "logs"

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}

ALERT_STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]

# Hard safety limits for imports / uploads.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_EVENTS_PER_IMPORT = 5_000_000

# Built-in defaults used when the JSON file is missing or incomplete.
DEFAULT_RULES: dict[str, Any] = {
    "version": 1,
    "severity_order": SEVERITY_ORDER,
    "rules": {
        "ssh_brute_force": {
            "enabled": True,
            "severity": "HIGH",
            "threshold": 10,
            "window_seconds": 300,
            "username_escalation_count": 3,
        },
        "success_after_failures": {
            "enabled": True,
            "severity": "HIGH",
            "failure_threshold": 5,
            "window_seconds": 600,
        },
        "port_scan": {
            "enabled": True,
            "severity": "MEDIUM",
            "distinct_port_threshold": 10,
            "failed_threshold": 5,
            "window_seconds": 300,
        },
        "suspicious_ip": {
            "enabled": True,
            "severity": "MEDIUM",
            "failure_threshold": 20,
            "window_seconds": 600,
            "denylist": [],
            "allowlist": ["127.0.0.1", "::1"],
        },
        "web_attack": {
            "enabled": True,
            "severity": "HIGH",
            "auth_failure_threshold": 20,
            "window_seconds": 300,
            "patterns": {},
        },
        "windows_security": {
            "enabled": True,
            "failed_logon_threshold": 5,
            "window_seconds": 600,
            "rule_severities": {
                "4625": "MEDIUM",
                "4648": "MEDIUM",
                "4672": "LOW",
                "4688": "INFO",
                "4697": "MEDIUM",
                "4720": "MEDIUM",
                "4728": "MEDIUM",
                "4732": "MEDIUM",
                "4740": "HIGH",
                "1102": "CRITICAL",
            },
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into a copy of ``base``."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_rules(path: str | Path | None = None) -> dict[str, Any]:
    """Load and merge rule configuration, falling back to defaults."""
    rules_path = Path(
        path or os.environ.get("MINISIEM_RULES", DEFAULT_RULES_PATH)
    ).expanduser()
    config = copy.deepcopy(DEFAULT_RULES)
    if rules_path.is_file():
        try:
            with rules_path.open("r", encoding="utf-8") as handle:
                user_rules = json.load(handle)
            if not isinstance(user_rules, dict):
                raise ValueError("rule configuration must be a JSON object")
            config = _deep_merge(config, user_rules)
        except (OSError, ValueError, json.JSONDecodeError):
            # A broken user config must not crash the tool; fall back to defaults.
            pass
    return config


def get_db_path(explicit: str | Path | None = None) -> Path:
    raw = explicit or os.environ.get("MINISIEM_DB") or DEFAULT_DB_PATH
    return Path(raw).expanduser().resolve()


def get_rules_path() -> Path:
    return Path(os.environ.get("MINISIEM_RULES", DEFAULT_RULES_PATH)).expanduser()
