"""Command-line interface for Log Analyzer & Mini SIEM."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

from .. import config
from ..analysis.risk_engine import RiskEngine
from ..collectors.file_collector import FileCollector
from ..collectors.linux_live_collector import LinuxLiveCollector
from ..database.db_manager import DBManager
from ..parsers.registry import ParserRegistry
from ..pipeline import AnalysisPipeline
from ..reports.html_report import default_report_path, generate_report
from ..utils.logger import get_logger, setup_logging
from ..utils.platform_detector import detect_platform, live_mode_notice

logger = get_logger("cli")

_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in __import__("os").environ
_RESET = "\033[0m"
_SEV_COLOR = {
    "INFO": "\033[96m",
    "LOW": "\033[92m",
    "MEDIUM": "\033[93m",
    "HIGH": "\033[91m",
    "CRITICAL": "\033[95m",
}
_BOLD = "\033[1m"


def colorize(text: str, color: str | None) -> str:
    if not _USE_COLOR or not color:
        return text
    return f"{color}{text}{_RESET}"


def banner() -> None:
    print(colorize("=" * 64, _BOLD))
    print(colorize(f"  {config.APP_NAME}  v{config.APP_VERSION}", _BOLD))
    print(f"  Author: {config.AUTHOR}")
    print(colorize("=" * 64, _BOLD))


def _cell(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    if len(text) > width:
        text = text[: max(0, width - 1)] + "…"
    return text.ljust(width)


def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    max_widths: Sequence[int] | None = None,
) -> None:
    """Render a simple aligned table. Cells may be (text, color) tuples."""
    prepared: list[list[tuple[str, str | None]]] = []
    for row in rows:
        cells: list[tuple[str, str | None]] = []
        for item in row:
            if isinstance(item, tuple) and len(item) == 2:
                cells.append((str(item[0]), item[1]))
            else:
                cells.append((str(item), None))
        prepared.append(cells)

    widths = [len(h) for h in headers]
    for row in prepared:
        for index, (text, _color) in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(text))
    if max_widths:
        widths = [min(w, m) for w, m in zip(widths, max_widths)]

    header_line = "  ".join(
        _cell(h, w) for h, w in zip(headers, widths)
    )
    print(colorize(header_line, _BOLD))
    print("  ".join("-" * w for w in widths))
    for row in prepared:
        parts = []
        for index, (text, color) in enumerate(row):
            if index >= len(widths):
                continue
            padded = _cell(text, widths[index])
            parts.append(colorize(padded, color))
        print("  ".join(parts))


def _severity_cell(severity: str) -> tuple[str, str | None]:
    return (severity, _SEV_COLOR.get(severity.upper()))


def _print_errors(errors: list[str], limit: int = 10) -> None:
    if not errors:
        return
    print(colorize(f"\nProcessing messages ({len(errors)}):", _BOLD))
    for error in errors[:limit]:
        print(f"  ! {error}")
    if len(errors) > limit:
        print(f"  … and {len(errors) - limit} more")


def _print_alerts(alerts: list[Any], limit: int = 50) -> None:
    if not alerts:
        print("\nNo alerts generated.")
        return
    print(colorize(f"\nAlerts ({len(alerts)}):", _BOLD))
    rows = []
    for alert in alerts[:limit]:
        rows.append(
            [
                alert.alert_id,
                _severity_cell(alert.severity),
                alert.category,
                alert.source_ip or "-",
                alert.username or "-",
                alert.event_count,
                alert.status,
                alert.title,
            ]
        )
    render_table(
        ["Alert ID", "Severity", "Category", "Source IP", "User", "Events", "Status", "Title"],
        rows,
        max_widths=[18, 9, 20, 16, 14, 7, 13, 48],
    )
    if len(alerts) > limit:
        print(f"… and {len(alerts) - limit} more (use 'alerts --limit')")


# --------------------------------------------------------------------- commands
def cmd_offline(args: argparse.Namespace, db_path: str | None) -> int:
    inputs: list[str] = list(args.file or []) + list(args.directory or [])
    if not inputs:
        print("error: provide --file and/or --directory", file=sys.stderr)
        return 2

    collector = FileCollector(inputs, recursive=not args.no_recursive)
    paths = collector.collect()
    for error in collector.errors:
        print(colorize(f"warning: {error}", "\033[93m"))
    if not paths:
        print("error: no readable log files found", file=sys.stderr)
        return 2

    banner()
    print(f"Mode      : Offline analysis")
    print(f"Database  : {config.get_db_path(db_path)}")
    print(f"Files     : {len(paths)}")
    print()

    db = DBManager(db_path)
    try:
        pipeline = AnalysisPipeline(db)
        registry = ParserRegistry()

        def progress(path: str, index: int, total: int) -> None:
            fmt = registry.detect_format_name(path)
            print(f"[{index}/{total}] {path}  (format: {fmt})")

        result = pipeline.analyze_paths(paths, fmt=args.format, progress=progress)
    finally:
        db.close()

    print()
    print(colorize("Analysis summary", _BOLD))
    print(f"  Events parsed      : {result.events_parsed}")
    print(f"  New events stored  : {result.events_inserted}")
    print(f"  Duplicates dropped : {result.duplicates_dropped}")
    print(f"  Findings           : {len(result.findings)}")
    print(f"  Alerts generated   : {result.alert_count}")
    print(f"  Session            : {result.session_id}")
    _print_alerts(result.alerts)
    _print_errors(result.errors)
    return 0


def cmd_live(args: argparse.Namespace, db_path: str | None) -> int:
    platform = detect_platform()
    if not platform.supports_live_monitoring:
        banner()
        print(live_mode_notice(platform))
        print("\nLive Linux monitoring is not available here.")
        print("Use offline mode instead, for example:")
        print("  python main.py offline --file /path/to/auth.log")
        print("  python main.py offline --file security.evtx")
        return 1

    collector = LinuxLiveCollector(
        extra_paths=args.source,
        poll_interval=args.interval,
        from_beginning=args.from_beginning,
        platform_info=platform,
    )
    sources = collector.discover_sources()
    banner()
    print(f"Mode      : Live Linux monitoring ({platform.description})")
    print(f"Database  : {config.get_db_path(db_path)}")
    print(f"Notice    : {live_mode_notice(platform)}")
    print()

    if not sources:
        print("No known log sources were found on this system.")
        print("Provide a source explicitly with --source /path/to/log")
        return 1

    rows = [
        [
            str(source.path),
            "yes" if source.readable else "no",
            source.parser_name or "-",
            source.reason or "",
        ]
        for source in sources
    ]
    render_table(["Log source", "Readable", "Parser", "Notes"], rows, max_widths=[46, 8, 18, 44])

    readable = [source for source in sources if source.readable]
    if not readable:
        print(
            "\nerror: none of the discovered log sources are readable.\n"
            "On Debian/Ubuntu add your user to the 'adm' group:\n"
            "  sudo usermod -aG adm $USER   (then log out and back in)\n"
            "Or run with appropriate privileges for the log files you need."
        )
        return 1

    db = DBManager(db_path)
    pipeline = AnalysisPipeline(db)
    session_id = pipeline.start_session(
        "live",
        f"Live monitoring ({platform.description})",
        [str(source.path) for source in readable],
    )
    rules = pipeline.rules_config
    max_window = 600
    for rule_cfg in rules.get("rules", {}).values():
        try:
            max_window = max(max_window, int(rule_cfg.get("window_seconds", 0)))
        except (TypeError, ValueError):
            continue

    print(f"\nLive session {session_id} started. Press Ctrl+C to stop.\n")
    deadline = time.time() + args.duration if args.duration else None
    buffer: list[Any] = []
    total_events = 0
    total_alerts = 0
    total_stored = 0
    last_flush = 0.0
    last_status = time.time()

    def flush(force: bool = False) -> None:
        nonlocal buffer, last_flush, total_alerts, total_stored
        if not buffer:
            return
        now = time.time()
        if not force and now - last_flush < 2 and len(buffer) < 200:
            return
        buffer = _trim_buffer(buffer, max_window)
        inserted, alerts = pipeline.process_events(buffer, session_id)
        total_stored += inserted
        for alert in alerts:
            total_alerts += 1
            sev = colorize(f"{alert.severity:8}", _SEV_COLOR.get(alert.severity))
            print(f"  [{sev}] {alert.title}  (IP: {alert.source_ip or '-'})")
        last_flush = now

    try:
        while True:
            new_events = collector.poll(readable)
            if new_events:
                buffer.extend(new_events)
                total_events += len(new_events)
                if getattr(args, "verbose", False):
                    for event in new_events:
                        print(
                            f"  event {event.timestamp or '-'} "
                            f"{event.source_ip or '-'} "
                            f"{event.event_type or '-'} "
                            f"{event.username or ''}".rstrip()
                        )
            flush()
            now = time.time()
            if now - last_status >= 15:
                print(
                    f"  … {total_events} events observed, "
                    f"{db.count_events(session_id)} stored, "
                    f"{total_alerts} alerts"
                )
                last_status = now
            if args.max_events and total_events >= args.max_events:
                print("\nReached --max-events limit.")
                break
            if deadline and time.time() >= deadline:
                print("\nReached --duration limit.")
                break
            time.sleep(collector.poll_interval)
    except KeyboardInterrupt:
        print("\nStopping live monitoring…")
    finally:
        flush(force=True)
        db.update_session(
            session_id,
            event_count=db.count_events(session_id),
            alert_count=db.count_alerts(session_id),
        )
        print(colorize("\nLive session summary", _BOLD))
        print(f"  Session           : {session_id}")
        print(f"  Events observed   : {total_events}")
        print(f"  New events stored : {total_stored}")
        print(f"  Duplicates skipped: {max(0, total_events - total_stored)}")
        print(f"  Alerts            : {total_alerts}")
        db.close()
    return 0


def _trim_buffer(buffer: list[Any], max_window: int) -> list[Any]:
    if not buffer:
        return buffer
    epochs = [e.timestamp_epoch for e in buffer if e.timestamp_epoch is not None]
    if not epochs:
        return buffer[-2000:]
    cutoff = max(epochs) - (max_window + 60)
    trimmed = [
        e for e in buffer if e.timestamp_epoch is None or e.timestamp_epoch >= cutoff
    ]
    return trimmed[-5000:]


def cmd_alerts(args: argparse.Namespace, db_path: str | None) -> int:
    db = DBManager(db_path)
    try:
        alerts = db.get_alerts(
            severity=args.severity,
            category=args.category,
            source_ip=args.ip,
            status=args.status,
            limit=args.limit,
        )
    finally:
        db.close()

    if args.json:
        print(json.dumps([alert.to_dict() for alert in alerts], indent=2, default=str))
        return 0

    banner()
    print(f"Alerts matching filters: {len(alerts)}")
    _print_alerts(alerts, limit=args.limit)
    return 0


def cmd_report(args: argparse.Namespace, db_path: str | None) -> int:
    db = DBManager(db_path)
    try:
        output = Path(args.output) if args.output else default_report_path()
        path = generate_report(
            db,
            output,
            title=args.title or f"{config.APP_NAME} — Security Report",
            event_limit=args.events,
        )
    finally:
        db.close()
    print(colorize("HTML report generated:", _BOLD), path)
    return 0


def cmd_status(args: argparse.Namespace, db_path: str | None) -> int:
    platform = detect_platform()
    db_file = config.get_db_path(db_path)
    db = DBManager(db_path)
    try:
        stats = db.overview_stats()
        sessions = db.get_sessions(limit=5)
        events = db.count_events()
        alerts = db.count_alerts()
    finally:
        db.close()

    banner()
    print(colorize("Environment", _BOLD))
    print(f"  Platform          : {platform.description} ({platform.system})")
    print(f"  WSL               : {'yes' if platform.is_wsl else 'no'}")
    print(f"  Live monitoring   : {'available' if platform.supports_live_monitoring else 'unavailable'}")
    print(f"  Live notice       : {live_mode_notice(platform)}")
    print()
    print(colorize("Database", _BOLD))
    print(f"  Path              : {db_file}")
    print(f"  Exists            : {'yes' if db_file.exists() else 'no'}")
    print(f"  Events            : {events}")
    print(f"  Alerts            : {alerts}")
    print(f"  Critical alerts   : {stats['critical_alerts']}")
    print(f"  High alerts       : {stats['high_alerts']}")
    print(f"  Open alerts       : {stats['open_alerts']}")
    print()
    print(colorize("Detection rules", _BOLD))
    rules = config.load_rules()
    rows = []
    for name, cfg in rules.get("rules", {}).items():
        details = []
        for key in ("threshold", "failure_threshold", "distinct_port_threshold", "failed_logon_threshold", "window_seconds"):
            if key in cfg:
                details.append(f"{key}={cfg[key]}")
        rows.append(
            [
                name,
                "yes" if cfg.get("enabled", True) else "no",
                cfg.get("severity", "-"),
                ", ".join(details) or "-",
            ]
        )
    render_table(["Rule", "Enabled", "Base severity", "Settings"], rows, max_widths=[26, 8, 14, 50])
    if sessions:
        print()
        print(colorize("Recent sessions", _BOLD))
        render_table(
            ["Session", "Created", "Mode", "Events", "Alerts", "Source"],
            [
                [s["session_id"], s["created_at"], s["mode"], s["event_count"], s["alert_count"], s["source_description"]]
                for s in sessions
            ],
            max_widths=[14, 22, 8, 8, 8, 50],
        )
    return 0


def cmd_rules(args: argparse.Namespace, db_path: str | None) -> int:
    rules = config.load_rules()
    if args.json:
        print(json.dumps(rules, indent=2))
        return 0
    banner()
    print(colorize("Configured detection rules", _BOLD))
    rows = []
    for name, cfg in rules.get("rules", {}).items():
        rows.append([name, "yes" if cfg.get("enabled", True) else "no", json.dumps(cfg, default=str)])
    render_table(["Rule", "Enabled", "Configuration"], rows, max_widths=[26, 8, 90])
    print(f"\nRule file: {config.get_rules_path()}")
    return 0


def cmd_dashboard(args: argparse.Namespace, db_path: str | None) -> int:
    from ..dashboard.app import run_dashboard

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            colorize(
                "warning: binding the dashboard to a non-local address exposes it "
                "to your network. There is no authentication.",
                "\033[93m",
            )
        )
    print(f"Starting dashboard at http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop.")
    run_dashboard(
        host=args.host,
        port=args.port,
        debug=args.debug,
        db_path=db_path,
    )
    return 0


# ----------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db", default=argparse.SUPPRESS, help="Path to the SQLite database file"
    )
    common.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="Verbose output",
    )

    parser = argparse.ArgumentParser(
        prog="main.py",
        description=f"{config.APP_NAME} — cross-platform log analysis and security monitoring.",
        epilog="Author: Debonmoy Pal",
        parents=[common],
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{config.APP_NAME} v{config.APP_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    offline = sub.add_parser(
        "offline", parents=[common], help="Analyze log files or directories offline"
    )
    offline.add_argument("--file", action="append", metavar="PATH", help="Log file to analyze (repeatable)")
    offline.add_argument("--directory", action="append", metavar="DIR", help="Directory of logs to analyze (repeatable)")
    offline.add_argument("--format", default="auto", help="Force a log format (default: auto-detect)")
    offline.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories")
    offline.set_defaults(func=cmd_offline)

    live = sub.add_parser(
        "live", parents=[common], help="Monitor live Linux log sources (Linux/WSL only)"
    )
    live.add_argument("--source", action="append", metavar="PATH", help="Additional log file to monitor (repeatable)")
    live.add_argument("--from-beginning", action="store_true", help="Read existing content instead of only new lines")
    live.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds (default 1.0)")
    live.add_argument("--duration", type=float, help="Stop after N seconds (useful for demos/tests)")
    live.add_argument("--max-events", type=int, help="Stop after N observed events")
    live.set_defaults(func=cmd_live)

    alerts = sub.add_parser("alerts", parents=[common], help="List stored alerts")
    alerts.add_argument("--severity", choices=config.SEVERITY_ORDER)
    alerts.add_argument("--category")
    alerts.add_argument("--ip", dest="ip")
    alerts.add_argument("--status", choices=config.ALERT_STATUSES)
    alerts.add_argument("--limit", type=int, default=50)
    alerts.add_argument("--json", action="store_true", help="Emit JSON")
    alerts.set_defaults(func=cmd_alerts)

    report = sub.add_parser("report", parents=[common], help="Generate a standalone HTML report")
    report.add_argument("--output", metavar="PATH", help="Output HTML path")
    report.add_argument("--title", help="Report title")
    report.add_argument("--events", type=int, default=100, help="Number of recent events to include")
    report.set_defaults(func=cmd_report)

    status = sub.add_parser("status", parents=[common], help="Show environment, database and rule status")
    status.set_defaults(func=cmd_status)

    rules = sub.add_parser("rules", parents=[common], help="Show configured detection rules")
    rules.add_argument("--json", action="store_true", help="Emit JSON")
    rules.set_defaults(func=cmd_rules)

    dashboard = sub.add_parser("dashboard", parents=[common], help="Start the optional web dashboard")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8080)
    dashboard.add_argument("--debug", action="store_true")
    dashboard.set_defaults(func=cmd_dashboard)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = getattr(args, "verbose", False)
    setup_logging(verbose=verbose, log_to_file=True)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    db_path = getattr(args, "db", None)
    try:
        return int(args.func(args, db_path) or 0)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI should report, not traceback-crash
        logger.error("Command failed: %s", exc)
        print(colorize(f"error: {exc}", "\033[91m"), file=sys.stderr)
        if verbose:
            import traceback

            traceback.print_exc()
        return 1
