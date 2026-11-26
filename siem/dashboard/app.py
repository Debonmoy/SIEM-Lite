"""Flask application factory for the Mini SIEM dashboard."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask

from .. import config
from ..database.db_manager import DBManager
from ..parsers.registry import ParserRegistry
from ..utils.platform_detector import detect_platform, live_mode_notice
from .routes import register_routes


def create_app(
    db_path: str | Path | None = None,
    rules_path: str | Path | None = None,
) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES
    app.config["DB"] = DBManager(db_path)
    app.config["RULES"] = config.load_rules(rules_path)
    app.config["REGISTRY"] = ParserRegistry()
    app.secret_key = os.environ.get("MINISIEM_SECRET_KEY") or secrets.token_hex(16)

    platform = detect_platform()

    @app.context_processor
    def inject_globals():
        return {
            "app_name": config.APP_NAME,
            "app_version": config.APP_VERSION,
            "author": config.AUTHOR,
            "platform_info": platform,
            "live_notice": live_mode_notice(platform),
            "max_upload_mb": config.MAX_UPLOAD_BYTES // (1024 * 1024),
        }

    register_routes(app)
    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    debug: bool = False,
    db_path: str | Path | None = None,
    rules_path: str | Path | None = None,
) -> None:
    app = create_app(db_path, rules_path)
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard()
