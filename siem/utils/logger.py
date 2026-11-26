"""Application logging.

We never log secrets or raw credentials. Parsed log content is only written to
the database, not to application log files, unless the caller explicitly asks.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from .. import config

_CONFIGURED = False


def setup_logging(verbose: bool = False, log_to_file: bool = False) -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("minisiem")
    if _CONFIGURED:
        if verbose:
            logger.setLevel(logging.DEBUG)
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler(stream=sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_to_file:
        try:
            config.LOG_DIR.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(
                config.LOG_DIR / "minisiem.log", encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            logger.warning("Could not create log file; continuing with stderr only")

    _CONFIGURED = True
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    base = logging.getLogger("minisiem")
    return base.getChild(name) if name else base


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
