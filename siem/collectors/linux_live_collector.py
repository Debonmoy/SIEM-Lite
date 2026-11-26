"""Live Linux log monitoring with rotation handling.

Only Linux (native or WSL) exposes these sources. On Windows the caller must
use offline analysis instead.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..models import Event
from ..parsers.registry import ParserRegistry
from ..utils.platform_detector import PlatformInfo, detect_platform
from .base_collector import BaseCollector

DEFAULT_SOURCES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
]


@dataclass
class LiveSource:
    path: Path
    readable: bool
    parser_name: str | None = None
    reason: str | None = None


class LinuxLiveCollector(BaseCollector):
    def __init__(
        self,
        extra_paths: list[str | Path] | None = None,
        poll_interval: float = 1.0,
        from_beginning: bool = False,
        platform_info: PlatformInfo | None = None,
    ):
        super().__init__()
        self.platform = platform_info or detect_platform()
        self.poll_interval = max(0.2, float(poll_interval))
        self.from_beginning = from_beginning
        self.extra_paths = [Path(p).expanduser() for p in (extra_paths or [])]
        self.registry = ParserRegistry()
        self._state: dict[str, dict] = {}
        self._parsers: dict[str, object] = {}
        self.sources: list[LiveSource] = []

    # ------------------------------------------------------------- discovery
    def discover_sources(self) -> list[LiveSource]:
        self.sources = []
        candidates: list[Path] = [Path(p) for p in DEFAULT_SOURCES]
        candidates.extend(self.extra_paths)
        seen: set[Path] = set()
        for path in candidates:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            if not path.exists():
                continue
            if not path.is_file():
                continue
            readable = os.access(path, os.R_OK)
            parser_name = None
            reason = None
            if readable:
                try:
                    parser_name = self.registry.detect_format_name(path)
                except Exception:  # noqa: BLE001
                    parser_name = "generic"
            else:
                reason = (
                    "permission denied; add your user to the 'adm' group or run "
                    "with appropriate privileges"
                )
            self.sources.append(
                LiveSource(
                    path=path,
                    readable=readable,
                    parser_name=parser_name,
                    reason=reason,
                )
            )
        return self.sources

    def collect(self) -> list[Path]:
        return [source.path for source in self.discover_sources() if source.readable]

    # --------------------------------------------------------------- polling
    def _get_parser(self, path: Path):
        key = str(path)
        if key not in self._parsers:
            self._parsers[key] = self.registry.detect(path)
        return self._parsers[key]

    def _read_new_lines(self, path: Path) -> list[str]:
        key = str(path)
        try:
            stat = path.stat()
        except OSError:
            return []

        state = self._state.get(key)
        if state is None:
            state = {
                "inode": stat.st_ino,
                "pos": 0 if self.from_beginning else stat.st_size,
                "buffer": b"",
            }
            self._state[key] = state
        elif state["inode"] != stat.st_ino or stat.st_size < state["pos"]:
            # Log rotation or truncation: restart from the beginning.
            state["inode"] = stat.st_ino
            state["pos"] = 0
            state["buffer"] = b""

        try:
            with path.open("rb") as handle:
                handle.seek(state["pos"])
                data = handle.read()
                state["pos"] = handle.tell()
        except OSError:
            return []

        if not data:
            return []
        state["buffer"] += data
        parts = state["buffer"].split(b"\n")
        state["buffer"] = parts.pop()
        return [
            part.decode("utf-8", errors="replace").rstrip("\r")
            for part in parts
            if part.strip()
        ]

    def poll(self, sources: list[LiveSource] | None = None) -> list[Event]:
        sources = sources or self.sources or self.discover_sources()
        events: list[Event] = []
        for source in sources:
            if not source.readable:
                continue
            parser = self._get_parser(source.path)
            for line in self._read_new_lines(source.path):
                try:
                    event = parser.parse_line(line, str(source.path))
                except Exception:  # noqa: BLE001 - keep monitoring despite bad lines
                    continue
                if event is None:
                    continue
                event.source_type = "live"
                event.source_file = str(source.path)
                events.append(event)
        return events

    def follow(
        self,
        sources: list[LiveSource] | None = None,
        max_events: int | None = None,
        duration: float | None = None,
    ) -> Iterator[Event]:
        sources = sources or self.sources or self.discover_sources()
        deadline = time.time() + duration if duration else None
        emitted = 0
        while True:
            for event in self.poll(sources):
                yield event
                emitted += 1
                if max_events and emitted >= max_events:
                    return
            if deadline and time.time() >= deadline:
                return
            time.sleep(self.poll_interval)
