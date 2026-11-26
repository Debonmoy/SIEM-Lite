"""Offline file/directory collector."""

from __future__ import annotations

from pathlib import Path

from ..utils.file_validator import ValidationError, discover_log_files, validate_read_path
from .base_collector import BaseCollector


class FileCollector(BaseCollector):
    def __init__(self, paths: list[str | Path], recursive: bool = True):
        super().__init__()
        self.paths = list(paths)
        self.recursive = recursive

    def collect(self) -> list[Path]:
        self.errors = []
        results: list[Path] = []
        seen: set[Path] = set()

        for raw in self.paths:
            try:
                resolved = validate_read_path(raw)
            except ValidationError as exc:
                self.errors.append(str(exc))
                continue

            if resolved.is_dir():
                try:
                    files = discover_log_files(resolved, recursive=self.recursive)
                except ValidationError as exc:
                    self.errors.append(str(exc))
                    continue
                if not files:
                    self.errors.append(f"No supported log files found in {resolved}")
                candidates = files
            else:
                candidates = [resolved]

            for candidate in candidates:
                try:
                    resolved_file = candidate.resolve()
                except OSError:
                    self.errors.append(f"Could not resolve path: {candidate}")
                    continue
                if resolved_file in seen:
                    continue
                seen.add(resolved_file)
                results.append(resolved_file)

        return sorted(results)
