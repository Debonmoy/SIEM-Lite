"""Filesystem and upload validation helpers.

All user-supplied paths pass through here. We never execute file contents and
we refuse symlink tricks / traversal in upload names.
"""

from __future__ import annotations

import os
from pathlib import Path

from .. import config

SUPPORTED_EXTENSIONS = {
    ".log",
    ".txt",
    ".evtx",
    ".xml",
    ".csv",
    ".json",
    ".jsonl",
    ".ndjson",
    ".out",
    ".err",
}

# Filenames with no extension that are still legitimate log sources.
KNOWN_LOG_NAMES = {
    "auth.log",
    "secure",
    "messages",
    "syslog",
    "access.log",
    "error.log",
    "access",
    "error",
    "nginx",
    "apache2",
}


class ValidationError(ValueError):
    """Raised when a path or upload fails safety checks."""


def validate_read_path(path: str | os.PathLike) -> Path:
    """Resolve and validate a path that the application may read."""
    if path is None:
        raise ValidationError("No path provided")
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValidationError(f"Path does not exist or is inaccessible: {path}") from exc

    if not os.access(resolved, os.R_OK):
        raise ValidationError(f"Path is not readable: {resolved}")
    if resolved.is_dir():
        return resolved
    if not resolved.is_file():
        raise ValidationError(f"Unsupported path type (not a regular file): {resolved}")
    return resolved


def is_supported_log_file(path: str | os.PathLike) -> bool:
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix in SUPPORTED_EXTENSIONS:
        return True
    return p.name.lower() in KNOWN_LOG_NAMES


def discover_log_files(directory: str | os.PathLike, recursive: bool = True) -> list[Path]:
    """Recursively discover candidate log files inside a directory."""
    root = validate_read_path(directory)
    if not root.is_dir():
        raise ValidationError(f"Not a directory: {root}")
    results: list[Path] = []
    iterator = root.rglob("*") if recursive else root.glob("*")
    for candidate in iterator:
        try:
            if candidate.is_file() and is_supported_log_file(candidate):
                if os.access(candidate, os.R_OK):
                    results.append(candidate.resolve())
        except OSError:
            continue
    return sorted(results)


def validate_upload_name(filename: str | None) -> str:
    """Return a safe basename for an uploaded file, rejecting traversal."""
    if not filename:
        raise ValidationError("Upload is missing a filename")
    # Normalise both slash styles, then take the final component only.
    name = filename.replace("\\", "/").split("/")[-1].strip()
    if not name or name in {".", ".."}:
        raise ValidationError("Invalid upload filename")
    if "\x00" in name:
        raise ValidationError("Invalid characters in upload filename")
    return name


def validate_upload_extension(filename: str) -> None:
    if not is_supported_log_file(filename):
        allowed = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise ValidationError(
            f"Unsupported file type for '{filename}'. Allowed extensions: {allowed}"
        )


def check_upload_size(size: int, limit: int | None = None) -> None:
    limit = limit or config.MAX_UPLOAD_BYTES
    if size <= 0:
        raise ValidationError("Uploaded file is empty")
    if size > limit:
        raise ValidationError(
            f"Uploaded file exceeds the {limit // (1024 * 1024)} MB limit"
        )


def safe_join(base: str | os.PathLike, name: str) -> Path:
    """Join ``name`` under ``base`` ensuring the result cannot escape ``base``."""
    base_path = Path(base).resolve()
    safe_name = validate_upload_name(name)
    target = (base_path / safe_name).resolve()
    if base_path != target and base_path not in target.parents:
        raise ValidationError("Path traversal attempt blocked")
    return target
