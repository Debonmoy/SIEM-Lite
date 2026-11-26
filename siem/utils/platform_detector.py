"""Operating-system and environment detection.

Live monitoring is only meaningful on Linux (native or WSL). The detector never
pretends that Windows host event logs are reachable through WSL.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformInfo:
    system: str  # "windows" | "linux" | "darwin" | "unknown"
    is_windows: bool
    is_linux: bool
    is_macos: bool
    is_wsl: bool
    supports_live_monitoring: bool
    live_unavailable_reason: str | None
    description: str


def _detect_wsl() -> bool:
    if sys.platform.startswith("linux"):
        if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
            return True
        try:
            with open("/proc/version", "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read().lower()
            return "microsoft" in content or "wsl" in content
        except OSError:
            return False
    return False


def detect_platform() -> PlatformInfo:
    raw = sys.platform
    is_windows = raw.startswith("win")
    is_macos = raw == "darwin"
    is_linux = raw.startswith("linux")
    is_wsl = _detect_wsl()

    if is_windows:
        system = "windows"
    elif is_macos:
        system = "darwin"
    elif is_linux:
        system = "linux"
    else:
        system = "unknown"

    if is_windows:
        reason = (
            "Live Linux monitoring is unavailable on native Windows. "
            "Use Offline Analysis mode to import Linux/Windows log files."
        )
    elif is_macos:
        reason = (
            "Live Linux monitoring is unavailable on macOS. "
            "Use Offline Analysis mode instead."
        )
    elif is_linux:
        reason = None
    else:
        reason = "Live monitoring is unavailable on this platform."

    supports_live = is_linux

    if is_wsl:
        description = "WSL (Linux subsystem on Windows)"
    elif is_windows:
        description = "Native Windows"
    elif is_macos:
        description = "macOS"
    elif is_linux:
        description = "Native Linux"
    else:
        description = platform.system() or "Unknown"

    return PlatformInfo(
        system=system,
        is_windows=is_windows,
        is_linux=is_linux,
        is_macos=is_macos,
        is_wsl=is_wsl,
        supports_live_monitoring=supports_live,
        live_unavailable_reason=reason,
        description=description,
    )


def live_mode_notice(info: PlatformInfo | None = None) -> str:
    """Human-readable explanation of live-mode availability."""
    info = info or detect_platform()
    if info.supports_live_monitoring:
        if info.is_wsl:
            return (
                "Live monitoring is running inside WSL. Only Linux logs visible "
                "from this WSL distribution are monitored; Windows host security "
                "logs (EVTX) are NOT captured live. Import them via offline mode."
            )
        return "Live Linux monitoring is available."
    return info.live_unavailable_reason or "Live monitoring unavailable."
