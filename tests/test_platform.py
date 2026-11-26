"""Cross-platform detection tests (Windows/Linux/WSL/macOS simulation)."""

from __future__ import annotations

import sys

from siem.cli import commands
from siem.utils.platform_detector import PlatformInfo, detect_platform, live_mode_notice


def _patch(monkeypatch, platform: str, wsl: bool):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(
        "siem.utils.platform_detector._detect_wsl", lambda: wsl
    )


def test_windows_platform(monkeypatch):
    _patch(monkeypatch, "win32", False)
    info = detect_platform()
    assert info.is_windows and not info.is_linux
    assert info.supports_live_monitoring is False
    assert "Windows" in (info.live_unavailable_reason or "")
    assert "unavailable" in live_mode_notice(info).lower()


def test_linux_platform(monkeypatch):
    _patch(monkeypatch, "linux", False)
    info = detect_platform()
    assert info.is_linux and not info.is_wsl
    assert info.supports_live_monitoring is True
    assert info.live_unavailable_reason is None


def test_wsl_platform(monkeypatch):
    _patch(monkeypatch, "linux", True)
    info = detect_platform()
    assert info.is_linux and info.is_wsl
    assert info.supports_live_monitoring is True
    notice = live_mode_notice(info)
    assert "WSL" in notice
    assert "Windows host" in notice


def test_macos_platform(monkeypatch):
    _patch(monkeypatch, "darwin", False)
    info = detect_platform()
    assert info.is_macos
    assert info.supports_live_monitoring is False


def test_live_cli_blocked_on_windows(monkeypatch, capsys):
    fake = PlatformInfo(
        system="windows",
        is_windows=True,
        is_linux=False,
        is_macos=False,
        is_wsl=False,
        supports_live_monitoring=False,
        live_unavailable_reason="Live Linux monitoring is unavailable on native Windows.",
        description="Native Windows",
    )
    monkeypatch.setattr(commands, "detect_platform", lambda: fake)
    code = commands.main(["live"])
    captured = capsys.readouterr()
    assert code == 1
    assert "unavailable" in captured.out.lower()
    assert "offline" in captured.out.lower()
