from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

entrypoint = importlib.import_module("towerscout_launcher.__main__")
from towerscout_launcher.windows_recovery_front_door import (  # noqa: E402
    WindowsRecoveryFrontDoorError,
    WindowsRecoveryFrontDoorErrorCode,
    WindowsRecoveryFrontDoorOutcome,
)


class _Instance:
    def __init__(self, acquired: bool) -> None:
        self.acquired = acquired

    def __enter__(self) -> _Instance:
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None


def _install_common(monkeypatch: pytest.MonkeyPatch, *, acquired: bool = True) -> None:
    package = SimpleNamespace(
        release_version="v1",
        compose_project="towerscout",
        image_digest="sha256:" + "a" * 64,
    )
    monkeypatch.setattr(entrypoint, "locate_package_root", lambda: Path("fixed"))
    monkeypatch.setattr(entrypoint, "load_package_identity", lambda _root: package)
    monkeypatch.setattr(
        entrypoint,
        "acquire_single_instance",
        lambda _identity: _Instance(acquired),
    )


def test_main_scans_recovery_before_opening_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common(monkeypatch)
    events: list[str] = []
    monkeypatch.setattr(
        entrypoint,
        "recover_native_windows_pending_repair",
        lambda: events.append("recovery")
        or WindowsRecoveryFrontDoorOutcome.NO_RECOVERY,
    )
    monkeypatch.setattr(entrypoint, "run_app", lambda: events.append("app") or 0)

    assert entrypoint.main() == 0
    assert events == ["recovery", "app"]


def test_main_reports_verified_rollback_before_opening_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common(monkeypatch)
    messages: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        entrypoint,
        "recover_native_windows_pending_repair",
        lambda: WindowsRecoveryFrontDoorOutcome.RECOVERED,
    )
    monkeypatch.setattr(
        entrypoint,
        "show_startup_recovery_message",
        lambda message, *, failed: messages.append((message, failed)),
    )
    monkeypatch.setattr(entrypoint, "run_app", lambda: 0)

    assert entrypoint.main() == 0
    assert messages == [(entrypoint._RECOVERY_COMPLETED_MESSAGE, False)]


def test_main_blocks_ui_when_recovery_remains_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common(monkeypatch)
    messages: list[tuple[str, bool]] = []

    def fail() -> WindowsRecoveryFrontDoorOutcome:
        raise WindowsRecoveryFrontDoorError(
            WindowsRecoveryFrontDoorErrorCode.RECOVERY_FAILED
        )

    monkeypatch.setattr(entrypoint, "recover_native_windows_pending_repair", fail)
    monkeypatch.setattr(
        entrypoint,
        "show_startup_recovery_message",
        lambda message, *, failed: messages.append((message, failed)),
    )
    monkeypatch.setattr(
        entrypoint,
        "run_app",
        lambda: pytest.fail("the main UI must remain closed"),
    )

    assert entrypoint.main() == 3
    assert messages == [(entrypoint._RECOVERY_PENDING_MESSAGE, True)]


def test_duplicate_instance_does_not_start_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common(monkeypatch, acquired=False)
    events: list[str] = []
    monkeypatch.setattr(
        entrypoint,
        "show_duplicate_instance_message",
        lambda: events.append("duplicate"),
    )
    monkeypatch.setattr(
        entrypoint,
        "recover_native_windows_pending_repair",
        lambda: pytest.fail("a duplicate process must not recover"),
    )

    assert entrypoint.main() == 2
    assert events == ["duplicate"]
