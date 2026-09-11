"""Adversarial tests for retained native Windows process directories."""

from __future__ import annotations

import hashlib
import inspect
import os
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_process_environment as process_environment  # noqa: E402
from towerscout_launcher.runtime_process_environment import (  # noqa: E402
    BoundWindowsProcessEnvironment,
    NativeWindowsProcessEnvironmentApi,
    ProcessEnvironmentInputError,
    ProcessEnvironmentInputErrorCode,
    _capture_windows_process_environment,
    capture_native_windows_process_environment,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathHierarchyTrust,
)

_CURRENT_USER = "S-1-5-21-100-200-300-1001"
_SYSTEM_ROOT = r"C:\Windows"
_TEMP = r"C:\Users\private\AppData\Local\Temp"
_PROFILE = r"C:\Users\private"
_LOCAL = r"C:\Users\private\AppData\Local"
_ROAMING = r"C:\Users\private\AppData\Roaming"


def _canonical(path: str) -> str:
    if path.startswith("\\\\?\\"):
        path = path[4:]
    return path.rstrip("\\").casefold()


def _file_id(path: str) -> bytes:
    return hashlib.sha256(_canonical(path).encode("utf-8")).digest()[:16]


def _facts(path: str) -> NativeDirectoryFacts:
    canonical = path if path.startswith("\\\\?\\") else rf"\\?\{path}"
    return NativeDirectoryFacts(
        final_path=canonical,
        volume_serial=7,
        file_id=_file_id(canonical),
        attributes=0x10,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


def _security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=_CURRENT_USER,
        dacl_present=True,
        allowed_aces=(AccessAllowedAce(_CURRENT_USER, 0x001F01FF, 0),),
    )


class _EnvironmentApi:
    supported = True

    def __init__(self) -> None:
        self.system_root = _SYSTEM_ROOT
        self.temp = _TEMP
        self.folders = {
            "user_profile": _PROFILE,
            "local_app_data": _LOCAL,
            "roaming_app_data": _ROAMING,
        }
        self.calls: list[str] = []
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None

    def _record(self, name: str) -> None:
        self.calls.append(name)
        if name == "windows_directory" and self.entered is not None:
            self.entered.set()
            release = self.release
            if release is not None and not release.wait(5):
                raise RuntimeError("test synchronization failed")

    def windows_directory(self) -> str:
        self._record("windows_directory")
        return self.system_root

    def temporary_directory(self) -> str:
        self._record("temporary_directory")
        return self.temp

    def known_folder_path(self, known_folder: str) -> str:
        self._record(known_folder)
        return self.folders[known_folder]


class _PathApi:
    supported = True

    def __init__(self) -> None:
        self.opened: list[tuple[str, bool, object]] = []
        self.closed: list[object] = []
        self.facts: dict[object, NativeDirectoryFacts] = {}
        self.security: dict[object, NativeSecurityFacts] = {}

    def current_user_sid(self) -> str:
        return _CURRENT_USER

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        handle = object()
        self.opened.append((path, follow_reparse, handle))
        self.facts[handle] = _facts(path)
        self.security[handle] = _security()
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        return self.facts[handle]

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self.security[handle]

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


def _capture(
    environment_api: _EnvironmentApi | None = None,
    path_api: _PathApi | None = None,
) -> BoundWindowsProcessEnvironment:
    return _capture_windows_process_environment(
        environment_api=environment_api or _EnvironmentApi(),
        path_api=path_api or _PathApi(),
    )


def test_captures_exact_five_directories_and_alias_contract() -> None:
    environment_api = _EnvironmentApi()
    path_api = _PathApi()

    with _capture(environment_api, path_api) as owner:
        captured = owner.capture()

        assert str(captured.system_root.final_path) == _SYSTEM_ROOT
        assert str(captured.temp_directory.final_path) == _TEMP
        assert str(captured.user_profile.final_path) == _PROFILE
        assert str(captured.local_app_data.final_path) == _LOCAL
        assert str(captured.roaming_app_data.final_path) == _ROAMING
        assert (
            len(
                {
                    captured.system_root.file_id,
                    captured.temp_directory.file_id,
                    captured.user_profile.file_id,
                    captured.local_app_data.file_id,
                    captured.roaming_app_data.file_id,
                }
            )
            == 5
        )
        assert all(
            item.is_directory
            for item in (
                captured.system_root,
                captured.temp_directory,
                captured.user_profile,
                captured.local_app_data,
                captured.roaming_app_data,
            )
        )
        assert repr(owner) == (
            "BoundWindowsProcessEnvironment(state='open', <redacted>)"
        )

    assert len(path_api.closed) == len(path_api.opened)
    assert environment_api.calls.count("windows_directory") >= 3


def test_native_resolution_does_not_read_python_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(*_arguments: object, **_keywords: object) -> str:
        raise AssertionError("ambient environment read")

    monkeypatch.setattr(os.environ, "get", reject)
    monkeypatch.setattr(os.environ, "__getitem__", reject, raising=False)

    with _capture() as owner:
        assert owner.capture().system_root.logical_name == "system_root"


def test_accepts_documented_native_temp_trailing_separator() -> None:
    environment_api = _EnvironmentApi()
    environment_api.temp = _TEMP + "\\"

    with _capture(environment_api) as owner:
        captured = owner.capture()

    assert str(captured.temp_directory.final_path) == _TEMP


@pytest.mark.parametrize(
    "path",
    (
        r"C:\Users\private\..\other",
        r"C:\Users\private\Temp ",
        r"C:/Users/private/AppData/Local/Temp",
        "C:\\Users\\private\\AppData\\Local\\Temp\\\\",
        r"\\server\share\Temp",
    ),
)
def test_rejects_invalid_or_remote_native_paths_without_disclosure(path: str) -> None:
    environment_api = _EnvironmentApi()
    environment_api.temp = path
    path_api = _PathApi()
    if path.startswith("\\\\server"):
        original_open = path_api.open_directory

        def remote_open(candidate: str, *, follow_reparse: bool) -> object:
            handle = original_open(candidate, follow_reparse=follow_reparse)
            path_api.facts[handle] = replace(path_api.facts[handle], drive_type=4)
            return handle

        path_api.open_directory = remote_open  # type: ignore[assignment]

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        _capture(environment_api, path_api)

    assert path not in str(raised.value)
    assert raised.value.code in {
        ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID,
        ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE,
    }


def test_rejects_duplicate_directory_paths_before_opening_handles() -> None:
    environment_api = _EnvironmentApi()
    environment_api.folders["roaming_app_data"] = _LOCAL
    path_api = _PathApi()

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        _capture(environment_api, path_api)

    assert raised.value.code is ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID
    assert path_api.opened == []


def test_rejects_native_api_path_drift_under_all_leases() -> None:
    environment_api = _EnvironmentApi()
    owner = _capture(environment_api)
    environment_api.temp = r"C:\Windows\Temp"

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        owner.capture()

    assert raised.value.code is ProcessEnvironmentInputErrorCode.INPUTS_CHANGED
    owner.close()


def test_rejects_filesystem_identity_drift_under_all_leases() -> None:
    environment_api = _EnvironmentApi()
    path_api = _PathApi()
    owner = _capture(environment_api, path_api)
    followed = next(
        handle
        for path, follow, handle in path_api.opened
        if follow and _canonical(path) == _canonical(_TEMP)
    )
    path_api.facts[followed] = replace(path_api.facts[followed], file_id=b"x" * 16)

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        owner.capture()

    assert raised.value.code is ProcessEnvironmentInputErrorCode.INPUTS_CHANGED
    owner.close()


@pytest.mark.parametrize("unsafe", ["reparse", "dacl"])
def test_rejects_unsafe_reparse_or_dacl_and_closes_all_handles(unsafe: str) -> None:
    environment_api = _EnvironmentApi()
    path_api = _PathApi()
    original_open = path_api.open_directory

    def unsafe_open(path: str, *, follow_reparse: bool) -> object:
        handle = original_open(path, follow_reparse=follow_reparse)
        if _canonical(path) == _canonical(_TEMP):
            if unsafe == "reparse":
                path_api.facts[handle] = replace(
                    path_api.facts[handle],
                    attributes=0x410,
                    reparse_tag=0x80000017,
                )
            else:
                path_api.security[handle] = replace(
                    _security(),
                    allowed_aces=(AccessAllowedAce("S-1-1-0", 0x40000, 0),),
                )
        return handle

    path_api.open_directory = unsafe_open  # type: ignore[method-assign]

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        _capture(environment_api, path_api)

    assert raised.value.code is ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID
    assert len(path_api.closed) == len(path_api.opened)


def test_different_api_names_resolving_to_one_identity_fail_closed() -> None:
    environment_api = _EnvironmentApi()
    path_api = _PathApi()
    original_open = path_api.open_directory

    def alias_open(path: str, *, follow_reparse: bool) -> object:
        handle = original_open(path, follow_reparse=follow_reparse)
        if _canonical(path) == _canonical(_ROAMING):
            path_api.facts[handle] = replace(
                path_api.facts[handle],
                volume_serial=7,
                file_id=_file_id(_LOCAL),
            )
        return handle

    path_api.open_directory = alias_open  # type: ignore[method-assign]

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        _capture(environment_api, path_api)

    assert raised.value.code is ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID
    assert len(path_api.closed) == len(path_api.opened)


def test_capture_and_close_are_serialized_across_threads() -> None:
    environment_api = _EnvironmentApi()
    owner = _capture(environment_api)
    entered = threading.Event()
    release = threading.Event()
    environment_api.entered = entered
    environment_api.release = release
    capture_error: list[BaseException] = []
    close_error: list[BaseException] = []

    def capture() -> None:
        try:
            owner.capture()
        except BaseException as error:
            capture_error.append(error)

    def close() -> None:
        try:
            owner.close()
        except BaseException as error:
            close_error.append(error)

    capture_thread = threading.Thread(target=capture)
    close_thread = threading.Thread(target=close)
    capture_thread.start()
    assert entered.wait(2)
    close_thread.start()
    time.sleep(0.05)
    assert close_thread.is_alive()
    release.set()
    capture_thread.join(2)
    close_thread.join(2)

    assert capture_error == []
    assert close_error == []
    assert owner.closed


def test_factory_cleanup_retries_ordinary_close_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_api = _EnvironmentApi()
    path_api = _PathApi()
    original = PathHierarchyTrust.close
    calls: dict[int, int] = {}
    original_resolve = process_environment._resolve_directories
    resolutions = 0

    def fail_after_open(
        api: object,
    ) -> process_environment._ResolvedDirectories:
        nonlocal resolutions
        resolutions += 1
        if resolutions == 2:
            raise RuntimeError("private resolution detail")
        return original_resolve(api)  # type: ignore[arg-type]

    def flaky(owner: PathHierarchyTrust) -> None:
        key = id(owner)
        calls[key] = calls.get(key, 0) + 1
        if calls[key] == 1:
            raise RuntimeError("private close detail")
        original(owner)

    monkeypatch.setattr(process_environment, "_resolve_directories", fail_after_open)
    monkeypatch.setattr(PathHierarchyTrust, "close", flaky)

    with pytest.raises(ProcessEnvironmentInputError) as raised:
        _capture(environment_api, path_api)

    assert (
        raised.value.code is ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE
    )
    assert calls
    assert all(count >= 2 for count in calls.values())
    assert len(path_api.closed) == len(path_api.opened)


def test_factory_cleanup_preserves_interruption_after_closing_every_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_api = _EnvironmentApi()
    path_api = _PathApi()
    original = PathHierarchyTrust.close
    calls: dict[int, int] = {}
    original_resolve = process_environment._resolve_directories
    resolutions = 0

    def interrupt_after_open(api: object) -> process_environment._ResolvedDirectories:
        nonlocal resolutions
        resolutions += 1
        if resolutions == 2:
            raise KeyboardInterrupt
        return original_resolve(api)  # type: ignore[arg-type]

    def interrupted_close(owner: PathHierarchyTrust) -> None:
        key = id(owner)
        calls[key] = calls.get(key, 0) + 1
        if calls[key] == 1:
            raise KeyboardInterrupt
        original(owner)

    monkeypatch.setattr(
        process_environment, "_resolve_directories", interrupt_after_open
    )
    monkeypatch.setattr(PathHierarchyTrust, "close", interrupted_close)

    with pytest.raises(KeyboardInterrupt):
        _capture(environment_api, path_api)

    assert all(count >= 2 for count in calls.values())
    assert len(path_api.closed) == len(path_api.opened)


def test_public_factory_has_no_injectable_trust_seams() -> None:
    signature = inspect.signature(capture_native_windows_process_environment)

    assert tuple(signature.parameters) == ()


def test_source_owner_remains_unwired() -> None:
    imports = []
    for path in (ROOT / "launcher" / "towerscout_launcher").glob("*.py"):
        if path.name == "runtime_process_environment.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "runtime_process_environment" in text:
            imports.append(path.name)

    # Only the retained probe and final source composer may consume this
    # owner.  Confirmation, repair, and the live launcher remain unwired.
    assert imports == [
        "runtime_acceleration_probe.py",
        "runtime_target_inputs.py",
    ]


def test_native_api_fails_closed_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "name", "posix")
        api = NativeWindowsProcessEnvironmentApi()

    assert not api.supported
    assert "private" not in repr(api)
