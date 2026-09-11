"""Retained native Windows process-environment directory inputs.

This source-only boundary resolves the five directories required by the
minimal child-process environment through fixed Windows APIs.  It retains the
complete trusted hierarchy for every directory and re-resolves the native API
values while all leases are held.  It reads no ambient Python environment,
accepts no caller paths, executes no child, and remains unwired from repair.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import threading
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, Sequence, TypeVar

from .runtime_acceleration_inputs import construct_windows_process_environment
from .target_contracts import FileIdentity, WindowsProcessEnvironment
from .windows_path_trust import (
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import WindowsSecurityError

_MAX_DIRECTORY_CHARACTERS = 32_767
_Result = TypeVar("_Result")


class ProcessEnvironmentInputErrorCode(str, Enum):
    """Stable, non-sensitive process-environment failure categories."""

    ENVIRONMENT_INVALID = "environment_invalid"
    INPUTS_CHANGED = "inputs_changed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class ProcessEnvironmentInputError(RuntimeError):
    """Sanitized failure from retained process-environment capture."""

    _MESSAGES = {
        ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID: (
            "The Windows process environment is invalid."
        ),
        ProcessEnvironmentInputErrorCode.INPUTS_CHANGED: (
            "The Windows process environment changed during verification."
        ),
        ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure Windows process-environment verification is unavailable."
        ),
    }

    def __init__(self, code: ProcessEnvironmentInputErrorCode) -> None:
        if type(code) is not ProcessEnvironmentInputErrorCode:
            raise ValueError("Unknown process-environment input error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"ProcessEnvironmentInputError(code={self.code.value!r})"


def _fail(code: ProcessEnvironmentInputErrorCode) -> NoReturn:
    raise ProcessEnvironmentInputError(code)


class WindowsProcessEnvironmentApi(Protocol):
    """Fixed native directory-resolution seam; it performs no discovery."""

    @property
    def supported(self) -> bool: ...

    def windows_directory(self) -> str: ...

    def known_folder_path(self, known_folder: str) -> str: ...

    def temporary_directory(self) -> str: ...


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )

    @classmethod
    def from_text(cls, value: str) -> "_Guid":
        raw = uuid.UUID(value).bytes_le
        return cls(
            int.from_bytes(raw[0:4], "little"),
            int.from_bytes(raw[4:6], "little"),
            int.from_bytes(raw[6:8], "little"),
            (ctypes.c_ubyte * 8).from_buffer_copy(raw[8:16]),
        )


_KNOWN_FOLDER_IDS = {
    "user_profile": _Guid.from_text("5e6c858f-0e22-4760-9afe-ea3317b67173"),
    "local_app_data": _Guid.from_text("f1b32785-6fba-4fcf-9d55-7b8e7f157091"),
    "roaming_app_data": _Guid.from_text("3eb685db-65f9-4cf6-a03a-e3ef65729f3d"),
}


class NativeWindowsProcessEnvironmentApi:
    """Resolve exact process directories through fixed Win32/Shell APIs."""

    __slots__ = ("_kernel32", "_ole32", "_shell32")

    def __init__(self) -> None:
        self._kernel32: Any | None = None
        self._ole32: Any | None = None
        self._shell32: Any | None = None
        win_dll = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or win_dll is None:
            return
        try:
            kernel32 = win_dll("kernel32", use_last_error=True)
            shell32 = win_dll("shell32", use_last_error=True)
            ole32 = win_dll("ole32", use_last_error=True)
            # GetTempPath2W is intentionally required.  Do not silently fall
            # back to ambient Python environment variables or caller paths.
            getattr(kernel32, "GetTempPath2W")
            self._kernel32 = kernel32
            self._shell32 = shell32
            self._ole32 = ole32
            self._bind()
        except (AttributeError, OSError, TypeError, ValueError):
            self._kernel32 = None
            self._shell32 = None
            self._ole32 = None

    @property
    def supported(self) -> bool:
        return (
            self._kernel32 is not None
            and self._shell32 is not None
            and self._ole32 is not None
        )

    def _bind(self) -> None:
        kernel32, shell32, ole32 = self._require()
        kernel32.GetWindowsDirectoryW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.GetWindowsDirectoryW.restype = ctypes.c_uint32
        kernel32.GetTempPath2W.argtypes = (ctypes.c_uint32, ctypes.c_wchar_p)
        kernel32.GetTempPath2W.restype = ctypes.c_uint32
        shell32.SHGetKnownFolderPath.argtypes = (
            ctypes.POINTER(_Guid),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
        ole32.CoTaskMemFree.restype = None

    def _require(self) -> tuple[Any, Any, Any]:
        if not self.supported:
            raise OSError("Native process-environment APIs are unavailable.")
        return self._kernel32, self._shell32, self._ole32

    def windows_directory(self) -> str:
        kernel32, _shell32, _ole32 = self._require()
        buffer = ctypes.create_unicode_buffer(_MAX_DIRECTORY_CHARACTERS + 1)
        length = int(kernel32.GetWindowsDirectoryW(buffer, len(buffer)))
        if length <= 0 or length >= len(buffer) or len(buffer.value) != length:
            raise OSError("Native Windows-directory resolution failed.")
        return buffer.value

    def known_folder_path(self, known_folder: str) -> str:
        if type(known_folder) is not str or known_folder not in _KNOWN_FOLDER_IDS:
            raise ValueError("Known Folder request is invalid.")
        _kernel32, shell32, ole32 = self._require()
        result = ctypes.c_wchar_p()
        status = int(
            shell32.SHGetKnownFolderPath(
                ctypes.byref(_KNOWN_FOLDER_IDS[known_folder]),
                0,
                None,
                ctypes.byref(result),
            )
        )
        try:
            if status != 0 or not result.value:
                raise OSError(status, "Known Folder resolution failed.")
            return result.value
        finally:
            if result:
                ole32.CoTaskMemFree(ctypes.cast(result, ctypes.c_void_p))

    def temporary_directory(self) -> str:
        kernel32, _shell32, _ole32 = self._require()
        buffer = ctypes.create_unicode_buffer(_MAX_DIRECTORY_CHARACTERS + 1)
        length = int(kernel32.GetTempPath2W(len(buffer), buffer))
        if length <= 0 or length >= len(buffer) or len(buffer.value) != length:
            raise OSError("Native temporary-directory resolution failed.")
        return buffer.value

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeWindowsProcessEnvironmentApi(state={state!r})"


@dataclass(frozen=True, slots=True, repr=False)
class _ResolvedDirectories:
    system_root: str
    temp_directory: str
    user_profile: str
    local_app_data: str
    roaming_app_data: str

    @property
    def ordered(self) -> tuple[str, ...]:
        return (
            self.system_root,
            self.temp_directory,
            self.user_profile,
            self.local_app_data,
            self.roaming_app_data,
        )


def _strip_extended_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _canonical_directory(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or len(value) > _MAX_DIRECTORY_CHARACTERS
    ):
        _fail(ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID)
    path = _strip_extended_prefix(value)
    if "/" in path:
        _fail(ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID)
    # GetTempPath2W documents a trailing separator.  Accept exactly one on a
    # non-root path, then require every other character to already be in the
    # canonical lexical spelling accepted by PureWindowsPath.
    candidate = path[:-1] if len(path) > 3 and path.endswith("\\") else path
    parsed = PureWindowsPath(candidate)
    if (
        not parsed.is_absolute()
        or not parsed.drive
        or not parsed.anchor
        or any(part in {".", ".."} for part in parsed.parts[1:])
        or any(part.endswith((".", " ")) for part in parsed.parts[1:])
        or any(":" in part for part in parsed.parts[1:])
        or str(parsed) != candidate
    ):
        _fail(ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID)
    normalized = ntpath.normpath(candidate)
    if str(PureWindowsPath(normalized)) != normalized:
        _fail(ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID)
    return normalized


def _path_key(value: str) -> str:
    return ntpath.normcase(_canonical_directory(value))


def _resolve_directories(api: WindowsProcessEnvironmentApi) -> _ResolvedDirectories:
    try:
        resolved = _ResolvedDirectories(
            system_root=_canonical_directory(api.windows_directory()),
            temp_directory=_canonical_directory(api.temporary_directory()),
            user_profile=_canonical_directory(api.known_folder_path("user_profile")),
            local_app_data=_canonical_directory(
                api.known_folder_path("local_app_data")
            ),
            roaming_app_data=_canonical_directory(
                api.known_folder_path("roaming_app_data")
            ),
        )
    except ProcessEnvironmentInputError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError, UnicodeError):
        raise ProcessEnvironmentInputError(
            ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE
        ) from None
    keys = tuple(_path_key(item) for item in resolved.ordered)
    if len(set(keys)) != len(keys):
        _fail(ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID)
    return resolved


def _directory_identity(
    logical_name: str,
    path: str,
    owner: PathHierarchyTrust,
) -> FileIdentity:
    snapshot = owner.root_snapshot
    return FileIdentity(
        logical_name=logical_name,
        # Publish the fixed API's canonical spelling for child processes while
        # retaining the resolved handle identity behind it.  Native final-path
        # queries commonly add a ``\\?\`` prefix that is unsuitable for a
        # SYSTEMROOT-style child environment value.
        final_path=PureWindowsPath(path),
        volume_serial=snapshot.identity.volume_serial,
        file_id=snapshot.identity.file_id,
        is_directory=True,
    )


def _environment(
    owners: Sequence[PathHierarchyTrust],
    paths: _ResolvedDirectories,
) -> WindowsProcessEnvironment:
    names = (
        "system_root",
        "temp_directory",
        "user_profile",
        "local_app_data",
        "roaming_app_data",
    )
    identities = tuple(
        _directory_identity(name, path, owner)
        for name, path, owner in zip(names, paths.ordered, owners, strict=True)
    )
    if len({(item.volume_serial, item.file_id) for item in identities}) != len(
        identities
    ):
        _fail(ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID)
    return construct_windows_process_environment(
        (
            ("SYSTEMROOT", identities[0]),
            ("WINDIR", identities[0]),
            ("TEMP", identities[1]),
            ("TMP", identities[1]),
            ("USERPROFILE", identities[2]),
            ("LOCALAPPDATA", identities[3]),
            ("APPDATA", identities[4]),
        )
    )


def _run_leases(
    owners: Sequence[PathHierarchyTrust],
    operation: Callable[[], _Result],
    index: int = 0,
) -> _Result:
    if index == len(owners):
        return operation()
    return owners[index].run_while_held(
        lambda: _run_leases(owners, operation, index + 1)
    )


class BoundWindowsProcessEnvironment:
    """Own all five trusted process directories as one capture authority."""

    __slots__ = (
        "_active_owner",
        "_api",
        "_expected_paths",
        "_lock",
        "_owners",
    )

    def __init__(
        self,
        *,
        api: WindowsProcessEnvironmentApi,
        expected_paths: _ResolvedDirectories,
        owners: tuple[PathHierarchyTrust, ...],
    ) -> None:
        if (
            type(expected_paths) is not _ResolvedDirectories
            or type(owners) is not tuple
            or len(owners) != 5
            or any(
                type(owner) is not PathHierarchyTrust or owner.closed
                for owner in owners
            )
            or len({id(owner) for owner in owners}) != len(owners)
        ):
            raise ValueError("Bound Windows process environment is invalid.")
        self._lock = threading.RLock()
        self._active_owner: int | None = None
        self._api = api
        self._expected_paths = expected_paths
        self._owners: tuple[PathHierarchyTrust, ...] | None = owners

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._owners is None

    def _capture_held(
        self, owners: tuple[PathHierarchyTrust, ...]
    ) -> WindowsProcessEnvironment:
        current = _resolve_directories(self._api)
        if tuple(_path_key(item) for item in current.ordered) != tuple(
            _path_key(item) for item in self._expected_paths.ordered
        ):
            _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
        for expected, owner in zip(current.ordered, owners, strict=True):
            owner.assert_unchanged_while_held()
            if _path_key(expected) != _path_key(owner.root_snapshot.final_path):
                _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
        try:
            return _environment(owners, current)
        except ProcessEnvironmentInputError:
            raise
        except (RuntimeError, TypeError, ValueError, UnicodeError):
            raise ProcessEnvironmentInputError(
                ProcessEnvironmentInputErrorCode.INPUTS_CHANGED
            ) from None

    def capture(self) -> WindowsProcessEnvironment:
        with self._lock:
            if self._active_owner is not None:
                _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
            owners = self._owners
            if owners is None:
                _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
            self._active_owner = threading.get_ident()
            try:
                return _run_leases(owners, lambda: self._capture_held(owners))
            except ProcessEnvironmentInputError:
                raise
            except WindowsSecurityError:
                raise ProcessEnvironmentInputError(
                    ProcessEnvironmentInputErrorCode.INPUTS_CHANGED
                ) from None
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise ProcessEnvironmentInputError(
                    ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE
                ) from None
            finally:
                self._active_owner = None

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
            owners = self._owners
            if owners is None:
                return
            interruption: BaseException | None = None
            for _attempt in range(3):
                for owner in reversed(owners):
                    if owner.closed:
                        continue
                    try:
                        owner.close()
                    except BaseException as error:
                        if not isinstance(error, Exception) and interruption is None:
                            interruption = error
                if all(owner.closed for owner in owners):
                    self._owners = None
                    break
            if interruption is not None:
                raise interruption
            if self._owners is not None:
                _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundWindowsProcessEnvironment":
        if self.closed:
            _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundWindowsProcessEnvironment(state={state!r}, <redacted>)"


def _close_partial(
    owners: Sequence[PathHierarchyTrust],
) -> tuple[BaseException | None, bool]:
    interruption: BaseException | None = None
    for _attempt in range(3):
        for owner in reversed(owners):
            if owner.closed:
                continue
            try:
                owner.close()
            except BaseException as error:
                if not isinstance(error, Exception) and interruption is None:
                    interruption = error
        if all(owner.closed for owner in owners):
            break
    return interruption, any(not owner.closed for owner in owners)


def _capture_windows_process_environment(
    *,
    environment_api: WindowsProcessEnvironmentApi,
    path_api: WindowsPathTrustApi,
) -> BoundWindowsProcessEnvironment:
    """Injectable test seam behind the fixed native public factory."""

    try:
        supported = environment_api.supported is True and path_api.supported is True
    except (OSError, RuntimeError, TypeError, ValueError):
        supported = False
    if not supported:
        _fail(ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE)

    owners: list[PathHierarchyTrust] = []
    result: BoundWindowsProcessEnvironment | None = None
    primary: BaseException | None = None
    try:
        expected = _resolve_directories(environment_api)
        for path in expected.ordered:
            owners.append(
                capture_path_hierarchy(
                    path,
                    purpose=PathTrustPurpose.PROCESS_ENVIRONMENT,
                    api=path_api,
                )
            )
        result = BoundWindowsProcessEnvironment(
            api=environment_api,
            expected_paths=expected,
            owners=tuple(owners),
        )
        first = result.capture()
        second = result.capture()
        if first != second:
            _fail(ProcessEnvironmentInputErrorCode.INPUTS_CHANGED)
        owners.clear()
        return result
    except BaseException as error:
        if isinstance(error, ProcessEnvironmentInputError) or not isinstance(
            error, Exception
        ):
            primary = error
        elif isinstance(error, WindowsSecurityError):
            primary = ProcessEnvironmentInputError(
                ProcessEnvironmentInputErrorCode.ENVIRONMENT_INVALID
            )
        else:
            primary = ProcessEnvironmentInputError(
                ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE
            )

    if result is not None:
        try:
            result.close()
        except BaseException as error:
            if primary is None or isinstance(primary, Exception):
                primary = error
        incomplete = not result.closed
    else:
        interruption, incomplete = _close_partial(owners)
        if interruption is not None and (
            primary is None or isinstance(primary, Exception)
        ):
            primary = interruption
    if primary is not None and not isinstance(primary, Exception):
        raise primary from None
    if incomplete:
        raise ProcessEnvironmentInputError(
            ProcessEnvironmentInputErrorCode.INPUTS_CHANGED
        ) from None
    if isinstance(primary, ProcessEnvironmentInputError):
        raise primary from None
    raise ProcessEnvironmentInputError(
        ProcessEnvironmentInputErrorCode.VERIFICATION_UNAVAILABLE
    ) from None


def capture_native_windows_process_environment() -> BoundWindowsProcessEnvironment:
    """Capture process directories through fixed native Windows providers."""

    return _capture_windows_process_environment(
        environment_api=NativeWindowsProcessEnvironmentApi(),
        path_api=NativeWindowsPathTrustApi(),
    )


__all__ = [
    "BoundWindowsProcessEnvironment",
    "NativeWindowsProcessEnvironmentApi",
    "ProcessEnvironmentInputError",
    "ProcessEnvironmentInputErrorCode",
    "WindowsProcessEnvironmentApi",
    "capture_native_windows_process_environment",
]
