r"""Protected Windows recovery-state root and current-user DPAPI primitives.

This source-only Gate-A layer resolves Local AppData through the Windows Known
Folder API, creates only the fixed ``TowerScout\Recovery\v1`` hierarchy, and
retains handle-bound trust for Local AppData plus every protected state
directory.  It also exposes purpose-separated current-user DPAPI protection.
No journal, backup, package file, container, or runtime mutation is wired here.
"""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .windows_path_trust import (
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import StableFileIdentity, WindowsSecurityError

_SCHEMA_VERSION = 1
_STATE_COMPONENTS = ("TowerScout", "Recovery", "v1")
_ENTROPY_DOMAIN = b"TowerScout.ProtectedState.v1"
_MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024
_MAX_PROTECTED_BYTES = 4 * 1024 * 1024
_MAX_PATH_CHARACTERS = 32_768
_SID = re.compile(r"^S-\d+(?:-\d+)+$", re.IGNORECASE)
_CRYPTPROTECT_UI_FORBIDDEN = 0x00000001
_ERROR_ALREADY_EXISTS = 183
_SDDL_REVISION_1 = 1
_COINIT_APARTMENTTHREADED = 0x00000002
_RPC_E_CHANGED_MODE = 0x80010106
_FOLDERID_LOCAL_APP_DATA = (
    0xF1B32785,
    0x6FBA,
    0x4FCF,
    (0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91),
)
_Result = TypeVar("_Result")


class ProtectedStateError(RuntimeError):
    """Sanitized failure at the protected-state boundary."""

    _MESSAGES = {
        "protected_state_unavailable": (
            "Protected TowerScout recovery storage is unavailable."
        ),
        "protected_state_unsafe": "Protected TowerScout recovery storage is unsafe.",
        "protected_data_invalid": "Protected TowerScout recovery data is invalid.",
        "protected_data_unavailable": (
            "Windows data protection is unavailable for TowerScout recovery."
        ),
    }

    def __init__(self, category: str) -> None:
        if category not in self._MESSAGES:
            raise ValueError("Unknown protected-state error category.")
        self.category = category
        super().__init__(self._MESSAGES[category])

    def __repr__(self) -> str:
        return f"ProtectedStateError(category={self.category!r})"


def _fail(category: str) -> NoReturn:
    raise ProtectedStateError(category)


class ProtectedDataPurpose(str, Enum):
    JOURNAL_GENERATION = "journal_generation"
    POINTER_TRANSITION = "pointer_transition"
    ENVIRONMENT_BACKUP = "environment_backup"
    CERTIFICATE_BACKUP = "certificate_backup"


@dataclass(frozen=True, slots=True, repr=False)
class CurrentUserProtectedBlob:
    """Opaque DPAPI ciphertext bound to one fixed TowerScout purpose."""

    purpose: ProtectedDataPurpose
    ciphertext: bytes = field(repr=False)
    ciphertext_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.purpose) is not ProtectedDataPurpose
            or type(self.ciphertext) is not bytes
            or not 1 <= len(self.ciphertext) <= _MAX_PROTECTED_BYTES
        ):
            raise ValueError("Protected data blob is invalid.")
        object.__setattr__(
            self,
            "ciphertext_sha256",
            hashlib.sha256(self.ciphertext).hexdigest(),
        )

    def __repr__(self) -> str:
        return f"CurrentUserProtectedBlob(purpose={self.purpose.value!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ProtectedStateEvidence:
    schema_version: int
    local_app_data_identity: StableFileIdentity = field(repr=False)
    state_root_identity: StableFileIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.local_app_data_identity) is not StableFileIdentity
            or type(self.state_root_identity) is not StableFileIdentity
        ):
            raise ValueError("Protected state evidence is invalid.")

    def __repr__(self) -> str:
        return (
            f"ProtectedStateEvidence(schema_version={self.schema_version}, <redacted>)"
        )


class WindowsProtectedStateApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def local_app_data_path(self) -> str: ...

    def ensure_directory(self, path: str, *, owner_sid: str) -> None: ...

    def protect_current_user(
        self, plaintext: bytes, *, entropy: bytes, flags: int
    ) -> bytes: ...

    def unprotect_current_user(
        self, ciphertext: bytes, *, entropy: bytes, flags: int
    ) -> bytes: ...


def _entropy(purpose: ProtectedDataPurpose) -> bytes:
    if type(purpose) is not ProtectedDataPurpose:
        _fail("protected_data_invalid")
    label = purpose.value.encode("ascii")
    return _ENTROPY_DOMAIN + len(label).to_bytes(4, "big") + label


def _is_purpose_entropy(value: object) -> bool:
    return type(value) is bytes and any(
        value == _entropy(purpose) for purpose in ProtectedDataPurpose
    )


def _validate_plaintext(plaintext: bytes) -> None:
    if type(plaintext) is not bytes or len(plaintext) > _MAX_PLAINTEXT_BYTES:
        _fail("protected_data_invalid")


def _protect_current_user_data_with_api(
    plaintext: bytes,
    purpose: ProtectedDataPurpose,
    *,
    api: WindowsProtectedStateApi,
) -> CurrentUserProtectedBlob:
    _validate_plaintext(plaintext)
    entropy = _entropy(purpose)
    try:
        if api.supported is not True:
            _fail("protected_data_unavailable")
        ciphertext = api.protect_current_user(
            plaintext,
            entropy=entropy,
            flags=_CRYPTPROTECT_UI_FORBIDDEN,
        )
    except ProtectedStateError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail("protected_data_unavailable")
    if type(ciphertext) is not bytes:
        _fail("protected_data_unavailable")
    try:
        return CurrentUserProtectedBlob(purpose, ciphertext)
    except ValueError:
        _fail("protected_data_unavailable")


def protect_current_user_data(
    plaintext: bytes,
    purpose: ProtectedDataPurpose,
) -> CurrentUserProtectedBlob:
    """Protect bytes for the current user with UI and machine scope disabled."""

    return _protect_current_user_data_with_api(
        plaintext,
        purpose,
        api=NativeWindowsProtectedStateApi(),
    )


def _unprotect_current_user_data_with_api(
    blob: CurrentUserProtectedBlob,
    purpose: ProtectedDataPurpose,
    *,
    api: WindowsProtectedStateApi,
) -> bytes:
    if (
        type(blob) is not CurrentUserProtectedBlob
        or type(purpose) is not ProtectedDataPurpose
        or blob.purpose is not purpose
    ):
        _fail("protected_data_invalid")
    entropy = _entropy(purpose)
    try:
        if api.supported is not True:
            _fail("protected_data_unavailable")
        plaintext = api.unprotect_current_user(
            blob.ciphertext,
            entropy=entropy,
            flags=_CRYPTPROTECT_UI_FORBIDDEN,
        )
    except ProtectedStateError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail("protected_data_invalid")
    _validate_plaintext(plaintext)
    return plaintext


def unprotect_current_user_data(
    blob: CurrentUserProtectedBlob,
    purpose: ProtectedDataPurpose,
) -> bytes:
    """Authenticate and decrypt one purpose-bound current-user DPAPI blob."""

    return _unprotect_current_user_data_with_api(
        blob,
        purpose,
        api=NativeWindowsProtectedStateApi(),
    )


def _canonical_directory(path: str) -> str:
    if type(path) is not str or not path or "\x00" in path:
        _fail("protected_state_unsafe")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if (
        len(normalized) > _MAX_PATH_CHARACTERS
        or not PureWindowsPath(normalized).is_absolute()
    ):
        _fail("protected_state_unsafe")
    return ntpath.normcase(normalized)


def _run_under_paths(
    paths: tuple[PathHierarchyTrust, ...],
    operation: Callable[[], _Result],
    index: int = 0,
) -> _Result:
    if index == len(paths):
        return operation()
    return paths[index].run_while_held(
        lambda: _run_under_paths(paths, operation, index + 1)
    )


class ProtectedStateRoot:
    """Own trusted Local AppData and protected state directory handles."""

    __slots__ = ("_api", "_lock", "_paths", "_root_path", "evidence")

    def __init__(
        self,
        api: WindowsProtectedStateApi,
        paths: tuple[PathHierarchyTrust, ...],
        root_path: str,
    ) -> None:
        if (
            len(paths) != 1 + len(_STATE_COMPONENTS)
            or any(
                type(path) is not PathHierarchyTrust or path.closed for path in paths
            )
            or paths[0].evidence.purpose is not PathTrustPurpose.LOCAL_APP_DATA
            or any(
                path.evidence.purpose is not PathTrustPurpose.PROTECTED_STATE
                for path in paths[1:]
            )
        ):
            raise ValueError("Protected state root is invalid.")
        self._api = api
        self._paths: tuple[PathHierarchyTrust, ...] | None = paths
        self._root_path = root_path
        self._lock = threading.RLock()
        self.evidence = ProtectedStateEvidence(
            _SCHEMA_VERSION,
            paths[0].root_snapshot.identity,
            paths[-1].root_snapshot.identity,
        )

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._paths is None

    def _run(self, operation: Callable[[], _Result]) -> _Result:
        with self._lock:
            paths = self._paths
            if paths is None or any(path.closed for path in paths):
                _fail("protected_state_unsafe")
            try:
                return _run_under_paths(paths, operation)
            except ProtectedStateError:
                raise
            except WindowsSecurityError:
                _fail("protected_state_unsafe")
            except (OSError, RuntimeError, TypeError, ValueError):
                _fail("protected_state_unavailable")

    def assert_unchanged(self) -> ProtectedStateEvidence:
        return self._run(lambda: self.evidence)

    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        return self._run(
            lambda: _protect_current_user_data_with_api(
                plaintext,
                purpose,
                api=self._api,
            )
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        return self._run(
            lambda: _unprotect_current_user_data_with_api(
                blob,
                purpose,
                api=self._api,
            )
        )

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        if not callable(operation):
            _fail("protected_state_unavailable")
        results: list[_Result] = []
        failures: list[BaseException] = []

        def invoke() -> None:
            try:
                results.append(operation(self._root_path))
            except BaseException as error:
                failures.append(error)

        self._run(invoke)
        if failures:
            raise failures[0]
        if len(results) != 1:
            _fail("protected_state_unsafe")
        return results[0]

    def close(self) -> None:
        with self._lock:
            paths = self._paths
            self._paths = None
            if paths is None:
                return
            failed = False
            for path in reversed(paths):
                try:
                    path.close()
                except BaseException:
                    failed = True
            if failed:
                _fail("protected_state_unsafe")

    def __enter__(self) -> ProtectedStateRoot:
        if self.closed:
            _fail("protected_state_unsafe")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"ProtectedStateRoot(state={state!r}, <redacted>)"


def _close_paths(paths: list[PathHierarchyTrust]) -> bool:
    failed = False
    for path in reversed(paths):
        try:
            path.close()
        except BaseException:
            failed = True
    return failed


def _capture_protected_state_root_with_apis(
    *,
    api: WindowsProtectedStateApi,
    path_api: WindowsPathTrustApi,
) -> ProtectedStateRoot:
    paths: list[PathHierarchyTrust] = []
    try:
        if api.supported is not True or path_api.supported is not True:
            _fail("protected_state_unavailable")
        owner_sid = api.current_user_sid()
        if type(owner_sid) is not str or not _SID.fullmatch(owner_sid):
            _fail("protected_state_unavailable")
        local_path = api.local_app_data_path()
        local_canonical = _canonical_directory(local_path)
        local_owner = capture_path_hierarchy(
            local_path,
            purpose=PathTrustPurpose.LOCAL_APP_DATA,
            api=path_api,
        )
        paths.append(local_owner)
        if (
            _canonical_directory(local_owner.root_snapshot.final_path)
            != local_canonical
        ):
            _fail("protected_state_unsafe")

        current = PureWindowsPath(local_path)
        for component in _STATE_COMPONENTS:
            current /= component
            state_path = str(current)

            def ensure_candidate(candidate: str = state_path) -> None:
                api.ensure_directory(candidate, owner_sid=owner_sid)

            _run_under_paths(
                tuple(paths),
                ensure_candidate,
            )
            owner = capture_path_hierarchy(
                state_path,
                purpose=PathTrustPurpose.PROTECTED_STATE,
                api=path_api,
            )
            paths.append(owner)
            if _canonical_directory(
                owner.root_snapshot.final_path
            ) != _canonical_directory(state_path):
                _fail("protected_state_unsafe")
        local_owner.assert_unchanged()
        return ProtectedStateRoot(api, tuple(paths), str(current))
    except ProtectedStateError:
        if _close_paths(paths):
            _fail("protected_state_unsafe")
        raise
    except WindowsSecurityError:
        _close_paths(paths)
        _fail("protected_state_unsafe")
    except (OSError, RuntimeError, TypeError, ValueError):
        _close_paths(paths)
        _fail("protected_state_unavailable")
    except BaseException:
        _close_paths(paths)
        raise


def capture_native_windows_protected_state_root() -> ProtectedStateRoot:
    """Create and retain the fixed protected current-user recovery root."""

    return _capture_protected_state_root_with_apis(
        api=NativeWindowsProtectedStateApi(),
        path_api=NativeWindowsPathTrustApi(),
    )


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", ctypes.c_int),
    )


class _DataBlob(ctypes.Structure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
    )


class NativeWindowsProtectedStateApi:
    """ctypes adapter for Known Folder, protected directory, and DPAPI calls."""

    __slots__ = ("_advapi32", "_crypt32", "_kernel32", "_ole32", "_shell32")

    def __init__(self) -> None:
        self._advapi32: Any | None = None
        self._crypt32: Any | None = None
        self._kernel32: Any | None = None
        self._ole32: Any | None = None
        self._shell32: Any | None = None
        loader = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or loader is None:
            return
        try:
            self._advapi32 = loader("advapi32", use_last_error=True)
            self._crypt32 = loader("crypt32", use_last_error=True)
            self._kernel32 = loader("kernel32", use_last_error=True)
            self._ole32 = loader("ole32", use_last_error=True)
            self._shell32 = loader("shell32", use_last_error=True)
            self._bind()
        except (AttributeError, OSError, TypeError, ValueError):
            self._advapi32 = None
            self._crypt32 = None
            self._kernel32 = None
            self._ole32 = None
            self._shell32 = None

    @property
    def supported(self) -> bool:
        return all(
            item is not None
            for item in (
                self._advapi32,
                self._crypt32,
                self._kernel32,
                self._ole32,
                self._shell32,
            )
        )

    def _require(self) -> tuple[Any, Any, Any, Any, Any]:
        if not self.supported:
            raise OSError("Native Windows protected-state APIs are unavailable.")
        return (
            self._advapi32,
            self._crypt32,
            self._kernel32,
            self._ole32,
            self._shell32,
        )

    def _bind(self) -> None:
        advapi32, crypt32, kernel32, ole32, shell32 = self._require()
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        )
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            ctypes.c_int
        )
        kernel32.CreateDirectoryW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.POINTER(_SecurityAttributes),
        )
        kernel32.CreateDirectoryW.restype = ctypes.c_int
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree.restype = ctypes.c_void_p
        crypt32.CryptProtectData.argtypes = (
            ctypes.POINTER(_DataBlob),
            ctypes.c_wchar_p,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(_DataBlob),
        )
        crypt32.CryptProtectData.restype = ctypes.c_int
        crypt32.CryptUnprotectData.argtypes = (
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(_DataBlob),
        )
        crypt32.CryptUnprotectData.restype = ctypes.c_int
        ole32.CoInitializeEx.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        ole32.CoInitializeEx.restype = ctypes.c_long
        ole32.CoUninitialize.argtypes = ()
        ole32.CoUninitialize.restype = None
        ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
        ole32.CoTaskMemFree.restype = None
        shell32.SHGetKnownFolderPath.argtypes = (
            ctypes.POINTER(_Guid),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long

    @staticmethod
    def _input_blob(value: bytes) -> tuple[_DataBlob, Any | None]:
        if not value:
            return _DataBlob(0, None), None
        buffer = ctypes.create_string_buffer(value, len(value))
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        return _DataBlob(len(value), pointer), buffer

    @staticmethod
    def _zero_buffer(buffer: Any | None, size: int) -> None:
        if buffer is not None and size:
            ctypes.memset(buffer, 0, size)

    @staticmethod
    def _copy_output(blob: _DataBlob, maximum: int) -> bytes:
        if blob.size > maximum or (blob.size and not blob.data):
            raise OSError("Native Windows protected data is invalid.")
        if not blob.size:
            return b""
        return ctypes.string_at(blob.data, int(blob.size))

    def current_user_sid(self) -> str:
        return NativeWindowsPathTrustApi().current_user_sid()

    def local_app_data_path(self) -> str:
        _advapi32, _crypt32, _kernel32, ole32, shell32 = self._require()
        initialized = False
        result = int(ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED))
        unsigned = result & 0xFFFFFFFF
        if result in (0, 1):
            initialized = True
        elif unsigned != _RPC_E_CHANGED_MODE:
            raise OSError("Native Windows COM initialization failed.")
        pointer = ctypes.c_void_p()
        data1, data2, data3, data4 = _FOLDERID_LOCAL_APP_DATA
        folder_id = _Guid(data1, data2, data3, (ctypes.c_ubyte * 8)(*data4))
        try:
            status = int(
                shell32.SHGetKnownFolderPath(
                    ctypes.byref(folder_id),
                    0,
                    None,
                    ctypes.byref(pointer),
                )
            )
            if status < 0 or not pointer:
                raise OSError("Native Windows Known Folder lookup failed.")
            value = ctypes.wstring_at(pointer)
            if not value or len(value) > _MAX_PATH_CHARACTERS:
                raise OSError("Native Windows Known Folder path is invalid.")
            return value
        finally:
            if pointer:
                ole32.CoTaskMemFree(pointer)
            if initialized:
                ole32.CoUninitialize()

    def ensure_directory(self, path: str, *, owner_sid: str) -> None:
        if (
            type(path) is not str
            or not path
            or "\x00" in path
            or len(path) > _MAX_PATH_CHARACTERS
            or type(owner_sid) is not str
            or not _SID.fullmatch(owner_sid)
        ):
            raise ValueError("Native Windows protected directory request is invalid.")
        advapi32, _crypt32, kernel32, _ole32, _shell32 = self._require()
        descriptor = ctypes.c_void_p()
        descriptor_size = ctypes.c_uint32()
        sddl = f"O:{owner_sid}D:P" f"(A;OICI;FA;;;SY)" f"(A;OICI;FA;;;{owner_sid})"
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            raise OSError("Native Windows directory descriptor creation failed.")
        try:
            attributes = _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes),
                descriptor,
                False,
            )
            ctypes.set_last_error(0)
            if kernel32.CreateDirectoryW(path, ctypes.byref(attributes)):
                return
            if ctypes.get_last_error() != _ERROR_ALREADY_EXISTS:
                raise OSError("Native Windows protected directory creation failed.")
        finally:
            if descriptor:
                kernel32.LocalFree(descriptor)

    def protect_current_user(
        self, plaintext: bytes, *, entropy: bytes, flags: int
    ) -> bytes:
        if (
            flags != _CRYPTPROTECT_UI_FORBIDDEN
            or type(plaintext) is not bytes
            or len(plaintext) > _MAX_PLAINTEXT_BYTES
            or not _is_purpose_entropy(entropy)
        ):
            raise ValueError("Native Windows data-protection request is invalid.")
        _advapi32, crypt32, kernel32, _ole32, _shell32 = self._require()
        input_blob, input_buffer = self._input_blob(plaintext)
        entropy_blob, entropy_buffer = self._input_blob(entropy)
        output = _DataBlob()
        try:
            if not crypt32.CryptProtectData(
                ctypes.byref(input_blob),
                None,
                ctypes.byref(entropy_blob),
                None,
                None,
                flags,
                ctypes.byref(output),
            ):
                raise OSError("Native Windows data protection failed.")
            return self._copy_output(output, _MAX_PROTECTED_BYTES)
        finally:
            self._zero_buffer(input_buffer, len(plaintext))
            if output.data:
                kernel32.LocalFree(ctypes.cast(output.data, ctypes.c_void_p))
            self._zero_buffer(entropy_buffer, len(entropy))

    def unprotect_current_user(
        self, ciphertext: bytes, *, entropy: bytes, flags: int
    ) -> bytes:
        if (
            flags != _CRYPTPROTECT_UI_FORBIDDEN
            or type(ciphertext) is not bytes
            or not 1 <= len(ciphertext) <= _MAX_PROTECTED_BYTES
            or not _is_purpose_entropy(entropy)
        ):
            raise ValueError("Native Windows data-protection request is invalid.")
        _advapi32, crypt32, kernel32, _ole32, _shell32 = self._require()
        input_blob, input_buffer = self._input_blob(ciphertext)
        entropy_blob, entropy_buffer = self._input_blob(entropy)
        output = _DataBlob()
        description = ctypes.c_void_p()
        try:
            if not crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                ctypes.byref(description),
                ctypes.byref(entropy_blob),
                None,
                None,
                flags,
                ctypes.byref(output),
            ):
                raise OSError("Native Windows protected data authentication failed.")
            return self._copy_output(output, _MAX_PLAINTEXT_BYTES)
        finally:
            if output.data and output.size:
                ctypes.memset(output.data, 0, int(output.size))
            if output.data:
                kernel32.LocalFree(ctypes.cast(output.data, ctypes.c_void_p))
            if description:
                kernel32.LocalFree(description)
            self._zero_buffer(input_buffer, len(ciphertext))
            self._zero_buffer(entropy_buffer, len(entropy))


__all__ = [
    "CurrentUserProtectedBlob",
    "ProtectedDataPurpose",
    "ProtectedStateError",
    "ProtectedStateEvidence",
    "ProtectedStateRoot",
    "capture_native_windows_protected_state_root",
    "protect_current_user_data",
    "unprotect_current_user_data",
]
