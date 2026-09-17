"""Native exact observe/apply/reconcile boundary for Windows ``.env``.

The adapter consumes complete caller-authenticated authority, reopens both
names without following a leaf reparse point, and invokes only ``ReplaceFileW``
or a non-overwriting write-through ``MoveFileExW``.  Every apparent success or
ordinary API failure is classified from exact post-call observations.  This
module does not create authority, append a journal generation, clean an orphan,
restore a prior state, or expose a production mutation entry point.
"""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
from enum import Enum
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .windows_environment_promotion import (
    EnvironmentPromotionAction,
    EnvironmentPromotionAuthority,
    EnvironmentPromotionObservation,
    decide_environment_promotion,
)
from .windows_environment_replacement import MAX_ENVIRONMENT_BYTES
from .windows_path_trust import (
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_security import (
    NativeFileFacts,
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsSecurityError,
)

_MAX_PATH_CHARACTERS = 32_768
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_Result = TypeVar("_Result")


class EnvironmentPromotionStorageErrorCode(str, Enum):
    INPUT_INVALID = "environment_promotion_storage_input_invalid"
    PLATFORM_UNAVAILABLE = "environment_promotion_storage_platform_unavailable"
    STATE_AMBIGUOUS = "environment_promotion_storage_state_ambiguous"
    APPLY_FAILED = "environment_promotion_storage_apply_failed"
    VERIFY_FAILED = "environment_promotion_storage_verify_failed"


class EnvironmentPromotionStorageError(RuntimeError):
    """Sanitized failure at the native environment-promotion boundary."""

    _MESSAGES = {
        EnvironmentPromotionStorageErrorCode.INPUT_INVALID: (
            "The environment promotion request is invalid."
        ),
        EnvironmentPromotionStorageErrorCode.PLATFORM_UNAVAILABLE: (
            "Secure Windows environment promotion is unavailable."
        ),
        EnvironmentPromotionStorageErrorCode.STATE_AMBIGUOUS: (
            "The environment promotion state is ambiguous."
        ),
        EnvironmentPromotionStorageErrorCode.APPLY_FAILED: (
            "The environment candidate could not be promoted safely."
        ),
        EnvironmentPromotionStorageErrorCode.VERIFY_FAILED: (
            "The promoted environment could not be verified safely."
        ),
    }

    def __init__(self, code: EnvironmentPromotionStorageErrorCode) -> None:
        if type(code) is not EnvironmentPromotionStorageErrorCode:
            raise ValueError("Unknown environment promotion storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentPromotionStorageError(code={self.code.value!r})"


class _WindowsEnvironmentPromotionApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def open_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def close_handle(self, handle: object) -> None: ...

    def replace_existing_file(self, destination: str, source: str) -> None: ...

    def move_new_file(self, source: str, destination: str) -> None: ...


def _fail(code: EnvironmentPromotionStorageErrorCode) -> NoReturn:
    raise EnvironmentPromotionStorageError(code)


def _call(
    operation: Callable[[], _Result],
    code: EnvironmentPromotionStorageErrorCode,
) -> _Result:
    try:
        return operation()
    except EnvironmentPromotionStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsEnvironmentPromotionApi, handle: object) -> None:
    try:
        api.close_handle(handle)
    except BaseException:
        return


def _path_key(path: str) -> str:
    value = path
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _paths(
    package_root: PathHierarchyTrust,
    authority: EnvironmentPromotionAuthority,
) -> tuple[str, str]:
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.evidence.root_identity != authority.package_root_identity
    ):
        _fail(EnvironmentPromotionStorageErrorCode.INPUT_INVALID)
    try:
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
    root_path = package_root.root_snapshot.final_path
    destination = ntpath.join(root_path, ".env")
    source = ntpath.join(root_path, authority.verified.temp_name)
    if (
        len(destination) > _MAX_PATH_CHARACTERS
        or len(source) > _MAX_PATH_CHARACTERS
        or _path_key(ntpath.dirname(destination)) != _path_key(root_path)
        or _path_key(ntpath.dirname(source)) != _path_key(root_path)
        or _path_key(destination) == _path_key(source)
    ):
        _fail(EnvironmentPromotionStorageErrorCode.INPUT_INVALID)
    return destination, source


def _read_exact(
    api: _WindowsEnvironmentPromotionApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        EnvironmentPromotionStorageErrorCode.VERIFY_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            EnvironmentPromotionStorageErrorCode.VERIFY_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _observe(
    api: _WindowsEnvironmentPromotionApi,
    path: str,
    package_root_identity: StableFileIdentity,
) -> EnvironmentDestinationObservation:
    handle = _call(
        lambda: api.open_file_if_exists(path),
        EnvironmentPromotionStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return EnvironmentDestinationObservation(False)
    held: object | None = handle
    try:
        facts = _call(
            lambda: api.query_file(handle),
            EnvironmentPromotionStorageErrorCode.VERIFY_FAILED,
        )
        security = _call(
            lambda: api.query_security(handle),
            EnvironmentPromotionStorageErrorCode.VERIFY_FAILED,
        )
        if (
            type(facts) is not NativeFileFacts
            or type(security) is not NativeSecurityFacts
        ):
            _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
        identity = StableFileIdentity(facts.volume_serial, facts.file_id)
        descriptor = security.security_descriptor_sha256
        if (
            facts.volume_serial != package_root_identity.volume_serial
            or _path_key(facts.final_path) != _path_key(path)
            or facts.drive_type != 3
            or facts.file_type != 1
            or facts.attributes
            & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
            or facts.reparse_tag != 0
            or facts.link_count != 1
            or not 0 <= facts.size <= MAX_ENVIRONMENT_BYTES
            or type(descriptor) is not str
        ):
            _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
        contents = _read_exact(api, handle, facts.size)
        _call(
            lambda: api.close_handle(handle),
            EnvironmentPromotionStorageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return EnvironmentDestinationObservation(
        True,
        identity,
        hashlib.sha256(contents).hexdigest(),
        len(contents),
        facts.attributes,
        descriptor,
    )


def _observe_both(
    api: _WindowsEnvironmentPromotionApi,
    authority: EnvironmentPromotionAuthority,
    destination: str,
    source: str,
) -> EnvironmentPromotionObservation:
    return EnvironmentPromotionObservation(
        _observe(api, destination, authority.package_root_identity),
        _observe(api, source, authority.package_root_identity),
    )


def _promote_while_root_held(
    package_root: PathHierarchyTrust,
    authority: EnvironmentPromotionAuthority,
    api: _WindowsEnvironmentPromotionApi,
) -> EnvironmentDestinationObservation:
    destination, source = _paths(package_root, authority)
    before = _observe_both(api, authority, destination, source)
    decision = decide_environment_promotion(authority, before)
    if decision.action is EnvironmentPromotionAction.ALREADY_APPLIED:
        return authority.expected_applied
    if decision.action is EnvironmentPromotionAction.BLOCK:
        _fail(EnvironmentPromotionStorageErrorCode.STATE_AMBIGUOUS)

    failed = False
    try:
        if decision.action is EnvironmentPromotionAction.REPLACE_EXISTING:
            api.replace_existing_file(destination, source)
        else:
            api.move_new_file(source, destination)
    except (OSError, RuntimeError, TypeError, ValueError):
        failed = True

    after = _observe_both(api, authority, destination, source)
    try:
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
    reconciled = decide_environment_promotion(authority, after)
    if reconciled.action is EnvironmentPromotionAction.ALREADY_APPLIED:
        return authority.expected_applied
    if failed and after == before:
        _fail(EnvironmentPromotionStorageErrorCode.APPLY_FAILED)
    _fail(EnvironmentPromotionStorageErrorCode.STATE_AMBIGUOUS)


def _promote_environment_with_api(
    package_root: PathHierarchyTrust,
    authority: EnvironmentPromotionAuthority,
    *,
    api: _WindowsEnvironmentPromotionApi,
) -> EnvironmentDestinationObservation:
    """Promote only complete authority while the package-root lease is held."""

    if (
        type(authority) is not EnvironmentPromotionAuthority
        or type(package_root) is not PathHierarchyTrust
        or api is None
    ):
        _fail(EnvironmentPromotionStorageErrorCode.INPUT_INVALID)
    supported = _call(
        lambda: api.supported,
        EnvironmentPromotionStorageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if supported is not True:
        _fail(EnvironmentPromotionStorageErrorCode.PLATFORM_UNAVAILABLE)
    try:
        result = package_root.run_while_held(
            lambda: _promote_while_root_held(package_root, authority, api)
        )
    except EnvironmentPromotionStorageError:
        raise
    except WindowsSecurityError:
        _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
    if type(result) is not EnvironmentDestinationObservation:
        _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
    return result


class NativeWindowsEnvironmentPromotionApi:
    """ctypes adapter exposing only exact promotion operations."""

    __slots__ = ("_files", "_kernel32", "_paths")

    def __init__(self) -> None:
        self._kernel32: Any | None = None
        self._files = NativeWindowsFileApi()
        self._paths = NativeWindowsPathTrustApi()
        loader = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or loader is None:
            return
        try:
            self._kernel32 = loader("kernel32", use_last_error=True)
            self._bind()
        except (AttributeError, OSError, TypeError, ValueError):
            self._kernel32 = None

    @property
    def supported(self) -> bool:
        return (
            self._kernel32 is not None
            and self._files.supported
            and self._paths.supported
        )

    def _require(self) -> Any:
        if self._kernel32 is None:
            raise OSError("Native Windows environment promotion is unavailable.")
        return self._kernel32

    def _bind(self) -> None:
        kernel32 = self._require()
        kernel32.ReplaceFileW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        kernel32.ReplaceFileW.restype = ctypes.c_int
        kernel32.MoveFileExW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.MoveFileExW.restype = ctypes.c_int

    @staticmethod
    def _last_error(message: str) -> NoReturn:
        raise OSError(ctypes.get_last_error(), message)

    def open_file_if_exists(self, path: str) -> object | None:
        return self._files.open_file_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._paths.query_security(handle)

    def seek_file(self, handle: object, offset: int) -> None:
        self._files.seek_file(handle, offset)

    def read_file(self, handle: object, maximum: int) -> bytes:
        return self._files.read_file(handle, maximum)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)

    def replace_existing_file(self, destination: str, source: str) -> None:
        kernel32 = self._require()
        ctypes.set_last_error(0)
        if not kernel32.ReplaceFileW(destination, source, None, 0, None, None):
            self._last_error("Native Windows environment replacement failed.")

    def move_new_file(self, source: str, destination: str) -> None:
        kernel32 = self._require()
        ctypes.set_last_error(0)
        if not kernel32.MoveFileExW(source, destination, 0x00000008):
            # MOVEFILE_WRITE_THROUGH without REPLACE_EXISTING.
            self._last_error("Native Windows environment move failed.")


class NativeWindowsEnvironmentPromotionStorage:
    """Production-shaped wrapper; no caller currently authorizes it."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _WindowsEnvironmentPromotionApi | None = None) -> None:
        self._api = api if api is not None else NativeWindowsEnvironmentPromotionApi()

    def promote_environment_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentPromotionAuthority,
    ) -> EnvironmentDestinationObservation:
        return _promote_environment_with_api(package_root, authority, api=self._api)

    def promote_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentPromotionAuthority,
    ) -> EnvironmentDestinationObservation:
        """Promote through a package-root lease already owned by this thread."""

        if (
            type(authority) is not EnvironmentPromotionAuthority
            or type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or self._api is None
        ):
            _fail(EnvironmentPromotionStorageErrorCode.INPUT_INVALID)
        supported = _call(
            lambda: self._api.supported,
            EnvironmentPromotionStorageErrorCode.PLATFORM_UNAVAILABLE,
        )
        if supported is not True:
            _fail(EnvironmentPromotionStorageErrorCode.PLATFORM_UNAVAILABLE)
        try:
            return _promote_while_root_held(package_root, authority, self._api)
        except EnvironmentPromotionStorageError:
            raise
        except WindowsSecurityError:
            _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)
        except Exception:
            _fail(EnvironmentPromotionStorageErrorCode.VERIFY_FAILED)


__all__ = [
    "EnvironmentPromotionStorageError",
    "EnvironmentPromotionStorageErrorCode",
    "NativeWindowsEnvironmentPromotionApi",
    "NativeWindowsEnvironmentPromotionStorage",
]
