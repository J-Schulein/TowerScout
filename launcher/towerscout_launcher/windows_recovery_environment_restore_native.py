"""Native exact apply/reconcile boundary for Windows environment rollback.

The adapter consumes caller-authenticated rollback authority, reopens names
without following a leaf reparse point, and either replaces the exact recorded
candidate with the journal-bound restore temp or deletes that exact candidate
by a held handle. Every ordinary API error is reconciled from exact post-state.
It does not append a journal generation or expose a product mutation call site.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ntpath
import os
import re
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement import MAX_ENVIRONMENT_BYTES
from .windows_path_trust import (
    AccessAllowedAce,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_recovery_environment_restore import (
    EnvironmentDestinationObservation,
    EnvironmentRestoreAction,
    EnvironmentRestoreAuthority,
    decide_environment_restore,
)
from .windows_security import (
    NativeFileFacts,
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsSecurityError,
)

_SCHEMA_VERSION = 1
_MAX_PATH_CHARACTERS = 32_768
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_TEMP_NAME = re.compile(r"^\.towerscout-env-[0-9a-f]{32}\.tmp$")
_Result = TypeVar("_Result")


class EnvironmentRestoreStorageErrorCode(str, Enum):
    INPUT_INVALID = "environment_restore_storage_input_invalid"
    PLATFORM_UNAVAILABLE = "environment_restore_storage_platform_unavailable"
    STATE_AMBIGUOUS = "environment_restore_storage_state_ambiguous"
    APPLY_FAILED = "environment_restore_storage_apply_failed"
    VERIFY_FAILED = "environment_restore_storage_verify_failed"


class EnvironmentRestoreStorageError(RuntimeError):
    """Sanitized failure at the native environment-restore boundary."""

    _MESSAGES = {
        EnvironmentRestoreStorageErrorCode.INPUT_INVALID: (
            "The environment restore request is invalid."
        ),
        EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE: (
            "Secure Windows environment restore is unavailable."
        ),
        EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS: (
            "The environment restore state is ambiguous."
        ),
        EnvironmentRestoreStorageErrorCode.APPLY_FAILED: (
            "The environment state could not be restored safely."
        ),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED: (
            "The restored environment could not be verified safely."
        ),
    }

    def __init__(self, code: EnvironmentRestoreStorageErrorCode) -> None:
        if type(code) is not EnvironmentRestoreStorageErrorCode:
            raise ValueError("Unknown environment restore storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentRestoreStorageError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentRestoreStorageAuthority:
    schema_version: int
    restore: EnvironmentRestoreAuthority = field(repr=False)
    restore_temp_name: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.restore) is not EnvironmentRestoreAuthority
            or (
                self.restore.original_present
                and (
                    type(self.restore_temp_name) is not str
                    or _TEMP_NAME.fullmatch(self.restore_temp_name) is None
                )
            )
            or (
                not self.restore.original_present and self.restore_temp_name is not None
            )
        ):
            raise ValueError("Environment restore storage authority is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentRestoreStorageAuthority("
            f"original_present={self.restore.original_present!r}, <redacted>)"
        )


class _WindowsEnvironmentRestoreApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def open_file_if_exists(self, path: str) -> object | None: ...

    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...

    def replace_existing_file(self, destination: str, source: str) -> None: ...


def _fail(code: EnvironmentRestoreStorageErrorCode) -> NoReturn:
    raise EnvironmentRestoreStorageError(code) from None


def _call(
    operation: Callable[[], _Result],
    code: EnvironmentRestoreStorageErrorCode,
) -> _Result:
    try:
        return operation()
    except EnvironmentRestoreStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsEnvironmentRestoreApi, handle: object) -> None:
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
    authority: EnvironmentRestoreStorageAuthority,
) -> tuple[str, str | None]:
    restore = authority.restore
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.evidence.root_identity != restore.package_root_identity
    ):
        _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
    try:
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    root_path = package_root.root_snapshot.final_path
    destination = ntpath.join(root_path, ".env")
    source = (
        None
        if authority.restore_temp_name is None
        else ntpath.join(root_path, authority.restore_temp_name)
    )
    if (
        len(destination) > _MAX_PATH_CHARACTERS
        or _path_key(ntpath.dirname(destination)) != _path_key(root_path)
        or (
            source is not None
            and (
                len(source) > _MAX_PATH_CHARACTERS
                or _path_key(ntpath.dirname(source)) != _path_key(root_path)
                or _path_key(source) == _path_key(destination)
            )
        )
    ):
        _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
    return destination, source


def _read_exact(
    api: _WindowsEnvironmentRestoreApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _inspect_handle(
    api: _WindowsEnvironmentRestoreApi,
    handle: object,
    *,
    path: str,
    package_root_identity: StableFileIdentity,
) -> tuple[EnvironmentDestinationObservation, NativeSecurityFacts]:
    facts = _call(
        lambda: api.query_file(handle),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
    )
    security = _call(
        lambda: api.query_security(handle),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
    )
    if type(facts) is not NativeFileFacts or type(security) is not NativeSecurityFacts:
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    identity = StableFileIdentity(facts.volume_serial, facts.file_id)
    descriptor = security.security_descriptor_sha256
    if (
        facts.volume_serial != package_root_identity.volume_serial
        or _path_key(facts.final_path) != _path_key(path)
        or _path_key(ntpath.dirname(facts.final_path))
        != _path_key(ntpath.dirname(path))
        or facts.drive_type != 3
        or facts.file_type != 1
        or facts.attributes
        & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        or facts.reparse_tag != 0
        or facts.link_count != 1
        or not 0 <= facts.size <= MAX_ENVIRONMENT_BYTES
        or type(descriptor) is not str
    ):
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    contents = _read_exact(api, handle, facts.size)
    return (
        EnvironmentDestinationObservation(
            True,
            identity,
            hashlib.sha256(contents).hexdigest(),
            len(contents),
            facts.attributes,
            descriptor,
        ),
        security,
    )


def _observe(
    api: _WindowsEnvironmentRestoreApi,
    path: str,
    package_root_identity: StableFileIdentity,
) -> EnvironmentDestinationObservation:
    handle = _call(
        lambda: api.open_file_if_exists(path),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return EnvironmentDestinationObservation(False)
    held: object | None = handle
    try:
        observed, _security = _inspect_handle(
            api,
            handle,
            path=path,
            package_root_identity=package_root_identity,
        )
        _call(
            lambda: api.close_handle(handle),
            EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return observed


def _validate_restore_temp_security(
    security: NativeSecurityFacts,
    current_user_sid: str,
) -> None:
    accepted = {current_user_sid.upper(), _SYSTEM_SID}
    if (
        security.owner_sid.upper() != current_user_sid.upper()
        or not security.dacl_present
        or not security.dacl_protected
        or len(security.allowed_aces) != 2
        or {ace.principal_sid.upper() for ace in security.allowed_aces} != accepted
        or any(
            type(ace) is not AccessAllowedAce
            or ace.access_mask != _FILE_ALL_ACCESS
            or ace.flags != 0
            for ace in security.allowed_aces
        )
    ):
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)


def _verify_restore_temp(
    api: _WindowsEnvironmentRestoreApi,
    path: str,
    authority: EnvironmentRestoreAuthority,
) -> None:
    handle = _call(
        lambda: api.open_file_if_exists(path),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)
    held: object | None = handle
    try:
        observed, security = _inspect_handle(
            api,
            handle,
            path=path,
            package_root_identity=authority.package_root_identity,
        )
        current_user_sid = _call(
            api.current_user_sid,
            EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE,
        )
        if (
            type(current_user_sid) is not str
            or _SID.fullmatch(current_user_sid) is None
        ):
            _fail(EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE)
        _validate_restore_temp_security(security, current_user_sid)
        if (
            observed.identity != authority.restore_temp_identity
            or observed.sha256 != authority.original_sha256
            or observed.size != authority.original_size
        ):
            _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)
        _call(
            lambda: api.close_handle(handle),
            EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)


def _delete_exact_candidate(
    api: _WindowsEnvironmentRestoreApi,
    path: str,
    authority: EnvironmentRestoreAuthority,
) -> bool:
    handle = _call(
        lambda: api.open_file_for_delete_if_exists(path),
        EnvironmentRestoreStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return False
    held: object | None = handle
    operation_failed = False
    try:
        observed, _security = _inspect_handle(
            api,
            handle,
            path=path,
            package_root_identity=authority.package_root_identity,
        )
        decision = decide_environment_restore(authority, observed)
        if decision.action is not EnvironmentRestoreAction.REMOVE_CANDIDATE:
            _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)
        second, _second_security = _inspect_handle(
            api,
            handle,
            path=path,
            package_root_identity=authority.package_root_identity,
        )
        if second != observed:
            _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)
        try:
            api.mark_file_for_deletion(handle)
        except Exception:
            operation_failed = True
        try:
            api.close_handle(handle)
        except Exception:
            operation_failed = True
        else:
            held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    after = _observe(api, path, authority.package_root_identity)
    reconciled = decide_environment_restore(authority, after)
    if reconciled.action is EnvironmentRestoreAction.ALREADY_RESTORED:
        return True
    if operation_failed and after == observed:
        _fail(EnvironmentRestoreStorageErrorCode.APPLY_FAILED)
    _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)


def _restore_while_root_held(
    package_root: PathHierarchyTrust,
    authority: EnvironmentRestoreStorageAuthority,
    api: _WindowsEnvironmentRestoreApi,
) -> EnvironmentDestinationObservation:
    destination, source = _paths(package_root, authority)
    restore = authority.restore
    before = _observe(api, destination, restore.package_root_identity)
    decision = decide_environment_restore(restore, before)
    if decision.action is EnvironmentRestoreAction.ALREADY_RESTORED:
        return before
    if decision.action is EnvironmentRestoreAction.BLOCK:
        _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)
    if decision.action is EnvironmentRestoreAction.REMOVE_CANDIDATE:
        _delete_exact_candidate(api, destination, restore)
        result = EnvironmentDestinationObservation(False)
    else:
        if source is None:
            _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
        _verify_restore_temp(api, source, restore)
        operation_failed = False
        try:
            api.replace_existing_file(destination, source)
        except Exception:
            operation_failed = True
        result = _observe(api, destination, restore.package_root_identity)
        after_source = _observe(api, source, restore.package_root_identity)
        reconciled = decide_environment_restore(restore, result)
        if (
            reconciled.action is not EnvironmentRestoreAction.ALREADY_RESTORED
            or after_source.present
        ):
            if operation_failed and result == before and after_source.present:
                _fail(EnvironmentRestoreStorageErrorCode.APPLY_FAILED)
            _fail(EnvironmentRestoreStorageErrorCode.STATE_AMBIGUOUS)
    try:
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    return result


def _restore_environment_with_api(
    package_root: PathHierarchyTrust,
    authority: EnvironmentRestoreStorageAuthority,
    *,
    api: _WindowsEnvironmentRestoreApi,
) -> EnvironmentDestinationObservation:
    """Restore only exact authority while retaining the package-root lease."""

    if (
        type(package_root) is not PathHierarchyTrust
        or type(authority) is not EnvironmentRestoreStorageAuthority
        or api is None
    ):
        _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
    supported = _call(
        lambda: api.supported,
        EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if supported is not True:
        _fail(EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE)
    try:
        result = package_root.run_while_held(
            lambda: _restore_while_root_held(package_root, authority, api)
        )
    except EnvironmentRestoreStorageError:
        raise
    except WindowsSecurityError:
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    if type(result) is not EnvironmentDestinationObservation:
        _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
    return result


class NativeWindowsEnvironmentRestoreApi:
    """ctypes adapter exposing only exact environment-restore operations."""

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
            raise OSError("Native Windows environment restore is unavailable.")
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

    @staticmethod
    def _last_error(message: str) -> NoReturn:
        raise OSError(ctypes.get_last_error(), message)

    def current_user_sid(self) -> str:
        return self._paths.current_user_sid()

    def open_file_if_exists(self, path: str) -> object | None:
        return self._files.open_file_if_exists(path)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._files.open_file_for_delete_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._paths.query_security(handle)

    def seek_file(self, handle: object, offset: int) -> None:
        self._files.seek_file(handle, offset)

    def read_file(self, handle: object, maximum: int) -> bytes:
        return self._files.read_file(handle, maximum)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._files.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)

    def replace_existing_file(self, destination: str, source: str) -> None:
        kernel32 = self._require()
        ctypes.set_last_error(0)
        if not kernel32.ReplaceFileW(destination, source, None, 0, None, None):
            self._last_error("Native Windows environment restoration failed.")


class NativeWindowsEnvironmentRestoreStorage:
    """Production-shaped wrapper; no caller currently authorizes it."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _WindowsEnvironmentRestoreApi | None = None) -> None:
        self._api = api if api is not None else NativeWindowsEnvironmentRestoreApi()

    def restore_environment_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentRestoreStorageAuthority,
    ) -> EnvironmentDestinationObservation:
        return _restore_environment_with_api(package_root, authority, api=self._api)

    def restore_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentRestoreStorageAuthority,
    ) -> EnvironmentDestinationObservation:
        if (
            type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or type(authority) is not EnvironmentRestoreStorageAuthority
            or self._api is None
        ):
            _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
        supported = _call(
            lambda: self._api.supported,
            EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE,
        )
        if supported is not True:
            _fail(EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE)
        try:
            return _restore_while_root_held(package_root, authority, self._api)
        except EnvironmentRestoreStorageError:
            raise
        except WindowsSecurityError:
            _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
        except Exception:
            _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)

    def observe_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        package_root_identity: StableFileIdentity,
    ) -> EnvironmentDestinationObservation:
        """Freshly observe the fixed package ``.env`` under the retained root."""

        if (
            type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or type(package_root_identity) is not StableFileIdentity
            or package_root.root_snapshot.identity != package_root_identity
            or self._api is None
        ):
            _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
        supported = _call(
            lambda: self._api.supported,
            EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE,
        )
        if supported is not True:
            _fail(EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE)
        try:
            package_root.assert_unchanged_while_held()
            root_path = package_root.root_snapshot.final_path
            destination = ntpath.join(root_path, ".env")
            if len(destination) > _MAX_PATH_CHARACTERS or _path_key(
                ntpath.dirname(destination)
            ) != _path_key(root_path):
                _fail(EnvironmentRestoreStorageErrorCode.INPUT_INVALID)
            observed = _observe(self._api, destination, package_root_identity)
            package_root.assert_unchanged_while_held()
            return observed
        except EnvironmentRestoreStorageError:
            raise
        except WindowsSecurityError:
            _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)
        except Exception:
            _fail(EnvironmentRestoreStorageErrorCode.VERIFY_FAILED)


__all__ = [
    "EnvironmentRestoreStorageAuthority",
    "EnvironmentRestoreStorageError",
    "EnvironmentRestoreStorageErrorCode",
    "NativeWindowsEnvironmentRestoreApi",
    "NativeWindowsEnvironmentRestoreStorage",
]
