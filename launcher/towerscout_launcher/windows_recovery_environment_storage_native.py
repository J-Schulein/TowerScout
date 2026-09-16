"""Native zero-byte storage for a planned Windows environment restore temp.

The adapter requires an already-held package-root lease. It may reconcile only
the exact planned-name, zero-byte, restrictive-DACL orphan left before a
generation-6 journal append. It has no content-write, move, replacement, or
package-environment deletion operation.
"""

from __future__ import annotations

import ntpath
import re
from typing import Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement_native import (
    NativeWindowsEnvironmentReplacementApi,
)
from .windows_path_trust import (
    AccessAllowedAce,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_recovery_environment_storage import (
    RecoveryEnvironmentStorageError,
    RecoveryEnvironmentStorageErrorCode,
)
from .windows_recovery_journal import (
    EnvironmentRestoreTempCreatedRecord,
    EnvironmentRestoreTempPlanRecord,
)
from .windows_security import (
    NativeFileFacts,
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsSecurityError,
)

_MAX_PATH_CHARACTERS = 32_768
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_TEMP_NAME = re.compile(r"^\.towerscout-env-[0-9a-f]{32}\.tmp$")
_Result = TypeVar("_Result")


class _WindowsRecoveryEnvironmentTempApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object: ...

    def reopen_file_for_verification(self, path: str) -> object: ...

    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def flush_file(self, handle: object) -> None: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...


class NativeWindowsRecoveryEnvironmentTempApi:
    """Restricted Windows file primitives for the recovery temp only."""

    __slots__ = ("_creation", "_files", "_paths")

    def __init__(self) -> None:
        self._creation = NativeWindowsEnvironmentReplacementApi()
        self._files = NativeWindowsFileApi()
        self._paths = NativeWindowsPathTrustApi()

    @property
    def supported(self) -> bool:
        return (
            self._creation.supported and self._files.supported and self._paths.supported
        )

    def current_user_sid(self) -> str:
        return self._paths.current_user_sid()

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        return self._creation.create_new_restricted_file(path, owner_sid=owner_sid)

    def reopen_file_for_verification(self, path: str) -> object:
        return self._files.open_file_for_identity(path)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._files.open_file_for_delete_if_exists(path)

    def reopen_file_if_exists(self, path: str) -> object | None:
        return self._files.open_file_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._paths.query_security(handle)

    def flush_file(self, handle: object) -> None:
        self._creation.flush_file(handle)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._files.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)


def _fail(code: RecoveryEnvironmentStorageErrorCode) -> NoReturn:
    raise RecoveryEnvironmentStorageError(code)


def _call(
    operation: Callable[[], _Result],
    code: RecoveryEnvironmentStorageErrorCode,
) -> _Result:
    try:
        return operation()
    except RecoveryEnvironmentStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsRecoveryEnvironmentTempApi, handle: object) -> None:
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


def _restore_temp_path(
    package_root: PathHierarchyTrust,
    package_root_identity: StableFileIdentity,
    temp_name: str,
) -> str:
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.evidence.root_identity != package_root_identity
        or type(temp_name) is not str
        or _TEMP_NAME.fullmatch(temp_name) is None
    ):
        _fail(RecoveryEnvironmentStorageErrorCode.INPUT_INVALID)
    try:
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED)
    root_path = package_root.root_snapshot.final_path
    temp_path = ntpath.join(root_path, temp_name)
    if len(temp_path) > _MAX_PATH_CHARACTERS or _path_key(
        ntpath.dirname(temp_path)
    ) != _path_key(root_path):
        _fail(RecoveryEnvironmentStorageErrorCode.INPUT_INVALID)
    return temp_path


def _current_user_sid(
    api: _WindowsRecoveryEnvironmentTempApi,
    code: RecoveryEnvironmentStorageErrorCode,
) -> str:
    sid = _call(api.current_user_sid, code)
    if type(sid) is not str or _SID.fullmatch(sid) is None:
        _fail(code)
    return sid


def _validate_security(
    security: object,
    current_user_sid: str,
    code: RecoveryEnvironmentStorageErrorCode,
) -> None:
    if type(security) is not NativeSecurityFacts:
        _fail(code)
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
        _fail(code)


def _validate_file(
    facts: object,
    *,
    expected_path: str,
    package_root_identity: StableFileIdentity,
    expected_identity: StableFileIdentity | None,
    code: RecoveryEnvironmentStorageErrorCode,
) -> StableFileIdentity:
    if type(facts) is not NativeFileFacts:
        _fail(code)
    identity = StableFileIdentity(facts.volume_serial, facts.file_id)
    if (
        facts.volume_serial != package_root_identity.volume_serial
        or _path_key(facts.final_path) != _path_key(expected_path)
        or _path_key(ntpath.dirname(facts.final_path))
        != _path_key(ntpath.dirname(expected_path))
        or facts.drive_type != 3
        or facts.file_type != 1
        or facts.attributes
        & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        or facts.reparse_tag != 0
        or facts.link_count != 1
        or facts.size != 0
        or (expected_identity is not None and identity != expected_identity)
    ):
        _fail(code)
    return identity


def _inspect_handle(
    api: _WindowsRecoveryEnvironmentTempApi,
    handle: object,
    *,
    expected_path: str,
    package_root_identity: StableFileIdentity,
    current_user_sid: str,
    expected_identity: StableFileIdentity | None,
    code: RecoveryEnvironmentStorageErrorCode,
) -> StableFileIdentity:
    identity = _validate_file(
        _call(lambda: api.query_file(handle), code),
        expected_path=expected_path,
        package_root_identity=package_root_identity,
        expected_identity=expected_identity,
        code=code,
    )
    _validate_security(
        _call(lambda: api.query_security(handle), code),
        current_user_sid,
        code,
    )
    return identity


def _remove_exact_planned_orphan(
    api: _WindowsRecoveryEnvironmentTempApi,
    *,
    path: str,
    package_root_identity: StableFileIdentity,
    current_user_sid: str,
) -> bool:
    handle = _call(
        lambda: api.open_file_for_delete_if_exists(path),
        RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return False
    held: object | None = handle
    try:
        identity = _inspect_handle(
            api,
            handle,
            expected_path=path,
            package_root_identity=package_root_identity,
            current_user_sid=current_user_sid,
            expected_identity=None,
            code=RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        _inspect_handle(
            api,
            handle,
            expected_path=path,
            package_root_identity=package_root_identity,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            code=RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        _call(
            lambda: api.mark_file_for_deletion(handle),
            RecoveryEnvironmentStorageErrorCode.CLEANUP_FAILED,
        )
        _call(
            lambda: api.close_handle(handle),
            RecoveryEnvironmentStorageErrorCode.CLEANUP_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    remaining = _call(
        lambda: api.reopen_file_if_exists(path),
        RecoveryEnvironmentStorageErrorCode.CLEANUP_FAILED,
    )
    if remaining is not None:
        _safe_close(api, remaining)
        _fail(RecoveryEnvironmentStorageErrorCode.CLEANUP_FAILED)
    return True


def _create_and_verify(
    api: _WindowsRecoveryEnvironmentTempApi,
    *,
    path: str,
    package_root_identity: StableFileIdentity,
    current_user_sid: str,
) -> StableFileIdentity:
    handle = _call(
        lambda: api.create_new_restricted_file(path, owner_sid=current_user_sid),
        RecoveryEnvironmentStorageErrorCode.CREATE_FAILED,
    )
    if handle is None:
        _fail(RecoveryEnvironmentStorageErrorCode.CREATE_FAILED)
    held: object | None = handle
    try:
        identity = _inspect_handle(
            api,
            handle,
            expected_path=path,
            package_root_identity=package_root_identity,
            current_user_sid=current_user_sid,
            expected_identity=None,
            code=RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        _call(
            lambda: api.flush_file(handle),
            RecoveryEnvironmentStorageErrorCode.CREATE_FAILED,
        )
        _inspect_handle(
            api,
            handle,
            expected_path=path,
            package_root_identity=package_root_identity,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            code=RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        _call(
            lambda: api.close_handle(handle),
            RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)

    reopened = _call(
        lambda: api.reopen_file_for_verification(path),
        RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
    )
    if reopened is None:
        _fail(RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED)
    held = reopened
    try:
        _inspect_handle(
            api,
            reopened,
            expected_path=path,
            package_root_identity=package_root_identity,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            code=RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        _call(
            lambda: api.close_handle(reopened),
            RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return identity


class NativeWindowsEnvironmentRestoreTempStorage:
    """Create/reconcile and verify only a journal-planned zero-byte temp."""

    __slots__ = ("_api",)

    def __init__(
        self,
        *,
        api: _WindowsRecoveryEnvironmentTempApi | None = None,
    ) -> None:
        self._api = NativeWindowsRecoveryEnvironmentTempApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsEnvironmentRestoreTempStorage(<redacted>)"

    def _require_supported(self) -> None:
        supported = _call(
            lambda: self._api.supported,
            RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE)

    def create_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        plan: EnvironmentRestoreTempPlanRecord,
    ) -> StableFileIdentity:
        self._require_supported()
        if (
            type(plan) is not EnvironmentRestoreTempPlanRecord
            or not plan.environment_present
        ):
            _fail(RecoveryEnvironmentStorageErrorCode.INPUT_INVALID)
        temp_name = plan.temp_name
        if type(temp_name) is not str:
            _fail(RecoveryEnvironmentStorageErrorCode.INPUT_INVALID)
        path = _restore_temp_path(
            package_root,
            plan.package_root_identity,
            temp_name,
        )
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        try:
            return _create_and_verify(
                self._api,
                path=path,
                package_root_identity=plan.package_root_identity,
                current_user_sid=current_user_sid,
            )
        except RecoveryEnvironmentStorageError as error:
            if error.code is not RecoveryEnvironmentStorageErrorCode.CREATE_FAILED:
                raise
        if not _remove_exact_planned_orphan(
            self._api,
            path=path,
            package_root_identity=plan.package_root_identity,
            current_user_sid=current_user_sid,
        ):
            _fail(RecoveryEnvironmentStorageErrorCode.CREATE_FAILED)
        return _create_and_verify(
            self._api,
            path=path,
            package_root_identity=plan.package_root_identity,
            current_user_sid=current_user_sid,
        )

    def verify_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        created: EnvironmentRestoreTempCreatedRecord,
    ) -> StableFileIdentity:
        self._require_supported()
        if (
            type(created) is not EnvironmentRestoreTempCreatedRecord
            or not created.environment_present
            or type(created.temp_name) is not str
            or type(created.temp_identity) is not StableFileIdentity
        ):
            _fail(RecoveryEnvironmentStorageErrorCode.INPUT_INVALID)
        path = _restore_temp_path(
            package_root,
            created.package_root_identity,
            created.temp_name,
        )
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        handle = _call(
            lambda: self._api.reopen_file_for_verification(path),
            RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
        )
        if handle is None:
            _fail(RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED)
        held: object | None = handle
        try:
            identity = _inspect_handle(
                self._api,
                handle,
                expected_path=path,
                package_root_identity=created.package_root_identity,
                current_user_sid=current_user_sid,
                expected_identity=created.temp_identity,
                code=RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
            )
            _call(
                lambda: self._api.close_handle(handle),
                RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED,
            )
            held = None
        finally:
            if held is not None:
                _safe_close(self._api, held)
        return identity


__all__ = [
    "NativeWindowsRecoveryEnvironmentTempApi",
    "NativeWindowsEnvironmentRestoreTempStorage",
]
