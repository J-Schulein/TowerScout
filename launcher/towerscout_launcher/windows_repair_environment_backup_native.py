"""Capture the exact pre-repair package environment under retained authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ntpath
from typing import Callable, cast, NoReturn, Protocol, TypeVar

from .windows_environment_replacement import MAX_ENVIRONMENT_BYTES
from .windows_path_trust import (
    NativeSecurityFacts,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_recovery_backup import (
    EnvironmentExactStateBackup,
    WindowsFileSecurityMetadata,
)
from .windows_recovery_journal import JournalStreamIdentity
from .windows_recovery_environment_restore_native import (
    NativeWindowsEnvironmentRestoreApi,
)
from .windows_security import NativeFileFacts, StableFileIdentity

_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_HASH_CHUNK_BYTES = 65_536
_Result = TypeVar("_Result")


class NativeRepairEnvironmentBackupErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_environment_backup_input_invalid"
    READ_FAILED = "native_repair_environment_backup_read_failed"
    VERIFY_FAILED = "native_repair_environment_backup_verify_failed"


class NativeRepairEnvironmentBackupError(RuntimeError):
    _MESSAGES = {
        NativeRepairEnvironmentBackupErrorCode.INPUT_INVALID: (
            "The repair environment backup request is invalid."
        ),
        NativeRepairEnvironmentBackupErrorCode.READ_FAILED: (
            "The original package environment could not be read safely."
        ),
        NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED: (
            "The original package environment could not be verified safely."
        ),
    }

    def __init__(self, code: NativeRepairEnvironmentBackupErrorCode) -> None:
        if type(code) is not NativeRepairEnvironmentBackupErrorCode:
            raise ValueError("Unknown native repair environment backup error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairEnvironmentBackupError(code={self.code.value!r})"


class RepairEnvironmentBackupApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def open_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security_evidence(
        self,
        handle: object,
    ) -> tuple[NativeSecurityFacts, bytes]: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def close_handle(self, handle: object) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class _CapturedEnvironment:
    identity: StableFileIdentity = field(repr=False)
    contents: bytes = field(repr=False)
    file_attributes: int
    security_evidence: bytes = field(repr=False)


def _fail(code: NativeRepairEnvironmentBackupErrorCode) -> NoReturn:
    raise NativeRepairEnvironmentBackupError(code) from None


def _call(
    operation: Callable[[], _Result],
    code: NativeRepairEnvironmentBackupErrorCode,
) -> _Result:
    failed = False
    result: _Result | None = None
    try:
        result = operation()
    except Exception:
        failed = True
    if failed:
        _fail(code)
    return cast(_Result, result)


def _safe_close(api: RepairEnvironmentBackupApi, handle: object) -> None:
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


def _read_exact(
    api: RepairEnvironmentBackupApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        NativeRepairEnvironmentBackupErrorCode.READ_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            NativeRepairEnvironmentBackupErrorCode.READ_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(NativeRepairEnvironmentBackupErrorCode.READ_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _inspect(
    api: RepairEnvironmentBackupApi,
    handle: object,
    *,
    path: str,
    package_identity: StableFileIdentity,
) -> _CapturedEnvironment:
    before = _call(
        lambda: api.query_file(handle),
        NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED,
    )
    security_before = _call(
        lambda: api.query_security_evidence(handle),
        NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED,
    )
    if (
        type(before) is not NativeFileFacts
        or type(security_before) is not tuple
        or len(security_before) != 2
        or type(security_before[0]) is not NativeSecurityFacts
        or type(security_before[1]) is not bytes
    ):
        _fail(NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED)
    security, evidence = security_before
    identity = StableFileIdentity(before.volume_serial, before.file_id)
    if (
        before.volume_serial != package_identity.volume_serial
        or _path_key(before.final_path) != _path_key(path)
        or _path_key(ntpath.dirname(before.final_path))
        != _path_key(ntpath.dirname(path))
        or before.drive_type != 3
        or before.file_type != 1
        or before.attributes
        & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        or before.reparse_tag != 0
        or before.link_count != 1
        or not 0 <= before.size <= MAX_ENVIRONMENT_BYTES
        or security.security_descriptor_sha256 != hashlib.sha256(evidence).hexdigest()
    ):
        _fail(NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED)
    contents = _read_exact(api, handle, before.size)
    after = _call(
        lambda: api.query_file(handle),
        NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED,
    )
    security_after = _call(
        lambda: api.query_security_evidence(handle),
        NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED,
    )
    if after != before or security_after != security_before:
        _fail(NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED)
    return _CapturedEnvironment(identity, contents, before.attributes, evidence)


def _capture_once(
    api: RepairEnvironmentBackupApi,
    *,
    path: str,
    package_identity: StableFileIdentity,
) -> _CapturedEnvironment | None:
    handle = _call(
        lambda: api.open_file_if_exists(path),
        NativeRepairEnvironmentBackupErrorCode.READ_FAILED,
    )
    if handle is None:
        return None
    held: object | None = handle
    try:
        captured = _inspect(
            api,
            handle,
            path=path,
            package_identity=package_identity,
        )
        _call(
            lambda: api.close_handle(handle),
            NativeRepairEnvironmentBackupErrorCode.READ_FAILED,
        )
        held = None
        return captured
    finally:
        if held is not None:
            _safe_close(api, held)


def capture_repair_environment_backup_while_package_root_held(
    package_root: PathHierarchyTrust,
    stream: JournalStreamIdentity,
    *,
    api: RepairEnvironmentBackupApi | None = None,
) -> EnvironmentExactStateBackup:
    """Capture the fixed ``.env`` twice while its package-root lease is held."""

    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or type(stream) is not JournalStreamIdentity
        or package_root.root_snapshot.identity != stream.package_root_identity
    ):
        _fail(NativeRepairEnvironmentBackupErrorCode.INPUT_INVALID)
    selected_api: RepairEnvironmentBackupApi = (
        NativeWindowsEnvironmentRestoreApi() if api is None else api
    )
    supported = _call(
        lambda: selected_api.supported,
        NativeRepairEnvironmentBackupErrorCode.READ_FAILED,
    )
    if supported is not True:
        _fail(NativeRepairEnvironmentBackupErrorCode.READ_FAILED)
    package_root.assert_unchanged_while_held()
    path = ntpath.join(package_root.root_snapshot.final_path, ".env")
    if _path_key(ntpath.dirname(path)) != _path_key(
        package_root.root_snapshot.final_path
    ):
        _fail(NativeRepairEnvironmentBackupErrorCode.INPUT_INVALID)
    first = _capture_once(
        selected_api,
        path=path,
        package_identity=stream.package_root_identity,
    )
    second = _capture_once(
        selected_api,
        path=path,
        package_identity=stream.package_root_identity,
    )
    package_root.assert_unchanged_while_held()
    if first != second:
        _fail(NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED)
    try:
        if second is None:
            return EnvironmentExactStateBackup(1, stream, None, None, None)
        security = WindowsFileSecurityMetadata(
            1,
            second.file_attributes,
            second.security_evidence,
        )
        return EnvironmentExactStateBackup(
            1,
            stream,
            second.identity,
            second.contents,
            security,
        )
    except ValueError:
        _fail(NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED)


__all__ = [
    "NativeRepairEnvironmentBackupError",
    "NativeRepairEnvironmentBackupErrorCode",
    "RepairEnvironmentBackupApi",
    "capture_repair_environment_backup_while_package_root_held",
]
