"""Build the exact package environment replacement plan under retained trust."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ntpath
from typing import Callable, cast, NoReturn, Protocol, TypeVar

from .target_contracts import FileIdentity, ResolvedRepairTarget
from .windows_environment_replacement import (
    MAX_ENVIRONMENT_BYTES,
    EnvironmentReplacementPlan,
    plan_ca_environment_replacement,
)
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery_backup import EnvironmentExactStateBackup
from .windows_recovery_environment_restore_native import (
    NativeWindowsEnvironmentRestoreApi,
)
from .windows_security import NativeFileFacts, StableFileIdentity

_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_HASH_CHUNK_BYTES = 65_536
_Result = TypeVar("_Result")


class NativeRepairEnvironmentPlanErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_environment_plan_input_invalid"
    READ_FAILED = "native_repair_environment_plan_read_failed"
    VERIFY_FAILED = "native_repair_environment_plan_verify_failed"


class NativeRepairEnvironmentPlanError(RuntimeError):
    _MESSAGES = {
        NativeRepairEnvironmentPlanErrorCode.INPUT_INVALID: (
            "The repair environment plan request is invalid."
        ),
        NativeRepairEnvironmentPlanErrorCode.READ_FAILED: (
            "The package environment source could not be read safely."
        ),
        NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED: (
            "The package environment plan could not be verified safely."
        ),
    }

    def __init__(self, code: NativeRepairEnvironmentPlanErrorCode) -> None:
        if type(code) is not NativeRepairEnvironmentPlanErrorCode:
            raise ValueError("Unknown native repair environment plan error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairEnvironmentPlanError(code={self.code.value!r})"


class RepairEnvironmentPlanApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def open_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def close_handle(self, handle: object) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class _CapturedSource:
    identity: StableFileIdentity = field(repr=False)
    contents: bytes = field(repr=False)


def _fail(code: NativeRepairEnvironmentPlanErrorCode) -> NoReturn:
    raise NativeRepairEnvironmentPlanError(code) from None


def _call(
    operation: Callable[[], _Result],
    code: NativeRepairEnvironmentPlanErrorCode,
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


def _safe_close(api: RepairEnvironmentPlanApi, handle: object) -> None:
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
    api: RepairEnvironmentPlanApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        NativeRepairEnvironmentPlanErrorCode.READ_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            NativeRepairEnvironmentPlanErrorCode.READ_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(NativeRepairEnvironmentPlanErrorCode.READ_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _capture_source_once(
    api: RepairEnvironmentPlanApi,
    expected: FileIdentity,
    package_identity: StableFileIdentity,
) -> _CapturedSource:
    path = str(expected.final_path)
    handle = _call(
        lambda: api.open_file_if_exists(path),
        NativeRepairEnvironmentPlanErrorCode.READ_FAILED,
    )
    if handle is None:
        _fail(NativeRepairEnvironmentPlanErrorCode.READ_FAILED)
    held: object | None = handle
    try:
        before = _call(
            lambda: api.query_file(handle),
            NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED,
        )
        if type(before) is not NativeFileFacts:
            _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
        identity = StableFileIdentity(before.volume_serial, before.file_id)
        expected_identity = StableFileIdentity(
            expected.volume_serial,
            expected.file_id,
        )
        if (
            identity != expected_identity
            or before.volume_serial != package_identity.volume_serial
            or _path_key(before.final_path) != _path_key(path)
            or before.drive_type != 3
            or before.file_type != 1
            or before.attributes
            & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
            or before.reparse_tag != 0
            or before.link_count != 1
            or type(expected.size_bytes) is not int
            or before.size != expected.size_bytes
            or not 0 <= before.size <= MAX_ENVIRONMENT_BYTES
        ):
            _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
        contents = _read_exact(api, handle, before.size)
        after = _call(
            lambda: api.query_file(handle),
            NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED,
        )
        if (
            after != before
            or type(expected.sha256) is not str
            or hashlib.sha256(contents).hexdigest() != expected.sha256
        ):
            _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(handle),
            NativeRepairEnvironmentPlanErrorCode.READ_FAILED,
        )
        held = None
        return _CapturedSource(identity, contents)
    finally:
        if held is not None:
            _safe_close(api, held)


def build_repair_environment_plan_while_package_root_held(
    package_root: PathHierarchyTrust,
    target: ResolvedRepairTarget,
    backup: EnvironmentExactStateBackup,
    *,
    api: RepairEnvironmentPlanApi | None = None,
) -> EnvironmentReplacementPlan:
    """Build and reverify the exact candidate from backup or fixed template."""

    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or type(target) is not ResolvedRepairTarget
        or type(backup) is not EnvironmentExactStateBackup
    ):
        _fail(NativeRepairEnvironmentPlanErrorCode.INPUT_INVALID)
    expected_package = StableFileIdentity(
        target.package_root.volume_serial,
        target.package_root.file_id,
    )
    if (
        package_root.root_snapshot.identity != expected_package
        or backup.stream.package_root_identity != expected_package
        or backup.stream.target_token_sha256 != target.target_token.digest_sha256
    ):
        _fail(NativeRepairEnvironmentPlanErrorCode.INPUT_INVALID)
    environment = target.compose.environment_file
    if environment is None:
        if backup.existed:
            _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
        selected_api: RepairEnvironmentPlanApi = (
            NativeWindowsEnvironmentRestoreApi() if api is None else api
        )
        if (
            _call(
                lambda: selected_api.supported,
                NativeRepairEnvironmentPlanErrorCode.READ_FAILED,
            )
            is not True
        ):
            _fail(NativeRepairEnvironmentPlanErrorCode.READ_FAILED)
        package_root.assert_unchanged_while_held()
        first = _capture_source_once(
            selected_api,
            target.compose.environment_source,
            expected_package,
        )
        second = _capture_source_once(
            selected_api,
            target.compose.environment_source,
            expected_package,
        )
        package_root.assert_unchanged_while_held()
        if first != second:
            _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
        source = second.contents
    else:
        expected_identity = StableFileIdentity(
            environment.volume_serial,
            environment.file_id,
        )
        if (
            not backup.existed
            or backup.identity != expected_identity
            or backup.contents is None
            or type(environment.size_bytes) is not int
            or len(backup.contents) != environment.size_bytes
            or hashlib.sha256(backup.contents).hexdigest() != environment.sha256
        ):
            _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
        source = backup.contents
    try:
        plan = plan_ca_environment_replacement(
            source,
            original_present=environment is not None,
        )
    except Exception:
        _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
    if (
        plan.original_contents != backup.contents
        or plan.original_sha256 != target.compose.environment_sha256
        or plan.candidate_sha256 != target.compose.planned_environment_sha256
    ):
        _fail(NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED)
    return plan


__all__ = [
    "NativeRepairEnvironmentPlanError",
    "NativeRepairEnvironmentPlanErrorCode",
    "RepairEnvironmentPlanApi",
    "build_repair_environment_plan_while_package_root_held",
]
