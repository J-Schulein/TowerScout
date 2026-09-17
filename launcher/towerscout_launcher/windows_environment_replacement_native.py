"""Journal-gated native staging for a future Windows ``.env`` replacement.

This module can create and verify a same-directory candidate temporary file,
but it cannot promote, replace, delete, or recover any package file. The caller
must provide durable journal receipts for every write-ahead transition.
"""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn, Protocol, TypeVar

from .windows_environment_replacement import (
    MAX_ENVIRONMENT_BYTES,
    EnvironmentReplacementPlan,
)
from .windows_path_trust import (
    AccessAllowedAce,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_security import (
    NativeFileFacts,
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsSecurityError,
)
from .target_contracts import ABSENT_FILE_SHA256
from .windows_recovery_environment_restore import EnvironmentDestinationObservation

_SCHEMA_VERSION = 1
_MAX_PATH_CHARACTERS = 32_768
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_TEMP_NAME = re.compile(r"^\.towerscout-env-[0-9a-f]{32}\.tmp$")
_Receipt = TypeVar("_Receipt")


class EnvironmentTempStageErrorCode(str, Enum):
    INPUT_INVALID = "environment_temp_stage_input_invalid"
    PLATFORM_UNAVAILABLE = "environment_temp_stage_platform_unavailable"
    JOURNAL_FAILED = "environment_temp_stage_journal_failed"
    CREATE_FAILED = "environment_temp_stage_create_failed"
    SECURITY_FAILED = "environment_temp_stage_security_failed"
    WRITE_FAILED = "environment_temp_stage_write_failed"
    VERIFY_FAILED = "environment_temp_stage_verify_failed"


class EnvironmentTempStageError(RuntimeError):
    """Sanitized failure while staging one journal-bound candidate file."""

    _MESSAGES = {
        EnvironmentTempStageErrorCode.INPUT_INVALID: (
            "The environment temporary-file request is invalid."
        ),
        EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE: (
            "Secure Windows environment staging is unavailable."
        ),
        EnvironmentTempStageErrorCode.JOURNAL_FAILED: (
            "The environment staging journal could not be advanced safely."
        ),
        EnvironmentTempStageErrorCode.CREATE_FAILED: (
            "The environment temporary file could not be created safely."
        ),
        EnvironmentTempStageErrorCode.SECURITY_FAILED: (
            "The environment temporary file security could not be verified."
        ),
        EnvironmentTempStageErrorCode.WRITE_FAILED: (
            "The environment temporary file could not be written durably."
        ),
        EnvironmentTempStageErrorCode.VERIFY_FAILED: (
            "The environment temporary file could not be verified safely."
        ),
    }

    def __init__(self, code: EnvironmentTempStageErrorCode) -> None:
        if type(code) is not EnvironmentTempStageErrorCode:
            raise ValueError("Unknown environment temporary-file error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentTempStageError(code={self.code.value!r})"


def _fail(code: EnvironmentTempStageErrorCode) -> NoReturn:
    raise EnvironmentTempStageError(code)


def _valid_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_temp_name(value: object) -> bool:
    return type(value) is str and _TEMP_NAME.fullmatch(value) is not None


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentTempPlanRecord:
    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    original_sha256: str = field(repr=False)
    candidate_sha256: str = field(repr=False)
    candidate_size: int
    temp_name: str = field(repr=False)
    original_present: bool
    original_identity: StableFileIdentity | None = field(default=None, repr=False)
    original_size: int | None = None
    original_file_attributes: int | None = None
    original_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or not _valid_hash(self.original_sha256)
            or not _valid_hash(self.candidate_sha256)
            or type(self.candidate_size) is not int
            or not 1 <= self.candidate_size <= MAX_ENVIRONMENT_BYTES
            or not _valid_temp_name(self.temp_name)
            or type(self.original_present) is not bool
        ):
            raise ValueError("Environment temporary-file plan record is invalid.")
        original_values = (
            self.original_identity,
            self.original_size,
            self.original_file_attributes,
            self.original_security_descriptor_sha256,
        )
        if self.original_present:
            if (
                type(self.original_identity) is not StableFileIdentity
                or self.original_identity == self.package_root_identity
                or type(self.original_size) is not int
                or not 0 <= self.original_size <= MAX_ENVIRONMENT_BYTES
                or type(self.original_file_attributes) is not int
                or not 0 <= self.original_file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.original_security_descriptor_sha256)
            ):
                raise ValueError("Environment temporary-file plan record is invalid.")
        elif self.original_sha256 != ABSENT_FILE_SHA256 or any(
            value is not None for value in original_values
        ):
            raise ValueError("Environment temporary-file plan record is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentTempPlanRecord("
            f"schema_version={self.schema_version}, "
            f"candidate_size={self.candidate_size}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentTempCreatedRecord:
    schema_version: int
    planned_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    temp_identity: StableFileIdentity = field(repr=False)
    candidate_sha256: str = field(repr=False)
    candidate_size: int
    candidate_file_attributes: int
    candidate_security_descriptor_sha256: str = field(repr=False)
    temp_name: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.planned_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.temp_identity) is not StableFileIdentity
            or self.temp_identity == self.package_root_identity
            or not _valid_hash(self.candidate_sha256)
            or type(self.candidate_size) is not int
            or not 1 <= self.candidate_size <= MAX_ENVIRONMENT_BYTES
            or type(self.candidate_file_attributes) is not int
            or not 0 <= self.candidate_file_attributes <= 0xFFFFFFFF
            or not _valid_hash(self.candidate_security_descriptor_sha256)
            or not _valid_temp_name(self.temp_name)
        ):
            raise ValueError("Environment temporary-file creation record is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentTempCreatedRecord("
            f"schema_version={self.schema_version}, "
            f"candidate_size={self.candidate_size}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentTempVerifiedRecord:
    schema_version: int
    created_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    temp_identity: StableFileIdentity = field(repr=False)
    candidate_sha256: str = field(repr=False)
    candidate_size: int
    candidate_file_attributes: int
    candidate_security_descriptor_sha256: str = field(repr=False)
    temp_name: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.created_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.temp_identity) is not StableFileIdentity
            or self.temp_identity == self.package_root_identity
            or not _valid_hash(self.candidate_sha256)
            or type(self.candidate_size) is not int
            or not 1 <= self.candidate_size <= MAX_ENVIRONMENT_BYTES
            or type(self.candidate_file_attributes) is not int
            or not 0 <= self.candidate_file_attributes <= 0xFFFFFFFF
            or not _valid_hash(self.candidate_security_descriptor_sha256)
            or not _valid_temp_name(self.temp_name)
        ):
            raise ValueError(
                "Environment temporary-file verification record is invalid."
            )

    def __repr__(self) -> str:
        return (
            "EnvironmentTempVerifiedRecord("
            f"schema_version={self.schema_version}, "
            f"candidate_size={self.candidate_size}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentAppliedRecord:
    schema_version: int
    verified_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    candidate_identity: StableFileIdentity = field(repr=False)
    candidate_sha256: str = field(repr=False)
    candidate_size: int
    candidate_file_attributes: int
    candidate_security_descriptor_sha256: str = field(repr=False)
    temp_name: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.verified_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.candidate_identity) is not StableFileIdentity
            or self.candidate_identity == self.package_root_identity
            or not _valid_hash(self.candidate_sha256)
            or type(self.candidate_size) is not int
            or not 1 <= self.candidate_size <= MAX_ENVIRONMENT_BYTES
            or type(self.candidate_file_attributes) is not int
            or not 0 <= self.candidate_file_attributes <= 0xFFFFFFFF
            or not _valid_hash(self.candidate_security_descriptor_sha256)
            or not _valid_temp_name(self.temp_name)
        ):
            raise ValueError("Applied environment record is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentAppliedRecord("
            f"schema_version={self.schema_version}, "
            f"candidate_size={self.candidate_size}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentTempPlannedReceipt:
    record: EnvironmentTempPlanRecord = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.record) is not EnvironmentTempPlanRecord or not _valid_hash(
            self.generation_sha256
        ):
            raise ValueError("Environment temporary-file planned receipt is invalid.")

    def __repr__(self) -> str:
        return "EnvironmentTempPlannedReceipt(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentTempCreatedReceipt:
    record: EnvironmentTempCreatedRecord = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.record) is not EnvironmentTempCreatedRecord or not _valid_hash(
            self.generation_sha256
        ):
            raise ValueError("Environment temporary-file created receipt is invalid.")

    def __repr__(self) -> str:
        return "EnvironmentTempCreatedReceipt(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentTempVerifiedReceipt:
    record: EnvironmentTempVerifiedRecord = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.record) is not EnvironmentTempVerifiedRecord or not _valid_hash(
            self.generation_sha256
        ):
            raise ValueError("Environment temporary-file verified receipt is invalid.")

    def __repr__(self) -> str:
        return "EnvironmentTempVerifiedReceipt(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class StagedEnvironmentCandidate:
    verified_receipt: EnvironmentTempVerifiedReceipt = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.verified_receipt) is not EnvironmentTempVerifiedReceipt:
            raise ValueError("Staged environment candidate is invalid.")

    def __repr__(self) -> str:
        return "StagedEnvironmentCandidate(<redacted>)"


class EnvironmentReplacementJournalPort(Protocol):
    """Durable transition port required before each staging side effect."""

    def record_environment_temp_planned(
        self, record: EnvironmentTempPlanRecord
    ) -> EnvironmentTempPlannedReceipt: ...

    def record_environment_temp_created(
        self, record: EnvironmentTempCreatedRecord
    ) -> EnvironmentTempCreatedReceipt: ...

    def record_environment_temp_verified(
        self, record: EnvironmentTempVerifiedRecord
    ) -> EnvironmentTempVerifiedReceipt: ...


class EnvironmentTempNameSource(Protocol):
    def new_environment_temp_name(self) -> str: ...


class _WindowsEnvironmentReplacementApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object: ...

    def open_existing_file_for_update(self, path: str) -> object: ...

    def reopen_file_for_verification(self, path: str) -> object: ...

    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def write_file(self, handle: object, contents: bytes) -> int: ...

    def flush_file(self, handle: object) -> None: ...

    def truncate_file(self, handle: object) -> None: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...


class NativeEnvironmentTempNameSource:
    def new_environment_temp_name(self) -> str:
        return f".towerscout-env-{secrets.token_hex(16)}.tmp"


def _path_key(path: str) -> str:
    value = path
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _safe_close(api: _WindowsEnvironmentReplacementApi, handle: object) -> None:
    try:
        api.close_handle(handle)
    except BaseException:
        return


def _call(
    operation: Any,
    code: EnvironmentTempStageErrorCode,
) -> Any:
    failed = False
    result: Any = None
    try:
        result = operation()
    except (OSError, RuntimeError, TypeError, ValueError):
        failed = True
    if failed:
        _fail(code)
    return result


def _journal_transition(
    operation: Any,
    expected_type: type[_Receipt],
    expected_record: object,
) -> _Receipt:
    receipt = _call(operation, EnvironmentTempStageErrorCode.JOURNAL_FAILED)
    if (
        type(receipt) is not expected_type
        or getattr(receipt, "record", None) != expected_record
    ):
        _fail(EnvironmentTempStageErrorCode.JOURNAL_FAILED)
    return receipt


def _validate_security(
    security: object,
    current_user_sid: str,
    *,
    error_code: EnvironmentTempStageErrorCode,
) -> None:
    if type(security) is not NativeSecurityFacts:
        _fail(error_code)
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
        or not _valid_hash(security.security_descriptor_sha256)
    ):
        _fail(error_code)


def _validate_file(
    facts: object,
    *,
    expected_path: str,
    package_root_identity: StableFileIdentity,
    expected_size: int,
    expected_identity: StableFileIdentity | None = None,
    error_code: EnvironmentTempStageErrorCode,
) -> StableFileIdentity:
    if type(facts) is not NativeFileFacts:
        _fail(error_code)
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
        or facts.size != expected_size
        or (expected_identity is not None and identity != expected_identity)
    ):
        _fail(error_code)
    return identity


def _write_all(
    api: _WindowsEnvironmentReplacementApi,
    handle: object,
    contents: bytes,
) -> None:
    offset = 0
    while offset < len(contents):
        written = _call(
            lambda: api.write_file(handle, contents[offset:]),
            EnvironmentTempStageErrorCode.WRITE_FAILED,
        )
        if type(written) is not int or not 0 < written <= len(contents) - offset:
            _fail(EnvironmentTempStageErrorCode.WRITE_FAILED)
        offset += written


def _read_exact(
    api: _WindowsEnvironmentReplacementApi,
    handle: object,
    expected_size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _temp_path(
    package_root: PathHierarchyTrust,
    package_root_identity: StableFileIdentity,
    temp_name: str,
) -> str:
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.evidence.root_identity != package_root_identity
        or not _valid_temp_name(temp_name)
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    package_path = package_root.root_snapshot.final_path
    path = ntpath.join(package_path, temp_name)
    if len(path) > _MAX_PATH_CHARACTERS or _path_key(ntpath.dirname(path)) != _path_key(
        package_path
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    return path


def _remove_exact_planned_orphan(
    api: _WindowsEnvironmentReplacementApi,
    *,
    path: str,
    package_root_identity: StableFileIdentity,
    current_user_sid: str,
) -> None:
    handle = _call(
        lambda: api.open_file_for_delete_if_exists(path),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return
    held: object | None = handle
    operation_failed = False
    try:
        identity = _validate_file(
            _call(
                lambda: api.query_file(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            ),
            expected_path=path,
            package_root_identity=package_root_identity,
            expected_size=0,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            _call(
                lambda: api.query_security(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            ),
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            _call(
                lambda: api.query_file(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            ),
            expected_path=path,
            package_root_identity=package_root_identity,
            expected_size=0,
            expected_identity=identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            _call(
                lambda: api.query_security(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            ),
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
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
    remaining = _call(
        lambda: api.reopen_file_if_exists(path),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    if remaining is not None:
        _safe_close(api, remaining)
        _fail(
            EnvironmentTempStageErrorCode.WRITE_FAILED
            if operation_failed
            else EnvironmentTempStageErrorCode.VERIFY_FAILED
        )


def _record_matches_request(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root_identity: StableFileIdentity,
    record: EnvironmentTempPlanRecord,
) -> bool:
    return record == EnvironmentTempPlanRecord(
        _SCHEMA_VERSION,
        package_root_identity,
        plan.original_sha256,
        plan.candidate_sha256,
        len(plan.candidate_contents),
        record.temp_name,
        original.present,
        original.identity,
        original.size,
        original.file_attributes,
        original.security_descriptor_sha256,
    )


class _FixedEnvironmentTempNameSource:
    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def new_environment_temp_name(self) -> str:
        return self._name


def _validate_original_observation(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root_identity: StableFileIdentity,
) -> None:
    if type(original) is not EnvironmentDestinationObservation:
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    expected_present = plan.original_contents is not None
    if original.present is not expected_present:
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    if not original.present:
        if plan.original_sha256 != ABSENT_FILE_SHA256:
            _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
        return
    if (
        original.identity == package_root_identity
        or original.sha256 != plan.original_sha256
        or original.size != len(plan.original_contents or b"")
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)


def _stage_while_root_held(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root: PathHierarchyTrust,
    journal: EnvironmentReplacementJournalPort,
    api: _WindowsEnvironmentReplacementApi,
    name_source: EnvironmentTempNameSource,
) -> StagedEnvironmentCandidate:
    temp_name = _call(
        name_source.new_environment_temp_name,
        EnvironmentTempStageErrorCode.INPUT_INVALID,
    )
    if not _valid_temp_name(temp_name):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    package_root_identity = package_root.evidence.root_identity
    _validate_original_observation(plan, original, package_root_identity)
    package_path = package_root.root_snapshot.final_path
    temp_path = ntpath.join(package_path, temp_name)
    if len(temp_path) > _MAX_PATH_CHARACTERS or _path_key(
        ntpath.dirname(temp_path)
    ) != _path_key(package_path):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)

    planned_record = EnvironmentTempPlanRecord(
        _SCHEMA_VERSION,
        package_root_identity,
        plan.original_sha256,
        plan.candidate_sha256,
        len(plan.candidate_contents),
        temp_name,
        original.present,
        original.identity,
        original.size,
        original.file_attributes,
        original.security_descriptor_sha256,
    )
    planned_receipt = _journal_transition(
        lambda: journal.record_environment_temp_planned(planned_record),
        EnvironmentTempPlannedReceipt,
        planned_record,
    )

    current_user_sid = _call(
        api.current_user_sid,
        EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if type(current_user_sid) is not str or not _SID.fullmatch(current_user_sid):
        _fail(EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE)

    handle = _call(
        lambda: api.create_new_restricted_file(
            temp_path,
            owner_sid=current_user_sid,
        ),
        EnvironmentTempStageErrorCode.CREATE_FAILED,
    )
    if handle is None:
        _fail(EnvironmentTempStageErrorCode.CREATE_FAILED)
    first_handle: object | None = handle
    try:
        created_facts = _call(
            lambda: api.query_file(handle),
            EnvironmentTempStageErrorCode.SECURITY_FAILED,
        )
        temp_identity = _validate_file(
            created_facts,
            expected_path=temp_path,
            package_root_identity=package_root_identity,
            expected_size=0,
            error_code=EnvironmentTempStageErrorCode.SECURITY_FAILED,
        )
        if type(created_facts) is not NativeFileFacts:
            _fail(EnvironmentTempStageErrorCode.SECURITY_FAILED)
        candidate_file_attributes = created_facts.attributes
        security = _call(
            lambda: api.query_security(handle),
            EnvironmentTempStageErrorCode.SECURITY_FAILED,
        )
        _validate_security(
            security,
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.SECURITY_FAILED,
        )
        if type(security) is not NativeSecurityFacts:
            _fail(EnvironmentTempStageErrorCode.SECURITY_FAILED)
        candidate_security_descriptor_sha256 = security.security_descriptor_sha256
        if type(candidate_security_descriptor_sha256) is not str or not _valid_hash(
            candidate_security_descriptor_sha256
        ):
            _fail(EnvironmentTempStageErrorCode.SECURITY_FAILED)
        created_record = EnvironmentTempCreatedRecord(
            _SCHEMA_VERSION,
            planned_receipt.generation_sha256,
            package_root_identity,
            temp_identity,
            plan.candidate_sha256,
            len(plan.candidate_contents),
            candidate_file_attributes,
            candidate_security_descriptor_sha256,
            temp_name,
        )
        created_receipt = _journal_transition(
            lambda: journal.record_environment_temp_created(created_record),
            EnvironmentTempCreatedReceipt,
            created_record,
        )

        _write_all(api, handle, plan.candidate_contents)
        _call(
            lambda: api.flush_file(handle),
            EnvironmentTempStageErrorCode.WRITE_FAILED,
        )
        written_facts = _call(
            lambda: api.query_file(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            written_facts,
            expected_path=temp_path,
            package_root_identity=package_root_identity,
            expected_size=len(plan.candidate_contents),
            expected_identity=temp_identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            type(written_facts) is not NativeFileFacts
            or written_facts.attributes != candidate_file_attributes
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        if (
            _read_exact(api, handle, len(plan.candidate_contents))
            != plan.candidate_contents
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        first_handle = None
    finally:
        if first_handle is not None:
            _safe_close(api, first_handle)

    reopened = _call(
        lambda: api.reopen_file_for_verification(temp_path),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    if reopened is None:
        _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
    reopened_handle: object | None = reopened
    try:
        reopened_facts = _call(
            lambda: api.query_file(reopened),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            reopened_facts,
            expected_path=temp_path,
            package_root_identity=package_root_identity,
            expected_size=len(plan.candidate_contents),
            expected_identity=temp_identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            type(reopened_facts) is not NativeFileFacts
            or reopened_facts.attributes != candidate_file_attributes
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        reopened_security = _call(
            lambda: api.query_security(reopened),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            reopened_security,
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            type(reopened_security) is not NativeSecurityFacts
            or reopened_security.security_descriptor_sha256
            != candidate_security_descriptor_sha256
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        reopened_contents = _read_exact(api, reopened, len(plan.candidate_contents))
        if hashlib.sha256(reopened_contents).hexdigest() != plan.candidate_sha256:
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(reopened),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        reopened_handle = None
    finally:
        if reopened_handle is not None:
            _safe_close(api, reopened_handle)

    verified_record = EnvironmentTempVerifiedRecord(
        _SCHEMA_VERSION,
        created_receipt.generation_sha256,
        package_root_identity,
        temp_identity,
        plan.candidate_sha256,
        len(plan.candidate_contents),
        candidate_file_attributes,
        candidate_security_descriptor_sha256,
        temp_name,
    )
    verified_receipt = _journal_transition(
        lambda: journal.record_environment_temp_verified(verified_record),
        EnvironmentTempVerifiedReceipt,
        verified_record,
    )
    return StagedEnvironmentCandidate(verified_receipt)


def _resume_environment_candidate_while_root_held(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root: PathHierarchyTrust,
    journal: EnvironmentReplacementJournalPort,
    planned_receipt: EnvironmentTempPlannedReceipt,
    created_receipt: EnvironmentTempCreatedReceipt | None,
    *,
    api: _WindowsEnvironmentReplacementApi,
) -> StagedEnvironmentCandidate:
    """Resume only one authenticated planned or created candidate temp."""

    if (
        type(plan) is not EnvironmentReplacementPlan
        or type(original) is not EnvironmentDestinationObservation
        or type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or type(planned_receipt) is not EnvironmentTempPlannedReceipt
        or (
            created_receipt is not None
            and type(created_receipt) is not EnvironmentTempCreatedReceipt
        )
        or journal is None
        or api is None
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    package_root_identity = package_root.evidence.root_identity
    _validate_original_observation(plan, original, package_root_identity)
    planned = planned_receipt.record
    try:
        matches_request = _record_matches_request(
            plan,
            original,
            package_root_identity,
            planned,
        )
    except ValueError:
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    if not matches_request:
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    path = _temp_path(package_root, package_root_identity, planned.temp_name)
    current_user_sid = _call(
        api.current_user_sid,
        EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if type(current_user_sid) is not str or _SID.fullmatch(current_user_sid) is None:
        _fail(EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE)

    if created_receipt is None:
        _remove_exact_planned_orphan(
            api,
            path=path,
            package_root_identity=package_root_identity,
            current_user_sid=current_user_sid,
        )
        return _stage_while_root_held(
            plan,
            original,
            package_root,
            journal,
            api,
            _FixedEnvironmentTempNameSource(planned.temp_name),
        )

    created = created_receipt.record
    if (
        created.planned_generation_sha256 != planned_receipt.generation_sha256
        or created.package_root_identity != package_root_identity
        or created.candidate_sha256 != plan.candidate_sha256
        or created.candidate_size != len(plan.candidate_contents)
        or created.temp_name != planned.temp_name
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    handle = _call(
        lambda: api.open_existing_file_for_update(path),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
    held: object | None = handle
    try:
        facts = _call(
            lambda: api.query_file(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if type(facts) is not NativeFileFacts or not 0 <= facts.size <= len(
            plan.candidate_contents
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        _validate_file(
            facts,
            expected_path=path,
            package_root_identity=package_root_identity,
            expected_size=facts.size,
            expected_identity=created.temp_identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        security = _call(
            lambda: api.query_security(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            security,
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            facts.attributes != created.candidate_file_attributes
            or type(security) is not NativeSecurityFacts
            or security.security_descriptor_sha256
            != created.candidate_security_descriptor_sha256
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        contents = _read_exact(api, handle, facts.size)
        if contents != plan.candidate_contents:
            second_facts = _call(
                lambda: api.query_file(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            _validate_file(
                second_facts,
                expected_path=path,
                package_root_identity=package_root_identity,
                expected_size=facts.size,
                expected_identity=created.temp_identity,
                error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            second_security = _call(
                lambda: api.query_security(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            _validate_security(
                second_security,
                current_user_sid,
                error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            if (
                type(second_facts) is not NativeFileFacts
                or second_facts.attributes != created.candidate_file_attributes
                or type(second_security) is not NativeSecurityFacts
                or second_security.security_descriptor_sha256
                != created.candidate_security_descriptor_sha256
            ):
                _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
            _call(
                lambda: api.truncate_file(handle),
                EnvironmentTempStageErrorCode.WRITE_FAILED,
            )
            truncated = _call(
                lambda: api.query_file(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            _validate_file(
                truncated,
                expected_path=path,
                package_root_identity=package_root_identity,
                expected_size=0,
                expected_identity=created.temp_identity,
                error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            truncated_security = _call(
                lambda: api.query_security(handle),
                EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            _validate_security(
                truncated_security,
                current_user_sid,
                error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
            )
            if (
                type(truncated) is not NativeFileFacts
                or truncated.attributes != created.candidate_file_attributes
                or type(truncated_security) is not NativeSecurityFacts
                or truncated_security.security_descriptor_sha256
                != created.candidate_security_descriptor_sha256
            ):
                _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
            _write_all(api, handle, plan.candidate_contents)
        _call(
            lambda: api.flush_file(handle),
            EnvironmentTempStageErrorCode.WRITE_FAILED,
        )
        written = _call(
            lambda: api.query_file(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            written,
            expected_path=path,
            package_root_identity=package_root_identity,
            expected_size=len(plan.candidate_contents),
            expected_identity=created.temp_identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            type(written) is not NativeFileFacts
            or written.attributes != created.candidate_file_attributes
            or _read_exact(api, handle, len(plan.candidate_contents))
            != plan.candidate_contents
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)

    reopened = _call(
        lambda: api.reopen_file_for_verification(path),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    if reopened is None:
        _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
    reopened_held: object | None = reopened
    try:
        reopened_facts = _call(
            lambda: api.query_file(reopened),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            reopened_facts,
            expected_path=path,
            package_root_identity=package_root_identity,
            expected_size=len(plan.candidate_contents),
            expected_identity=created.temp_identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        reopened_security = _call(
            lambda: api.query_security(reopened),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            reopened_security,
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            type(reopened_facts) is not NativeFileFacts
            or reopened_facts.attributes != created.candidate_file_attributes
            or type(reopened_security) is not NativeSecurityFacts
            or reopened_security.security_descriptor_sha256
            != created.candidate_security_descriptor_sha256
            or hashlib.sha256(
                _read_exact(api, reopened, len(plan.candidate_contents))
            ).hexdigest()
            != plan.candidate_sha256
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(reopened),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        reopened_held = None
    finally:
        if reopened_held is not None:
            _safe_close(api, reopened_held)

    verified = EnvironmentTempVerifiedRecord(
        _SCHEMA_VERSION,
        created_receipt.generation_sha256,
        package_root_identity,
        created.temp_identity,
        plan.candidate_sha256,
        len(plan.candidate_contents),
        created.candidate_file_attributes,
        created.candidate_security_descriptor_sha256,
        planned.temp_name,
    )
    receipt = _journal_transition(
        lambda: journal.record_environment_temp_verified(verified),
        EnvironmentTempVerifiedReceipt,
        verified,
    )
    return StagedEnvironmentCandidate(receipt)


def _verify_environment_candidate_while_root_held(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root: PathHierarchyTrust,
    planned_receipt: EnvironmentTempPlannedReceipt,
    created_receipt: EnvironmentTempCreatedReceipt,
    verified_receipt: EnvironmentTempVerifiedReceipt,
    *,
    api: _WindowsEnvironmentReplacementApi,
) -> StagedEnvironmentCandidate:
    """Reverify one immutable generation-3 temp without repairing drift."""

    if (
        type(plan) is not EnvironmentReplacementPlan
        or type(original) is not EnvironmentDestinationObservation
        or type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or type(planned_receipt) is not EnvironmentTempPlannedReceipt
        or type(created_receipt) is not EnvironmentTempCreatedReceipt
        or type(verified_receipt) is not EnvironmentTempVerifiedReceipt
        or api is None
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    package_root_identity = package_root.evidence.root_identity
    _validate_original_observation(plan, original, package_root_identity)
    planned = planned_receipt.record
    created = created_receipt.record
    verified = verified_receipt.record
    try:
        matches_request = _record_matches_request(
            plan,
            original,
            package_root_identity,
            planned,
        )
    except ValueError:
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    if (
        not matches_request
        or created.planned_generation_sha256 != planned_receipt.generation_sha256
        or verified.created_generation_sha256 != created_receipt.generation_sha256
        or created.package_root_identity != package_root_identity
        or verified.package_root_identity != package_root_identity
        or verified.temp_identity != created.temp_identity
        or verified.candidate_sha256 != plan.candidate_sha256
        or verified.candidate_size != len(plan.candidate_contents)
        or verified.candidate_file_attributes != created.candidate_file_attributes
        or verified.candidate_security_descriptor_sha256
        != created.candidate_security_descriptor_sha256
        or verified.temp_name != planned.temp_name
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    path = _temp_path(package_root, package_root_identity, verified.temp_name)
    current_user_sid = _call(
        api.current_user_sid,
        EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if type(current_user_sid) is not str or _SID.fullmatch(current_user_sid) is None:
        _fail(EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE)
    handle = _call(
        lambda: api.reopen_file_for_verification(path),
        EnvironmentTempStageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
    held: object | None = handle
    try:
        facts = _call(
            lambda: api.query_file(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            facts,
            expected_path=path,
            package_root_identity=package_root_identity,
            expected_size=verified.candidate_size,
            expected_identity=verified.temp_identity,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        security = _call(
            lambda: api.query_security(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            security,
            current_user_sid,
            error_code=EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        if (
            type(facts) is not NativeFileFacts
            or facts.attributes != verified.candidate_file_attributes
            or type(security) is not NativeSecurityFacts
            or security.security_descriptor_sha256
            != verified.candidate_security_descriptor_sha256
            or hashlib.sha256(
                _read_exact(api, handle, verified.candidate_size)
            ).hexdigest()
            != verified.candidate_sha256
        ):
            _fail(EnvironmentTempStageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(handle),
            EnvironmentTempStageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return StagedEnvironmentCandidate(verified_receipt)


def _stage_environment_candidate_with_api(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root: PathHierarchyTrust,
    journal: EnvironmentReplacementJournalPort,
    *,
    api: _WindowsEnvironmentReplacementApi,
    name_source: EnvironmentTempNameSource,
) -> StagedEnvironmentCandidate:
    """Stage a candidate only behind injected durable receipts and held trust."""

    if (
        type(plan) is not EnvironmentReplacementPlan
        or type(original) is not EnvironmentDestinationObservation
        or type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or journal is None
        or api is None
        or name_source is None
    ):
        _fail(EnvironmentTempStageErrorCode.INPUT_INVALID)
    supported = _call(
        lambda: api.supported,
        EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if supported is not True:
        _fail(EnvironmentTempStageErrorCode.PLATFORM_UNAVAILABLE)

    failed = False
    result: StagedEnvironmentCandidate | None = None
    try:
        result = package_root.run_while_held(
            lambda: _stage_while_root_held(
                plan,
                original,
                package_root,
                journal,
                api,
                name_source,
            )
        )
    except EnvironmentTempStageError:
        raise
    except WindowsSecurityError:
        failed = True
    except (OSError, RuntimeError, TypeError, ValueError):
        failed = True
    if failed or type(result) is not StagedEnvironmentCandidate:
        _fail(EnvironmentTempStageErrorCode.SECURITY_FAILED)
    return result


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", ctypes.c_int),
    )


class NativeWindowsEnvironmentReplacementApi:
    """ctypes adapter for restrictive same-directory candidate-file staging."""

    __slots__ = ("_advapi32", "_file_api", "_kernel32", "_path_api")

    def __init__(self) -> None:
        self._advapi32: Any | None = None
        self._kernel32: Any | None = None
        self._file_api = NativeWindowsFileApi()
        self._path_api = NativeWindowsPathTrustApi()
        loader = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or loader is None:
            return
        try:
            self._advapi32 = loader("advapi32", use_last_error=True)
            self._kernel32 = loader("kernel32", use_last_error=True)
            self._bind()
        except (AttributeError, OSError, TypeError, ValueError):
            self._advapi32 = None
            self._kernel32 = None

    @property
    def supported(self) -> bool:
        return (
            self._advapi32 is not None
            and self._kernel32 is not None
            and self._file_api.supported
            and self._path_api.supported
        )

    def _require(self) -> tuple[Any, Any]:
        if self._advapi32 is None or self._kernel32 is None:
            raise OSError("Native Windows environment staging is unavailable.")
        return self._advapi32, self._kernel32

    def _bind(self) -> None:
        advapi32, kernel32 = self._require()
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        )
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            ctypes.c_int
        )
        kernel32.CreateFileW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(_SecurityAttributes),
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.WriteFile.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        )
        kernel32.WriteFile.restype = ctypes.c_int
        kernel32.FlushFileBuffers.argtypes = (ctypes.c_void_p,)
        kernel32.FlushFileBuffers.restype = ctypes.c_int
        kernel32.SetEndOfFile.argtypes = (ctypes.c_void_p,)
        kernel32.SetEndOfFile.restype = ctypes.c_int
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree.restype = ctypes.c_void_p

    @staticmethod
    def _handle(value: object) -> ctypes.c_void_p:
        if type(value) is not int or value <= 0:
            raise OSError("Native Windows environment handle is invalid.")
        return ctypes.c_void_p(value)

    @staticmethod
    def _last_error(message: str) -> NoReturn:
        raise OSError(ctypes.get_last_error(), message)

    def current_user_sid(self) -> str:
        return self._path_api.current_user_sid()

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        if (
            type(path) is not str
            or not path
            or "\x00" in path
            or len(path) > _MAX_PATH_CHARACTERS
            or type(owner_sid) is not str
            or _SID.fullmatch(owner_sid) is None
        ):
            raise ValueError("Native Windows environment creation request is invalid.")
        advapi32, kernel32 = self._require()
        descriptor = ctypes.c_void_p()
        descriptor_size = ctypes.c_uint32()
        sddl = f"O:{owner_sid}D:P(A;;FA;;;SY)(A;;FA;;;{owner_sid})"
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            self._last_error("Native Windows environment descriptor creation failed.")
        invalid = ctypes.c_void_p(-1).value
        native: int | None = None
        try:
            attributes = _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes),
                descriptor,
                False,
            )
            ctypes.set_last_error(0)
            raw_handle = kernel32.CreateFileW(
                path,
                0xC0020000,  # GENERIC_READ | GENERIC_WRITE | READ_CONTROL
                0x00000001,  # FILE_SHARE_READ; deny write and delete sharing
                ctypes.byref(attributes),
                1,  # CREATE_NEW
                0x00200080,  # OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL
                None,
            )
            if raw_handle is None or raw_handle == invalid:
                self._last_error("Native Windows environment creation failed.")
            native = int(raw_handle)
            return native
        except BaseException:
            if native is not None and native != invalid:
                try:
                    self._file_api.close_handle(native)
                except BaseException:
                    pass
            raise
        finally:
            if descriptor:
                kernel32.LocalFree(descriptor)

    def reopen_file_for_verification(self, path: str) -> object:
        return self._file_api.open_file_for_identity(path)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._file_api.open_file_for_delete_if_exists(path)

    def reopen_file_if_exists(self, path: str) -> object | None:
        return self._file_api.open_file_if_exists(path)

    def open_existing_file_for_update(self, path: str) -> object:
        if (
            type(path) is not str
            or not path
            or "\x00" in path
            or len(path) > _MAX_PATH_CHARACTERS
        ):
            raise ValueError("Native Windows environment update request is invalid.")
        _advapi32, kernel32 = self._require()
        invalid = ctypes.c_void_p(-1).value
        native: int | None = None
        try:
            ctypes.set_last_error(0)
            raw_handle = kernel32.CreateFileW(
                path,
                0xC0020000,  # GENERIC_READ | GENERIC_WRITE | READ_CONTROL
                0x00000001,  # FILE_SHARE_READ; deny write and delete sharing
                None,
                3,  # OPEN_EXISTING
                0x00200080,  # OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL
                None,
            )
            if raw_handle is None or raw_handle == invalid:
                self._last_error("Native Windows environment update open failed.")
            native = int(raw_handle)
            return native
        except BaseException:
            if native is not None and native != invalid:
                try:
                    self._file_api.close_handle(native)
                except BaseException:
                    pass
            raise

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._file_api.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._path_api.query_security(handle)

    def write_file(self, handle: object, contents: bytes) -> int:
        if type(contents) is not bytes or not contents:
            raise ValueError("Native Windows environment write request is invalid.")
        _advapi32, kernel32 = self._require()
        amount = min(len(contents), _HASH_CHUNK_BYTES)
        buffer = ctypes.create_string_buffer(contents[:amount], amount)
        written = ctypes.c_uint32()
        if not kernel32.WriteFile(
            self._handle(handle),
            buffer,
            amount,
            ctypes.byref(written),
            None,
        ):
            self._last_error("Native Windows environment write failed.")
        return int(written.value)

    def flush_file(self, handle: object) -> None:
        _advapi32, kernel32 = self._require()
        if not kernel32.FlushFileBuffers(self._handle(handle)):
            self._last_error("Native Windows environment flush failed.")

    def truncate_file(self, handle: object) -> None:
        _advapi32, kernel32 = self._require()
        self._file_api.seek_file(handle, 0)
        if not kernel32.SetEndOfFile(self._handle(handle)):
            self._last_error("Native Windows environment truncate failed.")

    def seek_file(self, handle: object, offset: int) -> None:
        self._file_api.seek_file(handle, offset)

    def read_file(self, handle: object, maximum: int) -> bytes:
        return self._file_api.read_file(handle, maximum)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._file_api.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._file_api.close_handle(handle)


__all__ = [
    "EnvironmentAppliedRecord",
    "EnvironmentReplacementJournalPort",
    "EnvironmentTempCreatedReceipt",
    "EnvironmentTempCreatedRecord",
    "EnvironmentTempNameSource",
    "EnvironmentTempPlanRecord",
    "EnvironmentTempPlannedReceipt",
    "EnvironmentTempStageError",
    "EnvironmentTempStageErrorCode",
    "EnvironmentTempVerifiedReceipt",
    "EnvironmentTempVerifiedRecord",
    "NativeEnvironmentTempNameSource",
    "NativeWindowsEnvironmentReplacementApi",
    "StagedEnvironmentCandidate",
]
