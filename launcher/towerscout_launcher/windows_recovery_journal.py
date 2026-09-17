"""Authenticated recovery-journal generation and chain-selection primitives.

This source-only Gate-A layer defines canonical protected generation bytes and
validates one environment temporary-file transition chain. It does not read or
write journal files, repair pointers, clean artifacts, stage package files, or
enable repair/runtime mutation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn, Protocol, cast

from .windows_environment_replacement_native import (
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from .windows_protected_state import (
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from .windows_security import StableFileIdentity

_SCHEMA_VERSION = 1
_MAX_GENERATION_BYTES = 262_144
_MAX_POINTER_BYTES = 1_024
_MAX_JSON_DEPTH = 8
_MAX_JSON_ITEMS = 32
_MAX_JSON_NODES = 256
_MAX_JSON_STRING_CHARACTERS = 1_024
_MAX_CHAIN_CANDIDATES = 64
_MAX_SEQUENCE = 2**63 - 1
_MAX_PROTECTED_BACKUP_BYTES = 4 * 1024 * 1024
_MAX_ENVIRONMENT_BYTES = 262_144
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JOURNAL_ID = re.compile(r"^[0-9a-f]{32}$")
_BACKUP_NAME = re.compile(r"^recovery-backup-[0-9a-f]{32}\.blob$")
_ENVIRONMENT_TEMP_NAME = re.compile(r"^\.towerscout-env-[0-9a-f]{32}\.tmp$")

GENESIS_GENERATION_SHA256 = hashlib.sha256(
    b"TowerScout.AbsentRecoveryJournalGeneration.v1"
).hexdigest()


class RecoveryJournalErrorCode(str, Enum):
    INPUT_INVALID = "recovery_journal_input_invalid"
    GENERATION_INVALID = "recovery_journal_generation_invalid"
    AUTHENTICATION_FAILED = "recovery_journal_authentication_failed"
    POINTER_INVALID = "recovery_journal_pointer_invalid"
    CHAIN_INVALID = "recovery_journal_chain_invalid"


class RecoveryJournalError(RuntimeError):
    """Sanitized failure at the protected recovery-journal boundary."""

    _MESSAGES = {
        RecoveryJournalErrorCode.INPUT_INVALID: (
            "The recovery journal request is invalid."
        ),
        RecoveryJournalErrorCode.GENERATION_INVALID: (
            "A recovery journal generation is invalid."
        ),
        RecoveryJournalErrorCode.AUTHENTICATION_FAILED: (
            "A recovery journal generation could not be authenticated."
        ),
        RecoveryJournalErrorCode.POINTER_INVALID: (
            "The recovery journal pointer is invalid."
        ),
        RecoveryJournalErrorCode.CHAIN_INVALID: (
            "The recovery journal generation chain is invalid."
        ),
    }

    def __init__(self, code: RecoveryJournalErrorCode) -> None:
        if type(code) is not RecoveryJournalErrorCode:
            raise ValueError("Unknown recovery journal error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryJournalError(code={self.code.value!r})"


def _fail(code: RecoveryJournalErrorCode) -> NoReturn:
    raise RecoveryJournalError(code)


def _valid_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_journal_id(value: object) -> bool:
    return type(value) is str and _JOURNAL_ID.fullmatch(value) is not None


@dataclass(frozen=True, slots=True, repr=False)
class JournalStreamIdentity:
    schema_version: int
    journal_id: str = field(repr=False)
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_journal_id(self.journal_id)
            or not _valid_hash(self.target_token_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
        ):
            raise ValueError("Recovery journal stream identity is invalid.")

    def __repr__(self) -> str:
        return "JournalStreamIdentity(schema_version=1, <redacted>)"


class EnvironmentJournalState(str, Enum):
    BACKUP_PREPARING = "backup_preparing"
    BACKUP_VERIFIED = "backup_verified"
    ROLLBACK_ARMED = "rollback_armed"
    ROLLBACK_STARTED = "rollback_started"
    ENVIRONMENT_RESTORE_TEMP_PLANNED = "environment_restore_temp_planned"
    ENVIRONMENT_RESTORE_TEMP_CREATED = "environment_restore_temp_created"
    ENVIRONMENT_RESTORE_TEMP_VERIFIED = "environment_restore_temp_verified"
    ENVIRONMENT_TEMP_PLANNED = "environment_temp_planned"
    ENVIRONMENT_TEMP_CREATED = "environment_temp_created"
    ENVIRONMENT_TEMP_VERIFIED = "environment_temp_verified"


@dataclass(frozen=True, slots=True, repr=False)
class BackupPreparingRecord:
    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_name: str = field(repr=False)
    certificate_backup_name: str = field(repr=False)
    environment_present: bool
    environment_sha256: str | None = field(default=None, repr=False)
    environment_file_attributes: int | None = None
    environment_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )
    local_ca_present: bool = False
    local_ca_sha256: str | None = field(default=None, repr=False)
    local_ca_mode: int | None = None
    ca_bundle_present: bool = False
    ca_bundle_sha256: str | None = field(default=None, repr=False)
    ca_bundle_mode: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.environment_backup_name) is not str
            or _BACKUP_NAME.fullmatch(self.environment_backup_name) is None
            or type(self.certificate_backup_name) is not str
            or _BACKUP_NAME.fullmatch(self.certificate_backup_name) is None
            or self.environment_backup_name == self.certificate_backup_name
            or type(self.environment_present) is not bool
            or type(self.local_ca_present) is not bool
            or type(self.ca_bundle_present) is not bool
        ):
            raise ValueError("Backup preparation record is invalid.")
        environment_values = (
            self.environment_sha256,
            self.environment_file_attributes,
            self.environment_security_descriptor_sha256,
        )
        if self.environment_present:
            if (
                not _valid_hash(self.environment_sha256)
                or type(self.environment_file_attributes) is not int
                or not 0 <= self.environment_file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.environment_security_descriptor_sha256)
            ):
                raise ValueError("Backup environment state is invalid.")
        elif any(value is not None for value in environment_values):
            raise ValueError("Backup environment state is invalid.")
        self._validate_certificate_state(
            self.local_ca_present,
            self.local_ca_sha256,
            self.local_ca_mode,
        )
        self._validate_certificate_state(
            self.ca_bundle_present,
            self.ca_bundle_sha256,
            self.ca_bundle_mode,
        )

    @staticmethod
    def _validate_certificate_state(
        present: bool,
        sha256: str | None,
        mode: int | None,
    ) -> None:
        if present:
            if (
                not _valid_hash(sha256)
                or type(mode) is not int
                or not 0 <= mode <= 0o7777
            ):
                raise ValueError("Backup certificate state is invalid.")
        elif sha256 is not None or mode is not None:
            raise ValueError("Backup certificate state is invalid.")

    def __repr__(self) -> str:
        return (
            "BackupPreparingRecord("
            f"environment_present={self.environment_present!r}, "
            f"local_ca_present={self.local_ca_present!r}, "
            f"ca_bundle_present={self.ca_bundle_present!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class BackupVerifiedRecord:
    schema_version: int
    preparing_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_identity: StableFileIdentity = field(repr=False)
    environment_ciphertext_sha256: str = field(repr=False)
    environment_ciphertext_size: int
    certificate_backup_identity: StableFileIdentity = field(repr=False)
    certificate_ciphertext_sha256: str = field(repr=False)
    certificate_ciphertext_size: int

    def __post_init__(self) -> None:
        identities = (
            self.package_root_identity,
            self.environment_backup_identity,
            self.certificate_backup_identity,
        )
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.preparing_generation_sha256)
            or any(type(identity) is not StableFileIdentity for identity in identities)
            or len(set(identities)) != len(identities)
            or not _valid_hash(self.environment_ciphertext_sha256)
            or type(self.environment_ciphertext_size) is not int
            or not 1 <= self.environment_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
            or not _valid_hash(self.certificate_ciphertext_sha256)
            or type(self.certificate_ciphertext_size) is not int
            or not 1 <= self.certificate_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
        ):
            raise ValueError("Verified backup record is invalid.")

    def __repr__(self) -> str:
        return (
            "BackupVerifiedRecord("
            f"environment_ciphertext_size={self.environment_ciphertext_size}, "
            f"certificate_ciphertext_size={self.certificate_ciphertext_size}, "
            "<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RollbackArmedRecord:
    schema_version: int
    backup_verified_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_identity: StableFileIdentity = field(repr=False)
    environment_ciphertext_sha256: str = field(repr=False)
    environment_ciphertext_size: int
    certificate_backup_identity: StableFileIdentity = field(repr=False)
    certificate_ciphertext_sha256: str = field(repr=False)
    certificate_ciphertext_size: int

    def __post_init__(self) -> None:
        identities = (
            self.package_root_identity,
            self.environment_backup_identity,
            self.certificate_backup_identity,
        )
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.backup_verified_generation_sha256)
            or any(type(identity) is not StableFileIdentity for identity in identities)
            or len(set(identities)) != len(identities)
            or not _valid_hash(self.environment_ciphertext_sha256)
            or type(self.environment_ciphertext_size) is not int
            or not 1 <= self.environment_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
            or not _valid_hash(self.certificate_ciphertext_sha256)
            or type(self.certificate_ciphertext_size) is not int
            or not 1 <= self.certificate_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
        ):
            raise ValueError("Rollback armed record is invalid.")

    def __repr__(self) -> str:
        return (
            "RollbackArmedRecord("
            f"environment_ciphertext_size={self.environment_ciphertext_size}, "
            f"certificate_ciphertext_size={self.certificate_ciphertext_size}, "
            "<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RollbackStartedRecord:
    schema_version: int
    rollback_armed_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_identity: StableFileIdentity = field(repr=False)
    environment_ciphertext_sha256: str = field(repr=False)
    environment_ciphertext_size: int
    certificate_backup_identity: StableFileIdentity = field(repr=False)
    certificate_ciphertext_sha256: str = field(repr=False)
    certificate_ciphertext_size: int

    def __post_init__(self) -> None:
        identities = (
            self.package_root_identity,
            self.environment_backup_identity,
            self.certificate_backup_identity,
        )
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.rollback_armed_generation_sha256)
            or any(type(identity) is not StableFileIdentity for identity in identities)
            or len(set(identities)) != len(identities)
            or not _valid_hash(self.environment_ciphertext_sha256)
            or type(self.environment_ciphertext_size) is not int
            or not 1 <= self.environment_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
            or not _valid_hash(self.certificate_ciphertext_sha256)
            or type(self.certificate_ciphertext_size) is not int
            or not 1 <= self.certificate_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
        ):
            raise ValueError("Rollback started record is invalid.")

    def __repr__(self) -> str:
        return (
            "RollbackStartedRecord("
            f"environment_ciphertext_size={self.environment_ciphertext_size}, "
            f"certificate_ciphertext_size={self.certificate_ciphertext_size}, "
            "<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentRestoreTempPlanRecord:
    schema_version: int
    rollback_started_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_identity: StableFileIdentity = field(repr=False)
    environment_ciphertext_sha256: str = field(repr=False)
    environment_ciphertext_size: int
    environment_present: bool
    environment_sha256: str | None = field(default=None, repr=False)
    environment_size: int | None = None
    environment_file_attributes: int | None = None
    environment_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )
    temp_name: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.rollback_started_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.environment_backup_identity) is not StableFileIdentity
            or self.environment_backup_identity == self.package_root_identity
            or not _valid_hash(self.environment_ciphertext_sha256)
            or type(self.environment_ciphertext_size) is not int
            or not 1 <= self.environment_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
            or type(self.environment_present) is not bool
        ):
            raise ValueError("Environment restore temporary-file plan is invalid.")
        environment_values = (
            self.environment_sha256,
            self.environment_size,
            self.environment_file_attributes,
            self.environment_security_descriptor_sha256,
            self.temp_name,
        )
        if self.environment_present:
            if (
                not _valid_hash(self.environment_sha256)
                or type(self.environment_size) is not int
                or not 0 <= self.environment_size <= _MAX_ENVIRONMENT_BYTES
                or type(self.environment_file_attributes) is not int
                or not 0 <= self.environment_file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.environment_security_descriptor_sha256)
                or type(self.temp_name) is not str
                or _ENVIRONMENT_TEMP_NAME.fullmatch(self.temp_name) is None
            ):
                raise ValueError("Environment restore temporary-file plan is invalid.")
        elif any(value is not None for value in environment_values):
            raise ValueError("Environment restore temporary-file plan is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentRestoreTempPlanRecord("
            f"environment_present={self.environment_present!r}, "
            f"environment_size={self.environment_size!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentRestoreTempCreatedRecord:
    schema_version: int
    planned_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_identity: StableFileIdentity = field(repr=False)
    environment_ciphertext_sha256: str = field(repr=False)
    environment_ciphertext_size: int
    environment_present: bool
    environment_sha256: str | None = field(default=None, repr=False)
    environment_size: int | None = None
    environment_file_attributes: int | None = None
    environment_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )
    temp_name: str | None = field(default=None, repr=False)
    temp_identity: StableFileIdentity | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.planned_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.environment_backup_identity) is not StableFileIdentity
            or self.environment_backup_identity == self.package_root_identity
            or not _valid_hash(self.environment_ciphertext_sha256)
            or type(self.environment_ciphertext_size) is not int
            or not 1 <= self.environment_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
            or type(self.environment_present) is not bool
        ):
            raise ValueError("Environment restore temporary-file creation is invalid.")
        environment_values = (
            self.environment_sha256,
            self.environment_size,
            self.environment_file_attributes,
            self.environment_security_descriptor_sha256,
            self.temp_name,
            self.temp_identity,
        )
        if self.environment_present:
            if (
                not _valid_hash(self.environment_sha256)
                or type(self.environment_size) is not int
                or not 0 <= self.environment_size <= _MAX_ENVIRONMENT_BYTES
                or type(self.environment_file_attributes) is not int
                or not 0 <= self.environment_file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.environment_security_descriptor_sha256)
                or type(self.temp_name) is not str
                or _ENVIRONMENT_TEMP_NAME.fullmatch(self.temp_name) is None
                or type(self.temp_identity) is not StableFileIdentity
                or self.temp_identity
                in {self.package_root_identity, self.environment_backup_identity}
            ):
                raise ValueError(
                    "Environment restore temporary-file creation is invalid."
                )
        elif any(value is not None for value in environment_values):
            raise ValueError("Environment restore temporary-file creation is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentRestoreTempCreatedRecord("
            f"environment_present={self.environment_present!r}, "
            f"environment_size={self.environment_size!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentRestoreTempVerifiedRecord:
    schema_version: int
    created_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_backup_identity: StableFileIdentity = field(repr=False)
    environment_ciphertext_sha256: str = field(repr=False)
    environment_ciphertext_size: int
    environment_present: bool
    environment_sha256: str | None = field(default=None, repr=False)
    environment_size: int | None = None
    environment_file_attributes: int | None = None
    environment_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )
    temp_name: str | None = field(default=None, repr=False)
    temp_identity: StableFileIdentity | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.created_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.environment_backup_identity) is not StableFileIdentity
            or self.environment_backup_identity == self.package_root_identity
            or not _valid_hash(self.environment_ciphertext_sha256)
            or type(self.environment_ciphertext_size) is not int
            or not 1 <= self.environment_ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
            or type(self.environment_present) is not bool
        ):
            raise ValueError(
                "Environment restore temporary-file verification is invalid."
            )
        environment_values = (
            self.environment_sha256,
            self.environment_size,
            self.environment_file_attributes,
            self.environment_security_descriptor_sha256,
            self.temp_name,
            self.temp_identity,
        )
        if self.environment_present:
            if (
                not _valid_hash(self.environment_sha256)
                or type(self.environment_size) is not int
                or not 0 <= self.environment_size <= _MAX_ENVIRONMENT_BYTES
                or type(self.environment_file_attributes) is not int
                or not 0 <= self.environment_file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.environment_security_descriptor_sha256)
                or type(self.temp_name) is not str
                or _ENVIRONMENT_TEMP_NAME.fullmatch(self.temp_name) is None
                or type(self.temp_identity) is not StableFileIdentity
                or self.temp_identity
                in {self.package_root_identity, self.environment_backup_identity}
            ):
                raise ValueError(
                    "Environment restore temporary-file verification is invalid."
                )
        elif any(value is not None for value in environment_values):
            raise ValueError(
                "Environment restore temporary-file verification is invalid."
            )

    def __repr__(self) -> str:
        return (
            "EnvironmentRestoreTempVerifiedRecord("
            f"environment_present={self.environment_present!r}, "
            f"environment_size={self.environment_size!r}, <redacted>)"
        )


EnvironmentTempJournalRecord = (
    EnvironmentTempPlanRecord
    | EnvironmentTempCreatedRecord
    | EnvironmentTempVerifiedRecord
)
EnvironmentJournalRecord = (
    BackupPreparingRecord
    | BackupVerifiedRecord
    | RollbackArmedRecord
    | RollbackStartedRecord
    | EnvironmentRestoreTempPlanRecord
    | EnvironmentRestoreTempCreatedRecord
    | EnvironmentRestoreTempVerifiedRecord
    | EnvironmentTempJournalRecord
)

_RECORD_TYPE_BY_STATE: dict[EnvironmentJournalState, type[object]] = {
    EnvironmentJournalState.BACKUP_PREPARING: BackupPreparingRecord,
    EnvironmentJournalState.BACKUP_VERIFIED: BackupVerifiedRecord,
    EnvironmentJournalState.ROLLBACK_ARMED: RollbackArmedRecord,
    EnvironmentJournalState.ROLLBACK_STARTED: RollbackStartedRecord,
    EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED: (
        EnvironmentRestoreTempPlanRecord
    ),
    EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED: (
        EnvironmentRestoreTempCreatedRecord
    ),
    EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED: (
        EnvironmentRestoreTempVerifiedRecord
    ),
    EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED: EnvironmentTempPlanRecord,
    EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED: EnvironmentTempCreatedRecord,
    EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED: EnvironmentTempVerifiedRecord,
}


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentJournalGeneration:
    schema_version: int
    stream: JournalStreamIdentity = field(repr=False)
    sequence: int
    previous_generation_sha256: str = field(repr=False)
    state: EnvironmentJournalState
    record: EnvironmentJournalRecord = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.stream) is not JournalStreamIdentity
            or type(self.sequence) is not int
            or not 1 <= self.sequence <= _MAX_SEQUENCE
            or not _valid_hash(self.previous_generation_sha256)
            or type(self.state) is not EnvironmentJournalState
            or type(self.record) is not _RECORD_TYPE_BY_STATE.get(self.state)
            or type(self.record.schema_version) is not int
            or self.record.schema_version != _SCHEMA_VERSION
        ):
            raise ValueError("Environment journal generation is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentJournalGeneration("
            f"sequence={self.sequence}, state={self.state.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SealedEnvironmentJournalGeneration:
    protected_blob: CurrentUserProtectedBlob = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.protected_blob) is not CurrentUserProtectedBlob
            or self.protected_blob.purpose
            is not ProtectedDataPurpose.JOURNAL_GENERATION
            or not _valid_hash(self.generation_sha256)
            or self.generation_sha256 != self.protected_blob.ciphertext_sha256
        ):
            raise ValueError("Sealed recovery journal generation is invalid.")

    def __repr__(self) -> str:
        return "SealedEnvironmentJournalGeneration(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _AuthenticatedEnvironmentJournalGeneration:
    generation: EnvironmentJournalGeneration = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.generation) is not EnvironmentJournalGeneration or not _valid_hash(
            self.generation_sha256
        ):
            raise ValueError("Authenticated recovery journal generation is invalid.")

    def __repr__(self) -> str:
        return (
            "_AuthenticatedEnvironmentJournalGeneration("
            f"sequence={self.generation.sequence}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentJournalPointer:
    schema_version: int
    journal_id: str = field(repr=False)
    sequence: int
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_journal_id(self.journal_id)
            or type(self.sequence) is not int
            or not 1 <= self.sequence <= _MAX_SEQUENCE
            or not _valid_hash(self.generation_sha256)
        ):
            raise ValueError("Recovery journal pointer is invalid.")

    def __repr__(self) -> str:
        return f"EnvironmentJournalPointer(sequence={self.sequence}, <redacted>)"


class JournalPointerDisposition(str, Enum):
    CURRENT = "current"
    MISSING_REPAIR = "missing_repair"
    STALE_REPAIR = "stale_repair"


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentJournalChainSelection:
    generations: tuple[EnvironmentJournalGeneration, ...] = field(repr=False)
    generation_sha256s: tuple[str, ...] = field(repr=False)
    tip: EnvironmentJournalGeneration = field(repr=False)
    tip_generation_sha256: str = field(repr=False)
    pointer_disposition: JournalPointerDisposition

    def __post_init__(self) -> None:
        if (
            type(self.generations) is not tuple
            or not self.generations
            or any(
                type(item) is not EnvironmentJournalGeneration
                for item in self.generations
            )
            or type(self.generation_sha256s) is not tuple
            or len(self.generation_sha256s) != len(self.generations)
            or any(not _valid_hash(item) for item in self.generation_sha256s)
            or type(self.tip) is not EnvironmentJournalGeneration
            or self.tip != self.generations[-1]
            or not _valid_hash(self.tip_generation_sha256)
            or self.tip_generation_sha256 != self.generation_sha256s[-1]
            or type(self.pointer_disposition) is not JournalPointerDisposition
        ):
            raise ValueError("Recovery journal chain selection is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentJournalChainSelection("
            f"generations={len(self.generations)}, "
            f"pointer_disposition={self.pointer_disposition.value!r}, <redacted>)"
        )


class JournalProtectionPort(Protocol):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob: ...

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes: ...


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Non-finite JSON value.")


def _json_nodes(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeded.")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("JSON integer exceeded.")
        return 1
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING_CHARACTERS or "\x00" in value:
            raise ValueError("JSON string is invalid.")
        return 1
    if type(value) is list:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON list exceeded.")
        return 1 + sum(_json_nodes(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON object exceeded.")
        return 1 + sum(_json_nodes(item, depth=depth + 1) for item in value.values())
    raise ValueError("JSON value type is invalid.")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii", errors="strict")


def _load_canonical_json(
    raw: bytes,
    *,
    maximum: int,
    code: RecoveryJournalErrorCode,
) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise ValueError("JSON bytes are invalid.")
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            raise ValueError("JSON encoding is invalid.")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if type(parsed) is not dict or _json_nodes(parsed) > _MAX_JSON_NODES:
            raise ValueError("JSON root is invalid.")
        if _canonical_json(parsed) != raw:
            raise ValueError("JSON encoding is not canonical.")
        return parsed
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        _fail(code)


def _exact_keys(value: object, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise ValueError("JSON object shape is invalid.")
    return value


def _identity_to_json(identity: StableFileIdentity) -> dict[str, Any]:
    return {
        "file_id": identity.file_id.hex(),
        "volume_serial": identity.volume_serial,
    }


def _identity_from_json(value: object) -> StableFileIdentity:
    item = _exact_keys(value, frozenset({"file_id", "volume_serial"}))
    file_id = item["file_id"]
    volume_serial = item["volume_serial"]
    if (
        type(file_id) is not str
        or not re.fullmatch(r"[0-9a-f]{32}", file_id)
        or type(volume_serial) is not int
    ):
        raise ValueError("File identity is invalid.")
    return StableFileIdentity(volume_serial, bytes.fromhex(file_id))


def _stream_to_json(stream: JournalStreamIdentity) -> dict[str, Any]:
    return {
        "journal_id": stream.journal_id,
        "package_root_identity": _identity_to_json(stream.package_root_identity),
        "schema_version": stream.schema_version,
        "target_token_sha256": stream.target_token_sha256,
    }


def _stream_from_json(value: object) -> JournalStreamIdentity:
    item = _exact_keys(
        value,
        frozenset(
            {
                "journal_id",
                "package_root_identity",
                "schema_version",
                "target_token_sha256",
            }
        ),
    )
    return JournalStreamIdentity(
        item["schema_version"],
        item["journal_id"],
        item["target_token_sha256"],
        _identity_from_json(item["package_root_identity"]),
    )


def _record_to_json(record: EnvironmentJournalRecord) -> dict[str, Any]:
    if type(record) is BackupPreparingRecord:
        return {
            "ca_bundle_mode": record.ca_bundle_mode,
            "ca_bundle_present": record.ca_bundle_present,
            "ca_bundle_sha256": record.ca_bundle_sha256,
            "certificate_backup_name": record.certificate_backup_name,
            "environment_backup_name": record.environment_backup_name,
            "environment_file_attributes": record.environment_file_attributes,
            "environment_present": record.environment_present,
            "environment_security_descriptor_sha256": (
                record.environment_security_descriptor_sha256
            ),
            "environment_sha256": record.environment_sha256,
            "local_ca_mode": record.local_ca_mode,
            "local_ca_present": record.local_ca_present,
            "local_ca_sha256": record.local_ca_sha256,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "schema_version": record.schema_version,
        }
    if type(record) is BackupVerifiedRecord:
        return {
            "certificate_backup_identity": _identity_to_json(
                record.certificate_backup_identity
            ),
            "certificate_ciphertext_sha256": record.certificate_ciphertext_sha256,
            "certificate_ciphertext_size": record.certificate_ciphertext_size,
            "environment_backup_identity": _identity_to_json(
                record.environment_backup_identity
            ),
            "environment_ciphertext_sha256": record.environment_ciphertext_sha256,
            "environment_ciphertext_size": record.environment_ciphertext_size,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "preparing_generation_sha256": record.preparing_generation_sha256,
            "schema_version": record.schema_version,
        }
    if type(record) is RollbackArmedRecord:
        return {
            "certificate_backup_identity": _identity_to_json(
                record.certificate_backup_identity
            ),
            "certificate_ciphertext_sha256": record.certificate_ciphertext_sha256,
            "certificate_ciphertext_size": record.certificate_ciphertext_size,
            "environment_backup_identity": _identity_to_json(
                record.environment_backup_identity
            ),
            "environment_ciphertext_sha256": record.environment_ciphertext_sha256,
            "environment_ciphertext_size": record.environment_ciphertext_size,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "schema_version": record.schema_version,
            "backup_verified_generation_sha256": (
                record.backup_verified_generation_sha256
            ),
        }
    if type(record) is RollbackStartedRecord:
        return {
            "certificate_backup_identity": _identity_to_json(
                record.certificate_backup_identity
            ),
            "certificate_ciphertext_sha256": record.certificate_ciphertext_sha256,
            "certificate_ciphertext_size": record.certificate_ciphertext_size,
            "environment_backup_identity": _identity_to_json(
                record.environment_backup_identity
            ),
            "environment_ciphertext_sha256": record.environment_ciphertext_sha256,
            "environment_ciphertext_size": record.environment_ciphertext_size,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "rollback_armed_generation_sha256": (
                record.rollback_armed_generation_sha256
            ),
            "schema_version": record.schema_version,
        }
    if type(record) is EnvironmentRestoreTempPlanRecord:
        return {
            "environment_backup_identity": _identity_to_json(
                record.environment_backup_identity
            ),
            "environment_ciphertext_sha256": record.environment_ciphertext_sha256,
            "environment_ciphertext_size": record.environment_ciphertext_size,
            "environment_file_attributes": record.environment_file_attributes,
            "environment_present": record.environment_present,
            "environment_security_descriptor_sha256": (
                record.environment_security_descriptor_sha256
            ),
            "environment_sha256": record.environment_sha256,
            "environment_size": record.environment_size,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "rollback_started_generation_sha256": (
                record.rollback_started_generation_sha256
            ),
            "schema_version": record.schema_version,
            "temp_name": record.temp_name,
        }
    if type(record) is EnvironmentRestoreTempCreatedRecord:
        return {
            "environment_backup_identity": _identity_to_json(
                record.environment_backup_identity
            ),
            "environment_ciphertext_sha256": record.environment_ciphertext_sha256,
            "environment_ciphertext_size": record.environment_ciphertext_size,
            "environment_file_attributes": record.environment_file_attributes,
            "environment_present": record.environment_present,
            "environment_security_descriptor_sha256": (
                record.environment_security_descriptor_sha256
            ),
            "environment_sha256": record.environment_sha256,
            "environment_size": record.environment_size,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "planned_generation_sha256": record.planned_generation_sha256,
            "schema_version": record.schema_version,
            "temp_identity": (
                _identity_to_json(record.temp_identity)
                if record.temp_identity is not None
                else None
            ),
            "temp_name": record.temp_name,
        }
    if type(record) is EnvironmentRestoreTempVerifiedRecord:
        return {
            "created_generation_sha256": record.created_generation_sha256,
            "environment_backup_identity": _identity_to_json(
                record.environment_backup_identity
            ),
            "environment_ciphertext_sha256": record.environment_ciphertext_sha256,
            "environment_ciphertext_size": record.environment_ciphertext_size,
            "environment_file_attributes": record.environment_file_attributes,
            "environment_present": record.environment_present,
            "environment_security_descriptor_sha256": (
                record.environment_security_descriptor_sha256
            ),
            "environment_sha256": record.environment_sha256,
            "environment_size": record.environment_size,
            "package_root_identity": _identity_to_json(record.package_root_identity),
            "schema_version": record.schema_version,
            "temp_identity": (
                _identity_to_json(record.temp_identity)
                if record.temp_identity is not None
                else None
            ),
            "temp_name": record.temp_name,
        }
    environment_record = cast(EnvironmentTempJournalRecord, record)
    common: dict[str, Any] = {
        "candidate_sha256": environment_record.candidate_sha256,
        "candidate_size": environment_record.candidate_size,
        "package_root_identity": _identity_to_json(
            environment_record.package_root_identity
        ),
        "schema_version": environment_record.schema_version,
        "temp_name": environment_record.temp_name,
    }
    if type(record) is EnvironmentTempPlanRecord:
        common["original_sha256"] = record.original_sha256
        return common
    if type(record) is EnvironmentTempCreatedRecord:
        common["planned_generation_sha256"] = record.planned_generation_sha256
        common["temp_identity"] = _identity_to_json(record.temp_identity)
        return common
    if type(record) is EnvironmentTempVerifiedRecord:
        common["created_generation_sha256"] = record.created_generation_sha256
        common["temp_identity"] = _identity_to_json(record.temp_identity)
        return common
    raise ValueError("Environment journal record is invalid.")


def _record_from_json(
    value: object,
    state: EnvironmentJournalState,
) -> EnvironmentJournalRecord:
    if state is EnvironmentJournalState.BACKUP_PREPARING:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "ca_bundle_mode",
                    "ca_bundle_present",
                    "ca_bundle_sha256",
                    "certificate_backup_name",
                    "environment_backup_name",
                    "environment_file_attributes",
                    "environment_present",
                    "environment_security_descriptor_sha256",
                    "environment_sha256",
                    "local_ca_mode",
                    "local_ca_present",
                    "local_ca_sha256",
                    "package_root_identity",
                    "schema_version",
                }
            ),
        )
        return BackupPreparingRecord(
            item["schema_version"],
            _identity_from_json(item["package_root_identity"]),
            item["environment_backup_name"],
            item["certificate_backup_name"],
            item["environment_present"],
            item["environment_sha256"],
            item["environment_file_attributes"],
            item["environment_security_descriptor_sha256"],
            item["local_ca_present"],
            item["local_ca_sha256"],
            item["local_ca_mode"],
            item["ca_bundle_present"],
            item["ca_bundle_sha256"],
            item["ca_bundle_mode"],
        )
    if state is EnvironmentJournalState.BACKUP_VERIFIED:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "certificate_backup_identity",
                    "certificate_ciphertext_sha256",
                    "certificate_ciphertext_size",
                    "environment_backup_identity",
                    "environment_ciphertext_sha256",
                    "environment_ciphertext_size",
                    "package_root_identity",
                    "preparing_generation_sha256",
                    "schema_version",
                }
            ),
        )
        return BackupVerifiedRecord(
            item["schema_version"],
            item["preparing_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["environment_backup_identity"]),
            item["environment_ciphertext_sha256"],
            item["environment_ciphertext_size"],
            _identity_from_json(item["certificate_backup_identity"]),
            item["certificate_ciphertext_sha256"],
            item["certificate_ciphertext_size"],
        )
    if state is EnvironmentJournalState.ROLLBACK_ARMED:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "certificate_backup_identity",
                    "certificate_ciphertext_sha256",
                    "certificate_ciphertext_size",
                    "environment_backup_identity",
                    "environment_ciphertext_sha256",
                    "environment_ciphertext_size",
                    "package_root_identity",
                    "schema_version",
                    "backup_verified_generation_sha256",
                }
            ),
        )
        return RollbackArmedRecord(
            item["schema_version"],
            item["backup_verified_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["environment_backup_identity"]),
            item["environment_ciphertext_sha256"],
            item["environment_ciphertext_size"],
            _identity_from_json(item["certificate_backup_identity"]),
            item["certificate_ciphertext_sha256"],
            item["certificate_ciphertext_size"],
        )
    if state is EnvironmentJournalState.ROLLBACK_STARTED:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "certificate_backup_identity",
                    "certificate_ciphertext_sha256",
                    "certificate_ciphertext_size",
                    "environment_backup_identity",
                    "environment_ciphertext_sha256",
                    "environment_ciphertext_size",
                    "package_root_identity",
                    "rollback_armed_generation_sha256",
                    "schema_version",
                }
            ),
        )
        return RollbackStartedRecord(
            item["schema_version"],
            item["rollback_armed_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["environment_backup_identity"]),
            item["environment_ciphertext_sha256"],
            item["environment_ciphertext_size"],
            _identity_from_json(item["certificate_backup_identity"]),
            item["certificate_ciphertext_sha256"],
            item["certificate_ciphertext_size"],
        )
    if state is EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "environment_backup_identity",
                    "environment_ciphertext_sha256",
                    "environment_ciphertext_size",
                    "environment_file_attributes",
                    "environment_present",
                    "environment_security_descriptor_sha256",
                    "environment_sha256",
                    "environment_size",
                    "package_root_identity",
                    "rollback_started_generation_sha256",
                    "schema_version",
                    "temp_name",
                }
            ),
        )
        return EnvironmentRestoreTempPlanRecord(
            item["schema_version"],
            item["rollback_started_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["environment_backup_identity"]),
            item["environment_ciphertext_sha256"],
            item["environment_ciphertext_size"],
            item["environment_present"],
            item["environment_sha256"],
            item["environment_size"],
            item["environment_file_attributes"],
            item["environment_security_descriptor_sha256"],
            item["temp_name"],
        )
    if state is EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "environment_backup_identity",
                    "environment_ciphertext_sha256",
                    "environment_ciphertext_size",
                    "environment_file_attributes",
                    "environment_present",
                    "environment_security_descriptor_sha256",
                    "environment_sha256",
                    "environment_size",
                    "package_root_identity",
                    "planned_generation_sha256",
                    "schema_version",
                    "temp_identity",
                    "temp_name",
                }
            ),
        )
        temp_identity = item["temp_identity"]
        return EnvironmentRestoreTempCreatedRecord(
            item["schema_version"],
            item["planned_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["environment_backup_identity"]),
            item["environment_ciphertext_sha256"],
            item["environment_ciphertext_size"],
            item["environment_present"],
            item["environment_sha256"],
            item["environment_size"],
            item["environment_file_attributes"],
            item["environment_security_descriptor_sha256"],
            item["temp_name"],
            _identity_from_json(temp_identity) if temp_identity is not None else None,
        )
    if state is EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED:
        item = _exact_keys(
            value,
            frozenset(
                {
                    "created_generation_sha256",
                    "environment_backup_identity",
                    "environment_ciphertext_sha256",
                    "environment_ciphertext_size",
                    "environment_file_attributes",
                    "environment_present",
                    "environment_security_descriptor_sha256",
                    "environment_sha256",
                    "environment_size",
                    "package_root_identity",
                    "schema_version",
                    "temp_identity",
                    "temp_name",
                }
            ),
        )
        temp_identity = item["temp_identity"]
        return EnvironmentRestoreTempVerifiedRecord(
            item["schema_version"],
            item["created_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["environment_backup_identity"]),
            item["environment_ciphertext_sha256"],
            item["environment_ciphertext_size"],
            item["environment_present"],
            item["environment_sha256"],
            item["environment_size"],
            item["environment_file_attributes"],
            item["environment_security_descriptor_sha256"],
            item["temp_name"],
            _identity_from_json(temp_identity) if temp_identity is not None else None,
        )
    common = frozenset(
        {
            "candidate_sha256",
            "candidate_size",
            "package_root_identity",
            "schema_version",
            "temp_name",
        }
    )
    if state is EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED:
        item = _exact_keys(value, common | {"original_sha256"})
        if type(item["schema_version"]) is not int:
            raise ValueError("Environment record schema is invalid.")
        return EnvironmentTempPlanRecord(
            item["schema_version"],
            _identity_from_json(item["package_root_identity"]),
            item["original_sha256"],
            item["candidate_sha256"],
            item["candidate_size"],
            item["temp_name"],
        )
    if state is EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED:
        item = _exact_keys(
            value,
            common | {"planned_generation_sha256", "temp_identity"},
        )
        if type(item["schema_version"]) is not int:
            raise ValueError("Environment record schema is invalid.")
        return EnvironmentTempCreatedRecord(
            item["schema_version"],
            item["planned_generation_sha256"],
            _identity_from_json(item["package_root_identity"]),
            _identity_from_json(item["temp_identity"]),
            item["candidate_sha256"],
            item["candidate_size"],
            item["temp_name"],
        )
    item = _exact_keys(
        value,
        common | {"created_generation_sha256", "temp_identity"},
    )
    if type(item["schema_version"]) is not int:
        raise ValueError("Environment record schema is invalid.")
    return EnvironmentTempVerifiedRecord(
        item["schema_version"],
        item["created_generation_sha256"],
        _identity_from_json(item["package_root_identity"]),
        _identity_from_json(item["temp_identity"]),
        item["candidate_sha256"],
        item["candidate_size"],
        item["temp_name"],
    )


def _generation_to_bytes(generation: EnvironmentJournalGeneration) -> bytes:
    return _canonical_json(
        {
            "previous_generation_sha256": generation.previous_generation_sha256,
            "record": _record_to_json(generation.record),
            "schema_version": generation.schema_version,
            "sequence": generation.sequence,
            "state": generation.state.value,
            "stream": _stream_to_json(generation.stream),
        }
    )


def _generation_from_bytes(raw: bytes) -> EnvironmentJournalGeneration:
    try:
        item = _exact_keys(
            _load_canonical_json(
                raw,
                maximum=_MAX_GENERATION_BYTES,
                code=RecoveryJournalErrorCode.GENERATION_INVALID,
            ),
            frozenset(
                {
                    "previous_generation_sha256",
                    "record",
                    "schema_version",
                    "sequence",
                    "state",
                    "stream",
                }
            ),
        )
        state = EnvironmentJournalState(item["state"])
        return EnvironmentJournalGeneration(
            item["schema_version"],
            _stream_from_json(item["stream"]),
            item["sequence"],
            item["previous_generation_sha256"],
            state,
            _record_from_json(item["record"], state),
        )
    except RecoveryJournalError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(RecoveryJournalErrorCode.GENERATION_INVALID)


def protect_environment_journal_generation(
    generation: EnvironmentJournalGeneration,
    *,
    protection: JournalProtectionPort,
) -> SealedEnvironmentJournalGeneration:
    if type(generation) is not EnvironmentJournalGeneration:
        _fail(RecoveryJournalErrorCode.INPUT_INVALID)
    try:
        operation = getattr(protection, "protect")
        if not callable(operation):
            raise TypeError("Journal protection is unavailable.")
        protected = operation(
            _generation_to_bytes(generation),
            ProtectedDataPurpose.JOURNAL_GENERATION,
        )
    except Exception:
        _fail(RecoveryJournalErrorCode.AUTHENTICATION_FAILED)
    if type(protected) is not CurrentUserProtectedBlob:
        _fail(RecoveryJournalErrorCode.AUTHENTICATION_FAILED)
    try:
        return SealedEnvironmentJournalGeneration(
            protected,
            protected.ciphertext_sha256,
        )
    except ValueError:
        _fail(RecoveryJournalErrorCode.AUTHENTICATION_FAILED)


def _authenticate_environment_journal_generation(
    sealed: SealedEnvironmentJournalGeneration,
    *,
    protection: JournalProtectionPort,
) -> _AuthenticatedEnvironmentJournalGeneration:
    if type(sealed) is not SealedEnvironmentJournalGeneration:
        _fail(RecoveryJournalErrorCode.INPUT_INVALID)
    try:
        operation = getattr(protection, "unprotect")
        if not callable(operation):
            raise TypeError("Journal authentication is unavailable.")
        plaintext = operation(
            sealed.protected_blob,
            ProtectedDataPurpose.JOURNAL_GENERATION,
        )
    except Exception:
        _fail(RecoveryJournalErrorCode.AUTHENTICATION_FAILED)
    if type(plaintext) is not bytes:
        _fail(RecoveryJournalErrorCode.AUTHENTICATION_FAILED)
    generation = _generation_from_bytes(plaintext)
    try:
        return _AuthenticatedEnvironmentJournalGeneration(
            generation,
            sealed.generation_sha256,
        )
    except ValueError:
        _fail(RecoveryJournalErrorCode.GENERATION_INVALID)


def authenticate_environment_journal_generation(
    sealed: SealedEnvironmentJournalGeneration,
    *,
    protection: JournalProtectionPort,
) -> EnvironmentJournalGeneration:
    """Authenticate one generation without accepting caller-supplied identity."""

    return _authenticate_environment_journal_generation(
        sealed,
        protection=protection,
    ).generation


def encode_environment_journal_pointer(pointer: EnvironmentJournalPointer) -> bytes:
    if type(pointer) is not EnvironmentJournalPointer:
        _fail(RecoveryJournalErrorCode.POINTER_INVALID)
    return _canonical_json(
        {
            "generation_sha256": pointer.generation_sha256,
            "journal_id": pointer.journal_id,
            "schema_version": pointer.schema_version,
            "sequence": pointer.sequence,
        }
    )


def decode_environment_journal_pointer(raw: bytes) -> EnvironmentJournalPointer:
    try:
        item = _exact_keys(
            _load_canonical_json(
                raw,
                maximum=_MAX_POINTER_BYTES,
                code=RecoveryJournalErrorCode.POINTER_INVALID,
            ),
            frozenset(
                {
                    "generation_sha256",
                    "journal_id",
                    "schema_version",
                    "sequence",
                }
            ),
        )
        return EnvironmentJournalPointer(
            item["schema_version"],
            item["journal_id"],
            item["sequence"],
            item["generation_sha256"],
        )
    except RecoveryJournalError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(RecoveryJournalErrorCode.POINTER_INVALID)


def _validate_record_continuity(
    generations: tuple[_AuthenticatedEnvironmentJournalGeneration, ...],
) -> None:
    plan = generations[0].generation.record
    if type(plan) is BackupPreparingRecord:
        if (
            plan.package_root_identity
            != generations[0].generation.stream.package_root_identity
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if len(generations) == 1:
            return
        if len(generations) not in {2, 3, 4, 5, 6, 7}:
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        verified_generation = generations[1]
        verified = verified_generation.generation.record
        if (
            type(verified) is not BackupVerifiedRecord
            or verified_generation.generation.previous_generation_sha256
            != generations[0].generation_sha256
            or verified.preparing_generation_sha256 != generations[0].generation_sha256
            or verified.package_root_identity != plan.package_root_identity
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if len(generations) == 2:
            return
        armed_generation = generations[2]
        armed = armed_generation.generation.record
        if (
            type(armed) is not RollbackArmedRecord
            or armed_generation.generation.previous_generation_sha256
            != verified_generation.generation_sha256
            or armed.backup_verified_generation_sha256
            != verified_generation.generation_sha256
            or armed.package_root_identity != verified.package_root_identity
            or armed.environment_backup_identity != verified.environment_backup_identity
            or armed.environment_ciphertext_sha256
            != verified.environment_ciphertext_sha256
            or armed.environment_ciphertext_size != verified.environment_ciphertext_size
            or armed.certificate_backup_identity != verified.certificate_backup_identity
            or armed.certificate_ciphertext_sha256
            != verified.certificate_ciphertext_sha256
            or armed.certificate_ciphertext_size != verified.certificate_ciphertext_size
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if len(generations) == 3:
            return
        started_generation = generations[3]
        started = started_generation.generation.record
        if (
            type(started) is not RollbackStartedRecord
            or started_generation.generation.previous_generation_sha256
            != armed_generation.generation_sha256
            or started.rollback_armed_generation_sha256
            != armed_generation.generation_sha256
            or started.package_root_identity != armed.package_root_identity
            or started.environment_backup_identity != armed.environment_backup_identity
            or started.environment_ciphertext_sha256
            != armed.environment_ciphertext_sha256
            or started.environment_ciphertext_size != armed.environment_ciphertext_size
            or started.certificate_backup_identity != armed.certificate_backup_identity
            or started.certificate_ciphertext_sha256
            != armed.certificate_ciphertext_sha256
            or started.certificate_ciphertext_size != armed.certificate_ciphertext_size
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if len(generations) == 4:
            return
        restore_plan_generation = generations[4]
        restore_plan = restore_plan_generation.generation.record
        if (
            type(restore_plan) is not EnvironmentRestoreTempPlanRecord
            or restore_plan_generation.generation.previous_generation_sha256
            != started_generation.generation_sha256
            or restore_plan.rollback_started_generation_sha256
            != started_generation.generation_sha256
            or restore_plan.package_root_identity != started.package_root_identity
            or restore_plan.environment_backup_identity
            != started.environment_backup_identity
            or restore_plan.environment_ciphertext_sha256
            != started.environment_ciphertext_sha256
            or restore_plan.environment_ciphertext_size
            != started.environment_ciphertext_size
            or restore_plan.environment_present != plan.environment_present
            or restore_plan.environment_sha256 != plan.environment_sha256
            or restore_plan.environment_file_attributes
            != plan.environment_file_attributes
            or restore_plan.environment_security_descriptor_sha256
            != plan.environment_security_descriptor_sha256
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if len(generations) == 5:
            return
        restore_created_generation = generations[5]
        restore_created = restore_created_generation.generation.record
        if (
            type(restore_created) is not EnvironmentRestoreTempCreatedRecord
            or restore_created_generation.generation.previous_generation_sha256
            != restore_plan_generation.generation_sha256
            or restore_created.planned_generation_sha256
            != restore_plan_generation.generation_sha256
            or restore_created.package_root_identity
            != restore_plan.package_root_identity
            or restore_created.environment_backup_identity
            != restore_plan.environment_backup_identity
            or restore_created.environment_ciphertext_sha256
            != restore_plan.environment_ciphertext_sha256
            or restore_created.environment_ciphertext_size
            != restore_plan.environment_ciphertext_size
            or restore_created.environment_present
            is not restore_plan.environment_present
            or restore_created.environment_sha256 != restore_plan.environment_sha256
            or restore_created.environment_size != restore_plan.environment_size
            or restore_created.environment_file_attributes
            != restore_plan.environment_file_attributes
            or restore_created.environment_security_descriptor_sha256
            != restore_plan.environment_security_descriptor_sha256
            or restore_created.temp_name != restore_plan.temp_name
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if len(generations) == 6:
            return
        restore_verified_generation = generations[6]
        restore_verified = restore_verified_generation.generation.record
        if (
            type(restore_verified) is not EnvironmentRestoreTempVerifiedRecord
            or restore_verified_generation.generation.previous_generation_sha256
            != restore_created_generation.generation_sha256
            or restore_verified.created_generation_sha256
            != restore_created_generation.generation_sha256
            or restore_verified.package_root_identity
            != restore_created.package_root_identity
            or restore_verified.environment_backup_identity
            != restore_created.environment_backup_identity
            or restore_verified.environment_ciphertext_sha256
            != restore_created.environment_ciphertext_sha256
            or restore_verified.environment_ciphertext_size
            != restore_created.environment_ciphertext_size
            or restore_verified.environment_present
            is not restore_created.environment_present
            or restore_verified.environment_sha256 != restore_created.environment_sha256
            or restore_verified.environment_size != restore_created.environment_size
            or restore_verified.environment_file_attributes
            != restore_created.environment_file_attributes
            or restore_verified.environment_security_descriptor_sha256
            != restore_created.environment_security_descriptor_sha256
            or restore_verified.temp_name != restore_created.temp_name
            or restore_verified.temp_identity != restore_created.temp_identity
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        return
    if type(plan) is not EnvironmentTempPlanRecord:
        _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
    previous: _AuthenticatedEnvironmentJournalGeneration | None = None
    created: EnvironmentTempCreatedRecord | None = None
    for item in generations:
        generation = item.generation
        record = cast(EnvironmentTempJournalRecord, generation.record)
        if record.package_root_identity != generation.stream.package_root_identity:
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if (
            record.candidate_sha256 != plan.candidate_sha256
            or record.candidate_size != plan.candidate_size
            or record.temp_name != plan.temp_name
        ):
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        if previous is not None:
            if generation.previous_generation_sha256 != previous.generation_sha256:
                _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
            if type(record) is EnvironmentTempCreatedRecord:
                if record.planned_generation_sha256 != previous.generation_sha256:
                    _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
                created = record
            elif type(record) is EnvironmentTempVerifiedRecord:
                if (
                    created is None
                    or record.created_generation_sha256 != previous.generation_sha256
                    or record.temp_identity != created.temp_identity
                ):
                    _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        previous = item


def select_environment_journal_chain(
    sealed_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    pointer: EnvironmentJournalPointer | None,
    *,
    expected_stream: JournalStreamIdentity,
    protection: JournalProtectionPort,
) -> EnvironmentJournalChainSelection:
    if (
        type(sealed_generations) is not tuple
        or not sealed_generations
        or len(sealed_generations) > _MAX_CHAIN_CANDIDATES
        or type(expected_stream) is not JournalStreamIdentity
        or (pointer is not None and type(pointer) is not EnvironmentJournalPointer)
        or any(
            type(item) is not SealedEnvironmentJournalGeneration
            for item in sealed_generations
        )
    ):
        _fail(RecoveryJournalErrorCode.INPUT_INVALID)
    generations = tuple(
        _authenticate_environment_journal_generation(item, protection=protection)
        for item in sealed_generations
    )
    if any(item.generation.stream != expected_stream for item in generations):
        _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
    if len(generations) > 7:
        _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
    digests = tuple(item.generation_sha256 for item in generations)
    if len(set(digests)) != len(digests):
        _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
    ordered = tuple(sorted(generations, key=lambda item: item.generation.sequence))
    backup_states = (
        EnvironmentJournalState.BACKUP_PREPARING,
        EnvironmentJournalState.BACKUP_VERIFIED,
        EnvironmentJournalState.ROLLBACK_ARMED,
        EnvironmentJournalState.ROLLBACK_STARTED,
        EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
        EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
        EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED,
    )
    environment_temp_states = (
        EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
        EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
    )
    observed_states = tuple(item.generation.state for item in ordered)
    valid_states = observed_states == backup_states[: len(ordered)] or (
        observed_states == environment_temp_states[: len(ordered)]
    )
    if (
        tuple(item.generation.sequence for item in ordered)
        != tuple(range(1, len(ordered) + 1))
        or not valid_states
        or ordered[0].generation.previous_generation_sha256 != GENESIS_GENERATION_SHA256
    ):
        _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
    _validate_record_continuity(ordered)

    tip = ordered[-1]
    if pointer is None:
        disposition = JournalPointerDisposition.MISSING_REPAIR
    else:
        if pointer.journal_id != expected_stream.journal_id:
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        pointed = next(
            (
                item
                for item in ordered
                if item.generation.sequence == pointer.sequence
                and item.generation_sha256 == pointer.generation_sha256
            ),
            None,
        )
        if pointed is None:
            _fail(RecoveryJournalErrorCode.CHAIN_INVALID)
        disposition = (
            JournalPointerDisposition.CURRENT
            if pointed == tip
            else JournalPointerDisposition.STALE_REPAIR
        )
    try:
        return EnvironmentJournalChainSelection(
            tuple(item.generation for item in ordered),
            tuple(item.generation_sha256 for item in ordered),
            tip.generation,
            tip.generation_sha256,
            disposition,
        )
    except ValueError:
        _fail(RecoveryJournalErrorCode.CHAIN_INVALID)


__all__ = [
    "BackupPreparingRecord",
    "BackupVerifiedRecord",
    "EnvironmentJournalChainSelection",
    "EnvironmentJournalGeneration",
    "EnvironmentJournalPointer",
    "EnvironmentRestoreTempCreatedRecord",
    "EnvironmentRestoreTempPlanRecord",
    "EnvironmentRestoreTempVerifiedRecord",
    "EnvironmentJournalState",
    "GENESIS_GENERATION_SHA256",
    "JournalPointerDisposition",
    "JournalProtectionPort",
    "JournalStreamIdentity",
    "RecoveryJournalError",
    "RecoveryJournalErrorCode",
    "RollbackArmedRecord",
    "RollbackStartedRecord",
    "SealedEnvironmentJournalGeneration",
    "authenticate_environment_journal_generation",
    "decode_environment_journal_pointer",
    "encode_environment_journal_pointer",
    "protect_environment_journal_generation",
    "select_environment_journal_chain",
]
