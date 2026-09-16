"""Create-only persistence orchestration for prepared recovery backup blobs.

This Gate-A layer reauthenticates one persisted ``backup_preparing`` generation
and both exact-state envelopes before a narrow storage port may create the two
planned ciphertext blobs. It exposes no listing, deletion, restore, journal
advance, or repair/runtime mutation authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Callable, NoReturn, Protocol, TypeVar, cast

from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_backup import (
    BackupProtectionPort,
    CertificateExactStateBackup,
    EnvironmentExactStateBackup,
    SealedCertificateExactStateBackup,
    SealedEnvironmentExactStateBackup,
    authenticate_certificate_exact_state_backup,
    authenticate_environment_exact_state_backup,
)
from .windows_recovery_journal import (
    BackupPreparingRecord,
    EnvironmentJournalState,
    JournalProtectionPort,
    JournalStreamIdentity,
    RecoveryJournalError,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    load_persisted_environment_journal_chain_from_held_root,
)
from .windows_security import StableFileIdentity

_MAX_PROTECTED_BACKUP_BYTES = 4 * 1024 * 1024
_BACKUP_NAME = re.compile(r"^recovery-backup-[0-9a-f]{32}\.blob$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_Result = TypeVar("_Result")


class RecoveryBackupStorageErrorCode(str, Enum):
    INPUT_INVALID = "recovery_backup_storage_input_invalid"
    AUTHORITY_INVALID = "recovery_backup_storage_authority_invalid"
    STORAGE_UNAVAILABLE = "recovery_backup_storage_unavailable"
    WRITE_FAILED = "recovery_backup_storage_write_failed"
    VERIFY_FAILED = "recovery_backup_storage_verify_failed"


class RecoveryBackupStorageError(RuntimeError):
    """Sanitized failure at the recovery backup storage boundary."""

    _MESSAGES = {
        RecoveryBackupStorageErrorCode.INPUT_INVALID: (
            "The recovery backup storage request is invalid."
        ),
        RecoveryBackupStorageErrorCode.AUTHORITY_INVALID: (
            "The recovery backup storage authority is invalid."
        ),
        RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE: (
            "Protected recovery backup storage is unavailable."
        ),
        RecoveryBackupStorageErrorCode.WRITE_FAILED: (
            "A recovery backup blob could not be written durably."
        ),
        RecoveryBackupStorageErrorCode.VERIFY_FAILED: (
            "A recovery backup blob could not be verified durably."
        ),
    }

    def __init__(self, code: RecoveryBackupStorageErrorCode) -> None:
        if type(code) is not RecoveryBackupStorageErrorCode:
            raise ValueError("Unknown recovery backup storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryBackupStorageError(code={self.code.value!r})"


def _fail(code: RecoveryBackupStorageErrorCode) -> NoReturn:
    raise RecoveryBackupStorageError(code)


@dataclass(frozen=True, slots=True, repr=False)
class StoredRecoveryBackupBlob:
    name: str = field(repr=False)
    purpose: ProtectedDataPurpose
    identity: StableFileIdentity = field(repr=False)
    ciphertext_sha256: str = field(repr=False)
    ciphertext_size: int

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or _BACKUP_NAME.fullmatch(self.name) is None
            or self.purpose
            not in {
                ProtectedDataPurpose.ENVIRONMENT_BACKUP,
                ProtectedDataPurpose.CERTIFICATE_BACKUP,
            }
            or type(self.identity) is not StableFileIdentity
            or type(self.ciphertext_sha256) is not str
            or _SHA256.fullmatch(self.ciphertext_sha256) is None
            or type(self.ciphertext_size) is not int
            or not 1 <= self.ciphertext_size <= _MAX_PROTECTED_BACKUP_BYTES
        ):
            raise ValueError("Stored recovery backup blob is invalid.")

    def __repr__(self) -> str:
        return (
            "StoredRecoveryBackupBlob("
            f"purpose={self.purpose.value!r}, "
            f"ciphertext_size={self.ciphertext_size}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PersistedRecoveryBackupBlobs:
    environment: StoredRecoveryBackupBlob = field(repr=False)
    certificate: StoredRecoveryBackupBlob = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.environment) is not StoredRecoveryBackupBlob
            or self.environment.purpose is not ProtectedDataPurpose.ENVIRONMENT_BACKUP
            or type(self.certificate) is not StoredRecoveryBackupBlob
            or self.certificate.purpose is not ProtectedDataPurpose.CERTIFICATE_BACKUP
            or self.environment.name == self.certificate.name
            or self.environment.identity == self.certificate.identity
        ):
            raise ValueError("Persisted recovery backup blobs are invalid.")

    def __repr__(self) -> str:
        return "PersistedRecoveryBackupBlobs(<redacted>)"


class RecoveryBackupBlobStoragePort(Protocol):
    def create_backup_blob(
        self,
        root_path: str,
        name: str,
        blob: CurrentUserProtectedBlob,
    ) -> StoredRecoveryBackupBlob: ...


def _matches_environment_summary(
    record: BackupPreparingRecord,
    backup: EnvironmentExactStateBackup,
) -> bool:
    security = backup.security
    return (
        record.environment_present is backup.existed
        and record.environment_sha256
        == (backup.contents_sha256 if backup.existed else None)
        and record.environment_file_attributes
        == (security.file_attributes if security is not None else None)
        and record.environment_security_descriptor_sha256
        == (security.security_descriptor_sha256 if security is not None else None)
    )


def _matches_certificate_summary(
    record: BackupPreparingRecord,
    backup: CertificateExactStateBackup,
) -> bool:
    return (
        record.local_ca_present is backup.local_ca.existed
        and record.local_ca_sha256
        == (backup.local_ca.contents_sha256 if backup.local_ca.existed else None)
        and record.local_ca_mode == backup.local_ca.mode
        and record.ca_bundle_present is backup.ca_bundle.existed
        and record.ca_bundle_sha256
        == (backup.ca_bundle.contents_sha256 if backup.ca_bundle.existed else None)
        and record.ca_bundle_mode == backup.ca_bundle.mode
    )


def _storage_call(
    storage: object,
    root_path: str,
    name: str,
    blob: CurrentUserProtectedBlob,
) -> StoredRecoveryBackupBlob:
    try:
        operation = getattr(storage, "create_backup_blob")
        if not callable(operation):
            raise TypeError("Recovery backup storage is unavailable.")
        stored = operation(root_path, name, blob)
    except RecoveryBackupStorageError:
        raise
    except Exception:
        _fail(RecoveryBackupStorageErrorCode.WRITE_FAILED)
    if type(stored) is not StoredRecoveryBackupBlob:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    return stored


def _validate_receipt(
    stored: StoredRecoveryBackupBlob,
    *,
    name: str,
    blob: CurrentUserProtectedBlob,
) -> None:
    if (
        stored.name != name
        or stored.purpose is not blob.purpose
        or stored.ciphertext_sha256 != blob.ciphertext_sha256
        or stored.ciphertext_size != len(blob.ciphertext)
    ):
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)


def _run_under_root(
    root: JournalStorageRootPort,
    operation: Callable[[str], _Result],
) -> _Result:
    try:
        run = cast(
            Callable[[Callable[[str], _Result]], _Result],
            getattr(root, "run_journal_storage"),
        )
        if not callable(run):
            raise TypeError("Protected recovery backup root is unavailable.")
        return run(operation)
    except RecoveryBackupStorageError:
        raise
    except Exception:
        _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)


def persist_prepared_recovery_backup_blobs(
    environment_sealed: SealedEnvironmentExactStateBackup,
    certificate_sealed: SealedCertificateExactStateBackup,
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    storage: RecoveryBackupBlobStoragePort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
) -> PersistedRecoveryBackupBlobs:
    """Create and verify only the two blobs authorized by backup preparation."""

    if (
        type(environment_sealed) is not SealedEnvironmentExactStateBackup
        or type(certificate_sealed) is not SealedCertificateExactStateBackup
        or type(stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
    environment = authenticate_environment_exact_state_backup(
        environment_sealed,
        expected_stream=stream,
        protection=backup_protection,
    )
    certificates = authenticate_certificate_exact_state_backup(
        certificate_sealed,
        expected_stream=stream,
        protection=backup_protection,
    )

    def create(root_path: str) -> PersistedRecoveryBackupBlobs:
        try:
            prepared = load_persisted_environment_journal_chain_from_held_root(
                root_path,
                stream,
                storage=journal_storage,
                protection=journal_protection,
            )
        except RecoveryJournalStorageError as exc:
            if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        except RecoveryJournalError:
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        if (
            type(prepared) is not PersistedEnvironmentJournalChain
            or len(prepared.selection.generations) != 1
            or prepared.selection.tip.state
            is not EnvironmentJournalState.BACKUP_PREPARING
            or type(prepared.selection.tip.record) is not BackupPreparingRecord
        ):
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        record = prepared.selection.tip.record
        if not _matches_environment_summary(
            record,
            environment,
        ) or not _matches_certificate_summary(record, certificates):
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        environment_blob = environment_sealed.protected_blob
        environment_stored = _storage_call(
            storage,
            root_path,
            record.environment_backup_name,
            environment_blob,
        )
        _validate_receipt(
            environment_stored,
            name=record.environment_backup_name,
            blob=environment_blob,
        )
        certificate_blob = certificate_sealed.protected_blob
        certificate_stored = _storage_call(
            storage,
            root_path,
            record.certificate_backup_name,
            certificate_blob,
        )
        _validate_receipt(
            certificate_stored,
            name=record.certificate_backup_name,
            blob=certificate_blob,
        )
        try:
            return PersistedRecoveryBackupBlobs(
                environment_stored,
                certificate_stored,
            )
        except ValueError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)

    return _run_under_root(root, create)


__all__ = [
    "PersistedRecoveryBackupBlobs",
    "RecoveryBackupBlobStoragePort",
    "RecoveryBackupStorageError",
    "RecoveryBackupStorageErrorCode",
    "StoredRecoveryBackupBlob",
    "persist_prepared_recovery_backup_blobs",
]
