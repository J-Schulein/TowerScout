"""Persistence and durable verification for prepared recovery backup blobs.

This Gate-A layer reauthenticates persisted backup authority before narrow
storage ports may create or reverify the two planned ciphertext blobs. It may
advance only through ``rollback_armed`` and may activate that exact authenticated
generation through the metadata pointer. It exposes no listing, deletion,
restore, or repair/runtime mutation authority.
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
    BackupVerifiedRecord,
    EnvironmentJournalGeneration,
    EnvironmentJournalState,
    JournalPointerDisposition,
    JournalProtectionPort,
    JournalStreamIdentity,
    RecoveryJournalError,
    RollbackArmedRecord,
    protect_environment_journal_generation,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    append_persisted_environment_journal_generation_from_held_root,
    ensure_persisted_environment_journal_pointer_from_held_root,
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


class RecoveryBackupBlobVerificationPort(Protocol):
    def verify_backup_blob(
        self,
        root_path: str,
        expected: StoredRecoveryBackupBlob,
    ) -> StoredRecoveryBackupBlob: ...


class RecoveryBackupBlobReadPort(Protocol):
    def read_backup_blob(
        self,
        root_path: str,
        expected: StoredRecoveryBackupBlob,
    ) -> CurrentUserProtectedBlob: ...


def _matches_environment_summary(
    record: BackupPreparingRecord,
    backup: EnvironmentExactStateBackup,
) -> bool:
    security = backup.security
    return (
        record.environment_present is backup.existed
        and record.environment_original_identity == backup.identity
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


def _verification_call(
    storage: object,
    root_path: str,
    expected: StoredRecoveryBackupBlob,
) -> StoredRecoveryBackupBlob:
    try:
        operation = getattr(storage, "verify_backup_blob")
        if not callable(operation):
            raise TypeError("Recovery backup verification is unavailable.")
        verified = operation(root_path, expected)
    except RecoveryBackupStorageError:
        raise
    except Exception:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    if type(verified) is not StoredRecoveryBackupBlob or verified != expected:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    return verified


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


def persist_backup_verified_generation(
    environment_sealed: SealedEnvironmentExactStateBackup,
    certificate_sealed: SealedCertificateExactStateBackup,
    persisted_blobs: PersistedRecoveryBackupBlobs,
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    verification: RecoveryBackupBlobVerificationPort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Record backup verification after exact held-root blob rereads."""

    if (
        type(environment_sealed) is not SealedEnvironmentExactStateBackup
        or type(certificate_sealed) is not SealedCertificateExactStateBackup
        or type(persisted_blobs) is not PersistedRecoveryBackupBlobs
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

    def verify_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
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
        preparation_record = prepared.selection.tip.record
        environment_blob = environment_sealed.protected_blob
        certificate_blob = certificate_sealed.protected_blob
        if (
            not _matches_environment_summary(preparation_record, environment)
            or not _matches_certificate_summary(preparation_record, certificates)
            or persisted_blobs.environment.name
            != preparation_record.environment_backup_name
            or persisted_blobs.certificate.name
            != preparation_record.certificate_backup_name
        ):
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        _validate_receipt(
            persisted_blobs.environment,
            name=preparation_record.environment_backup_name,
            blob=environment_blob,
        )
        _validate_receipt(
            persisted_blobs.certificate,
            name=preparation_record.certificate_backup_name,
            blob=certificate_blob,
        )
        environment_verified = _verification_call(
            verification,
            root_path,
            persisted_blobs.environment,
        )
        certificate_verified = _verification_call(
            verification,
            root_path,
            persisted_blobs.certificate,
        )
        try:
            record = BackupVerifiedRecord(
                1,
                prepared.selection.tip_generation_sha256,
                stream.package_root_identity,
                environment_verified.identity,
                environment_verified.ciphertext_sha256,
                environment_verified.ciphertext_size,
                certificate_verified.identity,
                certificate_verified.ciphertext_sha256,
                certificate_verified.ciphertext_size,
            )
            generation = EnvironmentJournalGeneration(
                1,
                stream,
                2,
                prepared.selection.tip_generation_sha256,
                EnvironmentJournalState.BACKUP_VERIFIED,
                record,
            )
            sealed_generation = protect_environment_journal_generation(
                generation,
                protection=journal_protection,
            )
        except (RecoveryJournalError, ValueError):
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        try:
            persisted = append_persisted_environment_journal_generation_from_held_root(
                root_path,
                sealed_generation,
                stream=stream,
                storage=journal_storage,
                protection=journal_protection,
            )
        except RecoveryJournalStorageError as exc:
            if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
            if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                _fail(RecoveryBackupStorageErrorCode.WRITE_FAILED)
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        except RecoveryJournalError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        if (
            persisted.selection.tip != generation
            or persisted.selection.tip_generation_sha256
            != sealed_generation.generation_sha256
        ):
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        return persisted

    return _run_under_root(root, verify_and_record)


def persist_rollback_armed_generation(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    verification: RecoveryBackupBlobVerificationPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Arm rollback after a fresh held-root reread of both exact backup blobs."""

    if type(stream) is not JournalStreamIdentity:
        _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)

    def verify_and_arm(root_path: str) -> PersistedEnvironmentJournalChain:
        try:
            verified_chain = load_persisted_environment_journal_chain_from_held_root(
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
            type(verified_chain) is not PersistedEnvironmentJournalChain
            or len(verified_chain.selection.generations) != 2
            or verified_chain.selection.tip.state
            is not EnvironmentJournalState.BACKUP_VERIFIED
            or type(verified_chain.selection.generations[0].record)
            is not BackupPreparingRecord
            or type(verified_chain.selection.tip.record) is not BackupVerifiedRecord
        ):
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        preparing = verified_chain.selection.generations[0].record
        verified = verified_chain.selection.tip.record
        try:
            environment_expected = StoredRecoveryBackupBlob(
                preparing.environment_backup_name,
                ProtectedDataPurpose.ENVIRONMENT_BACKUP,
                verified.environment_backup_identity,
                verified.environment_ciphertext_sha256,
                verified.environment_ciphertext_size,
            )
            certificate_expected = StoredRecoveryBackupBlob(
                preparing.certificate_backup_name,
                ProtectedDataPurpose.CERTIFICATE_BACKUP,
                verified.certificate_backup_identity,
                verified.certificate_ciphertext_sha256,
                verified.certificate_ciphertext_size,
            )
        except ValueError:
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        environment_reverified = _verification_call(
            verification,
            root_path,
            environment_expected,
        )
        certificate_reverified = _verification_call(
            verification,
            root_path,
            certificate_expected,
        )
        try:
            record = RollbackArmedRecord(
                1,
                verified_chain.selection.tip_generation_sha256,
                stream.package_root_identity,
                environment_reverified.identity,
                environment_reverified.ciphertext_sha256,
                environment_reverified.ciphertext_size,
                certificate_reverified.identity,
                certificate_reverified.ciphertext_sha256,
                certificate_reverified.ciphertext_size,
            )
            generation = EnvironmentJournalGeneration(
                1,
                stream,
                3,
                verified_chain.selection.tip_generation_sha256,
                EnvironmentJournalState.ROLLBACK_ARMED,
                record,
            )
            sealed_generation = protect_environment_journal_generation(
                generation,
                protection=journal_protection,
            )
        except (RecoveryJournalError, ValueError):
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        try:
            persisted = append_persisted_environment_journal_generation_from_held_root(
                root_path,
                sealed_generation,
                stream=stream,
                storage=journal_storage,
                protection=journal_protection,
            )
        except RecoveryJournalStorageError as exc:
            if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
            if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                _fail(RecoveryBackupStorageErrorCode.WRITE_FAILED)
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        except RecoveryJournalError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        if (
            persisted.selection.tip != generation
            or persisted.selection.tip_generation_sha256
            != sealed_generation.generation_sha256
        ):
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        return persisted

    return _run_under_root(root, verify_and_arm)


def activate_persisted_rollback_armed_generation(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    verification: RecoveryBackupBlobVerificationPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Reverify both exact backups and make rollback_armed the current tip."""

    if type(stream) is not JournalStreamIdentity:
        _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)

    def verify_and_activate(root_path: str) -> PersistedEnvironmentJournalChain:
        try:
            armed_chain = load_persisted_environment_journal_chain_from_held_root(
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
            type(armed_chain) is not PersistedEnvironmentJournalChain
            or len(armed_chain.selection.generations) != 3
            or armed_chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_ARMED
            or type(armed_chain.selection.generations[0].record)
            is not BackupPreparingRecord
            or type(armed_chain.selection.tip.record) is not RollbackArmedRecord
        ):
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        preparing = armed_chain.selection.generations[0].record
        armed = armed_chain.selection.tip.record
        try:
            environment_expected = StoredRecoveryBackupBlob(
                preparing.environment_backup_name,
                ProtectedDataPurpose.ENVIRONMENT_BACKUP,
                armed.environment_backup_identity,
                armed.environment_ciphertext_sha256,
                armed.environment_ciphertext_size,
            )
            certificate_expected = StoredRecoveryBackupBlob(
                preparing.certificate_backup_name,
                ProtectedDataPurpose.CERTIFICATE_BACKUP,
                armed.certificate_backup_identity,
                armed.certificate_ciphertext_sha256,
                armed.certificate_ciphertext_size,
            )
        except ValueError:
            _fail(RecoveryBackupStorageErrorCode.AUTHORITY_INVALID)
        _verification_call(verification, root_path, environment_expected)
        _verification_call(verification, root_path, certificate_expected)
        try:
            activated = ensure_persisted_environment_journal_pointer_from_held_root(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
        except RecoveryJournalStorageError as exc:
            if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
            if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                _fail(RecoveryBackupStorageErrorCode.WRITE_FAILED)
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        except RecoveryJournalError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        if (
            type(activated) is not PersistedEnvironmentJournalChain
            or activated.selection.pointer_disposition
            is not JournalPointerDisposition.CURRENT
            or activated.selection.tip_generation_sha256
            != armed_chain.selection.tip_generation_sha256
            or activated.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_ARMED
        ):
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        return activated

    return _run_under_root(root, verify_and_activate)


__all__ = [
    "PersistedRecoveryBackupBlobs",
    "RecoveryBackupBlobReadPort",
    "RecoveryBackupBlobStoragePort",
    "RecoveryBackupBlobVerificationPort",
    "RecoveryBackupStorageError",
    "RecoveryBackupStorageErrorCode",
    "StoredRecoveryBackupBlob",
    "activate_persisted_rollback_armed_generation",
    "persist_backup_verified_generation",
    "persist_prepared_recovery_backup_blobs",
    "persist_rollback_armed_generation",
]
