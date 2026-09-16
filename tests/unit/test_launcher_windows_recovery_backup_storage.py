from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Callable, TypeVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_backup as backup  # noqa: E402
import towerscout_launcher.windows_recovery_backup_preparation as preparation  # noqa: E402
import towerscout_launcher.windows_recovery_backup_storage as blob_storage  # noqa: E402
import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal_storage as storage  # noqa: E402
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_Result = TypeVar("_Result")


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _stream() -> journal.JournalStreamIdentity:
    return journal.JournalStreamIdentity(1, "a" * 32, "b" * 64, _identity(7))


class _Protection:
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        return CurrentUserProtectedBlob(
            purpose,
            purpose.value.encode("ascii") + b":" + plaintext,
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        prefix = purpose.value.encode("ascii") + b":"
        if blob.purpose is not purpose or not blob.ciphertext.startswith(prefix):
            raise ValueError("private authentication detail")
        return blob.ciphertext[len(prefix) :]


class _NameSource:
    def __init__(self) -> None:
        self.calls = 0

    def new_backup_name(self) -> str:
        self.calls += 1
        return f"recovery-backup-{self.calls:032x}.blob"


class _Root:
    def __init__(self) -> None:
        self.active = False
        self.error: BaseException | None = None

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        if self.error is not None:
            raise self.error
        self.active = True
        try:
            return operation(r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1")
        finally:
            self.active = False


class _GenerationStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.files: dict[str, storage.StoredJournalGenerationFile] = {}

    def list_names(self, root_path: str) -> tuple[str, ...]:
        assert self.root.active
        del root_path
        return tuple(self.files)

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalGenerationFile:
        assert self.root.active
        del root_path
        stored = self.files[name]
        assert len(stored.contents) <= maximum
        return stored

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> storage.StoredJournalGenerationFile:
        assert self.root.active
        del root_path
        stored = storage.StoredJournalGenerationFile(
            _identity(20 + len(self.files)),
            contents,
        )
        self.files[name] = stored
        return stored


class _BlobStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.created: list[tuple[str, CurrentUserProtectedBlob]] = []
        self.verified: list[blob_storage.StoredRecoveryBackupBlob] = []
        self.receipt_override: blob_storage.StoredRecoveryBackupBlob | None = None
        self.verification_override: blob_storage.StoredRecoveryBackupBlob | None = None
        self.fail_at: int | None = None
        self.fail_verify_at: int | None = None

    def create_backup_blob(
        self,
        root_path: str,
        name: str,
        blob: CurrentUserProtectedBlob,
    ) -> blob_storage.StoredRecoveryBackupBlob:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.created.append((name, blob))
        if self.fail_at == len(self.created):
            raise OSError("private backup path")
        if self.receipt_override is not None:
            return self.receipt_override
        return blob_storage.StoredRecoveryBackupBlob(
            name,
            blob.purpose,
            _identity(30 + len(self.created)),
            blob.ciphertext_sha256,
            len(blob.ciphertext),
        )

    def verify_backup_blob(
        self,
        root_path: str,
        expected: blob_storage.StoredRecoveryBackupBlob,
    ) -> blob_storage.StoredRecoveryBackupBlob:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.verified.append(expected)
        if self.fail_verify_at == len(self.verified):
            raise OSError("private verification path")
        return self.verification_override or expected


def _sealed_backups(
    protection: _Protection,
    *,
    environment_contents: bytes | None = b"GOOGLE_API_KEY=private-value\r\n",
) -> tuple[
    journal.JournalStreamIdentity,
    backup.SealedEnvironmentExactStateBackup,
    backup.SealedCertificateExactStateBackup,
]:
    stream = _stream()
    environment = backup.EnvironmentExactStateBackup(
        1,
        stream,
        environment_contents,
        (
            None
            if environment_contents is None
            else backup.WindowsFileSecurityMetadata(1, 0x20, b"private-descriptor")
        ),
    )
    certificates = backup.CertificateExactStateBackup(
        1,
        stream,
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.LOCAL_CA,
            b"private-local-ca",
            0o644,
        ),
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.CA_BUNDLE,
            None,
            None,
        ),
    )
    return (
        stream,
        backup.protect_environment_exact_state_backup(
            environment,
            protection=protection,
        ),
        backup.protect_certificate_exact_state_backup(
            certificates,
            protection=protection,
        ),
    )


def _prepared(
    protection: _Protection,
    root: _Root,
    generations: _GenerationStorage,
    environment: backup.SealedEnvironmentExactStateBackup,
    certificates: backup.SealedCertificateExactStateBackup,
    stream: journal.JournalStreamIdentity,
) -> storage.PersistedEnvironmentJournalChain:
    return preparation.persist_backup_preparing_generation(
        environment,
        certificates,
        stream=stream,
        name_source=_NameSource(),
        root=root,
        storage=generations,
        backup_protection=protection,
        journal_protection=protection,
    )


def test_persist_prepared_blobs_writes_only_planned_ciphertexts_under_root() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    prepared = _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)

    persisted = blob_storage.persist_prepared_recovery_backup_blobs(
        environment,
        certificates,
        stream=stream,
        root=root,
        journal_storage=generations,
        storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )

    record = prepared.selection.tip.record
    assert type(record) is journal.BackupPreparingRecord
    assert [name for name, _blob in blobs.created] == [
        record.environment_backup_name,
        record.certificate_backup_name,
    ]
    assert [item.ciphertext for _name, item in blobs.created] == [
        environment.protected_blob.ciphertext,
        certificates.protected_blob.ciphertext,
    ]
    assert b"GOOGLE_API_KEY=private-value" not in blobs.created[0][1].ciphertext
    assert persisted.environment.ciphertext_sha256 == environment.backup_sha256
    assert persisted.certificate.ciphertext_sha256 == certificates.backup_sha256
    assert not root.active


def test_persist_backup_verified_reauthenticates_exact_blobs_under_root() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)
    persisted_blobs = blob_storage.persist_prepared_recovery_backup_blobs(
        environment,
        certificates,
        stream=stream,
        root=root,
        journal_storage=generations,
        storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )

    persisted = blob_storage.persist_backup_verified_generation(
        environment,
        certificates,
        persisted_blobs,
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )

    assert blobs.verified == [
        persisted_blobs.environment,
        persisted_blobs.certificate,
    ]
    assert len(persisted.selection.generations) == 2
    assert (
        persisted.selection.tip.state is journal.EnvironmentJournalState.BACKUP_VERIFIED
    )
    record = persisted.selection.tip.record
    assert type(record) is journal.BackupVerifiedRecord
    assert (
        record.preparing_generation_sha256 == persisted.selection.generation_sha256s[0]
    )
    assert record.environment_backup_identity == persisted_blobs.environment.identity
    assert record.environment_ciphertext_sha256 == environment.backup_sha256
    assert record.environment_ciphertext_size == len(
        environment.protected_blob.ciphertext
    )
    assert record.certificate_backup_identity == persisted_blobs.certificate.identity
    assert record.certificate_ciphertext_sha256 == certificates.backup_sha256
    assert record.certificate_ciphertext_size == len(
        certificates.protected_blob.ciphertext
    )
    assert not root.active


def test_backup_verified_rejects_receipt_drift_before_reverification() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    prepared = _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)
    persisted_blobs = blob_storage.persist_prepared_recovery_backup_blobs(
        environment,
        certificates,
        stream=stream,
        root=root,
        journal_storage=generations,
        storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )
    drifted = blob_storage.PersistedRecoveryBackupBlobs(
        blob_storage.StoredRecoveryBackupBlob(
            persisted_blobs.environment.name,
            persisted_blobs.environment.purpose,
            persisted_blobs.environment.identity,
            "f" * 64,
            persisted_blobs.environment.ciphertext_size,
        ),
        persisted_blobs.certificate,
    )

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_backup_verified_generation(
            environment,
            certificates,
            drifted,
            stream=stream,
            root=root,
            journal_storage=generations,
            verification=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    )
    assert not blobs.verified
    assert len(prepared.selection.generations) == 1
    assert len(generations.files) == 1


def test_backup_verified_preserves_preparing_on_second_reverification_failure() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)
    persisted_blobs = blob_storage.persist_prepared_recovery_backup_blobs(
        environment,
        certificates,
        stream=stream,
        root=root,
        journal_storage=generations,
        storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )
    blobs.fail_verify_at = 2

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_backup_verified_generation(
            environment,
            certificates,
            persisted_blobs,
            stream=stream,
            root=root,
            journal_storage=generations,
            verification=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    )
    assert len(blobs.verified) == 2
    assert len(generations.files) == 1
    assert "private" not in str(failure.value)


def test_backup_verified_retry_fails_closed_before_blob_reverification() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)
    persisted_blobs = blob_storage.persist_prepared_recovery_backup_blobs(
        environment,
        certificates,
        stream=stream,
        root=root,
        journal_storage=generations,
        storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )
    blob_storage.persist_backup_verified_generation(
        environment,
        certificates,
        persisted_blobs,
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        backup_protection=protection,
        journal_protection=protection,
    )
    blobs.verified.clear()

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_backup_verified_generation(
            environment,
            certificates,
            persisted_blobs,
            stream=stream,
            root=root,
            journal_storage=generations,
            verification=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code
        is blob_storage.RecoveryBackupStorageErrorCode.AUTHORITY_INVALID
    )
    assert not blobs.verified
    assert len(generations.files) == 2


def test_summary_drift_fails_before_root_or_blob_write() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    prepared = _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    _stream_again, changed_environment, _certificates_again = _sealed_backups(
        protection,
        environment_contents=b"GOOGLE_API_KEY=changed\r\n",
    )
    blobs = _BlobStorage(root)

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_prepared_recovery_backup_blobs(
            changed_environment,
            certificates,
            stream=stream,
            root=root,
            journal_storage=generations,
            storage=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code
        is blob_storage.RecoveryBackupStorageErrorCode.AUTHORITY_INVALID
    )
    assert not blobs.created


def test_second_blob_failure_preserves_first_and_sanitizes_detail() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)
    blobs.fail_at = 2

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_prepared_recovery_backup_blobs(
            environment,
            certificates,
            stream=stream,
            root=root,
            journal_storage=generations,
            storage=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.WRITE_FAILED
    )
    assert "private" not in str(failure.value)
    assert len(blobs.created) == 2


def test_wrong_receipt_fails_closed_after_first_create() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    blobs = _BlobStorage(root)
    blobs.receipt_override = blob_storage.StoredRecoveryBackupBlob(
        "recovery-backup-" + "f" * 32 + ".blob",
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        _identity(99),
        "e" * 64,
        7,
    )

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_prepared_recovery_backup_blobs(
            environment,
            certificates,
            stream=stream,
            root=root,
            journal_storage=generations,
            storage=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    )
    assert len(blobs.created) == 1


def test_root_failure_is_sanitized_and_process_control_propagates() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )

    root.error = OSError("private protected root")
    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_prepared_recovery_backup_blobs(
            environment,
            certificates,
            stream=stream,
            root=root,
            journal_storage=generations,
            storage=_BlobStorage(root),
            backup_protection=protection,
            journal_protection=protection,
        )
    assert (
        failure.value.code
        is blob_storage.RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE
    )
    assert "private" not in str(failure.value)

    root.error = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        blob_storage.persist_prepared_recovery_backup_blobs(
            environment,
            certificates,
            stream=stream,
            root=root,
            journal_storage=generations,
            storage=_BlobStorage(root),
            backup_protection=protection,
            journal_protection=protection,
        )


def test_missing_persisted_authority_fails_before_blob_write() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(
        protection,
        root,
        generations,
        environment,
        certificates,
        stream,
    )
    generations.files.clear()
    blobs = _BlobStorage(root)

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_prepared_recovery_backup_blobs(
            environment,
            certificates,
            stream=stream,
            root=root,
            journal_storage=generations,
            storage=blobs,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code
        is blob_storage.RecoveryBackupStorageErrorCode.AUTHORITY_INVALID
    )
    assert not blobs.created


def test_receipts_redact_names_hashes_and_identities() -> None:
    stored = blob_storage.StoredRecoveryBackupBlob(
        "recovery-backup-" + "1" * 32 + ".blob",
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        _identity(30),
        hashlib.sha256(b"ciphertext").hexdigest(),
        len(b"ciphertext"),
    )
    pair = blob_storage.PersistedRecoveryBackupBlobs(
        stored,
        blob_storage.StoredRecoveryBackupBlob(
            "recovery-backup-" + "2" * 32 + ".blob",
            ProtectedDataPurpose.CERTIFICATE_BACKUP,
            _identity(31),
            hashlib.sha256(b"certificate").hexdigest(),
            len(b"certificate"),
        ),
    )

    rendered = repr(stored) + repr(pair)
    assert stored.name not in rendered
    assert stored.ciphertext_sha256 not in rendered
    assert repr(stored.identity) not in rendered
