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
import towerscout_launcher.windows_recovery as recovery  # noqa: E402
import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal_storage as storage  # noqa: E402
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathHierarchyTrust,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_environment_storage import (  # noqa: E402
    RecoveryEnvironmentStorageError,
    RecoveryEnvironmentStorageErrorCode,
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


class _RejectingBackupProtection(_Protection):
    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        if purpose in {
            ProtectedDataPurpose.ENVIRONMENT_BACKUP,
            ProtectedDataPurpose.CERTIFICATE_BACKUP,
        }:
            raise ValueError("private backup authentication detail")
        return super().unprotect(blob, purpose)


class _NameSource:
    def __init__(self) -> None:
        self.calls = 0

    def new_backup_name(self) -> str:
        self.calls += 1
        return f"recovery-backup-{self.calls:032x}.blob"


class _EnvironmentTempNameSource:
    def __init__(self) -> None:
        self.calls = 0

    def new_environment_temp_name(self) -> str:
        self.calls += 1
        return f".towerscout-env-{self.calls:032x}.tmp"


class _PackagePathApi:
    supported = True

    def current_user_sid(self) -> str:
        return "S-1-5-21-1000"

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        return path

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, str)
        file_id = (
            _identity(7).file_id
            if handle.casefold() == r"C:\Users\reviewed-user\TowerScout".casefold()
            else hashlib.sha256(handle.casefold().encode("utf-16-le")).digest()[:16]
        )
        return NativeDirectoryFacts(handle, 7, file_id, 0x10, 3, 1, 0)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, str)
        return NativeSecurityFacts(self.current_user_sid(), True, ())

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, str)


class _EnvironmentStorage:
    def __init__(self) -> None:
        self.identity = _identity(50)
        self.created: list[journal.EnvironmentRestoreTempPlanRecord] = []
        self.verified: list[journal.EnvironmentRestoreTempCreatedRecord] = []
        self.create_error: RecoveryEnvironmentStorageError | None = None
        self.verification_identity: StableFileIdentity | None = None

    def create_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        plan: journal.EnvironmentRestoreTempPlanRecord,
    ) -> StableFileIdentity:
        package_root.assert_unchanged_while_held()
        self.created.append(plan)
        if self.create_error is not None:
            raise self.create_error
        return self.identity

    def verify_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        created: journal.EnvironmentRestoreTempCreatedRecord,
    ) -> StableFileIdentity:
        package_root.assert_unchanged_while_held()
        self.verified.append(created)
        assert created.temp_identity is not None
        return self.verification_identity or created.temp_identity


def _package_root() -> PathHierarchyTrust:
    return capture_path_hierarchy(
        r"C:\Users\reviewed-user\TowerScout",
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_PackagePathApi(),
    )


class _Root:
    def __init__(self) -> None:
        self.active = False
        self.calls = 0
        self.error: BaseException | None = None

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        if self.error is not None:
            raise self.error
        self.calls += 1
        self.active = True
        try:
            return operation(r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1")
        finally:
            self.active = False


class _GenerationStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.files: dict[str, storage.StoredJournalGenerationFile] = {}
        self.pointer: storage.StoredJournalPointerFile | None = None
        self.pointer_replacements = 0
        self.fail_pointer_replace: BaseException | None = None

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

    def read_pointer(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalPointerFile | None:
        assert self.root.active
        del root_path, name
        if self.pointer is not None:
            assert len(self.pointer.contents) <= maximum
        return self.pointer

    def replace_pointer(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> storage.StoredJournalPointerFile:
        assert self.root.active
        del root_path, name
        if self.fail_pointer_replace is not None:
            raise self.fail_pointer_replace
        self.pointer_replacements += 1
        self.pointer = storage.StoredJournalPointerFile(
            _identity(90 + self.pointer_replacements),
            contents,
        )
        return self.pointer


class _BlobStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.created: list[tuple[str, CurrentUserProtectedBlob]] = []
        self.files: dict[str, CurrentUserProtectedBlob] = {}
        self.read: list[blob_storage.StoredRecoveryBackupBlob] = []
        self.verified: list[blob_storage.StoredRecoveryBackupBlob] = []
        self.receipt_override: blob_storage.StoredRecoveryBackupBlob | None = None
        self.verification_override: blob_storage.StoredRecoveryBackupBlob | None = None
        self.fail_at: int | None = None
        self.fail_verify_at: int | None = None
        self.fail_read_at: int | None = None

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
        self.files[name] = blob
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

    def read_backup_blob(
        self,
        root_path: str,
        expected: blob_storage.StoredRecoveryBackupBlob,
    ) -> CurrentUserProtectedBlob:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.read.append(expected)
        if self.fail_read_at == len(self.read):
            raise OSError("private backup read path")
        return self.files[expected.name]


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


def _persist_and_activate_rollback(
    protection: _Protection,
    stream: journal.JournalStreamIdentity,
    environment: backup.SealedEnvironmentExactStateBackup,
    certificates: backup.SealedCertificateExactStateBackup,
    root: _Root,
    generations: _GenerationStorage,
    blobs: _BlobStorage,
) -> blob_storage.PersistedRecoveryBackupBlobs:
    _prepared(protection, root, generations, environment, certificates, stream)
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
    blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    blob_storage.activate_persisted_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    return persisted_blobs


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


def test_persist_rollback_armed_reverifies_exact_blobs_under_root() -> None:
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
    verified_chain = blob_storage.persist_backup_verified_generation(
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

    persisted = blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert len(blobs.verified) == 2
    assert blobs.verified == [persisted_blobs.environment, persisted_blobs.certificate]
    assert len(persisted.selection.generations) == 3
    assert (
        persisted.selection.tip.state is journal.EnvironmentJournalState.ROLLBACK_ARMED
    )
    record = persisted.selection.tip.record
    verified = verified_chain.selection.tip.record
    assert type(record) is journal.RollbackArmedRecord
    assert type(verified) is journal.BackupVerifiedRecord
    assert (
        record.backup_verified_generation_sha256
        == verified_chain.selection.tip_generation_sha256
    )
    assert record.environment_backup_identity == verified.environment_backup_identity
    assert (
        record.environment_ciphertext_sha256 == verified.environment_ciphertext_sha256
    )
    assert record.environment_ciphertext_size == verified.environment_ciphertext_size
    assert record.certificate_backup_identity == verified.certificate_backup_identity
    assert (
        record.certificate_ciphertext_sha256 == verified.certificate_ciphertext_sha256
    )
    assert record.certificate_ciphertext_size == verified.certificate_ciphertext_size
    assert len(generations.files) == 3
    assert not root.active


def test_activate_rollback_armed_reverifies_and_selects_tip_under_one_root() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(protection, root, generations, environment, certificates, stream)
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
    storage.ensure_persisted_environment_journal_pointer(
        stream,
        root=root,
        generation_storage=generations,
        pointer_storage=generations,
        protection=protection,
    )
    armed = blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    blobs.verified.clear()
    calls_before_activation = root.calls

    activated = blob_storage.activate_persisted_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert root.calls == calls_before_activation + 1
    assert blobs.verified == [persisted_blobs.environment, persisted_blobs.certificate]
    assert generations.pointer_replacements == 2
    assert activated.selection.tip_generation_sha256 == (
        armed.selection.tip_generation_sha256
    )
    assert (
        activated.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert generations.pointer is not None
    assert journal.decode_environment_journal_pointer(
        generations.pointer.contents
    ) == journal.EnvironmentJournalPointer(
        1,
        stream.journal_id,
        3,
        armed.selection.tip_generation_sha256,
    )


def test_activate_rollback_armed_is_idempotent_after_pointer_is_current() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(protection, root, generations, environment, certificates, stream)
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
    blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    first = blob_storage.activate_persisted_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    blobs.verified.clear()

    second = blob_storage.activate_persisted_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert second.selection == first.selection
    assert generations.pointer_replacements == 1
    assert blobs.verified == [persisted_blobs.environment, persisted_blobs.certificate]


def test_activate_rollback_armed_preserves_pointer_on_blob_failure() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(protection, root, generations, environment, certificates, stream)
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
    blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    blobs.verified.clear()
    blobs.fail_verify_at = 2

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.activate_persisted_rollback_armed_generation(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    )
    assert generations.pointer is None
    assert generations.pointer_replacements == 0


def test_activate_rollback_armed_repairs_pointer_after_write_failure() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    _prepared(protection, root, generations, environment, certificates, stream)
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
    blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    generations.fail_pointer_replace = OSError("private pointer path")

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.activate_persisted_rollback_armed_generation(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.WRITE_FAILED
    )
    assert "private" not in str(failure.value)
    assert generations.pointer is None

    generations.fail_pointer_replace = None
    activated = blob_storage.activate_persisted_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert (
        activated.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )


def test_begin_rollback_reloads_authority_and_selects_started_tip() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    initial_root = _Root()
    generations = _GenerationStorage(initial_root)
    blobs = _BlobStorage(initial_root)
    persisted_blobs = _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        initial_root,
        generations,
        blobs,
    )
    fresh_root = _Root()
    fresh_protection = _Protection()
    fresh_generations = _GenerationStorage(fresh_root)
    fresh_generations.files = dict(generations.files)
    fresh_generations.pointer = generations.pointer
    fresh_blobs = _BlobStorage(fresh_root)

    started = recovery.begin_persisted_rollback(
        stream=stream,
        root=fresh_root,
        journal_storage=fresh_generations,
        pointer_storage=fresh_generations,
        verification=fresh_blobs,
        journal_protection=fresh_protection,
    )

    assert fresh_root.calls == 1
    assert fresh_blobs.verified == [
        persisted_blobs.environment,
        persisted_blobs.certificate,
    ]
    assert len(started.selection.generations) == 4
    assert (
        started.selection.tip.state is journal.EnvironmentJournalState.ROLLBACK_STARTED
    )
    assert (
        started.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    record = started.selection.tip.record
    assert type(record) is journal.RollbackStartedRecord
    assert record.rollback_armed_generation_sha256 == (
        started.selection.generation_sha256s[2]
    )
    assert fresh_generations.pointer is not None
    assert journal.decode_environment_journal_pointer(
        fresh_generations.pointer.contents
    ) == journal.EnvironmentJournalPointer(
        1,
        stream.journal_id,
        4,
        started.selection.tip_generation_sha256,
    )
    assert not fresh_root.active


def test_begin_rollback_is_idempotent_after_started_pointer_is_current() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    persisted_blobs = _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    first = recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    replacements = generations.pointer_replacements
    blobs.verified.clear()

    second = recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert second.selection == first.selection
    assert len(generations.files) == 4
    assert generations.pointer_replacements == replacements
    assert blobs.verified == [persisted_blobs.environment, persisted_blobs.certificate]


def test_begin_rollback_preserves_armed_state_on_blob_failure() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    blobs.verified.clear()
    blobs.fail_verify_at = 2

    with pytest.raises(recovery.WindowsRecoveryError) as failure:
        recovery.begin_persisted_rollback(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert len(generations.files) == 3
    assert generations.pointer is not None
    assert (
        journal.decode_environment_journal_pointer(
            generations.pointer.contents
        ).sequence
        == 3
    )
    assert "private" not in str(failure.value)


def test_begin_rollback_repairs_armed_pointer_before_append() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    generations.pointer = None
    generations.fail_pointer_replace = OSError("private armed pointer path")

    with pytest.raises(recovery.WindowsRecoveryError) as failure:
        recovery.begin_persisted_rollback(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert len(generations.files) == 3
    assert generations.pointer is None
    assert "private" not in str(failure.value)

    generations.fail_pointer_replace = None
    started = recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert len(generations.files) == 4
    assert (
        started.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert (
        started.selection.tip.state is journal.EnvironmentJournalState.ROLLBACK_STARTED
    )


def test_begin_rollback_repairs_started_pointer_without_duplicate_append() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    generations.fail_pointer_replace = OSError("private pointer path")

    with pytest.raises(recovery.WindowsRecoveryError) as failure:
        recovery.begin_persisted_rollback(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert len(generations.files) == 4
    assert generations.pointer is not None
    assert (
        journal.decode_environment_journal_pointer(
            generations.pointer.contents
        ).sequence
        == 3
    )
    assert "private" not in str(failure.value)

    generations.fail_pointer_replace = None
    blobs.verified.clear()
    started = recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    assert len(generations.files) == 4
    assert (
        started.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert (
        started.selection.tip.state is journal.EnvironmentJournalState.ROLLBACK_STARTED
    )


def test_plan_environment_restore_authenticates_backups_and_selects_plan() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    initial_root = _Root()
    generations = _GenerationStorage(initial_root)
    blobs = _BlobStorage(initial_root)
    persisted_blobs = _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        initial_root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=initial_root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    fresh_root = _Root()
    fresh_protection = _Protection()
    fresh_generations = _GenerationStorage(fresh_root)
    fresh_generations.files = dict(generations.files)
    fresh_generations.pointer = generations.pointer
    fresh_blobs = _BlobStorage(fresh_root)
    fresh_blobs.files = dict(blobs.files)
    names = _EnvironmentTempNameSource()

    planned = recovery.plan_persisted_environment_restore(
        stream=stream,
        root=fresh_root,
        journal_storage=fresh_generations,
        pointer_storage=fresh_generations,
        backup_storage=fresh_blobs,
        backup_protection=fresh_protection,
        journal_protection=fresh_protection,
        name_source=names,
    )

    assert fresh_root.calls == 1
    assert fresh_blobs.read == [
        persisted_blobs.environment,
        persisted_blobs.certificate,
    ]
    assert len(planned.selection.generations) == 5
    assert planned.selection.tip.state is (
        journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED
    )
    assert planned.selection.pointer_disposition is (
        journal.JournalPointerDisposition.CURRENT
    )
    record = planned.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempPlanRecord
    assert record.rollback_started_generation_sha256 == (
        planned.selection.generation_sha256s[3]
    )
    assert record.environment_present
    assert record.environment_size == len(b"GOOGLE_API_KEY=private-value\r\n")
    assert record.temp_name == ".towerscout-env-" + "0" * 31 + "1.tmp"
    assert names.calls == 1
    assert not fresh_root.active


def test_plan_environment_restore_records_absence_without_temp_name() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(
        protection,
        environment_contents=None,
    )
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    names = _EnvironmentTempNameSource()

    planned = recovery.plan_persisted_environment_restore(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        name_source=names,
    )

    record = planned.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempPlanRecord
    assert not record.environment_present
    assert record.environment_sha256 is None
    assert record.environment_size is None
    assert record.temp_name is None
    assert names.calls == 0


@pytest.mark.parametrize("failure_index", (1, 2))
def test_plan_environment_restore_preserves_started_state_on_backup_read_failure(
    failure_index: int,
) -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    blobs.fail_read_at = failure_index

    with pytest.raises(recovery.WindowsRecoveryError) as failure:
        recovery.plan_persisted_environment_restore(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            backup_storage=blobs,
            backup_protection=protection,
            journal_protection=protection,
            name_source=_EnvironmentTempNameSource(),
        )

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert "private" not in str(failure.value)
    assert len(generations.files) == 4
    assert generations.pointer is not None
    assert (
        journal.decode_environment_journal_pointer(
            generations.pointer.contents
        ).sequence
        == 4
    )


def test_plan_environment_restore_preserves_started_state_on_auth_failure() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )

    with pytest.raises(recovery.WindowsRecoveryError) as failure:
        recovery.plan_persisted_environment_restore(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            backup_storage=blobs,
            backup_protection=_RejectingBackupProtection(),
            journal_protection=protection,
            name_source=_EnvironmentTempNameSource(),
        )

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.BACKUP_INVALID
    assert "private" not in str(failure.value)
    assert len(generations.files) == 4


def test_plan_environment_restore_repairs_pointer_without_duplicate_plan() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    names = _EnvironmentTempNameSource()
    generations.fail_pointer_replace = OSError("private planned pointer path")

    with pytest.raises(recovery.WindowsRecoveryError) as failure:
        recovery.plan_persisted_environment_restore(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            backup_storage=blobs,
            backup_protection=protection,
            journal_protection=protection,
            name_source=names,
        )

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert len(generations.files) == 5
    assert names.calls == 1
    generations.fail_pointer_replace = None

    planned = recovery.plan_persisted_environment_restore(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        name_source=names,
    )

    assert len(generations.files) == 5
    assert names.calls == 1
    assert planned.selection.pointer_disposition is (
        journal.JournalPointerDisposition.CURRENT
    )
    record = planned.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempPlanRecord
    assert record.temp_name == ".towerscout-env-" + "0" * 31 + "1.tmp"


def test_create_environment_restore_temp_records_exact_identity_and_repairs_pointer() -> (
    None
):
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    recovery.plan_persisted_environment_restore(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        name_source=_EnvironmentTempNameSource(),
    )
    package_root = _package_root()
    environment_storage = _EnvironmentStorage()
    generations.fail_pointer_replace = OSError("private created pointer path")
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: recovery.create_persisted_environment_restore_temp_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    environment_storage=environment_storage,
                    journal_protection=protection,
                )
            )

        assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
        assert "private" not in str(failure.value)
        assert len(generations.files) == 6
        assert len(environment_storage.created) == 1
        generations.fail_pointer_replace = None
        environment_storage.verification_identity = _identity(51)

        with pytest.raises(recovery.WindowsRecoveryError) as verification_failure:
            package_root.run_while_held(
                lambda: recovery.create_persisted_environment_restore_temp_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    environment_storage=environment_storage,
                    journal_protection=protection,
                )
            )

        assert verification_failure.value.code is (
            recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
        )
        assert len(generations.files) == 6
        assert len(environment_storage.created) == 1
        environment_storage.verification_identity = None

        created = package_root.run_while_held(
            lambda: recovery.create_persisted_environment_restore_temp_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                environment_storage=environment_storage,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert len(generations.files) == 6
    assert len(environment_storage.created) == 1
    assert len(environment_storage.verified) == 2
    assert created.selection.pointer_disposition is (
        journal.JournalPointerDisposition.CURRENT
    )
    record = created.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempCreatedRecord
    assert record.planned_generation_sha256 == created.selection.generation_sha256s[4]
    assert record.temp_identity == environment_storage.identity


def test_create_environment_restore_temp_records_absence_without_storage_call() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(
        protection,
        environment_contents=None,
    )
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    recovery.plan_persisted_environment_restore(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        name_source=_EnvironmentTempNameSource(),
    )
    package_root = _package_root()
    environment_storage = _EnvironmentStorage()
    try:
        created = package_root.run_while_held(
            lambda: recovery.create_persisted_environment_restore_temp_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                environment_storage=environment_storage,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert environment_storage.created == []
    assert environment_storage.verified == []
    record = created.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempCreatedRecord
    assert not record.environment_present
    assert record.temp_name is None
    assert record.temp_identity is None


def test_create_environment_restore_temp_preserves_plan_on_create_failure() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    generations = _GenerationStorage(root)
    blobs = _BlobStorage(root)
    _persist_and_activate_rollback(
        protection,
        stream,
        environment,
        certificates,
        root,
        generations,
        blobs,
    )
    recovery.begin_persisted_rollback(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    recovery.plan_persisted_environment_restore(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        name_source=_EnvironmentTempNameSource(),
    )
    package_root = _package_root()
    environment_storage = _EnvironmentStorage()
    environment_storage.create_error = RecoveryEnvironmentStorageError(
        RecoveryEnvironmentStorageErrorCode.CREATE_FAILED
    )
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: recovery.create_persisted_environment_restore_temp_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    environment_storage=environment_storage,
                    journal_protection=protection,
                )
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert len(generations.files) == 5
    assert generations.pointer is not None
    assert (
        journal.decode_environment_journal_pointer(
            generations.pointer.contents
        ).sequence
        == 5
    )


def test_rollback_armed_preserves_verified_on_second_blob_failure() -> None:
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
    blobs.fail_verify_at = 2

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_rollback_armed_generation(
            stream=stream,
            root=root,
            journal_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert (
        failure.value.code is blob_storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    )
    assert len(blobs.verified) == 2
    assert len(generations.files) == 2
    assert "private" not in str(failure.value)


def test_rollback_armed_retry_fails_before_blob_reverification() -> None:
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
    blob_storage.persist_rollback_armed_generation(
        stream=stream,
        root=root,
        journal_storage=generations,
        verification=blobs,
        journal_protection=protection,
    )
    blobs.verified.clear()

    with pytest.raises(blob_storage.RecoveryBackupStorageError) as failure:
        blob_storage.persist_rollback_armed_generation(
            stream=stream,
            root=root,
            journal_storage=generations,
            verification=blobs,
            journal_protection=protection,
        )

    assert (
        failure.value.code
        is blob_storage.RecoveryBackupStorageErrorCode.AUTHORITY_INVALID
    )
    assert not blobs.verified
    assert len(generations.files) == 3


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
