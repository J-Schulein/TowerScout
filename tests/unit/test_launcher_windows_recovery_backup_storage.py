from __future__ import annotations

import hashlib
import ntpath
import sys
from dataclasses import replace
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
import towerscout_launcher.windows_recovery_certificate_restore as cert_restore  # noqa: E402
import towerscout_launcher.windows_recovery as recovery  # noqa: E402
import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal_storage as storage  # noqa: E402
import towerscout_launcher.windows_recovery_manager as manager  # noqa: E402
from towerscout_launcher import (  # noqa: E402
    windows_recovery_cleanup_native as cleanup_native,
)
from towerscout_launcher.windows_recovery_certificate_storage import (  # noqa: E402
    CertificateRestoreTempIdentities,
    RecoveryCertificateStorageError,
    RecoveryCertificateStorageErrorCode,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    ABSENT_FILE_SHA256,
    MapProvider,
)
from towerscout_launcher.windows_certificate_replacement import (  # noqa: E402
    CertificateReplacementPlan,
)
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    plan_ca_environment_replacement,
)
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentAppliedRecord,
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
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
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_recovery_environment_restore_native import (  # noqa: E402
    EnvironmentRestoreStorageAuthority,
    EnvironmentRestoreStorageError,
    EnvironmentRestoreStorageErrorCode,
)
from towerscout_launcher.windows_recovery_runtime_authority import (  # noqa: E402
    RollbackRuntimeRecoveryAuthority,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_Result = TypeVar("_Result")


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _certificate_plan() -> CertificateReplacementPlan:
    local_ca = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"Y2FuZGlkYXRl\n"
        b"-----END CERTIFICATE-----\n"
    )
    return CertificateReplacementPlan(
        MapProvider.GOOGLE,
        "f" * 64,
        local_ca,
        b"system-bundle\n" + local_ca,
    )


def _runtime_authority() -> RollbackRuntimeRecoveryAuthority:
    return RollbackRuntimeRecoveryAuthority(
        1,
        "b" * 64,
        _identity(7),
        "1" * 64,
        tuple(f"{value:x}" * 64 for value in range(3, 11)),
        True,
    )


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


class _CertificateTempNameSource:
    def __init__(self) -> None:
        self.calls = 0

    def new_certificate_temp_name(self) -> str:
        self.calls += 1
        return f"recovery-certificate-{self.calls:032x}.tmp"


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
        self.written: list[
            tuple[journal.EnvironmentRestoreTempCreatedRecord, bytes]
        ] = []
        self.written_verified: list[journal.EnvironmentRestoreTempVerifiedRecord] = []
        self.create_error: RecoveryEnvironmentStorageError | None = None
        self.write_error: RecoveryEnvironmentStorageError | None = None
        self.verification_identity: StableFileIdentity | None = None
        self.written_verification_identity: StableFileIdentity | None = None

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

    def write_and_verify_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        created: journal.EnvironmentRestoreTempCreatedRecord,
        contents: bytes,
    ) -> StableFileIdentity:
        package_root.assert_unchanged_while_held()
        self.written.append((created, contents))
        if self.write_error is not None:
            raise self.write_error
        assert created.temp_identity is not None
        return created.temp_identity

    def verify_written_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        verified: journal.EnvironmentRestoreTempVerifiedRecord,
    ) -> StableFileIdentity:
        package_root.assert_unchanged_while_held()
        self.written_verified.append(verified)
        assert verified.temp_identity is not None
        return self.written_verification_identity or verified.temp_identity


class _EnvironmentRestoration:
    def __init__(self) -> None:
        self.calls: list[EnvironmentRestoreStorageAuthority] = []
        self.error: BaseException | None = None
        self.override: EnvironmentDestinationObservation | None = None

    def restore_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentRestoreStorageAuthority,
    ) -> EnvironmentDestinationObservation:
        package_root.assert_unchanged_while_held()
        self.calls.append(authority)
        if self.error is not None:
            raise self.error
        if self.override is not None:
            return self.override
        restore = authority.restore
        if not restore.original_present:
            return EnvironmentDestinationObservation(False)
        return EnvironmentDestinationObservation(
            True,
            restore.restore_temp_identity,
            restore.original_sha256,
            restore.original_size,
            restore.original_file_attributes,
            restore.original_security_descriptor_sha256,
        )


class _RuntimeAvailability:
    def __init__(self, stream: journal.JournalStreamIdentity) -> None:
        self.calls = 0
        self.error: BaseException | None = None
        self.evidence = recovery.RollbackRuntimeAvailabilityEvidence(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            "1" * 64,
            "2" * 64,
            tuple(f"{value:x}" * 64 for value in range(3, 11)),
            True,
        )

    def establish_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: journal.JournalStreamIdentity,
        authority: RollbackRuntimeRecoveryAuthority,
    ) -> recovery.RollbackRuntimeAvailabilityEvidence:
        package_root.assert_unchanged_while_held()
        assert stream.target_token_sha256 == self.evidence.target_token_sha256
        assert authority == _runtime_authority()
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.evidence


class _CertificateStorage:
    def __init__(self, root: "_Root") -> None:
        self.root = root
        self.identities = CertificateRestoreTempIdentities(_identity(61), None)
        self.created: list[journal.CertificateRestoreTempPlanRecord] = []
        self.verified: list[
            tuple[
                journal.CertificateRestoreTempPlanRecord,
                journal.CertificateRestoreTempCreatedRecord,
            ]
        ] = []
        self.written: list[tuple[bytes | None, bytes | None]] = []
        self.written_verified: list[
            tuple[
                journal.CertificateRestoreTempPlanRecord,
                journal.CertificateRestoreTempVerifiedRecord,
            ]
        ] = []
        self.create_error: RecoveryCertificateStorageError | None = None
        self.write_error: RecoveryCertificateStorageError | None = None
        self.verification_override: CertificateRestoreTempIdentities | None = None

    def create_certificate_restore_temps(
        self,
        root_path: str,
        plan: journal.CertificateRestoreTempPlanRecord,
    ) -> CertificateRestoreTempIdentities:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.created.append(plan)
        if self.create_error is not None:
            raise self.create_error
        return self.identities

    def verify_certificate_restore_temps(
        self,
        root_path: str,
        plan: journal.CertificateRestoreTempPlanRecord,
        created: journal.CertificateRestoreTempCreatedRecord,
    ) -> CertificateRestoreTempIdentities:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.verified.append((plan, created))
        return self.verification_override or self.identities

    def write_and_verify_certificate_restore_temps(
        self,
        root_path: str,
        plan: journal.CertificateRestoreTempPlanRecord,
        created: journal.CertificateRestoreTempCreatedRecord,
        *,
        local_ca_contents: bytes | None,
        ca_bundle_contents: bytes | None,
    ) -> CertificateRestoreTempIdentities:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        assert created.local_ca_temp_identity == self.identities.local_ca
        assert created.ca_bundle_temp_identity == self.identities.ca_bundle
        assert plan.local_ca_present is (local_ca_contents is not None)
        assert plan.ca_bundle_present is (ca_bundle_contents is not None)
        self.written.append((local_ca_contents, ca_bundle_contents))
        if self.write_error is not None:
            raise self.write_error
        return self.identities

    def verify_written_certificate_restore_temps(
        self,
        root_path: str,
        plan: journal.CertificateRestoreTempPlanRecord,
        verified: journal.CertificateRestoreTempVerifiedRecord,
    ) -> CertificateRestoreTempIdentities:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.written_verified.append((plan, verified))
        return self.verification_override or self.identities


class _CertificateRestoration:
    def __init__(
        self,
        stream: journal.JournalStreamIdentity,
        runtime: _RuntimeAvailability,
    ) -> None:
        self.calls = 0
        self.error: BaseException | None = None
        self.evidence = recovery.CertificateRestorationEvidence(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            runtime.evidence.runtime_evidence_sha256,
            runtime.evidence.container_evidence_sha256,
            runtime.evidence.volume_evidence_sha256s,
            recovery.CertificateDestinationRestoreEvidence(
                1,
                True,
                hashlib.sha256(b"private-local-ca").hexdigest(),
                len(b"private-local-ca"),
                0o644,
                "b" * 64,
            ),
            recovery.CertificateDestinationRestoreEvidence(
                1,
                False,
                destination_evidence_sha256="c" * 64,
            ),
        )

    def restore_certificates_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: journal.JournalStreamIdentity,
        authority: cert_restore.CertificateRestorationAuthority,
    ) -> recovery.CertificateRestorationEvidence:
        package_root.assert_unchanged_while_held()
        assert protected_root_path.endswith(r"TowerScout\Recovery\v1")
        assert stream.target_token_sha256 == authority.target_token_sha256
        assert authority.target_token_sha256 == self.evidence.target_token_sha256
        assert authority.local_ca.original_present
        assert authority.local_ca.restore_temp_identity is not None
        self.authority = authority
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.evidence


class _RuntimeRestart:
    def __init__(self, stream: journal.JournalStreamIdentity) -> None:
        self.restart_calls = 0
        self.verify_calls = 0
        self.error: BaseException | None = None
        self.evidence = recovery.RollbackRuntimeRestartEvidence(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            "d" * 64,
            "e" * 64,
            tuple(f"{value:x}" * 64 for value in range(1, 9)),
        )

    def restart_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: journal.JournalStreamIdentity,
        intent: journal.RollbackRuntimeRestartingRecord,
    ) -> recovery.RollbackRuntimeRestartEvidence:
        package_root.assert_unchanged_while_held()
        assert intent.package_root_identity == stream.package_root_identity
        self.restart_calls += 1
        if self.error is not None:
            raise self.error
        return self.evidence

    def verify_restarted_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: journal.JournalStreamIdentity,
        restarted: journal.RollbackRuntimeRestartedRecord,
    ) -> recovery.RollbackRuntimeRestartEvidence:
        package_root.assert_unchanged_while_held()
        assert restarted.package_root_identity == stream.package_root_identity
        self.verify_calls += 1
        if self.error is not None:
            raise self.error
        return self.evidence


class _RollbackVerification:
    def __init__(
        self,
        stream: journal.JournalStreamIdentity,
        restart: _RuntimeRestart,
    ) -> None:
        self.calls = 0
        self.error: BaseException | None = None
        self.evidence = recovery.RollbackVerificationEvidence(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            "f" * 64,
            "a" * 64,
            restart.evidence.runtime_evidence_sha256,
            restart.evidence.container_evidence_sha256,
            restart.evidence.volume_evidence_sha256s,
            "b" * 64,
            journal.RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
            True,
            True,
            True,
            True,
        )

    def verify_rollback_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: journal.JournalStreamIdentity,
        restarted: journal.RollbackRuntimeRestartedRecord,
    ) -> recovery.RollbackVerificationEvidence:
        package_root.assert_unchanged_while_held()
        assert restarted.package_root_identity == stream.package_root_identity
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.evidence


class _RecoveryCleanup:
    def __init__(self, stream: journal.JournalStreamIdentity) -> None:
        self.cleanup_calls = 0
        self.verify_calls = 0
        self.fail = False
        self.cleaned = False
        self.evidence = recovery.RecoveryCleanupEvidence(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            "c" * 64,
        )

    def cleanup_rollback_artifacts_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: journal.JournalStreamIdentity,
        chain: storage.PersistedEnvironmentJournalChain,
    ) -> recovery.RecoveryCleanupEvidence:
        package_root.assert_unchanged_while_held()
        assert protected_root_path.endswith(r"TowerScout\Recovery\v1")
        assert chain.selection.tip.state in {
            journal.EnvironmentJournalState.ROLLBACK_VERIFIED,
            journal.EnvironmentJournalState.RECOVERY_CLEANUP_PENDING,
        }
        assert stream.target_token_sha256 == self.evidence.target_token_sha256
        self.cleanup_calls += 1
        if self.fail:
            raise OSError("private cleanup detail")
        self.cleaned = True
        return self.evidence

    def verify_rollback_artifacts_cleaned_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: journal.JournalStreamIdentity,
        chain: storage.PersistedEnvironmentJournalChain,
    ) -> recovery.RecoveryCleanupEvidence:
        package_root.assert_unchanged_while_held()
        assert protected_root_path.endswith(r"TowerScout\Recovery\v1")
        assert chain.selection.tip.state is journal.EnvironmentJournalState.CLEANED
        assert stream.target_token_sha256 == self.evidence.target_token_sha256
        self.verify_calls += 1
        if not self.cleaned:
            raise OSError("private cleanup drift")
        return self.evidence


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
    environment_identity: StableFileIdentity = _identity(8),
) -> tuple[
    journal.JournalStreamIdentity,
    backup.SealedEnvironmentExactStateBackup,
    backup.SealedCertificateExactStateBackup,
]:
    stream = _stream()
    environment = backup.EnvironmentExactStateBackup(
        1,
        stream,
        environment_identity if environment_contents is not None else None,
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
    exact_environment = backup.authenticate_environment_exact_state_backup(
        environment,
        expected_stream=stream,
        protection=protection,
    )
    environment_plan = plan_ca_environment_replacement(
        (
            exact_environment.contents
            if exact_environment.contents is not None
            else b"TOWERSCOUT_GPU_MODE=auto\r\n"
        ),
        original_present=exact_environment.existed,
    )
    return preparation.persist_backup_preparing_generation(
        environment,
        certificates,
        environment_plan=environment_plan,
        certificate_plan=_certificate_plan(),
        runtime_authority=_runtime_authority(),
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


def _persist_created_environment_restore_state(
    protection: _Protection,
    *,
    environment_contents: bytes | None = b"GOOGLE_API_KEY=private-value\r\n",
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    _BlobStorage,
    PathHierarchyTrust,
    _EnvironmentStorage,
]:
    stream, environment, certificates = _sealed_backups(
        protection,
        environment_contents=environment_contents,
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
    return (
        stream,
        root,
        generations,
        blobs,
        package_root,
        environment_storage,
    )


def _persist_verified_environment_restore_state(
    protection: _Protection,
    *,
    environment_contents: bytes | None = b"GOOGLE_API_KEY=private-value\r\n",
) -> tuple[
    journal.JournalStreamIdentity,
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    _BlobStorage,
    PathHierarchyTrust,
    _EnvironmentStorage,
]:
    (
        stream,
        root,
        generations,
        blobs,
        package_root,
        environment_storage,
    ) = _persist_created_environment_restore_state(
        protection,
        environment_contents=environment_contents,
    )
    verified_chain = package_root.run_while_held(
        lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            backup_storage=blobs,
            environment_storage=environment_storage,
            backup_protection=protection,
            journal_protection=protection,
        )
    )
    preparing = verified_chain.selection.generations[0].record
    restore_verified = verified_chain.selection.generations[6].record
    assert type(preparing) is journal.BackupPreparingRecord
    assert type(restore_verified) is journal.EnvironmentRestoreTempVerifiedRecord
    provider_stream = journal.JournalStreamIdentity(
        1,
        "c" * 32,
        stream.target_token_sha256,
        stream.package_root_identity,
    )
    provider_temp_name = ".towerscout-env-" + "9" * 32 + ".tmp"
    provider_plan = EnvironmentTempPlanRecord(
        1,
        stream.package_root_identity,
        (
            restore_verified.environment_sha256
            if restore_verified.environment_present
            else ABSENT_FILE_SHA256
        ),
        preparing.environment_candidate_sha256,
        preparing.environment_candidate_size,
        provider_temp_name,
        restore_verified.environment_present,
        preparing.environment_original_identity,
        restore_verified.environment_size,
        restore_verified.environment_file_attributes,
        restore_verified.environment_security_descriptor_sha256,
    )
    sealed_generations: list[journal.SealedEnvironmentJournalGeneration] = []
    previous = journal.GENESIS_GENERATION_SHA256

    def add(state: journal.EnvironmentJournalState, record: object) -> str:
        nonlocal previous
        generation = journal.EnvironmentJournalGeneration(
            1,
            provider_stream,
            len(sealed_generations) + 1,
            previous,
            state,
            record,  # type: ignore[arg-type]
        )
        sealed = journal.protect_environment_journal_generation(
            generation,
            protection=protection,
        )
        sealed_generations.append(sealed)
        previous = sealed.generation_sha256
        return previous

    planned_hash = add(
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        provider_plan,
    )
    created = EnvironmentTempCreatedRecord(
        1,
        planned_hash,
        stream.package_root_identity,
        _identity(80),
        provider_plan.candidate_sha256,
        provider_plan.candidate_size,
        0x80,
        "d" * 64,
        provider_plan.temp_name,
    )
    created_hash = add(
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
        created,
    )
    provider_verified = EnvironmentTempVerifiedRecord(
        1,
        created_hash,
        stream.package_root_identity,
        created.temp_identity,
        created.candidate_sha256,
        created.candidate_size,
        created.candidate_file_attributes,
        created.candidate_security_descriptor_sha256,
        created.temp_name,
    )
    provider_verified_hash = add(
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
        provider_verified,
    )
    applied = EnvironmentAppliedRecord(
        1,
        provider_verified_hash,
        stream.package_root_identity,
        provider_verified.temp_identity,
        provider_verified.candidate_sha256,
        provider_verified.candidate_size,
        (
            provider_plan.original_file_attributes
            if provider_plan.original_present
            else provider_verified.candidate_file_attributes
        ),
        (
            provider_plan.original_security_descriptor_sha256
            if provider_plan.original_present
            else provider_verified.candidate_security_descriptor_sha256
        ),
        provider_verified.temp_name,
    )
    add(journal.EnvironmentJournalState.ENVIRONMENT_APPLIED, applied)
    for sequence, sealed in enumerate(sealed_generations, start=1):
        name = f"journal-{provider_stream.journal_id}-{sequence:020d}.generation"
        generations.files[name] = storage.StoredJournalGenerationFile(
            _identity(80 + sequence),
            sealed.protected_blob.ciphertext,
        )
    return (
        stream,
        provider_stream,
        root,
        generations,
        blobs,
        package_root,
        environment_storage,
    )


def _persist_restored_environment_state(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    PathHierarchyTrust,
]:
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    _restore_environment_generation(
        stream,
        provider_stream,
        root,
        generations,
        package_root,
        protection,
        _EnvironmentRestoration(),
    )
    return stream, provider_stream, root, generations, package_root


def _persist_runtime_available_state(
    protection: _Protection,
    *,
    environment_contents: bytes | None = b"GOOGLE_API_KEY=private-value\r\n",
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    _BlobStorage,
    PathHierarchyTrust,
    _RuntimeAvailability,
]:
    (
        stream,
        provider_stream,
        root,
        generations,
        blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(
        protection,
        environment_contents=environment_contents,
    )
    _restore_environment_generation(
        stream,
        provider_stream,
        root,
        generations,
        package_root,
        protection,
        _EnvironmentRestoration(),
    )
    availability = _RuntimeAvailability(stream)
    _record_runtime_available(
        stream,
        root,
        generations,
        package_root,
        protection,
        availability,
    )
    return stream, root, generations, blobs, package_root, availability


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


def test_write_environment_restore_temp_authenticates_backup_and_selects_verified() -> (
    None
):
    protection = _Protection()
    contents = b"GOOGLE_API_KEY=private-value\r\n"
    stream, root, generations, blobs, package_root, environment_storage = (
        _persist_created_environment_restore_state(
            protection,
            environment_contents=contents,
        )
    )
    blobs.read.clear()
    try:
        verified = package_root.run_while_held(
            lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                backup_storage=blobs,
                environment_storage=environment_storage,
                backup_protection=protection,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert len(blobs.read) == 1
    assert blobs.read[0].purpose is ProtectedDataPurpose.ENVIRONMENT_BACKUP
    assert len(environment_storage.written) == 1
    assert environment_storage.written[0][1] == contents
    assert environment_storage.written_verified == []
    assert len(generations.files) == 7
    assert verified.selection.pointer_disposition is (
        journal.JournalPointerDisposition.CURRENT
    )
    record = verified.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempVerifiedRecord
    assert record.created_generation_sha256 == verified.selection.generation_sha256s[5]
    assert record.environment_sha256 == hashlib.sha256(contents).hexdigest()
    assert record.temp_identity == environment_storage.identity


def test_write_environment_restore_temp_records_absence_without_storage_call() -> None:
    protection = _Protection()
    stream, root, generations, blobs, package_root, environment_storage = (
        _persist_created_environment_restore_state(
            protection,
            environment_contents=None,
        )
    )
    try:
        verified = package_root.run_while_held(
            lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                backup_storage=blobs,
                environment_storage=environment_storage,
                backup_protection=protection,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert environment_storage.written == []
    assert environment_storage.written_verified == []
    record = verified.selection.tip.record
    assert type(record) is journal.EnvironmentRestoreTempVerifiedRecord
    assert not record.environment_present
    assert record.temp_name is None
    assert record.temp_identity is None


def test_write_environment_restore_temp_preserves_created_on_write_failure() -> None:
    protection = _Protection()
    stream, root, generations, blobs, package_root, environment_storage = (
        _persist_created_environment_restore_state(protection)
    )
    environment_storage.write_error = RecoveryEnvironmentStorageError(
        RecoveryEnvironmentStorageErrorCode.WRITE_FAILED
    )
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    backup_storage=blobs,
                    environment_storage=environment_storage,
                    backup_protection=protection,
                    journal_protection=protection,
                )
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert "private" not in str(failure.value)
    assert len(generations.files) == 6
    assert len(environment_storage.written) == 1
    assert environment_storage.written_verified == []


def test_write_environment_restore_temp_repairs_pointer_without_second_write() -> None:
    protection = _Protection()
    stream, root, generations, blobs, package_root, environment_storage = (
        _persist_created_environment_restore_state(protection)
    )
    generations.fail_pointer_replace = OSError("private verified pointer path")
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as pointer_failure:
            package_root.run_while_held(
                lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    backup_storage=blobs,
                    environment_storage=environment_storage,
                    backup_protection=protection,
                    journal_protection=protection,
                )
            )

        assert (
            pointer_failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
        )
        assert len(generations.files) == 7
        assert len(environment_storage.written) == 1
        generations.fail_pointer_replace = None
        environment_storage.written_verification_identity = _identity(51)

        with pytest.raises(recovery.WindowsRecoveryError) as verification_failure:
            package_root.run_while_held(
                lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    backup_storage=blobs,
                    environment_storage=environment_storage,
                    backup_protection=protection,
                    journal_protection=protection,
                )
            )

        assert verification_failure.value.code is (
            recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
        )
        assert len(generations.files) == 7
        assert len(environment_storage.written) == 1
        environment_storage.written_verification_identity = None

        verified = package_root.run_while_held(
            lambda: recovery.write_persisted_environment_restore_temp_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                backup_storage=blobs,
                environment_storage=environment_storage,
                backup_protection=protection,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert len(generations.files) == 7
    assert len(environment_storage.written) == 1
    assert len(environment_storage.written_verified) == 2
    assert verified.selection.pointer_disposition is (
        journal.JournalPointerDisposition.CURRENT
    )
    assert verified.selection.tip.state is (
        journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED
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


def test_original_environment_identity_drift_fails_before_blob_write() -> None:
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
    _stream_again, changed_environment, _certificates_again = _sealed_backups(
        protection,
        environment_identity=_identity(80),
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


def _restore_environment_generation(
    stream: journal.JournalStreamIdentity,
    provider_stream: journal.JournalStreamIdentity,
    root: _Root,
    generations: _GenerationStorage,
    package_root: PathHierarchyTrust,
    protection: _Protection,
    restoration: _EnvironmentRestoration,
) -> storage.PersistedEnvironmentJournalChain:
    return package_root.run_while_held(
        lambda: recovery.persist_environment_restored_generation_from_held_package_root(
            stream=stream,
            provider_stream=provider_stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            journal_protection=protection,
            environment_restoration=restoration,
        )
    )


def test_environment_restore_reloads_provider_authority_and_selects_generation_8() -> (
    None
):
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    restoration = _EnvironmentRestoration()
    try:
        result = _restore_environment_generation(
            stream,
            provider_stream,
            root,
            generations,
            package_root,
            protection,
            restoration,
        )
    finally:
        package_root.close()

    assert len(restoration.calls) == 1
    authority = restoration.calls[0].restore
    assert authority.candidate_identity == _identity(80)
    assert authority.restore_temp_identity == environment_storage.identity
    assert len(result.selection.generations) == 8
    assert (
        result.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    record = result.selection.tip.record
    assert type(record) is journal.EnvironmentRestoredRecord
    assert record.environment_identity == environment_storage.identity


def test_environment_restore_restart_reverifies_and_repairs_only_pointer() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    restoration = _EnvironmentRestoration()
    try:
        first = _restore_environment_generation(
            stream,
            provider_stream,
            root,
            generations,
            package_root,
            protection,
            restoration,
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = _restore_environment_generation(
            stream,
            provider_stream,
            root,
            generations,
            package_root,
            protection,
            restoration,
        )
    finally:
        package_root.close()

    assert len(restoration.calls) == 2
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    assert (
        second.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )


def test_environment_restore_records_secure_absence() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(
        protection,
        environment_contents=None,
    )
    restoration = _EnvironmentRestoration()
    try:
        result = _restore_environment_generation(
            stream,
            provider_stream,
            root,
            generations,
            package_root,
            protection,
            restoration,
        )
    finally:
        package_root.close()

    record = result.selection.tip.record
    assert type(record) is journal.EnvironmentRestoredRecord
    assert record.environment_present is False
    assert record.environment_identity is None
    assert restoration.calls[0].restore.restore_temp_identity is None


def test_environment_restore_rejects_cross_transaction_provider_stream() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    wrong_provider = journal.JournalStreamIdentity(
        1,
        provider_stream.journal_id,
        "e" * 64,
        provider_stream.package_root_identity,
    )
    restoration = _EnvironmentRestoration()
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _restore_environment_generation(
                stream,
                wrong_provider,
                root,
                generations,
                package_root,
                protection,
                restoration,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.AUTHORITY_INVALID
    assert restoration.calls == []
    assert len(generations.files) == 11


def test_environment_restore_preserves_verified_tip_on_native_failure() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    restoration = _EnvironmentRestoration()
    restoration.error = EnvironmentRestoreStorageError(
        EnvironmentRestoreStorageErrorCode.APPLY_FAILED
    )
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _restore_environment_generation(
                stream,
                provider_stream,
                root,
                generations,
                package_root,
                protection,
                restoration,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert len(generations.files) == 11


def test_environment_restore_rejects_non_original_post_state() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        _blobs,
        package_root,
        _environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    restoration = _EnvironmentRestoration()
    restoration.override = EnvironmentDestinationObservation(
        True,
        _identity(99),
        "f" * 64,
        1,
        0x20,
        "e" * 64,
    )
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _restore_environment_generation(
                stream,
                provider_stream,
                root,
                generations,
                package_root,
                protection,
                restoration,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert len(generations.files) == 11


def _record_runtime_available(
    stream: journal.JournalStreamIdentity,
    root: _Root,
    generations: _GenerationStorage,
    package_root: PathHierarchyTrust,
    protection: _Protection,
    availability: _RuntimeAvailability,
) -> storage.PersistedEnvironmentJournalChain:
    return package_root.run_while_held(
        lambda: recovery.persist_rollback_runtime_available_generation_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            journal_protection=protection,
            runtime_availability=availability,
        )
    )


def test_rollback_runtime_available_is_attested_and_selected_once() -> None:
    protection = _Protection()
    stream, _provider_stream, root, generations, package_root = (
        _persist_restored_environment_state(protection)
    )
    availability = _RuntimeAvailability(stream)
    try:
        result = _record_runtime_available(
            stream,
            root,
            generations,
            package_root,
            protection,
            availability,
        )
    finally:
        package_root.close()

    assert availability.calls == 1
    assert len(result.selection.generations) == 9
    assert (
        result.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    record = result.selection.tip.record
    assert type(record) is journal.RollbackRuntimeAvailableRecord
    assert (
        record.runtime_evidence_sha256 == availability.evidence.runtime_evidence_sha256
    )
    assert (
        record.volume_evidence_sha256s == availability.evidence.volume_evidence_sha256s
    )


def test_rollback_runtime_available_restart_reverifies_and_repairs_pointer() -> None:
    protection = _Protection()
    stream, _provider_stream, root, generations, package_root = (
        _persist_restored_environment_state(protection)
    )
    availability = _RuntimeAvailability(stream)
    try:
        first = _record_runtime_available(
            stream,
            root,
            generations,
            package_root,
            protection,
            availability,
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = _record_runtime_available(
            stream,
            root,
            generations,
            package_root,
            protection,
            availability,
        )
    finally:
        package_root.close()

    assert availability.calls == 2
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    assert (
        second.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )


def test_rollback_runtime_available_rejects_restart_evidence_drift() -> None:
    protection = _Protection()
    stream, _provider_stream, root, generations, package_root = (
        _persist_restored_environment_state(protection)
    )
    availability = _RuntimeAvailability(stream)
    try:
        _record_runtime_available(
            stream,
            root,
            generations,
            package_root,
            protection,
            availability,
        )
        generation_count = len(generations.files)
        availability.evidence = replace(
            availability.evidence,
            container_evidence_sha256="f" * 64,
        )
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _record_runtime_available(
                stream,
                root,
                generations,
                package_root,
                protection,
                availability,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert len(generations.files) == generation_count


def test_rollback_runtime_available_preserves_restored_tip_on_failure() -> None:
    protection = _Protection()
    stream, _provider_stream, root, generations, package_root = (
        _persist_restored_environment_state(protection)
    )
    availability = _RuntimeAvailability(stream)
    availability.error = OSError("private runtime detail")
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _record_runtime_available(
                stream,
                root,
                generations,
                package_root,
                protection,
                availability,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert "private" not in str(failure.value)
    assert len(generations.files) == 12


def _plan_certificate_restore(
    stream: journal.JournalStreamIdentity,
    root: _Root,
    generations: _GenerationStorage,
    blobs: _BlobStorage,
    protection: _Protection,
    names: _CertificateTempNameSource,
    *,
    backup_protection: _Protection | None = None,
) -> storage.PersistedEnvironmentJournalChain:
    return recovery.plan_persisted_certificate_restore(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        backup_protection=backup_protection or protection,
        journal_protection=protection,
        name_source=names,
    )


def test_certificate_restore_plan_authenticates_backup_and_selects_generation_10() -> (
    None
):
    protection = _Protection()
    stream, root, generations, blobs, package_root, _availability = (
        _persist_runtime_available_state(protection)
    )
    names = _CertificateTempNameSource()
    try:
        result = _plan_certificate_restore(
            stream,
            root,
            generations,
            blobs,
            protection,
            names,
        )
    finally:
        package_root.close()

    assert names.calls == 1
    assert len(result.selection.generations) == 10
    assert (
        result.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    record = result.selection.tip.record
    assert type(record) is journal.CertificateRestoreTempPlanRecord
    assert record.local_ca_present is True
    assert record.local_ca_size == len(b"private-local-ca")
    assert record.local_ca_mode == 0o644
    assert record.local_ca_temp_name == f"recovery-certificate-{1:032x}.tmp"
    assert record.ca_bundle_present is False
    assert record.ca_bundle_temp_name is None


def test_certificate_restore_plan_restart_repairs_pointer_without_new_name() -> None:
    protection = _Protection()
    stream, root, generations, blobs, package_root, _availability = (
        _persist_runtime_available_state(protection)
    )
    names = _CertificateTempNameSource()
    try:
        first = _plan_certificate_restore(
            stream,
            root,
            generations,
            blobs,
            protection,
            names,
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = _plan_certificate_restore(
            stream,
            root,
            generations,
            blobs,
            protection,
            names,
        )
    finally:
        package_root.close()

    assert names.calls == 1
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    assert (
        second.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )


def test_certificate_restore_plan_preserves_runtime_tip_on_backup_auth_failure() -> (
    None
):
    protection = _Protection()
    stream, root, generations, blobs, package_root, _availability = (
        _persist_runtime_available_state(protection)
    )
    names = _CertificateTempNameSource()
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _plan_certificate_restore(
                stream,
                root,
                generations,
                blobs,
                protection,
                names,
                backup_protection=_RejectingBackupProtection(),
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.BACKUP_INVALID
    assert names.calls == 0
    assert len(generations.files) == 13


def _persist_certificate_restore_plan_state(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    _BlobStorage,
    PathHierarchyTrust,
]:
    stream, root, generations, blobs, package_root, _availability = (
        _persist_runtime_available_state(protection)
    )
    _plan_certificate_restore(
        stream,
        root,
        generations,
        blobs,
        protection,
        _CertificateTempNameSource(),
    )
    return stream, root, generations, blobs, package_root


def test_certificate_restore_temps_record_exact_identities_and_reverify() -> None:
    protection = _Protection()
    stream, root, generations, _blobs, package_root = (
        _persist_certificate_restore_plan_state(protection)
    )
    certificate_storage = _CertificateStorage(root)
    try:
        first = recovery.create_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            certificate_storage=certificate_storage,
            journal_protection=protection,
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = recovery.create_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            certificate_storage=certificate_storage,
            journal_protection=protection,
        )
    finally:
        package_root.close()

    assert len(certificate_storage.created) == 1
    assert len(certificate_storage.verified) == 1
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    record = second.selection.tip.record
    assert type(record) is journal.CertificateRestoreTempCreatedRecord
    assert record.local_ca_temp_identity == certificate_storage.identities.local_ca
    assert record.ca_bundle_temp_identity is None


def test_certificate_restore_temp_restart_rejects_identity_drift() -> None:
    protection = _Protection()
    stream, root, generations, _blobs, package_root = (
        _persist_certificate_restore_plan_state(protection)
    )
    certificate_storage = _CertificateStorage(root)
    try:
        recovery.create_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            certificate_storage=certificate_storage,
            journal_protection=protection,
        )
        generation_count = len(generations.files)
        certificate_storage.verification_override = CertificateRestoreTempIdentities(
            _identity(62),
            None,
        )
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            recovery.create_persisted_certificate_restore_temps(
                stream=stream,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                certificate_storage=certificate_storage,
                journal_protection=protection,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert len(generations.files) == generation_count


def test_certificate_restore_temps_write_exact_backup_and_reverify() -> None:
    protection = _Protection()
    stream, root, generations, blobs, package_root = (
        _persist_certificate_restore_plan_state(protection)
    )
    certificate_storage = _CertificateStorage(root)
    try:
        recovery.create_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            certificate_storage=certificate_storage,
            journal_protection=protection,
        )
        first = recovery.write_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            backup_storage=blobs,
            certificate_storage=certificate_storage,
            backup_protection=protection,
            journal_protection=protection,
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = recovery.write_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            backup_storage=blobs,
            certificate_storage=certificate_storage,
            backup_protection=protection,
            journal_protection=protection,
        )
    finally:
        package_root.close()

    assert certificate_storage.written == [(b"private-local-ca", None)]
    assert len(certificate_storage.written_verified) == 1
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    assert (
        second.selection.tip.state
        is journal.EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_VERIFIED
    )


def test_certificate_restore_temp_write_failure_keeps_created_tip() -> None:
    protection = _Protection()
    stream, root, generations, blobs, package_root = (
        _persist_certificate_restore_plan_state(protection)
    )
    certificate_storage = _CertificateStorage(root)
    certificate_storage.write_error = RecoveryCertificateStorageError(
        RecoveryCertificateStorageErrorCode.WRITE_FAILED
    )
    try:
        recovery.create_persisted_certificate_restore_temps(
            stream=stream,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            certificate_storage=certificate_storage,
            journal_protection=protection,
        )
        generation_count = len(generations.files)
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            recovery.write_persisted_certificate_restore_temps(
                stream=stream,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                backup_storage=blobs,
                certificate_storage=certificate_storage,
                backup_protection=protection,
                journal_protection=protection,
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.WRITE_FAILED
    assert len(generations.files) == generation_count


def _persist_certificate_temps_verified_state(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    PathHierarchyTrust,
]:
    stream, root, generations, blobs, package_root = (
        _persist_certificate_restore_plan_state(protection)
    )
    certificate_storage = _CertificateStorage(root)
    recovery.create_persisted_certificate_restore_temps(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        certificate_storage=certificate_storage,
        journal_protection=protection,
    )
    recovery.write_persisted_certificate_restore_temps(
        stream=stream,
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_storage=blobs,
        certificate_storage=certificate_storage,
        backup_protection=protection,
        journal_protection=protection,
    )
    return stream, root, generations, package_root


def _persist_certificates_restored_state(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    PathHierarchyTrust,
    _CertificateRestoration,
]:
    stream, root, generations, package_root = _persist_certificate_temps_verified_state(
        protection
    )
    restoration = _CertificateRestoration(stream, _RuntimeAvailability(stream))
    package_root.run_while_held(
        lambda: recovery.persist_certificates_restored_generation_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            restoration=restoration,
            journal_protection=protection,
        )
    )
    return stream, root, generations, package_root, restoration


def test_certificates_restored_reverifies_exact_runtime_and_destinations() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_certificate_temps_verified_state(
        protection
    )
    restoration = _CertificateRestoration(stream, _RuntimeAvailability(stream))
    try:
        first = package_root.run_while_held(
            lambda: recovery.persist_certificates_restored_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                restoration=restoration,
                journal_protection=protection,
            )
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = package_root.run_while_held(
            lambda: recovery.persist_certificates_restored_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                restoration=restoration,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert restoration.calls == 2
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    assert (
        second.selection.tip.state
        is journal.EnvironmentJournalState.CERTIFICATES_RESTORED
    )


def test_certificates_restored_rejects_destination_evidence_drift() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_certificate_temps_verified_state(
        protection
    )
    restoration = _CertificateRestoration(stream, _RuntimeAvailability(stream))
    restoration.evidence = replace(
        restoration.evidence,
        local_ca=replace(restoration.evidence.local_ca, mode=0o600),
    )
    generation_count = len(generations.files)
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: recovery.persist_certificates_restored_generation_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    restoration=restoration,
                    journal_protection=protection,
                )
            )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert len(generations.files) == generation_count


def _persist_runtime_restart_intent_state(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    PathHierarchyTrust,
]:
    stream, root, generations, package_root, _restoration = (
        _persist_certificates_restored_state(protection)
    )
    package_root.run_while_held(
        lambda: recovery.persist_rollback_runtime_restarting_generation_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            journal_protection=protection,
        )
    )
    return stream, root, generations, package_root


def test_runtime_restart_is_write_ahead_and_reverified_without_second_restart() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_runtime_restart_intent_state(
        protection
    )
    restart = _RuntimeRestart(stream)
    try:
        first = package_root.run_while_held(
            lambda: recovery.persist_rollback_runtime_restarted_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                restart=restart,
                journal_protection=protection,
            )
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = package_root.run_while_held(
            lambda: recovery.persist_rollback_runtime_restarted_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                restart=restart,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert restart.restart_calls == 1
    assert restart.verify_calls == 1
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip


def test_terminal_rollback_verification_requires_every_exact_local_condition() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_runtime_restart_intent_state(
        protection
    )
    restart = _RuntimeRestart(stream)
    try:
        package_root.run_while_held(
            lambda: recovery.persist_rollback_runtime_restarted_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                restart=restart,
                journal_protection=protection,
            )
        )
        package_root.run_while_held(
            lambda: recovery.persist_rollback_verifying_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                journal_protection=protection,
            )
        )
        verification = _RollbackVerification(stream, restart)
        verification.evidence = replace(
            verification.evidence,
            certificates_exact=False,
        )
        generation_count = len(generations.files)
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: recovery.persist_rollback_verified_generation_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    verification=verification,
                    journal_protection=protection,
                )
            )
        verification.evidence = replace(
            verification.evidence,
            certificates_exact=True,
        )
        terminal = package_root.run_while_held(
            lambda: recovery.persist_rollback_verified_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                verification=verification,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert len(generations.files) == generation_count + 1
    assert (
        terminal.selection.tip.state
        is journal.EnvironmentJournalState.ROLLBACK_VERIFIED
    )


def _persist_rollback_verified_state(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    _Root,
    _GenerationStorage,
    PathHierarchyTrust,
]:
    stream, root, generations, package_root = _persist_runtime_restart_intent_state(
        protection
    )
    restart = _RuntimeRestart(stream)
    package_root.run_while_held(
        lambda: recovery.persist_rollback_runtime_restarted_generation_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            restart=restart,
            journal_protection=protection,
        )
    )
    package_root.run_while_held(
        lambda: recovery.persist_rollback_verifying_generation_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            journal_protection=protection,
        )
    )
    package_root.run_while_held(
        lambda: recovery.persist_rollback_verified_generation_from_held_package_root(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            verification=_RollbackVerification(stream, restart),
            journal_protection=protection,
        )
    )
    return stream, root, generations, package_root


def test_recovery_cleanup_success_is_durable_and_reverified() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    cleanup = _RecoveryCleanup(stream)
    try:
        first = package_root.run_while_held(
            lambda: recovery.persist_recovery_cleaned_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                cleanup=cleanup,
                journal_protection=protection,
            )
        )
        generation_count = len(generations.files)
        generations.pointer = None
        second = package_root.run_while_held(
            lambda: recovery.persist_recovery_cleaned_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                cleanup=cleanup,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert cleanup.cleanup_calls == 1
    assert cleanup.verify_calls == 1
    assert len(generations.files) == generation_count
    assert first.selection.tip == second.selection.tip
    assert second.selection.tip.state is journal.EnvironmentJournalState.CLEANED


def test_recovery_cleanup_failure_persists_pending_then_retries_exactly() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    cleanup = _RecoveryCleanup(stream)
    cleanup.fail = True
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: recovery.persist_recovery_cleaned_generation_from_held_package_root(
                    stream=stream,
                    package_root=package_root,
                    root=root,
                    journal_storage=generations,
                    pointer_storage=generations,
                    cleanup=cleanup,
                    journal_protection=protection,
                )
            )
        pending_count = len(generations.files)
        cleanup.fail = False
        cleaned = package_root.run_while_held(
            lambda: recovery.persist_recovery_cleaned_generation_from_held_package_root(
                stream=stream,
                package_root=package_root,
                root=root,
                journal_storage=generations,
                pointer_storage=generations,
                cleanup=cleanup,
                journal_protection=protection,
            )
        )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.CLEANUP_PENDING
    assert "private" not in str(failure.value)
    assert len(generations.files) == pending_count + 1
    assert cleanup.cleanup_calls == 2
    assert cleaned.selection.tip.state is journal.EnvironmentJournalState.CLEANED
    assert len(cleaned.selection.generations) == 19


def test_fresh_process_manager_resumes_verified_environment_through_cleanup() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        blobs,
        package_root,
        environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    initial = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=generations,
        pointer_storage=generations,
        protection=protection,
    )
    assert initial is not None
    availability = _RuntimeAvailability(stream)
    certificate_storage = _CertificateStorage(root)
    restart = _RuntimeRestart(stream)
    cleanup = _RecoveryCleanup(stream)
    ports = manager.WindowsRecoveryManagerPorts(
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_verification=blobs,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        environment_name_source=_EnvironmentTempNameSource(),
        environment_storage=environment_storage,
        environment_restoration=_EnvironmentRestoration(),
        runtime_availability=availability,
        certificate_name_source=_CertificateTempNameSource(),
        certificate_storage=certificate_storage,
        certificate_restoration=_CertificateRestoration(stream, availability),
        runtime_restart=restart,
        rollback_verification=_RollbackVerification(stream, restart),
        cleanup=cleanup,
    )
    try:
        result = package_root.run_while_held(
            lambda: manager.resume_persisted_rollback_from_held_package_root(
                stream=stream,
                provider_stream=provider_stream,
                package_root=package_root,
                initial_chain=initial,
                ports=ports,
            )
        )
        reverified = package_root.run_while_held(
            lambda: manager.resume_persisted_rollback_from_held_package_root(
                stream=stream,
                provider_stream=provider_stream,
                package_root=package_root,
                initial_chain=result,
                ports=ports,
            )
        )
    finally:
        package_root.close()

    assert result.selection.tip.state is journal.EnvironmentJournalState.CLEANED
    assert len(result.selection.generations) == 18
    assert reverified.selection.tip == result.selection.tip
    assert availability.calls == 1
    assert restart.restart_calls == 1
    assert restart.verify_calls == 0
    assert cleanup.cleanup_calls == 1
    assert cleanup.verify_calls == 1


def test_fresh_process_manager_resumes_armed_rollback_through_cleanup() -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        blobs,
        package_root,
        environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    recovery_prefix = f"journal-{stream.journal_id}-"
    for name in tuple(generations.files):
        if name.startswith(recovery_prefix) and int(name[-31:-11]) > 3:
            del generations.files[name]
    generations.pointer = None
    initial = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=generations,
        pointer_storage=generations,
        protection=protection,
    )
    assert initial is not None
    assert initial.selection.tip.state is journal.EnvironmentJournalState.ROLLBACK_ARMED
    availability = _RuntimeAvailability(stream)
    certificate_storage = _CertificateStorage(root)
    restart = _RuntimeRestart(stream)
    ports = manager.WindowsRecoveryManagerPorts(
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_verification=blobs,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        environment_name_source=_EnvironmentTempNameSource(),
        environment_storage=environment_storage,
        environment_restoration=_EnvironmentRestoration(),
        runtime_availability=availability,
        certificate_name_source=_CertificateTempNameSource(),
        certificate_storage=certificate_storage,
        certificate_restoration=_CertificateRestoration(stream, availability),
        runtime_restart=restart,
        rollback_verification=_RollbackVerification(stream, restart),
        cleanup=_RecoveryCleanup(stream),
    )
    try:
        result = package_root.run_while_held(
            lambda: manager.resume_persisted_rollback_from_held_package_root(
                stream=stream,
                provider_stream=provider_stream,
                package_root=package_root,
                initial_chain=initial,
                ports=ports,
            )
        )
    finally:
        package_root.close()

    assert result.selection.tip.state is journal.EnvironmentJournalState.CLEANED
    assert len(result.selection.generations) == 18


@pytest.mark.parametrize(
    ("sequence", "operation_name"),
    (
        (7, "persist_environment_restored_generation_from_held_package_root"),
        (8, "persist_rollback_runtime_available_generation_from_held_package_root"),
        (9, "plan_persisted_certificate_restore"),
        (10, "create_persisted_certificate_restore_temps"),
        (11, "write_persisted_certificate_restore_temps"),
        (12, "persist_certificates_restored_generation_from_held_package_root"),
        (13, "persist_rollback_runtime_restarting_generation_from_held_package_root"),
        (14, "persist_rollback_runtime_restarted_generation_from_held_package_root"),
        (15, "persist_rollback_verifying_generation_from_held_package_root"),
        (16, "persist_rollback_verified_generation_from_held_package_root"),
        (17, "persist_recovery_cleaned_generation_from_held_package_root"),
    ),
)
def test_fresh_process_manager_resumes_each_post_environment_boundary(
    monkeypatch: pytest.MonkeyPatch,
    sequence: int,
    operation_name: str,
) -> None:
    protection = _Protection()
    (
        stream,
        provider_stream,
        root,
        generations,
        blobs,
        package_root,
        environment_storage,
    ) = _persist_verified_environment_restore_state(protection)
    initial = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=generations,
        pointer_storage=generations,
        protection=protection,
    )
    assert initial is not None
    availability = _RuntimeAvailability(stream)
    certificate_storage = _CertificateStorage(root)
    restart = _RuntimeRestart(stream)
    cleanup = _RecoveryCleanup(stream)
    ports = manager.WindowsRecoveryManagerPorts(
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_verification=blobs,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        environment_name_source=_EnvironmentTempNameSource(),
        environment_storage=environment_storage,
        environment_restoration=_EnvironmentRestoration(),
        runtime_availability=availability,
        certificate_name_source=_CertificateTempNameSource(),
        certificate_storage=certificate_storage,
        certificate_restoration=_CertificateRestoration(stream, availability),
        runtime_restart=restart,
        rollback_verification=_RollbackVerification(stream, restart),
        cleanup=cleanup,
    )
    original = getattr(manager, operation_name)

    def interrupt(**_kwargs: object) -> storage.PersistedEnvironmentJournalChain:
        raise RuntimeError("simulated abrupt process termination")

    monkeypatch.setattr(manager, operation_name, interrupt)
    try:
        with pytest.raises(RuntimeError, match="abrupt process termination"):
            package_root.run_while_held(
                lambda: manager.resume_persisted_rollback_from_held_package_root(
                    stream=stream,
                    provider_stream=provider_stream,
                    package_root=package_root,
                    initial_chain=initial,
                    ports=ports,
                )
            )
        interrupted = storage.load_persisted_environment_journal_chain_with_pointer(
            stream,
            root=root,
            generation_storage=generations,
            pointer_storage=generations,
            protection=protection,
        )
        assert interrupted is not None
        assert interrupted.selection.tip.sequence == sequence
        monkeypatch.setattr(manager, operation_name, original)
        completed = package_root.run_while_held(
            lambda: manager.resume_persisted_rollback_from_held_package_root(
                stream=stream,
                provider_stream=provider_stream,
                package_root=package_root,
                initial_chain=interrupted,
                ports=ports,
            )
        )
    finally:
        package_root.close()

    assert completed.selection.tip.state is journal.EnvironmentJournalState.CLEANED


def test_fresh_process_manager_retries_durable_cleanup_pending_state() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    initial = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=generations,
        pointer_storage=generations,
        protection=protection,
    )
    assert initial is not None
    provider_stream = journal.JournalStreamIdentity(
        1,
        "c" * 32,
        stream.target_token_sha256,
        stream.package_root_identity,
    )
    availability = _RuntimeAvailability(stream)
    restart = _RuntimeRestart(stream)
    cleanup = _RecoveryCleanup(stream)
    cleanup.fail = True
    blobs = _BlobStorage(root)
    ports = manager.WindowsRecoveryManagerPorts(
        root=root,
        journal_storage=generations,
        pointer_storage=generations,
        backup_verification=blobs,
        backup_storage=blobs,
        backup_protection=protection,
        journal_protection=protection,
        environment_name_source=_EnvironmentTempNameSource(),
        environment_storage=_EnvironmentStorage(),
        environment_restoration=_EnvironmentRestoration(),
        runtime_availability=availability,
        certificate_name_source=_CertificateTempNameSource(),
        certificate_storage=_CertificateStorage(root),
        certificate_restoration=_CertificateRestoration(stream, availability),
        runtime_restart=restart,
        rollback_verification=_RollbackVerification(stream, restart),
        cleanup=cleanup,
    )
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            package_root.run_while_held(
                lambda: manager.resume_persisted_rollback_from_held_package_root(
                    stream=stream,
                    provider_stream=provider_stream,
                    package_root=package_root,
                    initial_chain=initial,
                    ports=ports,
                )
            )
        pending = storage.load_persisted_environment_journal_chain_with_pointer(
            stream,
            root=root,
            generation_storage=generations,
            pointer_storage=generations,
            protection=protection,
        )
        assert pending is not None
        cleanup.fail = False
        completed = package_root.run_while_held(
            lambda: manager.resume_persisted_rollback_from_held_package_root(
                stream=stream,
                provider_stream=provider_stream,
                package_root=package_root,
                initial_chain=pending,
                ports=ports,
            )
        )
    finally:
        package_root.close()

    assert failure.value.code is recovery.WindowsRecoveryErrorCode.CLEANUP_PENDING
    assert pending.selection.tip.state is (
        journal.EnvironmentJournalState.RECOVERY_CLEANUP_PENDING
    )
    assert completed.selection.tip.state is journal.EnvironmentJournalState.CLEANED
    assert len(completed.selection.generations) == 19


class _NativeCleanupHandle:
    def __init__(self, path: str) -> None:
        self.path = path
        self.cursor = 0


class _NativeCleanupApi:
    supported = True

    def __init__(
        self,
        files: dict[str, tuple[StableFileIdentity, bytes]],
    ) -> None:
        self.files = files
        self.events: list[str] = []
        self.delete_error_path: str | None = None
        self.delete_error_after_mark_path: str | None = None
        self.security_overrides: dict[str, NativeSecurityFacts] = {}
        self.path_overrides: dict[str, str] = {}

    def current_user_sid(self) -> str:
        self.events.append("sid")
        return "S-1-5-21-1000"

    def open_file_for_delete_if_exists(
        self,
        path: str,
    ) -> _NativeCleanupHandle | None:
        self.events.append(f"delete-open:{path}")
        return _NativeCleanupHandle(path) if path in self.files else None

    def reopen_file_if_exists(self, path: str) -> _NativeCleanupHandle | None:
        self.events.append(f"optional:{path}")
        return _NativeCleanupHandle(path) if path in self.files else None

    def query_file(self, handle: object) -> NativeFileFacts:
        assert type(handle) is _NativeCleanupHandle
        identity, contents = self.files[handle.path]
        self.events.append(f"query:{handle.path}")
        return NativeFileFacts(
            self.path_overrides.get(handle.path, handle.path),
            identity.volume_serial,
            identity.file_id,
            0x80,
            1,
            len(contents),
            1,
            1,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert type(handle) is _NativeCleanupHandle
        self.events.append(f"security:{handle.path}")
        return self.security_overrides.get(
            handle.path,
            NativeSecurityFacts(
                "S-1-5-21-1000",
                True,
                (
                    AccessAllowedAce("S-1-5-21-1000", 0x001F01FF, 0),
                    AccessAllowedAce("S-1-5-18", 0x001F01FF, 0),
                ),
                dacl_protected=True,
            ),
        )

    def seek_file(self, handle: object, offset: int) -> None:
        assert type(handle) is _NativeCleanupHandle
        handle.cursor = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert type(handle) is _NativeCleanupHandle
        contents = self.files[handle.path][1]
        result = contents[handle.cursor : handle.cursor + maximum]
        handle.cursor += len(result)
        return result

    def mark_file_for_deletion(self, handle: object) -> None:
        assert type(handle) is _NativeCleanupHandle
        self.events.append(f"delete:{handle.path}")
        if self.delete_error_path == handle.path:
            raise OSError("private recovery artifact path")
        del self.files[handle.path]
        if self.delete_error_after_mark_path == handle.path:
            raise OSError("private recovery artifact path")

    def close_handle(self, handle: object) -> None:
        assert type(handle) is _NativeCleanupHandle
        self.events.append(f"close:{handle.path}")


def _recovery_chain(
    stream: journal.JournalStreamIdentity,
    root: _Root,
    generations: _GenerationStorage,
    protection: _Protection,
) -> storage.PersistedEnvironmentJournalChain:
    chain = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=generations,
        pointer_storage=generations,
        protection=protection,
    )
    assert chain is not None
    return chain


def _native_cleanup_files(
    chain: storage.PersistedEnvironmentJournalChain,
    protection: _Protection,
) -> tuple[
    dict[str, tuple[StableFileIdentity, bytes]],
    dict[str, str],
]:
    generations = chain.selection.generations
    preparing = generations[0].record
    verified_backups = generations[1].record
    environment_plan = generations[4].record
    environment_verified = generations[6].record
    certificate_plan = generations[9].record
    certificate_verified = generations[11].record
    assert type(preparing) is journal.BackupPreparingRecord
    assert type(verified_backups) is journal.BackupVerifiedRecord
    assert type(environment_plan) is journal.EnvironmentRestoreTempPlanRecord
    environment_verified_type = journal.EnvironmentRestoreTempVerifiedRecord
    assert type(environment_verified) is environment_verified_type
    assert type(certificate_plan) is journal.CertificateRestoreTempPlanRecord
    certificate_verified_type = journal.CertificateRestoreTempVerifiedRecord
    assert type(certificate_verified) is certificate_verified_type

    _stream_value, environment, certificates = _sealed_backups(protection)
    protected_root = r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1"
    package_root = r"C:\Users\reviewed-user\TowerScout"
    paths = {
        "environment_backup": ntpath.join(
            protected_root,
            preparing.environment_backup_name,
        ),
        "certificate_backup": ntpath.join(
            protected_root,
            preparing.certificate_backup_name,
        ),
    }
    files = {
        paths["environment_backup"]: (
            verified_backups.environment_backup_identity,
            environment.protected_blob.ciphertext,
        ),
        paths["certificate_backup"]: (
            verified_backups.certificate_backup_identity,
            certificates.protected_blob.ciphertext,
        ),
    }
    if environment_plan.environment_present:
        assert environment_plan.temp_name is not None
        assert environment_verified.temp_identity is not None
        paths["environment_temp"] = ntpath.join(
            package_root,
            environment_plan.temp_name,
        )
        files[paths["environment_temp"]] = (
            environment_verified.temp_identity,
            b"GOOGLE_API_KEY=private-value\r\n",
        )
    if certificate_plan.local_ca_present:
        assert certificate_plan.local_ca_temp_name is not None
        assert certificate_verified.local_ca_temp_identity is not None
        paths["local_ca_temp"] = ntpath.join(
            protected_root,
            certificate_plan.local_ca_temp_name,
        )
        files[paths["local_ca_temp"]] = (
            certificate_verified.local_ca_temp_identity,
            b"private-local-ca",
        )
    return files, paths


def _persist_native_cleanup(
    stream: journal.JournalStreamIdentity,
    root: _Root,
    generations: _GenerationStorage,
    package_root: PathHierarchyTrust,
    protection: _Protection,
    cleanup: cleanup_native.NativeWindowsRecoveryCleanup,
) -> storage.PersistedEnvironmentJournalChain:
    persist_cleaned = (
        recovery.persist_recovery_cleaned_generation_from_held_package_root
    )
    return package_root.run_while_held(
        lambda: persist_cleaned(
            stream=stream,
            package_root=package_root,
            root=root,
            journal_storage=generations,
            pointer_storage=generations,
            cleanup=cleanup,
            journal_protection=protection,
        )
    )


def test_native_cleanup_deletes_exact_artifacts_and_reverifies() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    chain = _recovery_chain(stream, root, generations, protection)
    files, paths = _native_cleanup_files(chain, protection)
    api = _NativeCleanupApi(files)
    cleanup = cleanup_native.NativeWindowsRecoveryCleanup(api=api)
    try:
        first = _persist_native_cleanup(
            stream,
            root,
            generations,
            package_root,
            protection,
            cleanup,
        )
        cleanup_error = cleanup_native.RecoveryCleanupStorageError
        run = cleanup.cleanup_rollback_artifacts_while_package_root_held
        with pytest.raises(cleanup_error) as denied:
            package_root.run_while_held(
                lambda: run(
                    package_root,
                    r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
                    stream,
                    first,
                )
            )
        second = _persist_native_cleanup(
            stream,
            root,
            generations,
            package_root,
            protection,
            cleanup,
        )
    finally:
        package_root.close()

    assert api.files == {}
    assert denied.value.code is (
        cleanup_native.RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID
    )
    assert first.selection.tip == second.selection.tip
    cleaned_state = journal.EnvironmentJournalState.CLEANED
    assert second.selection.tip.state is cleaned_state
    assert len(second.selection.generations) == 18
    assert {event for event in api.events if event.startswith("delete:")} == {
        f"delete:{path}" for path in paths.values()
    }
    for path in paths.values():
        assert api.events.count(f"query:{path}") == 2
        assert api.events.count(f"security:{path}") == 2


def test_native_cleanup_partial_failure_persists_then_resumes() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    chain = _recovery_chain(stream, root, generations, protection)
    files, paths = _native_cleanup_files(chain, protection)
    api = _NativeCleanupApi(files)
    api.delete_error_path = paths["local_ca_temp"]
    cleanup = cleanup_native.NativeWindowsRecoveryCleanup(api=api)
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _persist_native_cleanup(
                stream,
                root,
                generations,
                package_root,
                protection,
                cleanup,
            )
        pending = _recovery_chain(stream, root, generations, protection)
        assert paths["environment_temp"] not in api.files
        assert paths["local_ca_temp"] in api.files
        api.delete_error_path = None
        cleaned = _persist_native_cleanup(
            stream,
            root,
            generations,
            package_root,
            protection,
            cleanup,
        )
    finally:
        package_root.close()

    expected_error = recovery.WindowsRecoveryErrorCode.CLEANUP_PENDING
    assert failure.value.code is expected_error
    assert "private" not in str(failure.value)
    assert pending.selection.tip.state is (
        journal.EnvironmentJournalState.RECOVERY_CLEANUP_PENDING
    )
    assert len(cleaned.selection.generations) == 19
    cleaned_state = journal.EnvironmentJournalState.CLEANED
    assert cleaned.selection.tip.state is cleaned_state
    assert api.files == {}


@pytest.mark.parametrize(
    "failure_mode",
    ("contents", "identity", "path", "security"),
)
def test_native_cleanup_preserves_ambiguous_artifact_and_never_claims_clean(
    failure_mode: str,
) -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    chain = _recovery_chain(stream, root, generations, protection)
    files, paths = _native_cleanup_files(chain, protection)
    backup_path = paths["environment_backup"]
    identity, contents = files[backup_path]
    if failure_mode == "contents":
        files[backup_path] = (identity, b"x" * len(contents))
    elif failure_mode == "identity":
        files[backup_path] = (_identity(99), contents)
    api = _NativeCleanupApi(files)
    if failure_mode == "path":
        api.path_overrides[backup_path] = ntpath.join(
            ntpath.dirname(backup_path),
            "unrelated.blob",
        )
    elif failure_mode == "security":
        api.security_overrides[backup_path] = NativeSecurityFacts(
            "S-1-5-21-1000",
            True,
            (AccessAllowedAce("S-1-5-21-1000", 0x001F01FF, 0),),
            dacl_protected=True,
        )
    cleanup = cleanup_native.NativeWindowsRecoveryCleanup(api=api)
    try:
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _persist_native_cleanup(
                stream,
                root,
                generations,
                package_root,
                protection,
                cleanup,
            )
        pending = _recovery_chain(stream, root, generations, protection)
    finally:
        package_root.close()

    expected_error = recovery.WindowsRecoveryErrorCode.CLEANUP_PENDING
    assert failure.value.code is expected_error
    assert pending.selection.tip.state is (
        journal.EnvironmentJournalState.RECOVERY_CLEANUP_PENDING
    )
    assert backup_path in api.files
    assert f"delete:{backup_path}" not in api.events


def test_native_cleanup_reconciles_error_after_exact_absence() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    chain = _recovery_chain(stream, root, generations, protection)
    files, paths = _native_cleanup_files(chain, protection)
    api = _NativeCleanupApi(files)
    api.delete_error_after_mark_path = paths["certificate_backup"]
    cleanup = cleanup_native.NativeWindowsRecoveryCleanup(api=api)
    try:
        cleaned = _persist_native_cleanup(
            stream,
            root,
            generations,
            package_root,
            protection,
            cleanup,
        )
    finally:
        package_root.close()

    cleaned_state = journal.EnvironmentJournalState.CLEANED
    assert cleaned.selection.tip.state is cleaned_state
    assert api.files == {}


def test_native_cleanup_reverify_preserves_recreated_name() -> None:
    protection = _Protection()
    stream, root, generations, package_root = _persist_rollback_verified_state(
        protection
    )
    chain = _recovery_chain(stream, root, generations, protection)
    files, paths = _native_cleanup_files(chain, protection)
    original_files = dict(files)
    api = _NativeCleanupApi(files)
    cleanup = cleanup_native.NativeWindowsRecoveryCleanup(api=api)
    try:
        _persist_native_cleanup(
            stream,
            root,
            generations,
            package_root,
            protection,
            cleanup,
        )
        recreated_path = paths["environment_backup"]
        _identity_value, contents = original_files[recreated_path]
        api.files[recreated_path] = (_identity(99), contents)
        with pytest.raises(recovery.WindowsRecoveryError) as failure:
            _persist_native_cleanup(
                stream,
                root,
                generations,
                package_root,
                protection,
                cleanup,
            )
    finally:
        package_root.close()

    expected_error = recovery.WindowsRecoveryErrorCode.VERIFY_FAILED
    assert failure.value.code is expected_error
    assert recreated_path in api.files
    assert api.events.count(f"delete:{recreated_path}") == 1
