"""Fresh-process planning for authenticated Windows rollback.

This Gate-A layer may reverify the exact encrypted backups, restore the exact
package environment authorized by a matching applied provider journal, attest
that the prior runtime is available, and plan protected certificate staging.
It cannot yet restore certificates, clean completed transaction artifacts, or
mutate a runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Callable, NoReturn, Protocol, TypeVar, cast

from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_environment_replacement_native import (
    EnvironmentAppliedRecord,
    EnvironmentTempPlanRecord,
)
from .windows_recovery_backup import (
    BackupProtectionPort,
    CertificateExactStateBackup,
    EnvironmentExactStateBackup,
    RecoveryBackupError,
    SealedCertificateExactStateBackup,
    SealedEnvironmentExactStateBackup,
    authenticate_certificate_exact_state_backup,
    authenticate_environment_exact_state_backup,
)
from .windows_recovery_backup_storage import (
    RecoveryBackupBlobReadPort,
    RecoveryBackupBlobVerificationPort,
    RecoveryBackupStorageError,
    RecoveryBackupStorageErrorCode,
    StoredRecoveryBackupBlob,
)
from .windows_recovery_certificate_storage import (
    CertificateRestoreTempIdentities,
    CertificateRestoreTempStoragePort,
    RecoveryCertificateStorageError,
    RecoveryCertificateStorageErrorCode,
)
from .windows_recovery_environment_storage import (
    EnvironmentRestoreTempStoragePort,
    RecoveryEnvironmentStorageError,
    RecoveryEnvironmentStorageErrorCode,
)
from .windows_recovery_environment_restore import (
    EnvironmentDestinationObservation,
    EnvironmentRestoreAction,
    EnvironmentRestoreAuthority,
    decide_environment_restore,
)
from .windows_recovery_environment_restore_native import (
    EnvironmentRestoreStorageAuthority,
    EnvironmentRestoreStorageError,
    EnvironmentRestoreStorageErrorCode,
)
from .windows_recovery_journal import (
    BackupPreparingRecord,
    BackupVerifiedRecord,
    CertificateRestoreTempCreatedRecord,
    CertificateRestoreTempPlanRecord,
    CertificateRestoreTempVerifiedRecord,
    CertificatesRestoredRecord,
    EnvironmentJournalGeneration,
    EnvironmentJournalRecord,
    EnvironmentJournalState,
    EnvironmentRestoreTempCreatedRecord,
    EnvironmentRestoreTempPlanRecord,
    EnvironmentRestoreTempVerifiedRecord,
    EnvironmentRestoredRecord,
    JournalPointerDisposition,
    JournalProtectionPort,
    JournalStreamIdentity,
    RecoveryCleanedRecord,
    RecoveryCleanupPendingRecord,
    RecoveryJournalError,
    RollbackArmedRecord,
    RollbackProviderOutcome,
    RollbackRuntimeAvailableRecord,
    RollbackRuntimeRestartedRecord,
    RollbackRuntimeRestartingRecord,
    RollbackStartedRecord,
    RollbackVerifiedRecord,
    RollbackVerifyingRecord,
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
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_security import StableFileIdentity, WindowsSecurityError

_Result = TypeVar("_Result")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class WindowsRecoveryErrorCode(str, Enum):
    INPUT_INVALID = "windows_recovery_input_invalid"
    AUTHORITY_INVALID = "windows_recovery_authority_invalid"
    STORAGE_UNAVAILABLE = "windows_recovery_storage_unavailable"
    BACKUP_INVALID = "windows_recovery_backup_invalid"
    WRITE_FAILED = "windows_recovery_write_failed"
    VERIFY_FAILED = "windows_recovery_verify_failed"
    CLEANUP_PENDING = "windows_recovery_cleanup_pending"


class WindowsRecoveryError(RuntimeError):
    """Sanitized failure at the fresh-process recovery boundary."""

    _MESSAGES = {
        WindowsRecoveryErrorCode.INPUT_INVALID: (
            "The Windows recovery request is invalid."
        ),
        WindowsRecoveryErrorCode.AUTHORITY_INVALID: (
            "The Windows recovery authority is invalid."
        ),
        WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE: (
            "Protected Windows recovery storage is unavailable."
        ),
        WindowsRecoveryErrorCode.BACKUP_INVALID: (
            "A protected Windows recovery backup is invalid."
        ),
        WindowsRecoveryErrorCode.WRITE_FAILED: (
            "Windows recovery state could not be written durably."
        ),
        WindowsRecoveryErrorCode.VERIFY_FAILED: (
            "Windows recovery state could not be verified durably."
        ),
        WindowsRecoveryErrorCode.CLEANUP_PENDING: (
            "Windows recovery is verified, but protected cleanup remains pending."
        ),
    }

    def __init__(self, code: WindowsRecoveryErrorCode) -> None:
        if type(code) is not WindowsRecoveryErrorCode:
            raise ValueError("Unknown Windows recovery error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"WindowsRecoveryError(code={self.code.value!r})"


def _fail(code: WindowsRecoveryErrorCode) -> NoReturn:
    raise WindowsRecoveryError(code)


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
            raise TypeError("Protected recovery root is unavailable.")
        return run(operation)
    except WindowsRecoveryError:
        raise
    except Exception:
        _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)


def _load_chain(
    root_path: str,
    stream: JournalStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    try:
        chain = load_persisted_environment_journal_chain_from_held_root(
            root_path,
            stream,
            storage=storage,
            protection=protection,
        )
    except RecoveryJournalStorageError as exc:
        if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    except RecoveryJournalError:
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    if type(chain) is not PersistedEnvironmentJournalChain:
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    return chain


def _recovery_records(
    chain: PersistedEnvironmentJournalChain,
) -> tuple[BackupPreparingRecord, RollbackArmedRecord]:
    generations = chain.selection.generations
    if (
        len(generations)
        not in {
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
        }
        or type(generations[0].record) is not BackupPreparingRecord
        or generations[1].state is not EnvironmentJournalState.BACKUP_VERIFIED
        or type(generations[1].record) is not BackupVerifiedRecord
        or generations[2].state is not EnvironmentJournalState.ROLLBACK_ARMED
        or type(generations[2].record) is not RollbackArmedRecord
        or (
            len(generations) == 3
            and chain.selection.tip.state is not EnvironmentJournalState.ROLLBACK_ARMED
        )
        or (
            len(generations) == 4
            and chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_STARTED
        )
        or (
            len(generations) == 5
            and chain.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED
        )
        or (
            len(generations) == 6
            and chain.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED
        )
        or (
            len(generations) == 7
            and chain.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED
        )
        or (
            len(generations) == 8
            and chain.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORED
        )
        or (
            len(generations) == 9
            and chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE
        )
        or (
            len(generations) == 10
            and chain.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_PLANNED
        )
        or (
            len(generations) == 11
            and chain.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_CREATED
        )
        or (
            len(generations) == 12
            and chain.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_VERIFIED
        )
        or (
            len(generations) == 13
            and chain.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATES_RESTORED
        )
        or (
            len(generations) == 14
            and chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTING
        )
        or (
            len(generations) == 15
            and chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTED
        )
        or (
            len(generations) == 16
            and chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_VERIFYING
        )
        or (
            len(generations) == 17
            and chain.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_VERIFIED
        )
        or (
            len(generations) == 18
            and chain.selection.tip.state
            not in {
                EnvironmentJournalState.RECOVERY_CLEANUP_PENDING,
                EnvironmentJournalState.CLEANED,
            }
        )
        or (
            len(generations) == 19
            and chain.selection.tip.state is not EnvironmentJournalState.CLEANED
        )
    ):
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    return generations[0].record, generations[2].record


def _expected_backups(
    preparing: BackupPreparingRecord,
    armed: RollbackArmedRecord,
) -> tuple[StoredRecoveryBackupBlob, StoredRecoveryBackupBlob]:
    try:
        return (
            StoredRecoveryBackupBlob(
                preparing.environment_backup_name,
                ProtectedDataPurpose.ENVIRONMENT_BACKUP,
                armed.environment_backup_identity,
                armed.environment_ciphertext_sha256,
                armed.environment_ciphertext_size,
            ),
            StoredRecoveryBackupBlob(
                preparing.certificate_backup_name,
                ProtectedDataPurpose.CERTIFICATE_BACKUP,
                armed.certificate_backup_identity,
                armed.certificate_ciphertext_sha256,
                armed.certificate_ciphertext_size,
            ),
        )
    except ValueError:
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)


def _verify_backup(
    verification: RecoveryBackupBlobVerificationPort,
    root_path: str,
    expected: StoredRecoveryBackupBlob,
) -> None:
    try:
        verified = verification.verify_backup_blob(root_path, expected)
    except RecoveryBackupStorageError as exc:
        if exc.code is RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if type(verified) is not StoredRecoveryBackupBlob or verified != expected:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)


def _read_backup(
    storage: RecoveryBackupBlobReadPort,
    root_path: str,
    expected: StoredRecoveryBackupBlob,
) -> CurrentUserProtectedBlob:
    try:
        protected = storage.read_backup_blob(root_path, expected)
    except RecoveryBackupStorageError as exc:
        if exc.code is RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if (
        type(protected) is not CurrentUserProtectedBlob
        or protected.purpose is not expected.purpose
        or protected.ciphertext_sha256 != expected.ciphertext_sha256
        or len(protected.ciphertext) != expected.ciphertext_size
    ):
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return protected


def _authenticate_backups(
    stream: JournalStreamIdentity,
    environment_protected: CurrentUserProtectedBlob,
    certificate_protected: CurrentUserProtectedBlob,
    protection: BackupProtectionPort,
) -> tuple[EnvironmentExactStateBackup, CertificateExactStateBackup]:
    try:
        environment = authenticate_environment_exact_state_backup(
            SealedEnvironmentExactStateBackup(
                environment_protected,
                environment_protected.ciphertext_sha256,
            ),
            expected_stream=stream,
            protection=protection,
        )
        certificates = authenticate_certificate_exact_state_backup(
            SealedCertificateExactStateBackup(
                certificate_protected,
                certificate_protected.ciphertext_sha256,
            ),
            expected_stream=stream,
            protection=protection,
        )
    except (RecoveryBackupError, ValueError, AttributeError):
        _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)
    return environment, certificates


def _authenticate_environment_backup(
    stream: JournalStreamIdentity,
    protected: CurrentUserProtectedBlob,
    protection: BackupProtectionPort,
) -> EnvironmentExactStateBackup:
    try:
        return authenticate_environment_exact_state_backup(
            SealedEnvironmentExactStateBackup(
                protected,
                protected.ciphertext_sha256,
            ),
            expected_stream=stream,
            protection=protection,
        )
    except (RecoveryBackupError, ValueError, AttributeError):
        _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)


def _authenticate_certificate_backup(
    stream: JournalStreamIdentity,
    protected: CurrentUserProtectedBlob,
    protection: BackupProtectionPort,
) -> CertificateExactStateBackup:
    try:
        return authenticate_certificate_exact_state_backup(
            SealedCertificateExactStateBackup(
                protected,
                protected.ciphertext_sha256,
            ),
            expected_stream=stream,
            protection=protection,
        )
    except (RecoveryBackupError, ValueError, AttributeError):
        _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)


def _backup_summaries_match(
    preparing: BackupPreparingRecord,
    environment: EnvironmentExactStateBackup,
    certificates: CertificateExactStateBackup,
) -> bool:
    security = environment.security
    return (
        preparing.environment_present is environment.existed
        and preparing.environment_original_identity == environment.identity
        and preparing.environment_sha256
        == (environment.contents_sha256 if environment.existed else None)
        and preparing.environment_file_attributes
        == (security.file_attributes if security is not None else None)
        and preparing.environment_security_descriptor_sha256
        == (security.security_descriptor_sha256 if security is not None else None)
        and preparing.local_ca_present is certificates.local_ca.existed
        and preparing.local_ca_sha256
        == (
            certificates.local_ca.contents_sha256
            if certificates.local_ca.existed
            else None
        )
        and preparing.local_ca_mode == certificates.local_ca.mode
        and preparing.ca_bundle_present is certificates.ca_bundle.existed
        and preparing.ca_bundle_sha256
        == (
            certificates.ca_bundle.contents_sha256
            if certificates.ca_bundle.existed
            else None
        )
        and preparing.ca_bundle_mode == certificates.ca_bundle.mode
    )


def _assert_held_package_root(
    package_root: PathHierarchyTrust,
    stream: JournalStreamIdentity,
) -> None:
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.evidence.root_identity != stream.package_root_identity
    ):
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    try:
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)


def _create_environment_restore_temp(
    storage: EnvironmentRestoreTempStoragePort,
    package_root: PathHierarchyTrust,
    plan: EnvironmentRestoreTempPlanRecord,
) -> StableFileIdentity:
    try:
        identity = storage.create_environment_restore_temp_from_held_package_root(
            package_root,
            plan,
        )
    except RecoveryEnvironmentStorageError as exc:
        if exc.code is RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryEnvironmentStorageErrorCode.CREATE_FAILED:
            _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
        if exc.code is RecoveryEnvironmentStorageErrorCode.INPUT_INVALID:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if type(identity) is not StableFileIdentity:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return identity


def _verify_environment_restore_temp(
    storage: EnvironmentRestoreTempStoragePort,
    package_root: PathHierarchyTrust,
    created: EnvironmentRestoreTempCreatedRecord,
) -> None:
    try:
        identity = storage.verify_environment_restore_temp_from_held_package_root(
            package_root,
            created,
        )
    except RecoveryEnvironmentStorageError as exc:
        if exc.code is RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryEnvironmentStorageErrorCode.INPUT_INVALID:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if type(identity) is not StableFileIdentity or identity != created.temp_identity:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)


def _write_environment_restore_temp(
    storage: EnvironmentRestoreTempStoragePort,
    package_root: PathHierarchyTrust,
    created: EnvironmentRestoreTempCreatedRecord,
    contents: bytes,
) -> None:
    try:
        identity = (
            storage.write_and_verify_environment_restore_temp_from_held_package_root(
                package_root,
                created,
                contents,
            )
        )
    except RecoveryEnvironmentStorageError as exc:
        if exc.code is RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryEnvironmentStorageErrorCode.WRITE_FAILED:
            _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
        if exc.code is RecoveryEnvironmentStorageErrorCode.INPUT_INVALID:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if type(identity) is not StableFileIdentity or identity != created.temp_identity:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)


def _verify_written_environment_restore_temp(
    storage: EnvironmentRestoreTempStoragePort,
    package_root: PathHierarchyTrust,
    verified: EnvironmentRestoreTempVerifiedRecord,
) -> None:
    try:
        identity = (
            storage.verify_written_environment_restore_temp_from_held_package_root(
                package_root,
                verified,
            )
        )
    except RecoveryEnvironmentStorageError as exc:
        if exc.code is RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryEnvironmentStorageErrorCode.INPUT_INVALID:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if type(identity) is not StableFileIdentity or identity != verified.temp_identity:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)


def _environment_backup_matches_restore_record(
    record: EnvironmentRestoreTempCreatedRecord | EnvironmentRestoreTempVerifiedRecord,
    environment: EnvironmentExactStateBackup,
) -> bool:
    security = environment.security
    return (
        record.environment_present is environment.existed
        and record.environment_sha256
        == (environment.contents_sha256 if environment.existed else None)
        and record.environment_size
        == (len(environment.contents) if environment.contents is not None else None)
        and record.environment_file_attributes
        == (security.file_attributes if security is not None else None)
        and record.environment_security_descriptor_sha256
        == (security.security_descriptor_sha256 if security is not None else None)
    )


class EnvironmentRestoreTempNameSource(Protocol):
    def new_environment_temp_name(self) -> str: ...


class CertificateRestoreTempNameSource(Protocol):
    def new_certificate_temp_name(self) -> str: ...


class EnvironmentRestoreStoragePort(Protocol):
    def restore_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentRestoreStorageAuthority,
    ) -> EnvironmentDestinationObservation: ...


@dataclass(frozen=True, slots=True, repr=False)
class RollbackRuntimeAvailabilityEvidence:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)
    existing_container_retained: bool

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or _SHA256.fullmatch(self.runtime_evidence_sha256) is None
            or _SHA256.fullmatch(self.container_evidence_sha256) is None
            or type(self.volume_evidence_sha256s) is not tuple
            or len(self.volume_evidence_sha256s) != 8
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in self.volume_evidence_sha256s
            )
            or len(set(self.volume_evidence_sha256s)) != 8
            or type(self.existing_container_retained) is not bool
        ):
            raise ValueError("Rollback runtime availability evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "RollbackRuntimeAvailabilityEvidence("
            f"existing_container_retained={self.existing_container_retained!r}, "
            "<redacted>)"
        )


class RollbackRuntimeAvailabilityPort(Protocol):
    def establish_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
    ) -> RollbackRuntimeAvailabilityEvidence: ...


@dataclass(frozen=True, slots=True, repr=False)
class CertificateDestinationRestoreEvidence:
    schema_version: int
    present: bool
    contents_sha256: str | None = field(default=None, repr=False)
    size: int | None = None
    mode: int | None = None
    destination_evidence_sha256: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        values = (self.contents_sha256, self.size, self.mode)
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.present) is not bool
            or _SHA256.fullmatch(self.destination_evidence_sha256) is None
        ):
            raise ValueError("Certificate destination restore evidence is invalid.")
        if self.present:
            if (
                type(self.contents_sha256) is not str
                or _SHA256.fullmatch(self.contents_sha256) is None
                or type(self.size) is not int
                or self.size < 0
                or type(self.mode) is not int
                or not 0 <= self.mode <= 0o7777
            ):
                raise ValueError("Certificate destination restore evidence is invalid.")
        elif any(value is not None for value in values):
            raise ValueError("Certificate destination restore evidence is invalid.")

    def __repr__(self) -> str:
        return f"CertificateDestinationRestoreEvidence(present={self.present!r}, <redacted>)"


def _valid_runtime_evidence_values(
    runtime_sha256: object,
    container_sha256: object,
    volumes: object,
) -> bool:
    return (
        type(runtime_sha256) is str
        and _SHA256.fullmatch(runtime_sha256) is not None
        and type(container_sha256) is str
        and _SHA256.fullmatch(container_sha256) is not None
        and type(volumes) is tuple
        and len(volumes) == 8
        and all(
            type(value) is str and _SHA256.fullmatch(value) is not None
            for value in volumes
        )
        and len(set(volumes)) == 8
    )


@dataclass(frozen=True, slots=True, repr=False)
class CertificateRestorationEvidence:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)
    local_ca: CertificateDestinationRestoreEvidence = field(repr=False)
    ca_bundle: CertificateDestinationRestoreEvidence = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or not _valid_runtime_evidence_values(
                self.runtime_evidence_sha256,
                self.container_evidence_sha256,
                self.volume_evidence_sha256s,
            )
            or type(self.local_ca) is not CertificateDestinationRestoreEvidence
            or type(self.ca_bundle) is not CertificateDestinationRestoreEvidence
        ):
            raise ValueError("Certificate restoration evidence is invalid.")

    def __repr__(self) -> str:
        return "CertificateRestorationEvidence(<redacted>)"


class CertificateRestorationPort(Protocol):
    def restore_certificates_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        plan: CertificateRestoreTempPlanRecord,
        verified: CertificateRestoreTempVerifiedRecord,
    ) -> CertificateRestorationEvidence: ...


@dataclass(frozen=True, slots=True, repr=False)
class RollbackRuntimeRestartEvidence:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or not _valid_runtime_evidence_values(
                self.runtime_evidence_sha256,
                self.container_evidence_sha256,
                self.volume_evidence_sha256s,
            )
        ):
            raise ValueError("Rollback runtime restart evidence is invalid.")

    def __repr__(self) -> str:
        return "RollbackRuntimeRestartEvidence(<redacted>)"


class RollbackRuntimeRestartPort(Protocol):
    def restart_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        intent: RollbackRuntimeRestartingRecord,
    ) -> RollbackRuntimeRestartEvidence: ...

    def verify_restarted_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        restarted: RollbackRuntimeRestartedRecord,
    ) -> RollbackRuntimeRestartEvidence: ...


@dataclass(frozen=True, slots=True, repr=False)
class RollbackVerificationEvidence:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    environment_evidence_sha256: str = field(repr=False)
    certificate_evidence_sha256: str = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)
    readiness_evidence_sha256: str = field(repr=False)
    provider_outcome: RollbackProviderOutcome
    environment_exact: bool
    certificates_exact: bool
    runtime_condition_restored: bool
    readiness_condition_restored: bool

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or _SHA256.fullmatch(self.environment_evidence_sha256) is None
            or _SHA256.fullmatch(self.certificate_evidence_sha256) is None
            or _SHA256.fullmatch(self.readiness_evidence_sha256) is None
            or not _valid_runtime_evidence_values(
                self.runtime_evidence_sha256,
                self.container_evidence_sha256,
                self.volume_evidence_sha256s,
            )
            or type(self.provider_outcome) is not RollbackProviderOutcome
            or type(self.environment_exact) is not bool
            or type(self.certificates_exact) is not bool
            or type(self.runtime_condition_restored) is not bool
            or type(self.readiness_condition_restored) is not bool
        ):
            raise ValueError("Rollback verification evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "RollbackVerificationEvidence("
            f"provider_outcome={self.provider_outcome!r}, <redacted>)"
        )


class RollbackVerificationPort(Protocol):
    def verify_rollback_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        restarted: RollbackRuntimeRestartedRecord,
    ) -> RollbackVerificationEvidence: ...


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryCleanupEvidence:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    cleanup_evidence_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or _SHA256.fullmatch(self.cleanup_evidence_sha256) is None
        ):
            raise ValueError("Recovery cleanup evidence is invalid.")

    def __repr__(self) -> str:
        return "RecoveryCleanupEvidence(<redacted>)"


class RecoveryCleanupPort(Protocol):
    def cleanup_rollback_artifacts_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        chain: PersistedEnvironmentJournalChain,
    ) -> RecoveryCleanupEvidence: ...

    def verify_rollback_artifacts_cleaned_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        chain: PersistedEnvironmentJournalChain,
    ) -> RecoveryCleanupEvidence: ...


def _ensure_pointer(
    root_path: str,
    stream: JournalStreamIdentity,
    *,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    try:
        current = ensure_persisted_environment_journal_pointer_from_held_root(
            root_path,
            stream,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    except RecoveryJournalStorageError as exc:
        if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
            _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except RecoveryJournalError:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if (
        type(current) is not PersistedEnvironmentJournalChain
        or current.selection.pointer_disposition
        is not JournalPointerDisposition.CURRENT
    ):
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return current


def begin_persisted_rollback(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    verification: RecoveryBackupBlobVerificationPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Persist and select rollback_started without performing any restore."""

    if type(stream) is not JournalStreamIdentity:
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)

    def verify_and_start(root_path: str) -> PersistedEnvironmentJournalChain:
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        preparing, armed = _recovery_records(chain)
        environment_expected, certificate_expected = _expected_backups(
            preparing,
            armed,
        )
        _verify_backup(verification, root_path, environment_expected)
        _verify_backup(verification, root_path, certificate_expected)

        if chain.selection.tip.state is EnvironmentJournalState.ROLLBACK_ARMED:
            armed_current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                armed_current.selection.tip.state
                is not EnvironmentJournalState.ROLLBACK_ARMED
                or armed_current.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
                or type(armed_current.selection.tip.record) is not RollbackArmedRecord
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            current_armed = armed_current.selection.tip.record
            try:
                record = RollbackStartedRecord(
                    1,
                    armed_current.selection.tip_generation_sha256,
                    current_armed.package_root_identity,
                    current_armed.environment_backup_identity,
                    current_armed.environment_ciphertext_sha256,
                    current_armed.environment_ciphertext_size,
                    current_armed.certificate_backup_identity,
                    current_armed.certificate_ciphertext_sha256,
                    current_armed.certificate_ciphertext_size,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    4,
                    armed_current.selection.tip_generation_sha256,
                    EnvironmentJournalState.ROLLBACK_STARTED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if (
                chain.selection.tip != generation
                or chain.selection.tip_generation_sha256 != sealed.generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        started_current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(started_current.selection.generations) != 4
            or started_current.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_STARTED
            or started_current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        return started_current

    return _run_under_root(root, verify_and_start)


def plan_persisted_environment_restore(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    backup_storage: RecoveryBackupBlobReadPort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
    name_source: EnvironmentRestoreTempNameSource,
) -> PersistedEnvironmentJournalChain:
    """Persist and select an exact environment restore plan without applying it."""

    if type(stream) is not JournalStreamIdentity or not callable(
        getattr(name_source, "new_environment_temp_name", None)
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)

    def authenticate_and_plan(root_path: str) -> PersistedEnvironmentJournalChain:
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        if len(chain.selection.generations) not in {4, 5}:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        preparing, armed = _recovery_records(chain)
        started = chain.selection.generations[3]
        if (
            started.state is not EnvironmentJournalState.ROLLBACK_STARTED
            or type(started.record) is not RollbackStartedRecord
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        environment_expected, certificate_expected = _expected_backups(
            preparing,
            armed,
        )
        environment_protected = _read_backup(
            backup_storage,
            root_path,
            environment_expected,
        )
        certificate_protected = _read_backup(
            backup_storage,
            root_path,
            certificate_expected,
        )
        environment, certificates = _authenticate_backups(
            stream,
            environment_protected,
            certificate_protected,
            backup_protection,
        )
        if not _backup_summaries_match(preparing, environment, certificates):
            _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)

        if len(chain.selection.generations) == 4:
            started_current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                started_current.selection.tip != started
                or started_current.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            temp_name: str | None = None
            if environment.existed:
                try:
                    temp_name = name_source.new_environment_temp_name()
                except Exception:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            security = environment.security
            try:
                record = EnvironmentRestoreTempPlanRecord(
                    1,
                    started_current.selection.tip_generation_sha256,
                    stream.package_root_identity,
                    started.record.environment_backup_identity,
                    started.record.environment_ciphertext_sha256,
                    started.record.environment_ciphertext_size,
                    environment.existed,
                    environment.contents_sha256 if environment.existed else None,
                    (
                        len(environment.contents)
                        if environment.contents is not None
                        else None
                    ),
                    security.file_attributes if security is not None else None,
                    (
                        security.security_descriptor_sha256
                        if security is not None
                        else None
                    ),
                    temp_name,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    5,
                    started_current.selection.tip_generation_sha256,
                    EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if (
                chain.selection.tip != generation
                or chain.selection.tip_generation_sha256 != sealed.generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            existing = chain.selection.tip.record
            if (
                type(existing) is not EnvironmentRestoreTempPlanRecord
                or existing.environment_present is not environment.existed
                or existing.environment_sha256
                != (environment.contents_sha256 if environment.existed else None)
                or existing.environment_size
                != (
                    len(environment.contents)
                    if environment.contents is not None
                    else None
                )
            ):
                _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)

        planned_current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(planned_current.selection.generations) != 5
            or planned_current.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED
            or planned_current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        return planned_current

    return _run_under_root(root, authenticate_and_plan)


def create_persisted_environment_restore_temp_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    environment_storage: EnvironmentRestoreTempStoragePort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Persist generation 6 while the caller holds the matching package root.

    This creates or reverifies only the planned zero-byte temp. It does not write
    restore content, replace ``.env``, or activate any repair/runtime operation.
    """

    if (
        type(stream) is not JournalStreamIdentity
        or not callable(
            getattr(
                environment_storage,
                "create_environment_restore_temp_from_held_package_root",
                None,
            )
        )
        or not callable(
            getattr(
                environment_storage,
                "verify_environment_restore_temp_from_held_package_root",
                None,
            )
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def create_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {5, 6}
            or generations[4].state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED
            or type(generations[4].record) is not EnvironmentRestoreTempPlanRecord
            or (
                len(generations) == 6
                and (
                    chain.selection.tip.state
                    is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED
                    or type(chain.selection.tip.record)
                    is not EnvironmentRestoreTempCreatedRecord
                )
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        plan = generations[4].record

        if len(generations) == 5:
            planned_current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                planned_current.selection.tip != generations[4]
                or planned_current.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            temp_identity = (
                _create_environment_restore_temp(
                    environment_storage,
                    package_root,
                    plan,
                )
                if plan.environment_present
                else None
            )
            _assert_held_package_root(package_root, stream)
            try:
                record = EnvironmentRestoreTempCreatedRecord(
                    1,
                    planned_current.selection.tip_generation_sha256,
                    plan.package_root_identity,
                    plan.environment_backup_identity,
                    plan.environment_ciphertext_sha256,
                    plan.environment_ciphertext_size,
                    plan.environment_present,
                    plan.environment_sha256,
                    plan.environment_size,
                    plan.environment_file_attributes,
                    plan.environment_security_descriptor_sha256,
                    plan.temp_name,
                    temp_identity,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    6,
                    planned_current.selection.tip_generation_sha256,
                    EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if (
                chain.selection.tip != generation
                or chain.selection.tip_generation_sha256 != sealed.generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            created = chain.selection.tip.record
            if type(created) is not EnvironmentRestoreTempCreatedRecord:
                _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
            if created.environment_present:
                _verify_environment_restore_temp(
                    environment_storage,
                    package_root,
                    created,
                )
            _assert_held_package_root(package_root, stream)

        created_current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(created_current.selection.generations) != 6
            or created_current.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED
            or created_current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return created_current

    return _run_under_root(root, create_and_record)


def write_persisted_environment_restore_temp_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    backup_storage: RecoveryBackupBlobReadPort,
    environment_storage: EnvironmentRestoreTempStoragePort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Persist generation 7 without replacing or removing the package ``.env``."""

    if (
        type(stream) is not JournalStreamIdentity
        or not callable(
            getattr(
                environment_storage,
                "write_and_verify_environment_restore_temp_from_held_package_root",
                None,
            )
        )
        or not callable(
            getattr(
                environment_storage,
                "verify_written_environment_restore_temp_from_held_package_root",
                None,
            )
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def authenticate_write_and_record(
        root_path: str,
    ) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {6, 7}
            or generations[5].state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED
            or type(generations[5].record) is not EnvironmentRestoreTempCreatedRecord
            or (
                len(generations) == 7
                and (
                    chain.selection.tip.state
                    is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED
                    or type(chain.selection.tip.record)
                    is not EnvironmentRestoreTempVerifiedRecord
                )
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        preparing, armed = _recovery_records(chain)
        created = generations[5].record
        environment_expected, _certificate_expected = _expected_backups(
            preparing,
            armed,
        )
        if (
            created.environment_backup_identity != environment_expected.identity
            or created.environment_ciphertext_sha256
            != environment_expected.ciphertext_sha256
            or created.environment_ciphertext_size
            != environment_expected.ciphertext_size
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        environment_protected = _read_backup(
            backup_storage,
            root_path,
            environment_expected,
        )
        environment = _authenticate_environment_backup(
            stream,
            environment_protected,
            backup_protection,
        )
        if not _environment_backup_matches_restore_record(created, environment):
            _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)

        if len(generations) == 6:
            created_current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                created_current.selection.tip != generations[5]
                or created_current.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            contents = environment.contents
            if created.environment_present:
                if type(contents) is not bytes:
                    _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)
                _write_environment_restore_temp(
                    environment_storage,
                    package_root,
                    created,
                    contents,
                )
            _assert_held_package_root(package_root, stream)
            try:
                record = EnvironmentRestoreTempVerifiedRecord(
                    1,
                    created_current.selection.tip_generation_sha256,
                    created.package_root_identity,
                    created.environment_backup_identity,
                    created.environment_ciphertext_sha256,
                    created.environment_ciphertext_size,
                    created.environment_present,
                    created.environment_sha256,
                    created.environment_size,
                    created.environment_file_attributes,
                    created.environment_security_descriptor_sha256,
                    created.temp_name,
                    created.temp_identity,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    7,
                    created_current.selection.tip_generation_sha256,
                    EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if (
                chain.selection.tip != generation
                or chain.selection.tip_generation_sha256 != sealed.generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            verified = chain.selection.tip.record
            if type(
                verified
            ) is not EnvironmentRestoreTempVerifiedRecord or not _environment_backup_matches_restore_record(
                verified,
                environment,
            ):
                _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)
            if verified.environment_present:
                _verify_written_environment_restore_temp(
                    environment_storage,
                    package_root,
                    verified,
                )
            _assert_held_package_root(package_root, stream)

        verified_current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(verified_current.selection.generations) != 7
            or verified_current.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED
            or verified_current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return verified_current

    return _run_under_root(root, authenticate_write_and_record)


def _environment_restore_authority(
    recovery_chain: PersistedEnvironmentJournalChain,
    provider_chain: PersistedEnvironmentJournalChain,
    recovery_stream: JournalStreamIdentity,
    provider_stream: JournalStreamIdentity,
) -> EnvironmentRestoreStorageAuthority:
    recovery_generations = recovery_chain.selection.generations
    provider_generations = provider_chain.selection.generations
    if (
        len(recovery_generations) not in {7, 8}
        or type(recovery_generations[0].record) is not BackupPreparingRecord
        or type(recovery_generations[6].record)
        is not EnvironmentRestoreTempVerifiedRecord
        or (
            len(recovery_generations) == 8
            and type(recovery_generations[7].record) is not EnvironmentRestoredRecord
        )
        or len(provider_generations) != 4
        or provider_generations[0].state
        is not EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED
        or type(provider_generations[0].record) is not EnvironmentTempPlanRecord
        or provider_generations[3].state
        is not EnvironmentJournalState.ENVIRONMENT_APPLIED
        or type(provider_generations[3].record) is not EnvironmentAppliedRecord
        or provider_stream.journal_id == recovery_stream.journal_id
        or provider_stream.target_token_sha256 != recovery_stream.target_token_sha256
        or provider_stream.package_root_identity
        != recovery_stream.package_root_identity
    ):
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    preparing = recovery_generations[0].record
    verified = recovery_generations[6].record
    provider_plan = provider_generations[0].record
    applied = provider_generations[3].record
    original_matches = (
        provider_plan.original_present is preparing.environment_present
        and provider_plan.original_identity == preparing.environment_original_identity
        and provider_plan.original_file_attributes
        == verified.environment_file_attributes
        and provider_plan.original_security_descriptor_sha256
        == verified.environment_security_descriptor_sha256
        and (
            (
                preparing.environment_present
                and provider_plan.original_sha256 == verified.environment_sha256
                and provider_plan.original_size == verified.environment_size
            )
            or (
                not preparing.environment_present
                and provider_plan.original_identity is None
                and provider_plan.original_size is None
            )
        )
    )
    if (
        not original_matches
        or provider_plan.candidate_sha256 != preparing.environment_candidate_sha256
        or provider_plan.candidate_size != preparing.environment_candidate_size
        or applied.candidate_sha256 != preparing.environment_candidate_sha256
        or applied.candidate_size != preparing.environment_candidate_size
    ):
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    try:
        authority = EnvironmentRestoreAuthority(
            1,
            recovery_stream.package_root_identity,
            verified.environment_present,
            preparing.environment_original_identity,
            verified.environment_sha256,
            verified.environment_size,
            verified.environment_file_attributes,
            verified.environment_security_descriptor_sha256,
            preparing.environment_candidate_sha256,
            preparing.environment_candidate_size,
            applied.candidate_identity,
            applied.candidate_file_attributes,
            applied.candidate_security_descriptor_sha256,
            verified.temp_identity,
        )
        return EnvironmentRestoreStorageAuthority(
            1,
            authority,
            verified.temp_name,
        )
    except ValueError:
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)


def _restore_environment(
    storage: EnvironmentRestoreStoragePort,
    package_root: PathHierarchyTrust,
    authority: EnvironmentRestoreStorageAuthority,
) -> EnvironmentDestinationObservation:
    try:
        observed = storage.restore_environment_while_package_root_held(
            package_root,
            authority,
        )
    except EnvironmentRestoreStorageError as exc:
        if exc.code is EnvironmentRestoreStorageErrorCode.INPUT_INVALID:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        if exc.code is EnvironmentRestoreStorageErrorCode.PLATFORM_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is EnvironmentRestoreStorageErrorCode.APPLY_FAILED:
            _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if type(observed) is not EnvironmentDestinationObservation:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    try:
        decision = decide_environment_restore(authority.restore, observed)
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if decision.action is not EnvironmentRestoreAction.ALREADY_RESTORED:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return observed


def _restored_record_matches(
    record: EnvironmentRestoredRecord,
    observed: EnvironmentDestinationObservation,
) -> bool:
    return (
        record.environment_present is observed.present
        and record.environment_identity == observed.identity
        and record.environment_sha256 == observed.sha256
        and record.environment_size == observed.size
        and record.environment_file_attributes == observed.file_attributes
        and record.environment_security_descriptor_sha256
        == observed.security_descriptor_sha256
    )


def persist_environment_restored_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    provider_stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    journal_protection: JournalProtectionPort,
    environment_restoration: EnvironmentRestoreStoragePort,
) -> PersistedEnvironmentJournalChain:
    """Restore exact provider-applied state and select generation 8 once."""

    if (
        type(stream) is not JournalStreamIdentity
        or type(provider_stream) is not JournalStreamIdentity
        or not callable(
            getattr(
                environment_restoration,
                "restore_environment_while_package_root_held",
                None,
            )
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def restore_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        _recovery_records(chain)
        if len(chain.selection.generations) not in {7, 8}:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        provider_chain = _load_chain(
            root_path,
            provider_stream,
            journal_storage,
            journal_protection,
        )
        authority = _environment_restore_authority(
            chain,
            provider_chain,
            stream,
            provider_stream,
        )
        if len(chain.selection.generations) == 7:
            chain = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                len(chain.selection.generations) != 7
                or chain.selection.tip.state
                is not EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        observed = _restore_environment(
            environment_restoration,
            package_root,
            authority,
        )
        _assert_held_package_root(package_root, stream)

        if len(chain.selection.generations) == 7:
            verified = chain.selection.generations[6].record
            if type(verified) is not EnvironmentRestoreTempVerifiedRecord:
                _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
            try:
                record = EnvironmentRestoredRecord(
                    1,
                    chain.selection.tip_generation_sha256,
                    stream.package_root_identity,
                    observed.present,
                    observed.sha256,
                    observed.size,
                    observed.file_attributes,
                    observed.security_descriptor_sha256,
                    observed.identity,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    8,
                    chain.selection.tip_generation_sha256,
                    EnvironmentJournalState.ENVIRONMENT_RESTORED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if chain.selection.tip != generation:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            restored = chain.selection.tip.record
            if type(
                restored
            ) is not EnvironmentRestoredRecord or not _restored_record_matches(
                restored, observed
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(current.selection.generations) != 8
            or current.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_RESTORED
            or current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return current

    return _run_under_root(root, restore_and_record)


def _establish_rollback_runtime(
    availability: RollbackRuntimeAvailabilityPort,
    package_root: PathHierarchyTrust,
    stream: JournalStreamIdentity,
) -> RollbackRuntimeAvailabilityEvidence:
    try:
        evidence = availability.establish_rollback_runtime_while_package_root_held(
            package_root,
            stream,
        )
    except Exception:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if (
        type(evidence) is not RollbackRuntimeAvailabilityEvidence
        or evidence.target_token_sha256 != stream.target_token_sha256
        or evidence.package_root_identity != stream.package_root_identity
    ):
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return evidence


def _runtime_record_matches(
    record: RollbackRuntimeAvailableRecord,
    evidence: RollbackRuntimeAvailabilityEvidence,
) -> bool:
    return (
        record.package_root_identity == evidence.package_root_identity
        and record.runtime_evidence_sha256 == evidence.runtime_evidence_sha256
        and record.container_evidence_sha256 == evidence.container_evidence_sha256
        and record.volume_evidence_sha256s == evidence.volume_evidence_sha256s
        and record.existing_container_retained is evidence.existing_container_retained
    )


def persist_rollback_runtime_available_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    journal_protection: JournalProtectionPort,
    runtime_availability: RollbackRuntimeAvailabilityPort,
) -> PersistedEnvironmentJournalChain:
    """Attest one exact rollback runtime and select generation 9 once."""

    if type(stream) is not JournalStreamIdentity or not callable(
        getattr(
            runtime_availability,
            "establish_rollback_runtime_while_package_root_held",
            None,
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def establish_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        _recovery_records(chain)
        generations = chain.selection.generations
        if len(generations) not in {8, 9}:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        if len(generations) == 8:
            chain = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                len(chain.selection.generations) != 8
                or chain.selection.tip.state
                is not EnvironmentJournalState.ENVIRONMENT_RESTORED
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        evidence = _establish_rollback_runtime(
            runtime_availability,
            package_root,
            stream,
        )
        _assert_held_package_root(package_root, stream)

        if len(chain.selection.generations) == 8:
            try:
                record = RollbackRuntimeAvailableRecord(
                    1,
                    chain.selection.tip_generation_sha256,
                    stream.package_root_identity,
                    evidence.runtime_evidence_sha256,
                    evidence.container_evidence_sha256,
                    evidence.volume_evidence_sha256s,
                    evidence.existing_container_retained,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    9,
                    chain.selection.tip_generation_sha256,
                    EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if chain.selection.tip != generation:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            retry_record = chain.selection.tip.record
            if type(
                retry_record
            ) is not RollbackRuntimeAvailableRecord or not _runtime_record_matches(
                retry_record, evidence
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(current.selection.generations) != 9
            or current.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE
            or current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return current

    return _run_under_root(root, establish_and_record)


def _certificate_backup_matches_plan(
    plan: CertificateRestoreTempPlanRecord,
    backup: CertificateExactStateBackup,
) -> bool:
    return (
        plan.local_ca_present is backup.local_ca.existed
        and plan.local_ca_sha256
        == (backup.local_ca.contents_sha256 if backup.local_ca.existed else None)
        and plan.local_ca_size
        == (
            len(backup.local_ca.contents)
            if backup.local_ca.contents is not None
            else None
        )
        and plan.local_ca_mode == backup.local_ca.mode
        and plan.ca_bundle_present is backup.ca_bundle.existed
        and plan.ca_bundle_sha256
        == (backup.ca_bundle.contents_sha256 if backup.ca_bundle.existed else None)
        and plan.ca_bundle_size
        == (
            len(backup.ca_bundle.contents)
            if backup.ca_bundle.contents is not None
            else None
        )
        and plan.ca_bundle_mode == backup.ca_bundle.mode
    )


def plan_persisted_certificate_restore(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    backup_storage: RecoveryBackupBlobReadPort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
    name_source: CertificateRestoreTempNameSource,
) -> PersistedEnvironmentJournalChain:
    """Authenticate certificate backup and select generation 10 once."""

    if type(stream) is not JournalStreamIdentity or not callable(
        getattr(name_source, "new_certificate_temp_name", None)
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)

    def authenticate_and_plan(root_path: str) -> PersistedEnvironmentJournalChain:
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        preparing, armed = _recovery_records(chain)
        generations = chain.selection.generations
        if len(generations) not in {9, 10}:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        _environment_expected, certificate_expected = _expected_backups(
            preparing,
            armed,
        )
        certificate_protected = _read_backup(
            backup_storage,
            root_path,
            certificate_expected,
        )
        certificates = _authenticate_certificate_backup(
            stream,
            certificate_protected,
            backup_protection,
        )
        if not (
            preparing.local_ca_present is certificates.local_ca.existed
            and preparing.local_ca_sha256
            == (
                certificates.local_ca.contents_sha256
                if certificates.local_ca.existed
                else None
            )
            and preparing.local_ca_mode == certificates.local_ca.mode
            and preparing.ca_bundle_present is certificates.ca_bundle.existed
            and preparing.ca_bundle_sha256
            == (
                certificates.ca_bundle.contents_sha256
                if certificates.ca_bundle.existed
                else None
            )
            and preparing.ca_bundle_mode == certificates.ca_bundle.mode
        ):
            _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)

        if len(generations) == 9:
            chain = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                len(chain.selection.generations) != 9
                or chain.selection.tip.state
                is not EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                local_name = (
                    name_source.new_certificate_temp_name()
                    if certificates.local_ca.existed
                    else None
                )
                bundle_name = (
                    name_source.new_certificate_temp_name()
                    if certificates.ca_bundle.existed
                    else None
                )
            except Exception:
                _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            try:
                record = CertificateRestoreTempPlanRecord(
                    1,
                    chain.selection.tip_generation_sha256,
                    stream.package_root_identity,
                    certificate_expected.identity,
                    certificate_expected.ciphertext_sha256,
                    certificate_expected.ciphertext_size,
                    certificates.local_ca.existed,
                    (
                        certificates.local_ca.contents_sha256
                        if certificates.local_ca.existed
                        else None
                    ),
                    (
                        len(certificates.local_ca.contents)
                        if certificates.local_ca.contents is not None
                        else None
                    ),
                    certificates.local_ca.mode,
                    local_name,
                    certificates.ca_bundle.existed,
                    (
                        certificates.ca_bundle.contents_sha256
                        if certificates.ca_bundle.existed
                        else None
                    ),
                    (
                        len(certificates.ca_bundle.contents)
                        if certificates.ca_bundle.contents is not None
                        else None
                    ),
                    certificates.ca_bundle.mode,
                    bundle_name,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    10,
                    chain.selection.tip_generation_sha256,
                    EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_PLANNED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if chain.selection.tip != generation:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            existing_plan = chain.selection.tip.record
            if type(
                existing_plan
            ) is not CertificateRestoreTempPlanRecord or not _certificate_backup_matches_plan(
                existing_plan, certificates
            ):
                _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)

        current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(current.selection.generations) != 10
            or current.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_PLANNED
            or current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        return current

    return _run_under_root(root, authenticate_and_plan)


def _validate_certificate_temp_identities(
    plan: CertificateRestoreTempPlanRecord,
    identities: object,
) -> CertificateRestoreTempIdentities:
    if (
        type(identities) is not CertificateRestoreTempIdentities
        or (identities.local_ca is not None) is not plan.local_ca_present
        or (identities.ca_bundle is not None) is not plan.ca_bundle_present
    ):
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return identities


def _certificate_storage_failure(
    error: RecoveryCertificateStorageError,
    *,
    writing: bool,
) -> NoReturn:
    if error.code is RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE:
        _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
    if error.code is RecoveryCertificateStorageErrorCode.INPUT_INVALID:
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    if error.code in {
        RecoveryCertificateStorageErrorCode.CREATE_FAILED,
        RecoveryCertificateStorageErrorCode.WRITE_FAILED,
        RecoveryCertificateStorageErrorCode.CLEANUP_FAILED,
    }:
        _fail(
            WindowsRecoveryErrorCode.WRITE_FAILED
            if writing
            else WindowsRecoveryErrorCode.VERIFY_FAILED
        )
    _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)


def create_persisted_certificate_restore_temps(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    certificate_storage: CertificateRestoreTempStoragePort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Create/reverify exact zero-byte certificate temps and persist generation 11."""

    if (
        type(stream) is not JournalStreamIdentity
        or not callable(
            getattr(certificate_storage, "create_certificate_restore_temps", None)
        )
        or not callable(
            getattr(certificate_storage, "verify_certificate_restore_temps", None)
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)

    def create_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {10, 11}
            or type(generations[9].record) is not CertificateRestoreTempPlanRecord
            or (
                len(generations) == 11
                and type(generations[10].record)
                is not CertificateRestoreTempCreatedRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        plan = generations[9].record
        if len(generations) == 10:
            planned_current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                planned_current.selection.tip != generations[9]
                or planned_current.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                identities = _validate_certificate_temp_identities(
                    plan,
                    certificate_storage.create_certificate_restore_temps(
                        root_path,
                        plan,
                    ),
                )
            except RecoveryCertificateStorageError as exc:
                _certificate_storage_failure(exc, writing=True)
            except WindowsRecoveryError:
                raise
            except Exception:
                _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            try:
                record = CertificateRestoreTempCreatedRecord(
                    1,
                    planned_current.selection.tip_generation_sha256,
                    identities.local_ca,
                    identities.ca_bundle,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    11,
                    planned_current.selection.tip_generation_sha256,
                    EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_CREATED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if chain.selection.tip != generation:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            created = generations[10].record
            if type(created) is not CertificateRestoreTempCreatedRecord:
                _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
            try:
                identities = _validate_certificate_temp_identities(
                    plan,
                    certificate_storage.verify_certificate_restore_temps(
                        root_path,
                        plan,
                        created,
                    ),
                )
            except RecoveryCertificateStorageError as exc:
                _certificate_storage_failure(exc, writing=False)
            except WindowsRecoveryError:
                raise
            except Exception:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if (
                identities.local_ca != created.local_ca_temp_identity
                or identities.ca_bundle != created.ca_bundle_temp_identity
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(current.selection.generations) != 11
            or current.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_CREATED
            or current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        return current

    return _run_under_root(root, create_and_record)


def write_persisted_certificate_restore_temps(
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    backup_storage: RecoveryBackupBlobReadPort,
    certificate_storage: CertificateRestoreTempStoragePort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Write exact authenticated certificate bytes and persist generation 12."""

    if (
        type(stream) is not JournalStreamIdentity
        or not callable(
            getattr(
                certificate_storage,
                "write_and_verify_certificate_restore_temps",
                None,
            )
        )
        or not callable(
            getattr(
                certificate_storage,
                "verify_written_certificate_restore_temps",
                None,
            )
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)

    def authenticate_write_and_record(
        root_path: str,
    ) -> PersistedEnvironmentJournalChain:
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {11, 12}
            or type(generations[9].record) is not CertificateRestoreTempPlanRecord
            or type(generations[10].record) is not CertificateRestoreTempCreatedRecord
            or (
                len(generations) == 12
                and type(generations[11].record)
                is not CertificateRestoreTempVerifiedRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        preparing, armed = _recovery_records(chain)
        plan = generations[9].record
        created = generations[10].record
        _environment_expected, certificate_expected = _expected_backups(
            preparing,
            armed,
        )
        certificate_protected = _read_backup(
            backup_storage,
            root_path,
            certificate_expected,
        )
        certificates = _authenticate_certificate_backup(
            stream,
            certificate_protected,
            backup_protection,
        )
        if not _certificate_backup_matches_plan(plan, certificates):
            _fail(WindowsRecoveryErrorCode.BACKUP_INVALID)

        if len(generations) == 11:
            created_current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                created_current.selection.tip != generations[10]
                or created_current.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                identities = _validate_certificate_temp_identities(
                    plan,
                    certificate_storage.write_and_verify_certificate_restore_temps(
                        root_path,
                        plan,
                        created,
                        local_ca_contents=certificates.local_ca.contents,
                        ca_bundle_contents=certificates.ca_bundle.contents,
                    ),
                )
            except RecoveryCertificateStorageError as exc:
                _certificate_storage_failure(exc, writing=True)
            except WindowsRecoveryError:
                raise
            except Exception:
                _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            if (
                identities.local_ca != created.local_ca_temp_identity
                or identities.ca_bundle != created.ca_bundle_temp_identity
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            try:
                record = CertificateRestoreTempVerifiedRecord(
                    1,
                    created_current.selection.tip_generation_sha256,
                    created.local_ca_temp_identity,
                    created.ca_bundle_temp_identity,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    12,
                    created_current.selection.tip_generation_sha256,
                    EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_VERIFIED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=journal_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if chain.selection.tip != generation:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        else:
            verified = generations[11].record
            if type(verified) is not CertificateRestoreTempVerifiedRecord:
                _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
            try:
                identities = _validate_certificate_temp_identities(
                    plan,
                    certificate_storage.verify_written_certificate_restore_temps(
                        root_path,
                        plan,
                        verified,
                    ),
                )
            except RecoveryCertificateStorageError as exc:
                _certificate_storage_failure(exc, writing=False)
            except WindowsRecoveryError:
                raise
            except Exception:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            if (
                identities.local_ca != verified.local_ca_temp_identity
                or identities.ca_bundle != verified.ca_bundle_temp_identity
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(current.selection.generations) != 12
            or current.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_VERIFIED
            or current.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        return current

    return _run_under_root(root, authenticate_write_and_record)


def _append_recovery_generation(
    root_path: str,
    *,
    stream: JournalStreamIdentity,
    previous_sha256: str,
    sequence: int,
    state: EnvironmentJournalState,
    record: EnvironmentJournalRecord,
    journal_storage: JournalGenerationStoragePort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    try:
        generation = EnvironmentJournalGeneration(
            1,
            stream,
            sequence,
            previous_sha256,
            state,
            record,
        )
        sealed = protect_environment_journal_generation(
            generation,
            protection=journal_protection,
        )
    except (RecoveryJournalError, ValueError):
        _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
    try:
        chain = append_persisted_environment_journal_generation_from_held_root(
            root_path,
            sealed,
            stream=stream,
            storage=journal_storage,
            protection=journal_protection,
        )
    except RecoveryJournalStorageError as exc:
        if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(WindowsRecoveryErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
            _fail(WindowsRecoveryErrorCode.WRITE_FAILED)
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    except RecoveryJournalError:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    if chain.selection.tip != generation:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return chain


def _destination_matches_plan(
    *,
    present: bool,
    sha256: str | None,
    size: int | None,
    mode: int | None,
    evidence: CertificateDestinationRestoreEvidence,
) -> bool:
    return (
        evidence.present is present
        and evidence.contents_sha256 == sha256
        and evidence.size == size
        and evidence.mode == mode
    )


def persist_certificates_restored_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    restoration: CertificateRestorationPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Restore/reverify both exact certificate destinations and persist generation 13."""

    if type(stream) is not JournalStreamIdentity or not callable(
        getattr(restoration, "restore_certificates_while_package_root_held", None)
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def restore_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {12, 13}
            or type(generations[8].record) is not RollbackRuntimeAvailableRecord
            or type(generations[9].record) is not CertificateRestoreTempPlanRecord
            or type(generations[11].record) is not CertificateRestoreTempVerifiedRecord
            or (
                len(generations) == 13
                and type(generations[12].record) is not CertificatesRestoredRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        runtime = generations[8].record
        plan = generations[9].record
        verified = generations[11].record
        if len(generations) == 12:
            current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if current.selection.tip != generations[11]:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        try:
            evidence = restoration.restore_certificates_while_package_root_held(
                package_root,
                root_path,
                stream,
                plan,
                verified,
            )
        except WindowsRecoveryError:
            raise
        except Exception:
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        if (
            type(evidence) is not CertificateRestorationEvidence
            or evidence.target_token_sha256 != stream.target_token_sha256
            or evidence.package_root_identity != stream.package_root_identity
            or evidence.runtime_evidence_sha256 != runtime.runtime_evidence_sha256
            or evidence.container_evidence_sha256 != runtime.container_evidence_sha256
            or evidence.volume_evidence_sha256s != runtime.volume_evidence_sha256s
            or not _destination_matches_plan(
                present=plan.local_ca_present,
                sha256=plan.local_ca_sha256,
                size=plan.local_ca_size,
                mode=plan.local_ca_mode,
                evidence=evidence.local_ca,
            )
            or not _destination_matches_plan(
                present=plan.ca_bundle_present,
                sha256=plan.ca_bundle_sha256,
                size=plan.ca_bundle_size,
                mode=plan.ca_bundle_mode,
                evidence=evidence.ca_bundle,
            )
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)

        if len(generations) == 12:
            record = CertificatesRestoredRecord(
                1,
                chain.selection.tip_generation_sha256,
                stream.package_root_identity,
                evidence.runtime_evidence_sha256,
                evidence.container_evidence_sha256,
                evidence.volume_evidence_sha256s,
                evidence.local_ca.destination_evidence_sha256,
                evidence.ca_bundle.destination_evidence_sha256,
            )
            chain = _append_recovery_generation(
                root_path,
                stream=stream,
                previous_sha256=chain.selection.tip_generation_sha256,
                sequence=13,
                state=EnvironmentJournalState.CERTIFICATES_RESTORED,
                record=record,
                journal_storage=journal_storage,
                journal_protection=journal_protection,
            )
        else:
            existing = generations[12].record
            if (
                type(existing) is not CertificatesRestoredRecord
                or existing.runtime_evidence_sha256 != evidence.runtime_evidence_sha256
                or existing.container_evidence_sha256
                != evidence.container_evidence_sha256
                or existing.volume_evidence_sha256s != evidence.volume_evidence_sha256s
                or existing.local_ca_destination_evidence_sha256
                != evidence.local_ca.destination_evidence_sha256
                or existing.ca_bundle_destination_evidence_sha256
                != evidence.ca_bundle.destination_evidence_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        selected = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(selected.selection.generations) != 13
            or selected.selection.tip.state
            is not EnvironmentJournalState.CERTIFICATES_RESTORED
            or selected.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return selected

    return _run_under_root(root, restore_and_record)


def persist_rollback_runtime_restarting_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Make the generation-14 restart intent durable before runtime mutation."""

    if type(stream) is not JournalStreamIdentity:
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def record_intent(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {13, 14}
            or type(generations[12].record) is not CertificatesRestoredRecord
            or (
                len(generations) == 14
                and type(generations[13].record) is not RollbackRuntimeRestartingRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        if len(generations) == 13:
            current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if current.selection.tip != generations[12]:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            restored = generations[12].record
            record = RollbackRuntimeRestartingRecord(
                1,
                current.selection.tip_generation_sha256,
                stream.package_root_identity,
                restored.runtime_evidence_sha256,
                restored.container_evidence_sha256,
                restored.volume_evidence_sha256s,
            )
            chain = _append_recovery_generation(
                root_path,
                stream=stream,
                previous_sha256=current.selection.tip_generation_sha256,
                sequence=14,
                state=EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTING,
                record=record,
                journal_storage=journal_storage,
                journal_protection=journal_protection,
            )
        selected = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(selected.selection.generations) != 14
            or selected.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTING
            or selected.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return selected

    return _run_under_root(root, record_intent)


def _restart_evidence_matches(
    evidence: object,
    stream: JournalStreamIdentity,
) -> bool:
    return (
        type(evidence) is RollbackRuntimeRestartEvidence
        and evidence.target_token_sha256 == stream.target_token_sha256
        and evidence.package_root_identity == stream.package_root_identity
    )


def persist_rollback_runtime_restarted_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    restart: RollbackRuntimeRestartPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Restart/reverify the exact prior runtime and persist generation 15."""

    if (
        type(stream) is not JournalStreamIdentity
        or not callable(
            getattr(
                restart,
                "restart_rollback_runtime_while_package_root_held",
                None,
            )
        )
        or not callable(
            getattr(
                restart,
                "verify_restarted_rollback_runtime_while_package_root_held",
                None,
            )
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def restart_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {14, 15}
            or type(generations[13].record) is not RollbackRuntimeRestartingRecord
            or (
                len(generations) == 15
                and type(generations[14].record) is not RollbackRuntimeRestartedRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        intent = generations[13].record
        try:
            if len(generations) == 14:
                current = _ensure_pointer(
                    root_path,
                    stream,
                    generation_storage=journal_storage,
                    pointer_storage=pointer_storage,
                    protection=journal_protection,
                )
                if current.selection.tip != generations[13]:
                    _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
                evidence = restart.restart_rollback_runtime_while_package_root_held(
                    package_root,
                    stream,
                    intent,
                )
            else:
                restarted = generations[14].record
                if type(restarted) is not RollbackRuntimeRestartedRecord:
                    _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
                evidence = (
                    restart.verify_restarted_rollback_runtime_while_package_root_held(
                        package_root,
                        stream,
                        restarted,
                    )
                )
        except WindowsRecoveryError:
            raise
        except Exception:
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        if not _restart_evidence_matches(evidence, stream):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)

        if len(generations) == 14:
            record = RollbackRuntimeRestartedRecord(
                1,
                chain.selection.tip_generation_sha256,
                stream.package_root_identity,
                evidence.runtime_evidence_sha256,
                evidence.container_evidence_sha256,
                evidence.volume_evidence_sha256s,
            )
            chain = _append_recovery_generation(
                root_path,
                stream=stream,
                previous_sha256=chain.selection.tip_generation_sha256,
                sequence=15,
                state=EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTED,
                record=record,
                journal_storage=journal_storage,
                journal_protection=journal_protection,
            )
        else:
            existing = generations[14].record
            if (
                type(existing) is not RollbackRuntimeRestartedRecord
                or existing.runtime_evidence_sha256 != evidence.runtime_evidence_sha256
                or existing.container_evidence_sha256
                != evidence.container_evidence_sha256
                or existing.volume_evidence_sha256s != evidence.volume_evidence_sha256s
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        selected = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(selected.selection.generations) != 15
            or selected.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTED
            or selected.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return selected

    return _run_under_root(root, restart_and_record)


def persist_rollback_verifying_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Persist generation 16 before terminal rollback verification."""

    if type(stream) is not JournalStreamIdentity:
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def record_intent(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {15, 16}
            or type(generations[14].record) is not RollbackRuntimeRestartedRecord
            or (
                len(generations) == 16
                and type(generations[15].record) is not RollbackVerifyingRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        if len(generations) == 15:
            current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if current.selection.tip != generations[14]:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            record = RollbackVerifyingRecord(
                1,
                current.selection.tip_generation_sha256,
                stream.package_root_identity,
            )
            chain = _append_recovery_generation(
                root_path,
                stream=stream,
                previous_sha256=current.selection.tip_generation_sha256,
                sequence=16,
                state=EnvironmentJournalState.ROLLBACK_VERIFYING,
                record=record,
                journal_storage=journal_storage,
                journal_protection=journal_protection,
            )
        selected = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(selected.selection.generations) != 16
            or selected.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_VERIFYING
            or selected.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return selected

    return _run_under_root(root, record_intent)


def persist_rollback_verified_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    verification: RollbackVerificationPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Verify exact local/runtime rollback and persist terminal generation 17."""

    if type(stream) is not JournalStreamIdentity or not callable(
        getattr(verification, "verify_rollback_while_package_root_held", None)
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def verify_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {16, 17}
            or type(generations[14].record) is not RollbackRuntimeRestartedRecord
            or type(generations[15].record) is not RollbackVerifyingRecord
            or (
                len(generations) == 17
                and type(generations[16].record) is not RollbackVerifiedRecord
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        restarted = generations[14].record
        if len(generations) == 16:
            current = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if current.selection.tip != generations[15]:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        try:
            evidence = verification.verify_rollback_while_package_root_held(
                package_root,
                stream,
                restarted,
            )
        except WindowsRecoveryError:
            raise
        except Exception:
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        if (
            type(evidence) is not RollbackVerificationEvidence
            or evidence.target_token_sha256 != stream.target_token_sha256
            or evidence.package_root_identity != stream.package_root_identity
            or evidence.runtime_evidence_sha256 != restarted.runtime_evidence_sha256
            or evidence.container_evidence_sha256 != restarted.container_evidence_sha256
            or evidence.volume_evidence_sha256s != restarted.volume_evidence_sha256s
            or not evidence.environment_exact
            or not evidence.certificates_exact
            or not evidence.runtime_condition_restored
            or not evidence.readiness_condition_restored
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)

        if len(generations) == 16:
            record = RollbackVerifiedRecord(
                1,
                chain.selection.tip_generation_sha256,
                stream.package_root_identity,
                evidence.environment_evidence_sha256,
                evidence.certificate_evidence_sha256,
                evidence.runtime_evidence_sha256,
                evidence.container_evidence_sha256,
                evidence.volume_evidence_sha256s,
                evidence.readiness_evidence_sha256,
                evidence.provider_outcome,
            )
            chain = _append_recovery_generation(
                root_path,
                stream=stream,
                previous_sha256=chain.selection.tip_generation_sha256,
                sequence=17,
                state=EnvironmentJournalState.ROLLBACK_VERIFIED,
                record=record,
                journal_storage=journal_storage,
                journal_protection=journal_protection,
            )
        else:
            existing = generations[16].record
            if (
                type(existing) is not RollbackVerifiedRecord
                or existing.environment_evidence_sha256
                != evidence.environment_evidence_sha256
                or existing.certificate_evidence_sha256
                != evidence.certificate_evidence_sha256
                or existing.runtime_evidence_sha256 != evidence.runtime_evidence_sha256
                or existing.container_evidence_sha256
                != evidence.container_evidence_sha256
                or existing.volume_evidence_sha256s != evidence.volume_evidence_sha256s
                or existing.readiness_evidence_sha256
                != evidence.readiness_evidence_sha256
                or existing.provider_outcome is not evidence.provider_outcome
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        selected = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            len(selected.selection.generations) != 17
            or selected.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_VERIFIED
            or selected.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return selected

    return _run_under_root(root, verify_and_record)


def _cleanup_evidence_matches(
    evidence: object,
    stream: JournalStreamIdentity,
) -> bool:
    return (
        type(evidence) is RecoveryCleanupEvidence
        and evidence.target_token_sha256 == stream.target_token_sha256
        and evidence.package_root_identity == stream.package_root_identity
    )


def persist_recovery_cleaned_generation_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    journal_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    cleanup: RecoveryCleanupPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Clean exact terminal artifacts or durably retain cleanup-pending state."""

    if (
        type(stream) is not JournalStreamIdentity
        or not callable(
            getattr(
                cleanup,
                "cleanup_rollback_artifacts_while_package_root_held",
                None,
            )
        )
        or not callable(
            getattr(
                cleanup,
                "verify_rollback_artifacts_cleaned_while_package_root_held",
                None,
            )
        )
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    _assert_held_package_root(package_root, stream)

    def cleanup_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        _assert_held_package_root(package_root, stream)
        chain = _load_chain(root_path, stream, journal_storage, journal_protection)
        generations = chain.selection.generations
        if (
            len(generations) not in {17, 18, 19}
            or type(generations[16].record) is not RollbackVerifiedRecord
            or (
                len(generations) == 18
                and type(generations[17].record)
                not in {RecoveryCleanupPendingRecord, RecoveryCleanedRecord}
            )
            or (
                len(generations) == 19
                and (
                    type(generations[17].record) is not RecoveryCleanupPendingRecord
                    or type(generations[18].record) is not RecoveryCleanedRecord
                )
            )
        ):
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        already_cleaned = type(generations[-1].record) is RecoveryCleanedRecord
        current = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if current.selection.tip != generations[-1]:
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)

        if already_cleaned:
            try:
                verified_evidence = (
                    cleanup.verify_rollback_artifacts_cleaned_while_package_root_held(
                        package_root,
                        root_path,
                        stream,
                        current,
                    )
                )
            except WindowsRecoveryError:
                raise
            except Exception:
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            cleaned_record = generations[-1].record
            if (
                not _cleanup_evidence_matches(verified_evidence, stream)
                or type(cleaned_record) is not RecoveryCleanedRecord
                or cleaned_record.cleanup_evidence_sha256
                != verified_evidence.cleanup_evidence_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            _assert_held_package_root(package_root, stream)
            return current

        cleanup_succeeded = False
        evidence: RecoveryCleanupEvidence | None = None
        try:
            candidate = cleanup.cleanup_rollback_artifacts_while_package_root_held(
                package_root,
                root_path,
                stream,
                current,
            )
            if _cleanup_evidence_matches(candidate, stream):
                evidence = candidate
                cleanup_succeeded = True
        except Exception:
            cleanup_succeeded = False
        _assert_held_package_root(package_root, stream)

        if not cleanup_succeeded or evidence is None:
            if len(generations) == 17:
                pending_record = RecoveryCleanupPendingRecord(
                    1,
                    current.selection.tip_generation_sha256,
                    stream.package_root_identity,
                )
                chain = _append_recovery_generation(
                    root_path,
                    stream=stream,
                    previous_sha256=current.selection.tip_generation_sha256,
                    sequence=18,
                    state=EnvironmentJournalState.RECOVERY_CLEANUP_PENDING,
                    record=pending_record,
                    journal_storage=journal_storage,
                    journal_protection=journal_protection,
                )
            else:
                chain = current
            pending = _ensure_pointer(
                root_path,
                stream,
                generation_storage=journal_storage,
                pointer_storage=pointer_storage,
                protection=journal_protection,
            )
            if (
                pending.selection.tip.state
                is not EnvironmentJournalState.RECOVERY_CLEANUP_PENDING
                or pending.selection.tip_generation_sha256
                != chain.selection.tip_generation_sha256
            ):
                _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
            _fail(WindowsRecoveryErrorCode.CLEANUP_PENDING)

        cleaned_record = RecoveryCleanedRecord(
            1,
            current.selection.tip_generation_sha256,
            stream.package_root_identity,
            evidence.cleanup_evidence_sha256,
        )
        chain = _append_recovery_generation(
            root_path,
            stream=stream,
            previous_sha256=current.selection.tip_generation_sha256,
            sequence=len(generations) + 1,
            state=EnvironmentJournalState.CLEANED,
            record=cleaned_record,
            journal_storage=journal_storage,
            journal_protection=journal_protection,
        )
        selected = _ensure_pointer(
            root_path,
            stream,
            generation_storage=journal_storage,
            pointer_storage=pointer_storage,
            protection=journal_protection,
        )
        if (
            selected.selection.tip.state is not EnvironmentJournalState.CLEANED
            or selected.selection.tip_generation_sha256
            != chain.selection.tip_generation_sha256
        ):
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        _assert_held_package_root(package_root, stream)
        return selected

    return _run_under_root(root, cleanup_and_record)


__all__ = [
    "CertificateRestoreTempNameSource",
    "CertificateRestoreTempStoragePort",
    "CertificateDestinationRestoreEvidence",
    "CertificateRestorationEvidence",
    "CertificateRestorationPort",
    "EnvironmentRestoreStoragePort",
    "RollbackRuntimeAvailabilityEvidence",
    "RollbackRuntimeAvailabilityPort",
    "RollbackRuntimeRestartEvidence",
    "RollbackRuntimeRestartPort",
    "RollbackVerificationEvidence",
    "RollbackVerificationPort",
    "RecoveryCleanupEvidence",
    "RecoveryCleanupPort",
    "WindowsRecoveryError",
    "WindowsRecoveryErrorCode",
    "begin_persisted_rollback",
    "create_persisted_certificate_restore_temps",
    "create_persisted_environment_restore_temp_from_held_package_root",
    "plan_persisted_environment_restore",
    "plan_persisted_certificate_restore",
    "persist_environment_restored_generation_from_held_package_root",
    "persist_certificates_restored_generation_from_held_package_root",
    "persist_recovery_cleaned_generation_from_held_package_root",
    "persist_rollback_runtime_available_generation_from_held_package_root",
    "persist_rollback_runtime_restarted_generation_from_held_package_root",
    "persist_rollback_runtime_restarting_generation_from_held_package_root",
    "persist_rollback_verified_generation_from_held_package_root",
    "persist_rollback_verifying_generation_from_held_package_root",
    "write_persisted_environment_restore_temp_from_held_package_root",
    "write_persisted_certificate_restore_temps",
]
