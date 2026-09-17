"""Fresh-process planning for authenticated Windows rollback.

This Gate-A layer may reverify the exact encrypted backups, advance an
authenticated journal through ``environment_restore_temp_verified``, and write
original environment bytes only to that plan's exact temporary file. It cannot
replace or remove package files, clean completed transaction artifacts, or
mutate a runtime.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable, NoReturn, Protocol, TypeVar, cast

from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
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
from .windows_recovery_environment_storage import (
    EnvironmentRestoreTempStoragePort,
    RecoveryEnvironmentStorageError,
    RecoveryEnvironmentStorageErrorCode,
)
from .windows_recovery_journal import (
    BackupPreparingRecord,
    BackupVerifiedRecord,
    EnvironmentJournalGeneration,
    EnvironmentJournalState,
    EnvironmentRestoreTempCreatedRecord,
    EnvironmentRestoreTempPlanRecord,
    EnvironmentRestoreTempVerifiedRecord,
    JournalPointerDisposition,
    JournalProtectionPort,
    JournalStreamIdentity,
    RecoveryJournalError,
    RollbackArmedRecord,
    RollbackStartedRecord,
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


class WindowsRecoveryErrorCode(str, Enum):
    INPUT_INVALID = "windows_recovery_input_invalid"
    AUTHORITY_INVALID = "windows_recovery_authority_invalid"
    STORAGE_UNAVAILABLE = "windows_recovery_storage_unavailable"
    BACKUP_INVALID = "windows_recovery_backup_invalid"
    WRITE_FAILED = "windows_recovery_write_failed"
    VERIFY_FAILED = "windows_recovery_verify_failed"


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
        len(generations) not in {3, 4, 5, 6, 7}
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


def _backup_summaries_match(
    preparing: BackupPreparingRecord,
    environment: EnvironmentExactStateBackup,
    certificates: CertificateExactStateBackup,
) -> bool:
    security = environment.security
    return (
        preparing.environment_present is environment.existed
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


__all__ = [
    "WindowsRecoveryError",
    "WindowsRecoveryErrorCode",
    "begin_persisted_rollback",
    "create_persisted_environment_restore_temp_from_held_package_root",
    "plan_persisted_environment_restore",
    "write_persisted_environment_restore_temp_from_held_package_root",
]
