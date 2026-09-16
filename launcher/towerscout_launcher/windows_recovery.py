"""Fresh-process admission to authenticated Windows rollback.

This Gate-A layer may reverify the exact encrypted backups and advance an
authenticated journal only from ``rollback_armed`` to ``rollback_started``.
It cannot decrypt or restore backups, clean artifacts, replace package files,
or mutate a runtime.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable, NoReturn, TypeVar, cast

from .windows_protected_state import ProtectedDataPurpose
from .windows_recovery_backup_storage import (
    RecoveryBackupBlobVerificationPort,
    RecoveryBackupStorageError,
    RecoveryBackupStorageErrorCode,
    StoredRecoveryBackupBlob,
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

_Result = TypeVar("_Result")


class WindowsRecoveryErrorCode(str, Enum):
    INPUT_INVALID = "windows_recovery_input_invalid"
    AUTHORITY_INVALID = "windows_recovery_authority_invalid"
    STORAGE_UNAVAILABLE = "windows_recovery_storage_unavailable"
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
        len(generations) not in {3, 4}
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


__all__ = [
    "WindowsRecoveryError",
    "WindowsRecoveryErrorCode",
    "begin_persisted_rollback",
]
