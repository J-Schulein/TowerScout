"""Fresh-process coordinator for the authenticated Windows rollback chain.

The individual recovery operations remain purpose-separated in
``windows_recovery``.  This module supplies the missing restart coordinator: it
accepts one already authenticated chain, reloads authority inside every
operation, and advances only the next valid state while the matching package
root remains held.  It does not resolve targets or enable repair mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn, TypedDict

from .windows_path_trust import PathHierarchyTrust
from .windows_recovery import (
    CertificateRestorationPort,
    CertificateRestoreTempNameSource,
    EnvironmentRestoreStoragePort,
    EnvironmentRestoreTempNameSource,
    RecoveryCleanupPort,
    RollbackRuntimeAvailabilityPort,
    RollbackRuntimeRestartPort,
    RollbackVerificationPort,
    WindowsRecoveryError,
    WindowsRecoveryErrorCode,
    begin_persisted_rollback,
    create_persisted_certificate_restore_temps,
    create_persisted_environment_restore_temp_from_held_package_root,
    persist_certificates_restored_generation_from_held_package_root,
    persist_environment_restored_generation_from_held_package_root,
    persist_recovery_cleaned_generation_from_held_package_root,
    persist_rollback_runtime_available_generation_from_held_package_root,
    persist_rollback_runtime_restarted_generation_from_held_package_root,
    persist_rollback_runtime_restarting_generation_from_held_package_root,
    persist_rollback_verified_generation_from_held_package_root,
    persist_rollback_verifying_generation_from_held_package_root,
    plan_persisted_certificate_restore,
    plan_persisted_environment_restore,
    write_persisted_certificate_restore_temps,
    write_persisted_environment_restore_temp_from_held_package_root,
)
from .windows_recovery_backup import BackupProtectionPort
from .windows_recovery_backup_storage import (
    RecoveryBackupBlobReadPort,
    RecoveryBackupBlobVerificationPort,
)
from .windows_recovery_certificate_storage import CertificateRestoreTempStoragePort
from .windows_recovery_environment_storage import EnvironmentRestoreTempStoragePort
from .windows_recovery_journal import (
    EnvironmentJournalState,
    JournalProtectionPort,
    JournalStreamIdentity,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
)


@dataclass(frozen=True, slots=True, repr=False)
class WindowsRecoveryManagerPorts:
    """All narrow capabilities required to resume one rollback."""

    root: JournalStorageRootPort = field(repr=False)
    journal_storage: JournalGenerationStoragePort = field(repr=False)
    pointer_storage: JournalPointerStoragePort = field(repr=False)
    backup_verification: RecoveryBackupBlobVerificationPort = field(repr=False)
    backup_storage: RecoveryBackupBlobReadPort = field(repr=False)
    backup_protection: BackupProtectionPort = field(repr=False)
    journal_protection: JournalProtectionPort = field(repr=False)
    environment_name_source: EnvironmentRestoreTempNameSource = field(repr=False)
    environment_storage: EnvironmentRestoreTempStoragePort = field(repr=False)
    environment_restoration: EnvironmentRestoreStoragePort = field(repr=False)
    runtime_availability: RollbackRuntimeAvailabilityPort = field(repr=False)
    certificate_name_source: CertificateRestoreTempNameSource = field(repr=False)
    certificate_storage: CertificateRestoreTempStoragePort = field(repr=False)
    certificate_restoration: CertificateRestorationPort = field(repr=False)
    runtime_restart: RollbackRuntimeRestartPort = field(repr=False)
    rollback_verification: RollbackVerificationPort = field(repr=False)
    cleanup: RecoveryCleanupPort = field(repr=False)

    def __repr__(self) -> str:
        return "WindowsRecoveryManagerPorts(<redacted>)"


class _CommonArguments(TypedDict):
    stream: JournalStreamIdentity
    root: JournalStorageRootPort
    journal_storage: JournalGenerationStoragePort
    pointer_storage: JournalPointerStoragePort
    journal_protection: JournalProtectionPort


_STATE_BY_SEQUENCE = {
    3: EnvironmentJournalState.ROLLBACK_ARMED,
    4: EnvironmentJournalState.ROLLBACK_STARTED,
    5: EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
    6: EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
    7: EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED,
    8: EnvironmentJournalState.ENVIRONMENT_RESTORED,
    9: EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE,
    10: EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_PLANNED,
    11: EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_CREATED,
    12: EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_VERIFIED,
    13: EnvironmentJournalState.CERTIFICATES_RESTORED,
    14: EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTING,
    15: EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTED,
    16: EnvironmentJournalState.ROLLBACK_VERIFYING,
    17: EnvironmentJournalState.ROLLBACK_VERIFIED,
}


def _fail(code: WindowsRecoveryErrorCode) -> NoReturn:
    raise WindowsRecoveryError(code) from None


def _validated_sequence(
    chain: PersistedEnvironmentJournalChain,
    stream: JournalStreamIdentity,
) -> int:
    if (
        type(chain) is not PersistedEnvironmentJournalChain
        or chain.selection.tip.stream != stream
        or chain.selection.tip.sequence != len(chain.selection.generations)
    ):
        _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
    sequence = chain.selection.tip.sequence
    state = chain.selection.tip.state
    expected = _STATE_BY_SEQUENCE.get(sequence)
    if expected is not None:
        if state is not expected:
            _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)
        return sequence
    if sequence == 18 and state in {
        EnvironmentJournalState.RECOVERY_CLEANUP_PENDING,
        EnvironmentJournalState.CLEANED,
    }:
        return sequence
    if sequence == 19 and state is EnvironmentJournalState.CLEANED:
        return sequence
    _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)


def _validate_streams(
    stream: JournalStreamIdentity,
    provider_stream: JournalStreamIdentity,
) -> None:
    if (
        type(stream) is not JournalStreamIdentity
        or type(provider_stream) is not JournalStreamIdentity
        or stream.journal_id == provider_stream.journal_id
        or stream.target_token_sha256 != provider_stream.target_token_sha256
        or stream.package_root_identity != provider_stream.package_root_identity
    ):
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)


def _common_arguments(
    stream: JournalStreamIdentity,
    ports: WindowsRecoveryManagerPorts,
) -> _CommonArguments:
    return {
        "stream": stream,
        "root": ports.root,
        "journal_storage": ports.journal_storage,
        "pointer_storage": ports.pointer_storage,
        "journal_protection": ports.journal_protection,
    }


def _advance_environment_restore(
    sequence: int,
    *,
    stream: JournalStreamIdentity,
    provider_stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    ports: WindowsRecoveryManagerPorts,
) -> PersistedEnvironmentJournalChain:
    common = _common_arguments(stream, ports)
    if sequence == 3:
        return begin_persisted_rollback(
            **common,
            verification=ports.backup_verification,
        )
    if sequence == 4:
        return plan_persisted_environment_restore(
            **common,
            backup_storage=ports.backup_storage,
            backup_protection=ports.backup_protection,
            name_source=ports.environment_name_source,
        )
    if sequence == 5:
        return create_persisted_environment_restore_temp_from_held_package_root(
            **common,
            package_root=package_root,
            environment_storage=ports.environment_storage,
        )
    if sequence == 6:
        return write_persisted_environment_restore_temp_from_held_package_root(
            **common,
            package_root=package_root,
            backup_storage=ports.backup_storage,
            environment_storage=ports.environment_storage,
            backup_protection=ports.backup_protection,
        )
    if sequence == 7:
        return persist_environment_restored_generation_from_held_package_root(
            **common,
            provider_stream=provider_stream,
            package_root=package_root,
            environment_restoration=ports.environment_restoration,
        )
    if sequence == 8:
        return persist_rollback_runtime_available_generation_from_held_package_root(
            **common,
            package_root=package_root,
            runtime_availability=ports.runtime_availability,
        )
    _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)


def _advance_certificate_and_runtime_restore(
    sequence: int,
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    ports: WindowsRecoveryManagerPorts,
) -> PersistedEnvironmentJournalChain:
    common = _common_arguments(stream, ports)
    if sequence == 9:
        return plan_persisted_certificate_restore(
            **common,
            backup_storage=ports.backup_storage,
            backup_protection=ports.backup_protection,
            name_source=ports.certificate_name_source,
        )
    if sequence == 10:
        return create_persisted_certificate_restore_temps(
            **common,
            certificate_storage=ports.certificate_storage,
        )
    if sequence == 11:
        return write_persisted_certificate_restore_temps(
            **common,
            backup_storage=ports.backup_storage,
            certificate_storage=ports.certificate_storage,
            backup_protection=ports.backup_protection,
        )
    if sequence == 12:
        return persist_certificates_restored_generation_from_held_package_root(
            **common,
            package_root=package_root,
            restoration=ports.certificate_restoration,
        )
    if sequence == 13:
        return persist_rollback_runtime_restarting_generation_from_held_package_root(
            **common,
            package_root=package_root,
        )
    if sequence == 14:
        return persist_rollback_runtime_restarted_generation_from_held_package_root(
            **common,
            package_root=package_root,
            restart=ports.runtime_restart,
        )
    if sequence == 15:
        return persist_rollback_verifying_generation_from_held_package_root(
            **common,
            package_root=package_root,
        )
    if sequence == 16:
        return persist_rollback_verified_generation_from_held_package_root(
            **common,
            package_root=package_root,
            verification=ports.rollback_verification,
        )
    _fail(WindowsRecoveryErrorCode.AUTHORITY_INVALID)


def resume_persisted_rollback_from_held_package_root(
    *,
    stream: JournalStreamIdentity,
    provider_stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    initial_chain: PersistedEnvironmentJournalChain,
    ports: WindowsRecoveryManagerPorts,
) -> PersistedEnvironmentJournalChain:
    """Resume one authenticated rollback from any durable sequence 3 through 19."""

    _validate_streams(stream, provider_stream)
    if type(ports) is not WindowsRecoveryManagerPorts:
        _fail(WindowsRecoveryErrorCode.INPUT_INVALID)
    sequence = _validated_sequence(initial_chain, stream)
    chain = initial_chain

    while sequence < 17:
        if sequence <= 8:
            chain = _advance_environment_restore(
                sequence,
                stream=stream,
                provider_stream=provider_stream,
                package_root=package_root,
                ports=ports,
            )
        else:
            chain = _advance_certificate_and_runtime_restore(
                sequence,
                stream=stream,
                package_root=package_root,
                ports=ports,
            )
        advanced = _validated_sequence(chain, stream)
        if advanced != sequence + 1:
            _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
        sequence = advanced

    chain = persist_recovery_cleaned_generation_from_held_package_root(
        **_common_arguments(stream, ports),
        package_root=package_root,
        cleanup=ports.cleanup,
    )
    _validated_sequence(chain, stream)
    if chain.selection.tip.state is not EnvironmentJournalState.CLEANED:
        _fail(WindowsRecoveryErrorCode.VERIFY_FAILED)
    return chain


__all__ = [
    "WindowsRecoveryManagerPorts",
    "resume_persisted_rollback_from_held_package_root",
]
