"""Compose exact repair inputs through durable rollback-armed activation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import secrets
from typing import NoReturn, Protocol

from .runtime_target_resolution import BoundResolvedRepairTarget
from .target_contracts import ResolvedRepairTarget
from .windows_certificate_replacement import CertificateReplacementPlan
from .windows_environment_replacement import EnvironmentReplacementPlan
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery_backup import (
    protect_certificate_exact_state_backup,
    protect_environment_exact_state_backup,
)
from .windows_recovery_backup_preparation import (
    NativeRecoveryBackupNameSource,
    RecoveryBackupNameSource,
    persist_backup_preparing_generation,
)
from .windows_recovery_backup_storage import (
    activate_persisted_rollback_armed_generation,
    persist_backup_verified_generation,
    persist_prepared_recovery_backup_blobs,
    persist_rollback_armed_generation,
)
from .windows_recovery_backup_storage_native import (
    NativeWindowsRecoveryBackupBlobStorage,
)
from .windows_recovery_journal import (
    EnvironmentJournalState,
    JournalPointerDisposition,
    JournalStreamIdentity,
)
from .windows_recovery_journal_storage import PersistedEnvironmentJournalChain
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_recovery_readiness_authority import RollbackReadinessAuthority
from .windows_recovery_runtime_authority import (
    RollbackRuntimeRecoveryAuthority,
    derive_rollback_runtime_recovery_authority,
)
from .windows_repair_certificate_backup_native import (
    capture_repair_certificate_backup_while_target_held,
)
from .windows_repair_certificate_plan_native import (
    build_repair_certificate_plan_while_target_held,
)
from .windows_repair_environment_backup_native import (
    capture_repair_environment_backup_while_package_root_held,
)
from .windows_repair_environment_plan_native import (
    build_repair_environment_plan_while_package_root_held,
)
from .windows_repair_readiness_native import (
    capture_repair_readiness_authority_while_target_held,
)
from .windows_security import StableFileIdentity
from .windows_transaction_context import HeldWindowsTransactionContext


class NativeRepairRollbackPreparationErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_rollback_preparation_input_invalid"
    STATE_PENDING = "native_repair_rollback_preparation_state_pending"
    PREPARATION_FAILED = "native_repair_rollback_preparation_failed"


class NativeRepairRollbackPreparationError(RuntimeError):
    _MESSAGES = {
        NativeRepairRollbackPreparationErrorCode.INPUT_INVALID: (
            "The repair rollback preparation request is invalid."
        ),
        NativeRepairRollbackPreparationErrorCode.STATE_PENDING: (
            "Existing recovery state must be resolved before repair."
        ),
        NativeRepairRollbackPreparationErrorCode.PREPARATION_FAILED: (
            "Durable repair rollback preparation could not be completed."
        ),
    }

    def __init__(self, code: NativeRepairRollbackPreparationErrorCode) -> None:
        if type(code) is not NativeRepairRollbackPreparationErrorCode:
            raise ValueError("Unknown native rollback preparation error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairRollbackPreparationError(code={self.code.value!r})"


class RecoveryJournalIdSource(Protocol):
    def new_journal_id(self) -> str: ...


class NativeRecoveryJournalIdSource:
    def new_journal_id(self) -> str:
        return secrets.token_hex(16)


@dataclass(frozen=True, slots=True, repr=False)
class PreparedRepairRollback:
    target: ResolvedRepairTarget = field(repr=False)
    stream: JournalStreamIdentity = field(repr=False)
    environment_plan: EnvironmentReplacementPlan = field(repr=False)
    certificate_plan: CertificateReplacementPlan = field(repr=False)
    runtime_authority: RollbackRuntimeRecoveryAuthority = field(repr=False)
    readiness_authority: RollbackReadinessAuthority = field(repr=False)
    activated: PersistedEnvironmentJournalChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.target) is not ResolvedRepairTarget
            or type(self.stream) is not JournalStreamIdentity
            or type(self.environment_plan) is not EnvironmentReplacementPlan
            or type(self.certificate_plan) is not CertificateReplacementPlan
            or type(self.runtime_authority) is not RollbackRuntimeRecoveryAuthority
            or type(self.readiness_authority) is not RollbackReadinessAuthority
            or type(self.activated) is not PersistedEnvironmentJournalChain
            or self.runtime_authority.target_token_sha256
            != self.stream.target_token_sha256
            or self.target.target_token.digest_sha256 != self.stream.target_token_sha256
            or StableFileIdentity(
                self.target.package_root.volume_serial,
                self.target.package_root.file_id,
            )
            != self.stream.package_root_identity
            or self.runtime_authority.package_root_identity
            != self.stream.package_root_identity
            or self.readiness_authority.target_token_sha256
            != self.stream.target_token_sha256
            or self.readiness_authority.package_root_identity
            != self.stream.package_root_identity
            or len(self.activated.selection.generations) != 3
            or self.activated.selection.tip.state
            is not EnvironmentJournalState.ROLLBACK_ARMED
            or self.activated.selection.pointer_disposition
            is not JournalPointerDisposition.CURRENT
            or self.activated.selection.tip.stream != self.stream
        ):
            raise ValueError("Prepared repair rollback is invalid.")

    def __repr__(self) -> str:
        return "PreparedRepairRollback(state='rollback_armed', <redacted>)"


def _fail(code: NativeRepairRollbackPreparationErrorCode) -> NoReturn:
    raise NativeRepairRollbackPreparationError(code) from None


def prepare_native_windows_repair_rollback(
    owner: BoundResolvedRepairTarget,
    context: HeldWindowsTransactionContext,
    *,
    journal_id_source: RecoveryJournalIdSource | None = None,
    backup_name_source: RecoveryBackupNameSource | None = None,
    journal_storage: NativeWindowsJournalGenerationStorage | None = None,
    pointer_storage: NativeWindowsJournalPointerStorage | None = None,
    backup_storage: NativeWindowsRecoveryBackupBlobStorage | None = None,
) -> PreparedRepairRollback:
    """Persist exact encrypted backups and activate rollback before mutation."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(context) is not HeldWindowsTransactionContext
        or context.closed
    ):
        _fail(NativeRepairRollbackPreparationErrorCode.INPUT_INVALID)
    scan = context.recovery_scan
    if scan.mutation_blocked:
        _fail(NativeRepairRollbackPreparationErrorCode.STATE_PENDING)
    target = owner.target
    try:
        package_identity = StableFileIdentity(
            target.package_root.volume_serial,
            target.package_root.file_id,
        )
        context.assert_target_binding(
            target.target_token.digest_sha256,
            package_identity,
        )
        selected_id_source = (
            NativeRecoveryJournalIdSource()
            if journal_id_source is None
            else journal_id_source
        )
        journal_id = selected_id_source.new_journal_id()
        stream = JournalStreamIdentity(
            1,
            journal_id,
            target.target_token.digest_sha256,
            package_identity,
        )
    except Exception:
        _fail(NativeRepairRollbackPreparationErrorCode.INPUT_INVALID)
    selected_names = (
        NativeRecoveryBackupNameSource()
        if backup_name_source is None
        else backup_name_source
    )
    selected_journal = (
        NativeWindowsJournalGenerationStorage()
        if journal_storage is None
        else journal_storage
    )
    selected_pointer = (
        NativeWindowsJournalPointerStorage()
        if pointer_storage is None
        else pointer_storage
    )
    selected_backup = (
        NativeWindowsRecoveryBackupBlobStorage()
        if backup_storage is None
        else backup_storage
    )

    def prepare(
        package_root: PathHierarchyTrust,
        protected_root: ProtectedStateRoot,
    ) -> PreparedRepairRollback:
        environment = capture_repair_environment_backup_while_package_root_held(
            package_root,
            stream,
        )
        certificates = capture_repair_certificate_backup_while_target_held(
            owner,
            stream,
        )
        environment_plan = build_repair_environment_plan_while_package_root_held(
            package_root,
            target,
            environment,
        )
        certificate_plan = build_repair_certificate_plan_while_target_held(owner)
        runtime_authority = derive_rollback_runtime_recovery_authority(target)
        readiness_authority = capture_repair_readiness_authority_while_target_held(
            owner
        )
        environment_sealed = protect_environment_exact_state_backup(
            environment,
            protection=protected_root,
        )
        certificate_sealed = protect_certificate_exact_state_backup(
            certificates,
            protection=protected_root,
        )
        persist_backup_preparing_generation(
            environment_sealed,
            certificate_sealed,
            environment_plan=environment_plan,
            certificate_plan=certificate_plan,
            runtime_authority=runtime_authority,
            readiness_authority=readiness_authority,
            stream=stream,
            name_source=selected_names,
            root=protected_root,
            storage=selected_journal,
            backup_protection=protected_root,
            journal_protection=protected_root,
        )
        blobs = persist_prepared_recovery_backup_blobs(
            environment_sealed,
            certificate_sealed,
            stream=stream,
            root=protected_root,
            journal_storage=selected_journal,
            storage=selected_backup,
            backup_protection=protected_root,
            journal_protection=protected_root,
        )
        persist_backup_verified_generation(
            environment_sealed,
            certificate_sealed,
            blobs,
            stream=stream,
            root=protected_root,
            journal_storage=selected_journal,
            verification=selected_backup,
            backup_protection=protected_root,
            journal_protection=protected_root,
        )
        persist_rollback_armed_generation(
            stream=stream,
            root=protected_root,
            journal_storage=selected_journal,
            verification=selected_backup,
            journal_protection=protected_root,
        )
        activated = activate_persisted_rollback_armed_generation(
            stream=stream,
            root=protected_root,
            journal_storage=selected_journal,
            pointer_storage=selected_pointer,
            verification=selected_backup,
            journal_protection=protected_root,
        )
        return PreparedRepairRollback(
            owner.target,
            stream,
            environment_plan,
            certificate_plan,
            runtime_authority,
            readiness_authority,
            activated,
        )

    failed = False
    result: object = None
    try:
        owner.assert_unchanged()
        result = context.run_with_transaction_roots_held(prepare)
        owner.assert_unchanged()
    except Exception:
        failed = True
    if failed or type(result) is not PreparedRepairRollback:
        _fail(NativeRepairRollbackPreparationErrorCode.PREPARATION_FAILED)
    return result


__all__ = [
    "NativeRecoveryJournalIdSource",
    "NativeRepairRollbackPreparationError",
    "NativeRepairRollbackPreparationErrorCode",
    "PreparedRepairRollback",
    "RecoveryJournalIdSource",
    "prepare_native_windows_repair_rollback",
]
