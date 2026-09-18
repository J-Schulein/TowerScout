"""Apply the journal-bound package environment and link it forward."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import secrets
from typing import NoReturn, Protocol

from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_environment_promotion_native import (
    NativeWindowsEnvironmentPromotionStorage,
)
from .windows_environment_promotion_storage import (
    persist_environment_applied_generation,
)
from .windows_environment_replacement_journal import (
    PersistedEnvironmentReplacementJournal,
)
from .windows_environment_replacement_storage import (
    stage_or_resume_persisted_environment_candidate,
)
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_recovery_journal import (
    BackupPreparingRecord,
    EnvironmentJournalState,
    JournalPointerDisposition,
    JournalStreamIdentity,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    PersistedEnvironmentJournalChain,
    load_persisted_environment_journal_chain_from_held_root,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_repair_certificate_execution_native import (
    AppliedRepairCertificates,
)
from .windows_repair_provider_linkage import persist_forward_provider_linkage
from .windows_repair_transaction_journal import (
    RepairTransactionPointerDisposition,
    RepairTransactionState,
    authenticate_terminal_provider_link,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
)
from .windows_transaction_context import HeldWindowsTransactionContext


class NativeRepairEnvironmentExecutionErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_environment_execution_input_invalid"
    APPLY_FAILED = "native_repair_environment_execution_apply_failed"


class NativeRepairEnvironmentExecutionError(RuntimeError):
    _MESSAGES = {
        NativeRepairEnvironmentExecutionErrorCode.INPUT_INVALID: (
            "The repair environment execution request is invalid."
        ),
        NativeRepairEnvironmentExecutionErrorCode.APPLY_FAILED: (
            "The repair environment could not be applied safely."
        ),
    }

    def __init__(self, code: NativeRepairEnvironmentExecutionErrorCode) -> None:
        if type(code) is not NativeRepairEnvironmentExecutionErrorCode:
            raise ValueError("Unknown native environment execution error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairEnvironmentExecutionError(code={self.code.value!r})"


class ProviderJournalIdSource(Protocol):
    def new_provider_journal_id(self) -> str: ...


class NativeProviderJournalIdSource:
    def new_provider_journal_id(self) -> str:
        return secrets.token_hex(16)


@dataclass(frozen=True, slots=True, repr=False)
class AppliedRepairEnvironment:
    certificates: AppliedRepairCertificates = field(repr=False)
    provider_stream: JournalStreamIdentity = field(repr=False)
    provider: PersistedEnvironmentJournalChain = field(repr=False)
    forward: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.certificates) is not AppliedRepairCertificates
            or type(self.provider_stream) is not JournalStreamIdentity
            or type(self.provider) is not PersistedEnvironmentJournalChain
            or type(self.forward) is not PersistedRepairTransactionChain
            or self.provider.selection.tip.stream != self.provider_stream
            or len(self.provider.selection.generations) != 4
            or self.provider.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_APPLIED
            or self.provider.selection.pointer_disposition
            is not JournalPointerDisposition.CURRENT
            or len(self.forward.selection.generations) != 8
            or self.forward.selection.tip.state
            is not RepairTransactionState.ENVIRONMENT_APPLIED
            or self.forward.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.forward.selection.tip.stream != self.certificates.prepared.stream
        ):
            raise ValueError("Applied repair environment state is invalid.")
        authenticate_terminal_provider_link(self.forward.selection, self.provider)

    def __repr__(self) -> str:
        return "AppliedRepairEnvironment(state='environment_applied', <redacted>)"


def _fail(code: NativeRepairEnvironmentExecutionErrorCode) -> NoReturn:
    raise NativeRepairEnvironmentExecutionError(code) from None


def _original_observation(
    certificates: AppliedRepairCertificates,
) -> EnvironmentDestinationObservation:
    record = certificates.prepared.rollback.activated.selection.generations[0].record
    if type(record) is not BackupPreparingRecord:
        _fail(NativeRepairEnvironmentExecutionErrorCode.INPUT_INVALID)
    try:
        if not record.environment_present:
            return EnvironmentDestinationObservation(False)
        return EnvironmentDestinationObservation(
            True,
            record.environment_original_identity,
            record.environment_sha256,
            (
                len(certificates.prepared.rollback.environment_plan.original_contents)
                if certificates.prepared.rollback.environment_plan.original_contents
                is not None
                else None
            ),
            record.environment_file_attributes,
            record.environment_security_descriptor_sha256,
        )
    except ValueError:
        _fail(NativeRepairEnvironmentExecutionErrorCode.INPUT_INVALID)


def apply_native_windows_repair_environment(
    owner: BoundResolvedRepairTarget,
    context: HeldWindowsTransactionContext,
    certificates: AppliedRepairCertificates,
    *,
    journal_id_source: ProviderJournalIdSource | None = None,
    journal_storage: JournalGenerationStoragePort | None = None,
    pointer_storage: JournalPointerStoragePort | None = None,
) -> AppliedRepairEnvironment:
    """Stage, promote, and durably link the exact provider environment."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(certificates) is not AppliedRepairCertificates
    ):
        _fail(NativeRepairEnvironmentExecutionErrorCode.INPUT_INVALID)
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
    try:
        selected_ids = (
            NativeProviderJournalIdSource()
            if journal_id_source is None
            else journal_id_source
        )
        provider_id = selected_ids.new_provider_journal_id()
        forward_stream = certificates.prepared.stream
        if provider_id in {
            forward_stream.journal_id,
            forward_stream.rollback_journal_id,
        }:
            raise ValueError
        provider_stream = JournalStreamIdentity(
            1,
            provider_id,
            forward_stream.target_token_sha256,
            forward_stream.package_root_identity,
        )
        original = _original_observation(certificates)
    except NativeRepairEnvironmentExecutionError:
        raise
    except Exception:
        _fail(NativeRepairEnvironmentExecutionErrorCode.INPUT_INVALID)

    def apply(
        package_root: PathHierarchyTrust,
        protected_root: ProtectedStateRoot,
    ) -> AppliedRepairEnvironment:
        journal = PersistedEnvironmentReplacementJournal(
            stream=provider_stream,
            root=protected_root,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            protection=protected_root,
        )
        stage_or_resume_persisted_environment_candidate(
            certificates.prepared.rollback.environment_plan,
            original,
            package_root,
            journal,
        )
        provider_staged = protected_root.run_journal_storage(
            lambda root_path: load_persisted_environment_journal_chain_from_held_root(
                root_path,
                provider_stream,
                storage=selected_journal,
                protection=protected_root,
            )
        )
        if (
            type(provider_staged) is not PersistedEnvironmentJournalChain
            or len(provider_staged.selection.generations) != 3
            or provider_staged.selection.tip.state
            is not EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED
        ):
            _fail(NativeRepairEnvironmentExecutionErrorCode.APPLY_FAILED)
        linked = persist_forward_provider_linkage(
            certificates.forward,
            provider_staged,
            root=protected_root,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            protection=protected_root,
        )
        provider_applied = persist_environment_applied_generation(
            stream=provider_stream,
            package_root=package_root,
            root=protected_root,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            journal_protection=protected_root,
            promotion=NativeWindowsEnvironmentPromotionStorage(),
        )
        linked = persist_forward_provider_linkage(
            linked,
            provider_applied,
            root=protected_root,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            protection=protected_root,
        )
        return AppliedRepairEnvironment(
            certificates,
            provider_stream,
            provider_applied,
            linked,
        )

    failed = False
    result: object = None
    try:
        context.assert_target_binding(
            certificates.prepared.stream.target_token_sha256,
            certificates.prepared.stream.package_root_identity,
        )
        owner.assert_unchanged()
        result = context.run_with_transaction_roots(apply)
    except Exception:
        failed = True
    if failed or type(result) is not AppliedRepairEnvironment:
        _fail(NativeRepairEnvironmentExecutionErrorCode.APPLY_FAILED)
    return result


__all__ = [
    "AppliedRepairEnvironment",
    "NativeProviderJournalIdSource",
    "NativeRepairEnvironmentExecutionError",
    "NativeRepairEnvironmentExecutionErrorCode",
    "ProviderJournalIdSource",
    "apply_native_windows_repair_environment",
]
