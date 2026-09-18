"""Stage the first durable forward repair state after rollback is armed."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import secrets
from typing import NoReturn, Protocol

from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery_certificate_storage_native import (
    NativeWindowsRepairCertificateTempStorage,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_repair_certificate_staging import (
    NativeRepairCertificateTempNameSource,
    RepairCertificateTempNameSource,
    stage_repair_certificate_candidates,
)
from .windows_repair_rollback_preparation_native import PreparedRepairRollback
from .windows_repair_transaction_journal import (
    RepairTransactionPointerDisposition,
    RepairTransactionState,
    RepairTransactionStreamIdentity,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
)
from .windows_transaction_context import HeldWindowsTransactionContext


class NativeRepairForwardPreparationErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_forward_preparation_input_invalid"
    PREPARATION_FAILED = "native_repair_forward_preparation_failed"


class NativeRepairForwardPreparationError(RuntimeError):
    _MESSAGES = {
        NativeRepairForwardPreparationErrorCode.INPUT_INVALID: (
            "The forward repair preparation request is invalid."
        ),
        NativeRepairForwardPreparationErrorCode.PREPARATION_FAILED: (
            "The forward repair state could not be prepared durably."
        ),
    }

    def __init__(self, code: NativeRepairForwardPreparationErrorCode) -> None:
        if type(code) is not NativeRepairForwardPreparationErrorCode:
            raise ValueError("Unknown native forward preparation error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairForwardPreparationError(code={self.code.value!r})"


class ForwardJournalIdSource(Protocol):
    def new_forward_journal_id(self) -> str: ...


class NativeForwardJournalIdSource:
    def new_forward_journal_id(self) -> str:
        return secrets.token_hex(16)


@dataclass(frozen=True, slots=True, repr=False)
class PreparedRepairForward:
    rollback: PreparedRepairRollback = field(repr=False)
    stream: RepairTransactionStreamIdentity = field(repr=False)
    staged: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.rollback) is not PreparedRepairRollback
            or type(self.stream) is not RepairTransactionStreamIdentity
            or type(self.staged) is not PersistedRepairTransactionChain
            or self.stream.rollback_journal_id != self.rollback.stream.journal_id
            or self.stream.rollback_armed_generation_sha256
            != self.rollback.activated.selection.tip_generation_sha256
            or self.stream.target_token_sha256
            != self.rollback.stream.target_token_sha256
            or self.stream.package_root_identity
            != self.rollback.stream.package_root_identity
            or len(self.staged.selection.generations) != 3
            or self.staged.selection.tip.state
            is not RepairTransactionState.CERTIFICATE_TEMP_VERIFIED
            or self.staged.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.staged.selection.tip.stream != self.stream
        ):
            raise ValueError("Prepared repair forward state is invalid.")

    def __repr__(self) -> str:
        return "PreparedRepairForward(state='certificate_temp_verified', <redacted>)"


def _fail(code: NativeRepairForwardPreparationErrorCode) -> NoReturn:
    raise NativeRepairForwardPreparationError(code) from None


def prepare_native_windows_repair_forward(
    owner: BoundResolvedRepairTarget,
    context: HeldWindowsTransactionContext,
    rollback: PreparedRepairRollback,
    *,
    journal_id_source: ForwardJournalIdSource | None = None,
    certificate_name_source: RepairCertificateTempNameSource | None = None,
    journal_storage: NativeWindowsJournalGenerationStorage | None = None,
    pointer_storage: NativeWindowsJournalPointerStorage | None = None,
    certificate_storage: NativeWindowsRepairCertificateTempStorage | None = None,
) -> PreparedRepairForward:
    """Create and verify forward candidate temps without target mutation."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(rollback) is not PreparedRepairRollback
    ):
        _fail(NativeRepairForwardPreparationErrorCode.INPUT_INVALID)
    try:
        context.assert_target_binding(
            rollback.stream.target_token_sha256,
            rollback.stream.package_root_identity,
        )
        selected_ids = (
            NativeForwardJournalIdSource()
            if journal_id_source is None
            else journal_id_source
        )
        journal_id = selected_ids.new_forward_journal_id()
        stream = RepairTransactionStreamIdentity(
            1,
            journal_id,
            rollback.stream.journal_id,
            rollback.activated.selection.tip_generation_sha256,
            rollback.stream.target_token_sha256,
            rollback.stream.package_root_identity,
        )
    except Exception:
        _fail(NativeRepairForwardPreparationErrorCode.INPUT_INVALID)
    selected_names = (
        NativeRepairCertificateTempNameSource()
        if certificate_name_source is None
        else certificate_name_source
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
    selected_certificates = (
        NativeWindowsRepairCertificateTempStorage()
        if certificate_storage is None
        else certificate_storage
    )

    def stage(
        _package_root: PathHierarchyTrust,
        protected_root: ProtectedStateRoot,
    ) -> PreparedRepairForward:
        staged = stage_repair_certificate_candidates(
            stream,
            rollback.activated,
            rollback.certificate_plan,
            root=protected_root,
            name_source=selected_names,
            certificate_storage=selected_certificates,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            protection=protected_root,
        )
        return PreparedRepairForward(rollback, stream, staged)

    failed = False
    result: object = None
    try:
        owner.assert_unchanged()
        result = context.run_with_transaction_roots_held(stage)
        owner.assert_unchanged()
    except Exception:
        failed = True
    if failed or type(result) is not PreparedRepairForward:
        _fail(NativeRepairForwardPreparationErrorCode.PREPARATION_FAILED)
    return result


__all__ = [
    "ForwardJournalIdSource",
    "NativeForwardJournalIdSource",
    "NativeRepairForwardPreparationError",
    "NativeRepairForwardPreparationErrorCode",
    "PreparedRepairForward",
    "prepare_native_windows_repair_forward",
]
