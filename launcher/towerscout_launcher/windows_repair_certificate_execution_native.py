"""Apply exact staged certificates after durable rollback is current."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn

from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery_certificate_storage_native import (
    NativeWindowsRepairCertificateTempStorage,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_repair_certificate_apply import apply_repair_certificates
from .windows_repair_certificate_cleanup import (
    cleanup_applied_repair_certificate_candidates,
)
from .windows_repair_forward_preparation_native import PreparedRepairForward
from .windows_repair_transaction_journal import (
    RepairTransactionPointerDisposition,
    RepairTransactionState,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
)
from .windows_transaction_context import HeldWindowsTransactionContext


class NativeRepairCertificateExecutionErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_certificate_execution_input_invalid"
    APPLY_FAILED = "native_repair_certificate_execution_apply_failed"


class NativeRepairCertificateExecutionError(RuntimeError):
    _MESSAGES = {
        NativeRepairCertificateExecutionErrorCode.INPUT_INVALID: (
            "The repair certificate execution request is invalid."
        ),
        NativeRepairCertificateExecutionErrorCode.APPLY_FAILED: (
            "The repair certificates could not be applied safely."
        ),
    }

    def __init__(self, code: NativeRepairCertificateExecutionErrorCode) -> None:
        if type(code) is not NativeRepairCertificateExecutionErrorCode:
            raise ValueError("Unknown native certificate execution error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairCertificateExecutionError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class AppliedRepairCertificates:
    prepared: PreparedRepairForward = field(repr=False)
    forward: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.prepared) is not PreparedRepairForward
            or type(self.forward) is not PersistedRepairTransactionChain
            or len(self.forward.selection.generations) != 4
            or self.forward.selection.tip.state
            is not RepairTransactionState.CERTIFICATES_APPLIED
            or self.forward.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.forward.selection.tip.stream != self.prepared.stream
            or self.forward.selection.generation_sha256s[:3]
            != self.prepared.staged.selection.generation_sha256s
        ):
            raise ValueError("Applied repair certificate state is invalid.")

    def __repr__(self) -> str:
        return "AppliedRepairCertificates(state='certificates_applied', <redacted>)"


def _fail(code: NativeRepairCertificateExecutionErrorCode) -> NoReturn:
    raise NativeRepairCertificateExecutionError(code) from None


def apply_native_windows_repair_certificates(
    owner: BoundResolvedRepairTarget,
    context: HeldWindowsTransactionContext,
    prepared: PreparedRepairForward,
    *,
    journal_storage: JournalGenerationStoragePort | None = None,
    pointer_storage: JournalPointerStoragePort | None = None,
    certificate_storage: NativeWindowsRepairCertificateTempStorage | None = None,
) -> AppliedRepairCertificates:
    """Apply both candidates and delete only their exact protected-root temps."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(prepared) is not PreparedRepairForward
    ):
        _fail(NativeRepairCertificateExecutionErrorCode.INPUT_INVALID)
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

    def apply(
        _package_root: PathHierarchyTrust,
        protected_root: ProtectedStateRoot,
    ) -> AppliedRepairCertificates:
        forward = apply_repair_certificates(
            owner,
            prepared.rollback.activated,
            prepared.staged,
            prepared.rollback.certificate_plan,
            root=protected_root,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            protection=protected_root,
        )
        cleanup_applied_repair_certificate_candidates(
            forward,
            prepared.rollback.certificate_plan,
            root=protected_root,
            certificate_storage=selected_certificates,
            generation_storage=selected_journal,
            pointer_storage=selected_pointer,
            protection=protected_root,
        )
        return AppliedRepairCertificates(prepared, forward)

    failed = False
    result: object = None
    try:
        context.assert_target_binding(
            prepared.stream.target_token_sha256,
            prepared.stream.package_root_identity,
        )
        owner.assert_unchanged()
        result = context.run_with_transaction_roots_held(apply)
        owner.assert_unchanged()
    except Exception:
        failed = True
    if failed or type(result) is not AppliedRepairCertificates:
        _fail(NativeRepairCertificateExecutionErrorCode.APPLY_FAILED)
    return result


__all__ = [
    "AppliedRepairCertificates",
    "NativeRepairCertificateExecutionError",
    "NativeRepairCertificateExecutionErrorCode",
    "apply_native_windows_repair_certificates",
]
