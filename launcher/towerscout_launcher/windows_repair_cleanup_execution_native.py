"""Delete exact committed-repair backups and persist terminal cleanup state."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
from typing import Any, cast, NoReturn, Protocol

from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery import RecoveryCleanupEvidence
from .windows_recovery_cleanup_native import NativeWindowsRecoveryCleanup
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    PersistedEnvironmentJournalChain,
    RecoveryJournalStorageError,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_repair_terminal_verification_native import CommittedRepair
from .windows_repair_transaction_journal import (
    RepairTransactionGeneration,
    RepairTransactionJournalError,
    RepairTransactionPointerDisposition,
    RepairTransactionState,
    RepairTransitionRecord,
    protect_repair_transaction_generation,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
    append_persisted_repair_transaction_generation_from_held_root,
    ensure_persisted_repair_transaction_pointer_from_held_root,
)
from .windows_transaction_context import HeldWindowsTransactionContext

_PENDING_DOMAIN = b"TowerScout.RepairCleanupPending.v1"
_CLEANED_DOMAIN = b"TowerScout.RepairCleaned.v1"


class NativeRepairCleanupExecutionErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_cleanup_execution_input_invalid"
    CLEANUP_PENDING = "native_repair_cleanup_pending"
    CLEANUP_FAILED = "native_repair_cleanup_execution_failed"


class NativeRepairCleanupExecutionError(RuntimeError):
    _MESSAGES = {
        NativeRepairCleanupExecutionErrorCode.INPUT_INVALID: (
            "The repair cleanup request is invalid."
        ),
        NativeRepairCleanupExecutionErrorCode.CLEANUP_PENDING: (
            "Repair succeeded, but protected recovery cleanup remains pending."
        ),
        NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED: (
            "The repair cleanup state could not be persisted safely."
        ),
    }

    def __init__(self, code: NativeRepairCleanupExecutionErrorCode) -> None:
        if type(code) is not NativeRepairCleanupExecutionErrorCode:
            raise ValueError("Unknown native repair cleanup error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairCleanupExecutionError(code={self.code.value!r})"


class RepairCleanupPort(Protocol):
    def cleanup_committed_repair_artifacts_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        rollback: PersistedEnvironmentJournalChain,
        forward: PersistedRepairTransactionChain,
    ) -> RecoveryCleanupEvidence: ...


def _fail(code: NativeRepairCleanupExecutionErrorCode) -> NoReturn:
    raise NativeRepairCleanupExecutionError(code) from None


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _evidence(domain: bytes, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    _add(digest, domain)
    for value in values:
        _add(digest, value.encode("ascii", errors="strict"))
    return digest.hexdigest()


def _append(
    root_path: str,
    current: PersistedRepairTransactionChain,
    state: RepairTransactionState,
    evidence_sha256: str,
    *,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: ProtectedStateRoot,
) -> PersistedRepairTransactionChain:
    try:
        stream = current.selection.tip.stream
        persisted = ensure_persisted_repair_transaction_pointer_from_held_root(
            root_path,
            stream,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
        if (
            persisted is None
            or persisted.selection.generation_sha256s
            != current.selection.generation_sha256s
            or persisted.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
        ):
            raise ValueError
        previous = persisted.selection.tip_generation_sha256
        generation = RepairTransactionGeneration(
            1,
            stream,
            len(persisted.selection.generations) + 1,
            previous,
            state,
            RepairTransitionRecord(
                1,
                previous,
                stream.package_root_identity,
                evidence_sha256,
            ),
        )
        sealed = protect_repair_transaction_generation(
            generation,
            protection=protection,
        )
        append_persisted_repair_transaction_generation_from_held_root(
            root_path,
            sealed,
            stream=stream,
            storage=generation_storage,
            protection=protection,
        )
        selected = ensure_persisted_repair_transaction_pointer_from_held_root(
            root_path,
            stream,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    except (RepairTransactionJournalError, RecoveryJournalStorageError, ValueError):
        _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED)
    if selected is None or selected.selection.tip != generation:
        _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED)
    return selected


@dataclass(frozen=True, slots=True, repr=False)
class CleanedRepair:
    committed: CommittedRepair = field(repr=False)
    forward: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.committed) is not CommittedRepair
            or type(self.forward) is not PersistedRepairTransactionChain
            or len(self.forward.selection.generations) != 15
            or self.forward.selection.tip.state is not RepairTransactionState.CLEANED
            or self.forward.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.forward.selection.generation_sha256s[:14]
            != self.committed.forward.selection.generation_sha256s
        ):
            raise ValueError("Cleaned repair state is invalid.")

    def __repr__(self) -> str:
        return "CleanedRepair(state='cleaned', <redacted>)"


def cleanup_committed_native_windows_repair(
    context: HeldWindowsTransactionContext,
    committed: CommittedRepair,
    *,
    cleanup: RepairCleanupPort | None = None,
    journal_storage: JournalGenerationStoragePort | None = None,
    pointer_storage: JournalPointerStoragePort | None = None,
) -> CleanedRepair:
    """Remove exact encrypted backups or durably record cleanup pending."""

    if (
        type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(committed) is not CommittedRepair
    ):
        _fail(NativeRepairCleanupExecutionErrorCode.INPUT_INVALID)
    stream = committed.forward.selection.tip.stream
    rollback = committed.started.stopped.environment.certificates.prepared.rollback
    selected_cleanup = NativeWindowsRecoveryCleanup() if cleanup is None else cleanup
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
    result: CleanedRepair | None = None
    cleanup_pending = False
    try:
        context.assert_target_binding(
            stream.target_token_sha256,
            stream.package_root_identity,
        )

        def remove(
            package_root: PathHierarchyTrust,
            protected_root: ProtectedStateRoot,
        ) -> CleanedRepair | None:
            def while_root_held(root_path: str) -> CleanedRepair | None:
                nonlocal cleanup_pending
                try:
                    evidence = selected_cleanup.cleanup_committed_repair_artifacts_while_package_root_held(
                        package_root,
                        root_path,
                        rollback.activated,
                        committed.forward,
                    )
                except BaseException as error:
                    if not isinstance(error, Exception):
                        raise
                    pending = _append(
                        root_path,
                        committed.forward,
                        RepairTransactionState.RECOVERY_CLEANUP_PENDING,
                        _evidence(
                            _PENDING_DOMAIN,
                            (
                                stream.target_token_sha256,
                                committed.forward.selection.tip_generation_sha256,
                            ),
                        ),
                        generation_storage=selected_journal,
                        pointer_storage=selected_pointer,
                        protection=protected_root,
                    )
                    if (
                        pending.selection.tip.state
                        is not RepairTransactionState.RECOVERY_CLEANUP_PENDING
                    ):
                        _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED)
                    cleanup_pending = True
                    return None
                if type(evidence) is not RecoveryCleanupEvidence:
                    _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED)
                cleaned = _append(
                    root_path,
                    committed.forward,
                    RepairTransactionState.CLEANED,
                    _evidence(
                        _CLEANED_DOMAIN,
                        (
                            stream.target_token_sha256,
                            evidence.cleanup_evidence_sha256,
                        ),
                    ),
                    generation_storage=selected_journal,
                    pointer_storage=selected_pointer,
                    protection=protected_root,
                )
                return CleanedRepair(committed, cleaned)

            return cast(
                CleanedRepair | None,
                protected_root.run_journal_storage(while_root_held),
            )

        result = context.run_with_transaction_roots_held(remove)
    except NativeRepairCleanupExecutionError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED)
    if cleanup_pending:
        _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_PENDING)
    if type(result) is not CleanedRepair:
        _fail(NativeRepairCleanupExecutionErrorCode.CLEANUP_FAILED)
    return result


__all__ = [
    "CleanedRepair",
    "NativeRepairCleanupExecutionError",
    "NativeRepairCleanupExecutionErrorCode",
    "cleanup_committed_native_windows_repair",
]
