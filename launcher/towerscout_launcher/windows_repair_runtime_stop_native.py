"""Durably stop/remove the exact pre-repair container after provider apply."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
from typing import Any, cast, NoReturn

from .runtime_target_observation import ObservationOperation
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    RecoveryJournalStorageError,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_repair_environment_execution_native import AppliedRepairEnvironment
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

_INTENT_DOMAIN = b"TowerScout.RepairRuntimeStopping.v1"
_STOPPED_DOMAIN = b"TowerScout.RepairRuntimeStopped.v1"


class NativeRepairRuntimeStopErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_runtime_stop_input_invalid"
    STOP_FAILED = "native_repair_runtime_stop_failed"


class NativeRepairRuntimeStopError(RuntimeError):
    _MESSAGES = {
        NativeRepairRuntimeStopErrorCode.INPUT_INVALID: (
            "The repair runtime stop request is invalid."
        ),
        NativeRepairRuntimeStopErrorCode.STOP_FAILED: (
            "The exact repair runtime could not be stopped safely."
        ),
    }

    def __init__(self, code: NativeRepairRuntimeStopErrorCode) -> None:
        if type(code) is not NativeRepairRuntimeStopErrorCode:
            raise ValueError("Unknown native repair runtime stop error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairRuntimeStopError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class StoppedRepairRuntime:
    environment: AppliedRepairEnvironment = field(repr=False)
    forward: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.environment) is not AppliedRepairEnvironment
            or type(self.forward) is not PersistedRepairTransactionChain
            or len(self.forward.selection.generations) != 10
            or self.forward.selection.tip.state
            is not RepairTransactionState.RUNTIME_STOPPED
            or self.forward.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.forward.selection.generation_sha256s[:8]
            != self.environment.forward.selection.generation_sha256s
        ):
            raise ValueError("Stopped repair runtime state is invalid.")

    def __repr__(self) -> str:
        return "StoppedRepairRuntime(state='runtime_stopped', <redacted>)"


def _fail(code: NativeRepairRuntimeStopErrorCode) -> NoReturn:
    raise NativeRepairRuntimeStopError(code) from None


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
    stream = current.selection.tip.stream
    try:
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
        _fail(NativeRepairRuntimeStopErrorCode.STOP_FAILED)
    if selected is None or selected.selection.tip != generation:
        _fail(NativeRepairRuntimeStopErrorCode.STOP_FAILED)
    return selected


def stop_native_windows_repair_runtime(
    owner: BoundResolvedRepairTarget,
    context: HeldWindowsTransactionContext,
    environment: AppliedRepairEnvironment,
    *,
    journal_storage: JournalGenerationStoragePort | None = None,
    pointer_storage: JournalPointerStoragePort | None = None,
) -> StoppedRepairRuntime:
    """Persist stop intent, remove only the exact container, and attest it."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(environment) is not AppliedRepairEnvironment
    ):
        _fail(NativeRepairRuntimeStopErrorCode.INPUT_INVALID)
    target = environment.certificates.prepared.rollback.target
    stream = environment.forward.selection.tip.stream
    if owner.target is not target or target.target_token.digest_sha256 != (
        stream.target_token_sha256
    ):
        _fail(NativeRepairRuntimeStopErrorCode.INPUT_INVALID)
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

    def stop(
        _package_root: PathHierarchyTrust,
        protected_root: ProtectedStateRoot,
    ) -> StoppedRepairRuntime:
        def while_root_held(root_path: str) -> StoppedRepairRuntime:
            intent = _append(
                root_path,
                environment.forward,
                RepairTransactionState.RUNTIME_STOPPING,
                _evidence(
                    _INTENT_DOMAIN,
                    (
                        stream.target_token_sha256,
                        target.container.private_inspect_sha256,
                        hashlib.sha256(
                            target.container.container_id.encode("ascii")
                        ).hexdigest(),
                    ),
                ),
                generation_storage=selected_journal,
                pointer_storage=selected_pointer,
                protection=protected_root,
            )
            executed = owner.execute_scoped_repair_container_removal()
            if (
                type(executed) is not TargetObservationProcessResult
                or executed.operation
                is not ObservationOperation.RUNTIME_REMOVE_EXACT_CONTAINER
                or executed.exit_code != 0
                or not owner.closed
            ):
                _fail(NativeRepairRuntimeStopErrorCode.STOP_FAILED)
            stopped = _append(
                root_path,
                intent,
                RepairTransactionState.RUNTIME_STOPPED,
                _evidence(
                    _STOPPED_DOMAIN,
                    (
                        stream.target_token_sha256,
                        executed.authority_sha256,
                        executed.stderr_sha256,
                        str(executed.exit_code),
                    ),
                ),
                generation_storage=selected_journal,
                pointer_storage=selected_pointer,
                protection=protected_root,
            )
            return StoppedRepairRuntime(environment, stopped)

        return cast(
            StoppedRepairRuntime,
            protected_root.run_journal_storage(while_root_held),
        )

    failed = False
    result: object = None
    try:
        context.assert_target_binding(
            stream.target_token_sha256,
            stream.package_root_identity,
        )
        result = context.run_with_transaction_roots(stop)
    except Exception:
        failed = True
    if failed or type(result) is not StoppedRepairRuntime:
        _fail(NativeRepairRuntimeStopErrorCode.STOP_FAILED)
    return result


__all__ = [
    "NativeRepairRuntimeStopError",
    "NativeRepairRuntimeStopErrorCode",
    "StoppedRepairRuntime",
    "stop_native_windows_repair_runtime",
]
