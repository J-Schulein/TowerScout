"""Verify every intended repair outcome and durably commit success."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
import time
from typing import Any, Callable, cast, NoReturn, Protocol

from .runtime_target_observation import (
    CertificateTargetDestination,
    ObservationOperation,
)
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_certificate_replacement import CertificateReplacementPlan
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import ProtectedStateRoot
from .windows_recovery import CertificateDestinationRestoreEvidence
from .windows_recovery_certificate_restore_native import (
    observe_certificate_destination_while_target_held,
)
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_recovery_environment_restore_native import (
    NativeWindowsEnvironmentRestoreStorage,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    RecoveryJournalStorageError,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_repair_runtime_start_native import StartedRepairRuntime
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
from .windows_security import StableFileIdentity
from .windows_transaction_context import HeldWindowsTransactionContext

_VERIFYING_DOMAIN = b"TowerScout.RepairSuccessVerifying.v1"
_COMMITTED_DOMAIN = b"TowerScout.RepairCommitted.v1"
_READINESS_TIMEOUT_SECONDS = 180.0
_READINESS_POLL_SECONDS = 2.0


class NativeRepairTerminalVerificationErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_terminal_verification_input_invalid"
    VERIFY_FAILED = "native_repair_terminal_verification_failed"


class NativeRepairTerminalVerificationError(RuntimeError):
    _MESSAGES = {
        NativeRepairTerminalVerificationErrorCode.INPUT_INVALID: (
            "The terminal repair verification request is invalid."
        ),
        NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED: (
            "The repaired state could not be verified safely."
        ),
    }

    def __init__(self, code: NativeRepairTerminalVerificationErrorCode) -> None:
        if type(code) is not NativeRepairTerminalVerificationErrorCode:
            raise ValueError("Unknown terminal repair verification error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairTerminalVerificationError(code={self.code.value!r})"


class EnvironmentObservationPort(Protocol):
    def observe_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        package_root_identity: StableFileIdentity,
    ) -> EnvironmentDestinationObservation: ...


class CertificateObservationPort(Protocol):
    def __call__(
        self,
        owner: BoundResolvedRepairTarget,
        destination: CertificateTargetDestination,
    ) -> CertificateDestinationRestoreEvidence: ...


def _fail(code: NativeRepairTerminalVerificationErrorCode) -> NoReturn:
    raise NativeRepairTerminalVerificationError(code) from None


def _close(owner: BoundResolvedRepairTarget | None) -> bool:
    if owner is None or owner.closed:
        return False
    failed = False
    try:
        owner.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    return failed or not owner.closed


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
        _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
    if selected is None or selected.selection.tip != generation:
        _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
    return selected


def _environment_matches(
    observed: EnvironmentDestinationObservation,
    started: StartedRepairRuntime,
) -> bool:
    record = started.stopped.environment.provider.selection.tip.record
    return (
        type(observed) is EnvironmentDestinationObservation
        and observed.present
        and observed.identity == record.candidate_identity
        and observed.sha256 == record.candidate_sha256
        and observed.size == record.candidate_size
        and observed.file_attributes == record.candidate_file_attributes
        and observed.security_descriptor_sha256
        == record.candidate_security_descriptor_sha256
    )


def _certificate_matches(
    observed: CertificateDestinationRestoreEvidence,
    sha256: str,
    size: int,
    mode: int,
) -> bool:
    return (
        type(observed) is CertificateDestinationRestoreEvidence
        and observed.present
        and observed.contents_sha256 == sha256
        and observed.size == size
        and observed.mode == mode
    )


def _result(
    value: object,
    operation: ObservationOperation,
) -> TargetObservationProcessResult:
    if (
        not isinstance(value, TargetObservationProcessResult)
        or type(value) is not TargetObservationProcessResult
        or value.operation is not operation
        or value.exit_code != 0
    ):
        _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
    return cast(TargetObservationProcessResult, value)


def _wait_for_readiness(
    owner: BoundResolvedRepairTarget,
    *,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
) -> TargetObservationProcessResult:
    deadline = clock() + _READINESS_TIMEOUT_SECONDS
    while True:
        value = owner.execute_scoped_process(
            "rollback_readiness_probe",
            (owner.target.container.container_id,),
        )
        if type(value) is not TargetObservationProcessResult:
            _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
        result = cast(TargetObservationProcessResult, value)
        if result.exit_code == 0:
            if result.stdout not in {
                b"setup_required\n",
                b"degraded\n",
                b"ready\n",
            }:
                _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
            return result
        if result.stdout or clock() >= deadline:
            _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
        sleeper(min(_READINESS_POLL_SECONDS, max(0.0, deadline - clock())))


def _verify(
    package_root: PathHierarchyTrust,
    started: StartedRepairRuntime,
    *,
    environment: EnvironmentObservationPort,
    certificate_observer: CertificateObservationPort,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
) -> str:
    owner = started.owner
    stream = started.forward.selection.tip.stream
    plan: CertificateReplacementPlan = (
        started.stopped.environment.certificates.prepared.rollback.certificate_plan
    )
    try:
        owner.assert_unchanged()
        observed_environment = environment.observe_environment_while_package_root_held(
            package_root,
            stream.package_root_identity,
        )
        if not _environment_matches(observed_environment, started):
            raise ValueError
        local_ca = certificate_observer(
            owner,
            CertificateTargetDestination.LOCAL_CA,
        )
        ca_bundle = certificate_observer(
            owner,
            CertificateTargetDestination.CA_BUNDLE,
        )
        if not _certificate_matches(
            local_ca,
            plan.local_ca_sha256,
            len(plan.local_ca_contents),
            plan.local_ca_mode,
        ) or not _certificate_matches(
            ca_bundle,
            plan.ca_bundle_sha256,
            len(plan.ca_bundle_contents),
            plan.ca_bundle_mode,
        ):
            raise ValueError
        owner.assert_unchanged()
        readiness = _wait_for_readiness(
            owner,
            clock=clock,
            sleeper=sleeper,
        )
        provider = _result(
            owner.execute_scoped_process(
                "rollback_provider_probe",
                (owner.target.container.container_id,),
            ),
            ObservationOperation.ROLLBACK_PROVIDER_PROBE,
        )
        if provider.stdout != b"success\n":
            raise ValueError
        owner.assert_unchanged()
        return _evidence(
            _COMMITTED_DOMAIN,
            (
                owner.target.target_token.digest_sha256,
                owner.target.container.private_inspect_sha256,
                observed_environment.sha256 or "",
                local_ca.destination_evidence_sha256,
                ca_bundle.destination_evidence_sha256,
                readiness.authority_sha256,
                hashlib.sha256(readiness.stdout).hexdigest(),
                provider.authority_sha256,
                hashlib.sha256(provider.stdout).hexdigest(),
            ),
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)


@dataclass(frozen=True, slots=True, repr=False)
class CommittedRepair:
    started: StartedRepairRuntime = field(repr=False)
    forward: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.started) is not StartedRepairRuntime
            or not self.started.owner.closed
            or type(self.forward) is not PersistedRepairTransactionChain
            or len(self.forward.selection.generations) != 14
            or self.forward.selection.tip.state is not RepairTransactionState.COMMITTED
            or self.forward.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.forward.selection.generation_sha256s[:12]
            != self.started.forward.selection.generation_sha256s
        ):
            raise ValueError("Committed repair state is invalid.")

    def __repr__(self) -> str:
        return "CommittedRepair(state='committed', <redacted>)"


def verify_and_commit_native_windows_repair(
    context: HeldWindowsTransactionContext,
    started: StartedRepairRuntime,
    *,
    environment: EnvironmentObservationPort | None = None,
    certificate_observer: CertificateObservationPort = (
        observe_certificate_destination_while_target_held
    ),
    journal_storage: JournalGenerationStoragePort | None = None,
    pointer_storage: JournalPointerStoragePort | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> CommittedRepair:
    """Persist intent, verify exact repaired state, close authority, and commit."""

    if (
        type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(started) is not StartedRepairRuntime
        or started.owner.closed
        or not callable(certificate_observer)
        or not callable(clock)
        or not callable(sleeper)
    ):
        _fail(NativeRepairTerminalVerificationErrorCode.INPUT_INVALID)
    stream = started.forward.selection.tip.stream
    selected_environment = (
        NativeWindowsEnvironmentRestoreStorage() if environment is None else environment
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
    result: CommittedRepair | None = None
    try:
        context.assert_target_binding(
            stream.target_token_sha256,
            stream.package_root_identity,
        )

        def terminal(
            package_root: PathHierarchyTrust,
            protected_root: ProtectedStateRoot,
        ) -> CommittedRepair:
            def while_root_held(root_path: str) -> CommittedRepair:
                verifying = _append(
                    root_path,
                    started.forward,
                    RepairTransactionState.SUCCESS_VERIFYING,
                    _evidence(
                        _VERIFYING_DOMAIN,
                        (
                            stream.target_token_sha256,
                            started.owner.target.target_token.digest_sha256,
                            started.forward.selection.tip_generation_sha256,
                        ),
                    ),
                    generation_storage=selected_journal,
                    pointer_storage=selected_pointer,
                    protection=protected_root,
                )
                evidence_sha256 = _verify(
                    package_root,
                    started,
                    environment=selected_environment,
                    certificate_observer=certificate_observer,
                    clock=clock,
                    sleeper=sleeper,
                )
                if _close(started.owner):
                    _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
                committed = _append(
                    root_path,
                    verifying,
                    RepairTransactionState.COMMITTED,
                    evidence_sha256,
                    generation_storage=selected_journal,
                    pointer_storage=selected_pointer,
                    protection=protected_root,
                )
                return CommittedRepair(started, committed)

            return cast(
                CommittedRepair,
                protected_root.run_journal_storage(while_root_held),
            )

        result = context.run_with_transaction_roots_held(terminal)
    except BaseException as error:
        cleanup_failed = _close(started.owner)
        if not isinstance(error, Exception):
            raise
        if cleanup_failed:
            _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
        _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
    if type(result) is not CommittedRepair:
        _fail(NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED)
    return result


__all__ = [
    "CommittedRepair",
    "NativeRepairTerminalVerificationError",
    "NativeRepairTerminalVerificationErrorCode",
    "verify_and_commit_native_windows_repair",
]
