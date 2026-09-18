"""Capture and start the exact repaired profile from authenticated absence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
import threading
from typing import Any, Callable, cast, NoReturn, Protocol

from .runtime_target_inputs import capture_native_windows_target_resolution_plan_inputs
from .runtime_target_observation_backend import (
    RecreatedTargetResolutionSnapshots,
)
from .runtime_target_observation_native import (
    capture_native_windows_target_observation_backend,
)
from .runtime_target_plan import (
    TargetResolutionPlanInputs,
    assemble_target_resolution_plan,
)
from .runtime_target_resolution import (
    AbsentResolvedRuntimeTarget,
    AbsentTargetResolutionSnapshot,
    BoundResolvedRepairTarget,
    TargetResolutionPlan,
    TargetResolutionSnapshot,
    capture_bound_resolved_repair_target,
    resolve_absent_runtime_target,
    resolve_present_runtime_target,
)
from .target_contracts import FileIdentity, ResolvedRepairTarget
from .windows_environment_replacement_native import EnvironmentAppliedRecord
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
from .windows_repair_runtime_stop_native import StoppedRepairRuntime
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

_STARTING_DOMAIN = b"TowerScout.RepairRuntimeStarting.v1"
_STARTED_DOMAIN = b"TowerScout.RepairRuntimeStarted.v1"


class NativeRepairRuntimeStartErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_runtime_start_input_invalid"
    CAPTURE_FAILED = "native_repair_runtime_start_capture_failed"
    START_FAILED = "native_repair_runtime_start_failed"


class NativeRepairRuntimeStartError(RuntimeError):
    _MESSAGES = {
        NativeRepairRuntimeStartErrorCode.INPUT_INVALID: (
            "The repair runtime start request is invalid."
        ),
        NativeRepairRuntimeStartErrorCode.CAPTURE_FAILED: (
            "The stopped repair profile could not be verified safely."
        ),
        NativeRepairRuntimeStartErrorCode.START_FAILED: (
            "The repaired runtime could not be started safely."
        ),
    }

    def __init__(self, code: NativeRepairRuntimeStartErrorCode) -> None:
        if type(code) is not NativeRepairRuntimeStartErrorCode:
            raise ValueError("Unknown native repair runtime start error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairRuntimeStartError(code={self.code.value!r})"


class _PlanInputOwner(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture(self) -> TargetResolutionPlanInputs: ...

    def close(self) -> None: ...


class _AbsentBackend(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture_absent(
        self, plan: TargetResolutionPlan
    ) -> AbsentTargetResolutionSnapshot: ...

    def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot: ...

    def start_absent_repair(
        self,
        plan: TargetResolutionPlan,
        expected: AbsentResolvedRuntimeTarget,
    ) -> RecreatedTargetResolutionSnapshots: ...

    def close(self) -> None: ...


def _fail(code: NativeRepairRuntimeStartErrorCode) -> NoReturn:
    raise NativeRepairRuntimeStartError(code) from None


def _close(resource: object | None) -> bool:
    if resource is None:
        return False
    try:
        closed = getattr(resource, "closed")
        if closed is True:
            return False
        operation = getattr(resource, "close")
        if not callable(operation):
            return True
        operation()
        return getattr(resource, "closed") is not True
    except Exception:
        return True


def _applied_record(stopped: StoppedRepairRuntime) -> EnvironmentAppliedRecord:
    record = stopped.environment.provider.selection.tip.record
    if type(record) is not EnvironmentAppliedRecord:
        _fail(NativeRepairRuntimeStartErrorCode.INPUT_INVALID)
    return record


def _candidate_file_matches(
    identity: FileIdentity | None,
    record: EnvironmentAppliedRecord,
) -> bool:
    if type(identity) is not FileIdentity:
        return False
    candidate = cast(FileIdentity, identity)
    return (
        not candidate.is_directory
        and candidate.logical_name == ".env"
        and candidate.sha256 == record.candidate_sha256
        and candidate.size_bytes == record.candidate_size
        and StableFileIdentity(candidate.volume_serial, candidate.file_id)
        == record.candidate_identity
    )


def _plan_matches(
    plan: TargetResolutionPlan,
    original: ResolvedRepairTarget,
    record: EnvironmentAppliedRecord,
) -> bool:
    environment = plan.environment_file
    return (
        type(plan) is TargetResolutionPlan
        and _candidate_file_matches(environment, record)
        and plan.environment_source == environment
        and plan.environment_sha256 == record.candidate_sha256
        and plan.planned_environment_sha256 == record.candidate_sha256
        and plan.package_root == original.package_root
        and plan.process_environment == original.process_environment
        and plan.release_identity == original.release_identity
        and plan.security_artifacts == original.security_artifacts
        and plan.runtime == original.runtime
        and plan.endpoint == original.endpoint
        and plan.compose_provider == original.compose_provider
        and plan.ordered_compose_files == original.compose.ordered_files
        and plan.compose_project == original.compose_project
        and plan.acceleration == original.acceleration
        and plan.provider is original.provider
        and plan.port == original.port
        and plan.configured_image_reference == original.image.configured_reference
        and plan.pinned_image_digest == original.image.pinned_digest
        and plan.certificate == original.certificate
    )


def _absent_matches(
    observed: AbsentResolvedRuntimeTarget,
    original: ResolvedRepairTarget,
) -> bool:
    return (
        type(observed) is AbsentResolvedRuntimeTarget
        and observed.compose.pre_model_sha256 == original.compose.post_model_sha256
        and observed.compose.post_model_sha256 == original.compose.post_model_sha256
        and observed.image == original.image
        and observed.volumes == original.volumes
    )


def _present_matches(
    observed: ResolvedRepairTarget,
    original: ResolvedRepairTarget,
    record: EnvironmentAppliedRecord,
) -> bool:
    return (
        type(observed) is ResolvedRepairTarget
        and _plan_matches(observed_to_plan(observed), original, record)
        and observed.compose.pre_model_sha256 == original.compose.post_model_sha256
        and observed.compose.post_model_sha256 == original.compose.post_model_sha256
        and observed.image == original.image
        and observed.volumes == original.volumes
        and observed.container.container_id != original.container.container_id
    )


def observed_to_plan(target: ResolvedRepairTarget) -> TargetResolutionPlan:
    """Project a resolved target back to the exact plan fields for comparison."""

    return TargetResolutionPlan(
        package_root=target.package_root,
        process_environment=target.process_environment,
        release_identity=target.release_identity,
        security_artifacts=target.security_artifacts,
        runtime=target.runtime,
        endpoint=target.endpoint,
        compose_provider=target.compose_provider,
        ordered_compose_files=target.compose.ordered_files,
        environment_sha256=target.compose.environment_sha256,
        planned_environment_sha256=target.compose.planned_environment_sha256,
        environment_source=target.compose.environment_source,
        environment_file=target.compose.environment_file,
        compose_project=target.compose_project,
        acceleration=target.acceleration,
        provider=target.provider,
        port=target.port,
        configured_image_reference=target.image.configured_reference,
        pinned_image_digest=target.image.pinned_digest,
        certificate=target.certificate,
    )


class BoundAbsentRepairRuntimeTarget:
    """Retain one twice-captured absent repaired profile until exact start."""

    __slots__ = (
        "_backend",
        "_closed",
        "_lock",
        "_observation",
        "_original",
        "_plan",
        "_record",
    )

    def __init__(
        self,
        plan: TargetResolutionPlan,
        backend: _AbsentBackend,
        observation: AbsentResolvedRuntimeTarget,
        original: ResolvedRepairTarget,
        record: EnvironmentAppliedRecord,
    ) -> None:
        if (
            not _plan_matches(plan, original, record)
            or observation.plan is not plan
            or not _absent_matches(observation, original)
            or backend.closed
            or not backend.supported
        ):
            _close(backend)
            _fail(NativeRepairRuntimeStartErrorCode.CAPTURE_FAILED)
        self._lock = threading.RLock()
        self._closed = False
        self._plan = plan
        self._backend: _AbsentBackend | None = backend
        self._observation = observation
        self._original = original
        self._record = record

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def start(self) -> tuple[BoundResolvedRepairTarget, int]:
        with self._lock:
            backend = self._backend
            if self._closed or backend is None:
                _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)
            owner: BoundResolvedRepairTarget | None = None
            try:
                snapshots = backend.start_absent_repair(
                    self._plan,
                    self._observation,
                )
                first = resolve_present_runtime_target(self._plan, snapshots.first)
                second = resolve_present_runtime_target(self._plan, snapshots.second)
                if (
                    snapshots.command_exit_code != 0
                    or first != second
                    or not _present_matches(first, self._original, self._record)
                    or not _present_matches(second, self._original, self._record)
                ):
                    raise ValueError
                self._backend = None
                self._closed = True
                owner = capture_bound_resolved_repair_target(
                    self._plan,
                    backend=cast(Any, backend),
                )
                if not _present_matches(owner.target, self._original, self._record):
                    raise ValueError
                return owner, snapshots.command_exit_code
            except BaseException as error:
                if owner is not None:
                    _close(owner)
                if not self._closed:
                    self._closed = True
                    self._backend = None
                    _close(backend)
                if not isinstance(error, Exception):
                    raise
                _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)

    def close(self) -> None:
        with self._lock:
            backend = self._backend
            self._backend = None
            self._closed = True
        if _close(backend):
            _fail(NativeRepairRuntimeStartErrorCode.CAPTURE_FAILED)

    def __repr__(self) -> str:
        return "BoundAbsentRepairRuntimeTarget(<redacted>)"


def capture_native_absent_repair_runtime_target(
    stopped: StoppedRepairRuntime,
    *,
    input_capture: Callable[[Any], _PlanInputOwner] = (
        capture_native_windows_target_resolution_plan_inputs
    ),
    backend_capture: Callable[[TargetResolutionPlan], _AbsentBackend] = (
        capture_native_windows_target_observation_backend
    ),
) -> BoundAbsentRepairRuntimeTarget:
    """Capture candidate `.env`, exact absence, image, and all volumes twice."""

    if type(stopped) is not StoppedRepairRuntime:
        _fail(NativeRepairRuntimeStartErrorCode.INPUT_INVALID)
    original = stopped.environment.certificates.prepared.rollback.target
    record = _applied_record(stopped)
    inputs: _PlanInputOwner | None = None
    backend: _AbsentBackend | None = None
    result: BoundAbsentRepairRuntimeTarget | None = None
    try:
        inputs = input_capture(original.provider)
        if inputs.closed or not inputs.supported:
            raise ValueError
        first_plan = assemble_target_resolution_plan(
            inputs.capture(), certificate=original.certificate
        )
        second_plan = assemble_target_resolution_plan(
            inputs.capture(), certificate=original.certificate
        )
        if (
            first_plan.authority_sha256 != second_plan.authority_sha256
            or not _plan_matches(first_plan, original, record)
            or not _plan_matches(second_plan, original, record)
        ):
            raise ValueError
        backend = backend_capture(second_plan)
        if _close(inputs):
            raise ValueError
        inputs = None
        first_absent = resolve_absent_runtime_target(
            second_plan, backend.capture_absent(second_plan)
        )
        second_absent = resolve_absent_runtime_target(
            second_plan, backend.capture_absent(second_plan)
        )
        if (
            first_absent != second_absent
            or first_absent.observation_binding_sha256
            != second_absent.observation_binding_sha256
            or not _absent_matches(second_absent, original)
        ):
            raise ValueError
        result = BoundAbsentRepairRuntimeTarget(
            second_plan,
            backend,
            second_absent,
            original,
            record,
        )
        backend = None
    except BaseException as error:
        cleanup_failed = _close(backend) or _close(inputs)
        if not isinstance(error, Exception):
            raise
        if cleanup_failed:
            _fail(NativeRepairRuntimeStartErrorCode.CAPTURE_FAILED)
        _fail(NativeRepairRuntimeStartErrorCode.CAPTURE_FAILED)
    if result is None:
        _fail(NativeRepairRuntimeStartErrorCode.CAPTURE_FAILED)
    return result


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
            generation, protection=protection
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
        _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)
    if selected is None or selected.selection.tip != generation:
        _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)
    return selected


@dataclass(frozen=True, slots=True, repr=False)
class StartedRepairRuntime:
    stopped: StoppedRepairRuntime = field(repr=False)
    owner: BoundResolvedRepairTarget = field(repr=False)
    forward: PersistedRepairTransactionChain = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.stopped) is not StoppedRepairRuntime
            or type(self.owner) is not BoundResolvedRepairTarget
            or self.owner.closed
            or type(self.forward) is not PersistedRepairTransactionChain
            or len(self.forward.selection.generations) != 12
            or self.forward.selection.tip.state
            is not RepairTransactionState.RUNTIME_STARTED
            or self.forward.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
            or self.forward.selection.generation_sha256s[:10]
            != self.stopped.forward.selection.generation_sha256s
        ):
            raise ValueError("Started repair runtime state is invalid.")

    def __repr__(self) -> str:
        return "StartedRepairRuntime(state='runtime_started', <redacted>)"


def start_native_windows_repair_runtime(
    context: HeldWindowsTransactionContext,
    stopped: StoppedRepairRuntime,
    *,
    absent_capture: Callable[[StoppedRepairRuntime], BoundAbsentRepairRuntimeTarget] = (
        capture_native_absent_repair_runtime_target
    ),
    journal_storage: JournalGenerationStoragePort | None = None,
    pointer_storage: JournalPointerStoragePort | None = None,
) -> StartedRepairRuntime:
    """Verify exact absence, persist start intent, then start and rebind."""

    if (
        type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(stopped) is not StoppedRepairRuntime
        or not callable(absent_capture)
    ):
        _fail(NativeRepairRuntimeStartErrorCode.INPUT_INVALID)
    stream = stopped.forward.selection.tip.stream
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
    absent: BoundAbsentRepairRuntimeTarget | None = None
    result: StartedRepairRuntime | None = None
    try:
        absent = absent_capture(stopped)
        selected_absent = absent

        def start(
            _package_root: PathHierarchyTrust,
            protected_root: ProtectedStateRoot,
        ) -> StartedRepairRuntime:
            def while_root_held(root_path: str) -> StartedRepairRuntime:
                starting = _append(
                    root_path,
                    stopped.forward,
                    RepairTransactionState.RUNTIME_STARTING,
                    _evidence(
                        _STARTING_DOMAIN,
                        (
                            stream.target_token_sha256,
                            stopped.forward.selection.tip_generation_sha256,
                        ),
                    ),
                    generation_storage=selected_journal,
                    pointer_storage=selected_pointer,
                    protection=protected_root,
                )
                owner, exit_code = selected_absent.start()
                try:
                    started = _append(
                        root_path,
                        starting,
                        RepairTransactionState.RUNTIME_STARTED,
                        _evidence(
                            _STARTED_DOMAIN,
                            (
                                stream.target_token_sha256,
                                owner.target.target_token.digest_sha256,
                                owner.target.container.private_inspect_sha256,
                                str(exit_code),
                            ),
                        ),
                        generation_storage=selected_journal,
                        pointer_storage=selected_pointer,
                        protection=protected_root,
                    )
                    return StartedRepairRuntime(stopped, owner, started)
                except BaseException:
                    _close(owner)
                    raise

            return cast(
                StartedRepairRuntime,
                protected_root.run_journal_storage(while_root_held),
            )

        context.assert_target_binding(
            stream.target_token_sha256,
            stream.package_root_identity,
        )
        result = context.run_with_transaction_roots(start)
        absent = None
    except BaseException as error:
        cleanup_failed = _close(absent)
        if not isinstance(error, Exception):
            raise
        if cleanup_failed:
            _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)
        _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)
    if result is None:
        _fail(NativeRepairRuntimeStartErrorCode.START_FAILED)
    return result


__all__ = [
    "BoundAbsentRepairRuntimeTarget",
    "NativeRepairRuntimeStartError",
    "NativeRepairRuntimeStartErrorCode",
    "StartedRepairRuntime",
    "capture_native_absent_repair_runtime_target",
    "start_native_windows_repair_runtime",
]
