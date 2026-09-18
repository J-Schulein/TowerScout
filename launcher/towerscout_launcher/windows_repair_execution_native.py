"""One fail-closed native Windows repair transaction coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, NoReturn

from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_repair_certificate_execution_native import (
    apply_native_windows_repair_certificates,
)
from .windows_repair_cleanup_execution_native import (
    CleanedRepair,
    cleanup_committed_native_windows_repair,
)
from .windows_repair_environment_execution_native import (
    apply_native_windows_repair_environment,
)
from .windows_repair_forward_preparation_native import (
    prepare_native_windows_repair_forward,
)
from .windows_repair_rollback_preparation_native import (
    prepare_native_windows_repair_rollback,
)
from .windows_repair_runtime_start_native import (
    StartedRepairRuntime,
    start_native_windows_repair_runtime,
)
from .windows_repair_runtime_stop_native import stop_native_windows_repair_runtime
from .windows_repair_terminal_verification_native import (
    CommittedRepair,
    verify_and_commit_native_windows_repair,
)
from .windows_transaction_context import HeldWindowsTransactionContext


class NativeRepairExecutionOutcome(str, Enum):
    REPAIR_SUCCEEDED = "repair_succeeded"


class NativeRepairExecutionErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_execution_input_invalid"
    EXECUTION_FAILED = "native_repair_execution_failed"
    REPAIR_ROLLED_BACK = "repair_rolled_back"
    RECOVERY_PENDING = "repair_recovery_pending"


class NativeRepairExecutionError(RuntimeError):
    _MESSAGES = {
        NativeRepairExecutionErrorCode.INPUT_INVALID: (
            "The native repair execution request is invalid."
        ),
        NativeRepairExecutionErrorCode.EXECUTION_FAILED: (
            "The repair could not be prepared safely."
        ),
        NativeRepairExecutionErrorCode.REPAIR_ROLLED_BACK: (
            "The repair did not complete and the prior state was restored."
        ),
        NativeRepairExecutionErrorCode.RECOVERY_PENDING: (
            "The repair did not complete and still requires recovery."
        ),
    }

    def __init__(self, code: NativeRepairExecutionErrorCode) -> None:
        if type(code) is not NativeRepairExecutionErrorCode:
            raise ValueError("Unknown native repair execution error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairExecutionError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class NativeRepairExecutionHooks:
    """Required once-only authorization boundaries supplied by confirmation."""

    before_mutation: Callable[[], None]
    before_restart: Callable[[], None]
    terminal: Callable[[BoundResolvedRepairTarget], None]

    def __post_init__(self) -> None:
        if not all(
            callable(item)
            for item in (
                self.before_mutation,
                self.before_restart,
                self.terminal,
            )
        ):
            raise ValueError("Native repair execution hooks are invalid.")

    def __repr__(self) -> str:
        return "NativeRepairExecutionHooks(<redacted>)"


@dataclass(frozen=True, slots=True)
class NativeRepairExecutionResult:
    outcome: NativeRepairExecutionOutcome
    cleanup_recovered: bool

    def __post_init__(self) -> None:
        if (
            self.outcome is not NativeRepairExecutionOutcome.REPAIR_SUCCEEDED
            or type(self.cleanup_recovered) is not bool
        ):
            raise ValueError("Native repair execution result is invalid.")


def _fail(code: NativeRepairExecutionErrorCode) -> NoReturn:
    raise NativeRepairExecutionError(code) from None


def _close(*owners: BoundResolvedRepairTarget | None) -> bool:
    failed = False
    seen: set[int] = set()
    for owner in owners:
        if owner is None or id(owner) in seen:
            continue
        seen.add(id(owner))
        try:
            if not owner.closed:
                owner.close()
            failed = failed or not owner.closed
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            failed = True
    return failed


def execute_native_windows_repair(
    owner: BoundResolvedRepairTarget,
    context: HeldWindowsTransactionContext,
    hooks: NativeRepairExecutionHooks,
) -> NativeRepairExecutionResult:
    """Run all durable repair stages and recover every post-arm failure."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(context) is not HeldWindowsTransactionContext
        or context.closed
        or type(hooks) is not NativeRepairExecutionHooks
    ):
        _fail(NativeRepairExecutionErrorCode.INPUT_INVALID)
    armed = False
    committed = False
    started: StartedRepairRuntime | None = None
    cleaned: CleanedRepair | None = None
    try:
        hooks.before_mutation()
        rollback = prepare_native_windows_repair_rollback(owner, context)
        armed = True
        forward = prepare_native_windows_repair_forward(owner, context, rollback)
        certificates = apply_native_windows_repair_certificates(
            owner,
            context,
            forward,
        )
        environment = apply_native_windows_repair_environment(
            owner,
            context,
            certificates,
        )
        hooks.before_restart()
        stopped = stop_native_windows_repair_runtime(
            owner,
            context,
            environment,
        )
        started = start_native_windows_repair_runtime(context, stopped)
        hooks.terminal(started.owner)
        verified: CommittedRepair = verify_and_commit_native_windows_repair(
            context,
            started,
        )
        committed = True
        cleaned = cleanup_committed_native_windows_repair(context, verified)
    except BaseException as error:
        if not isinstance(error, Exception):
            _close(owner, None if started is None else started.owner)
            raise
        cleanup_failed = _close(
            owner,
            None if started is None else started.owner,
        )
        if not armed:
            _fail(NativeRepairExecutionErrorCode.EXECUTION_FAILED)
        try:
            recovered = context.refresh_and_resume_pending_recovery()
        except BaseException as recovery_error:
            if not isinstance(recovery_error, Exception):
                raise
            _fail(NativeRepairExecutionErrorCode.RECOVERY_PENDING)
        if cleanup_failed or recovered.mutation_blocked:
            _fail(NativeRepairExecutionErrorCode.RECOVERY_PENDING)
        if committed:
            return NativeRepairExecutionResult(
                NativeRepairExecutionOutcome.REPAIR_SUCCEEDED,
                cleanup_recovered=True,
            )
        _fail(NativeRepairExecutionErrorCode.REPAIR_ROLLED_BACK)
    if type(cleaned) is not CleanedRepair:
        _fail(NativeRepairExecutionErrorCode.RECOVERY_PENDING)
    return NativeRepairExecutionResult(
        NativeRepairExecutionOutcome.REPAIR_SUCCEEDED,
        cleanup_recovered=False,
    )


__all__ = [
    "NativeRepairExecutionError",
    "NativeRepairExecutionErrorCode",
    "NativeRepairExecutionHooks",
    "NativeRepairExecutionOutcome",
    "NativeRepairExecutionResult",
    "execute_native_windows_repair",
]
