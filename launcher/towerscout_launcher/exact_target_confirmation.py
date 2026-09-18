"""Fail-closed confirmation ownership for one exact native repair target.

This module connects the production exact-target facade and retained Windows
lock/recovery context to the launcher confirmation lifetime, then supplies the
ordered authorization boundaries required by the native repair transaction.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Callable, NoReturn, Protocol, cast

from .runtime_target_factory import capture_native_windows_resolved_target
from .runtime_target_resolution import (
    BoundResolvedRepairTarget,
)
from .target_contracts import MapProvider, PublicRepairSummary, ResolvedRepairTarget
from .windows_recovery_scan import PackageRecoveryJournalScan
from .windows_transaction_context import (
    HeldWindowsTransactionContext,
    capture_native_windows_transaction_context,
)
from .windows_repair_execution_native import (
    NativeRepairExecutionError,
    NativeRepairExecutionErrorCode,
    NativeRepairExecutionHooks,
    NativeRepairExecutionResult,
    execute_native_windows_repair,
)

CONFIRMATION_TEXT = "REPAIR TLS AND RESTART"
DEFAULT_CONFIRMATION_TIMEOUT_SECONDS = 120.0


class ExactTargetConfirmationErrorCode(str, Enum):
    TARGET_UNAVAILABLE = "target_unavailable"
    TARGET_CHANGED = "target_changed"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_EXPIRED = "confirmation_expired"
    RECOVERY_REQUIRED = "recovery_required"
    REPAIR_FAILED = "repair_failed"
    REPAIR_ROLLED_BACK = "repair_rolled_back"
    MUTATION_DISABLED = "mutation_disabled"


_PUBLIC_MESSAGES = {
    ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE: (
        "TowerScout could not verify one exact repair target. No changes were made."
    ),
    ExactTargetConfirmationErrorCode.TARGET_CHANGED: (
        "The verified repair target changed. No changes were made; refresh and try "
        "again."
    ),
    ExactTargetConfirmationErrorCode.CONFIRMATION_REQUIRED: (
        "The required confirmation was not entered. No changes were made."
    ),
    ExactTargetConfirmationErrorCode.CONFIRMATION_EXPIRED: (
        "The repair confirmation expired. No changes were made; start again to "
        "verify a fresh target."
    ),
    ExactTargetConfirmationErrorCode.RECOVERY_REQUIRED: (
        "A prior repair must finish recovery before a new repair can start. "
        "No new changes were made."
    ),
    ExactTargetConfirmationErrorCode.REPAIR_FAILED: (
        "The repair could not begin safely. No runtime change was completed."
    ),
    ExactTargetConfirmationErrorCode.REPAIR_ROLLED_BACK: (
        "The repair did not complete. The prior TowerScout state was restored."
    ),
    ExactTargetConfirmationErrorCode.MUTATION_DISABLED: (
        "The exact repair target was verified, but repair remains disabled until "
        "the remaining Gate A safety work is complete. No changes were made."
    ),
}


class ExactTargetConfirmationError(RuntimeError):
    def __init__(self, code: ExactTargetConfirmationErrorCode) -> None:
        self.code = code
        self.public_message = _PUBLIC_MESSAGES[code]
        super().__init__(self.public_message)


class ExactTargetConfirmationState(str, Enum):
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    CLOSED = "closed"


class TargetRevalidationStage(str, Enum):
    BEFORE_CONFIRMATION = "before_confirmation"
    BEFORE_MUTATION = "before_mutation"
    BEFORE_RESTART = "before_restart"
    TERMINAL = "terminal"


class _ExactTargetOwner(Protocol):
    @property
    def target(self) -> ResolvedRepairTarget: ...

    @property
    def closed(self) -> bool: ...

    def assert_unchanged(self) -> object: ...

    def close(self) -> None: ...


class _TransactionContext(Protocol):
    @property
    def closed(self) -> bool: ...

    @property
    def recovery_scan(self) -> PackageRecoveryJournalScan: ...

    def assert_unchanged(self) -> PackageRecoveryJournalScan: ...

    def close(self) -> None: ...


_RepairExecutor = Callable[
    [
        BoundResolvedRepairTarget,
        HeldWindowsTransactionContext,
        NativeRepairExecutionHooks,
    ],
    NativeRepairExecutionResult,
]


def _fail(code: ExactTargetConfirmationErrorCode) -> NoReturn:
    raise ExactTargetConfirmationError(code) from None


def _discard_resources(*resources: object | None) -> None:
    seen: set[int] = set()
    for resource in resources:
        if resource is None or id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            close = getattr(resource, "close", None)
            if callable(close):
                close()
        except BaseException:
            pass


class ExactTargetConfirmationTransaction:
    """Own one held exact target from resolution through confirmation cleanup."""

    __slots__ = (
        "_clock",
        "_context",
        "_deadline",
        "_lock",
        "_owner",
        "_stage",
        "_state",
        "_summary",
    )

    def __init__(
        self,
        owner: _ExactTargetOwner,
        context: _TransactionContext,
        *,
        timeout_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            not isinstance(owner, BoundResolvedRepairTarget)
            or not isinstance(context, HeldWindowsTransactionContext)
            or owner.closed
            or context.closed
            or not 1.0 <= timeout_seconds <= 600.0
            or not callable(clock)
        ):
            _discard_resources(owner, context)
            _fail(ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE)
        validation_failed = False
        interruption: BaseException | None = None
        try:
            now = clock()
            summary = owner.target.to_public_summary()
            owner.assert_unchanged()
            context.assert_unchanged()
        except BaseException as error:
            if isinstance(error, Exception):
                validation_failed = True
            else:
                interruption = error
        if validation_failed or interruption is not None:
            _discard_resources(owner, context)
        if interruption is not None:
            raise interruption
        if validation_failed:
            _fail(ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE)
        self._lock = threading.RLock()
        self._owner: _ExactTargetOwner | None = owner
        self._context: _TransactionContext | None = context
        self._clock = clock
        self._deadline = now + timeout_seconds
        self._summary = summary
        self._state = ExactTargetConfirmationState.AWAITING_CONFIRMATION
        self._stage = TargetRevalidationStage.BEFORE_CONFIRMATION

    @property
    def summary(self) -> PublicRepairSummary:
        return self._summary

    @property
    def state(self) -> ExactTargetConfirmationState:
        with self._lock:
            return self._state

    @property
    def stage(self) -> TargetRevalidationStage:
        with self._lock:
            return self._stage

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._state is ExactTargetConfirmationState.CLOSED

    def _close_while_locked(self) -> None:
        owner = self._owner
        context = self._context
        self._owner = None
        self._context = None
        self._state = ExactTargetConfirmationState.CLOSED
        if owner is None and context is None:
            return
        failed = False
        interruption: BaseException | None = None
        for resource in (owner, context):
            if resource is None:
                continue
            try:
                resource.close()
            except BaseException as error:
                if isinstance(error, Exception):
                    failed = True
                elif interruption is None:
                    interruption = error
        if interruption is not None:
            raise interruption
        if failed:
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)

    def _assert_live_while_locked(self) -> _ExactTargetOwner:
        owner = self._owner
        context = self._context
        if owner is None or self._state in {
            ExactTargetConfirmationState.CANCELLED,
            ExactTargetConfirmationState.CLOSED,
        }:
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
        try:
            expired = self._clock() >= self._deadline
        except Exception:
            expired = True
        if expired:
            self._close_while_locked()
            _fail(ExactTargetConfirmationErrorCode.CONFIRMATION_EXPIRED)
        if context is None or owner.closed or context.closed:
            self._close_while_locked()
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
        return owner

    def confirm(self, typed_text: str) -> None:
        with self._lock:
            if self._state is not ExactTargetConfirmationState.AWAITING_CONFIRMATION:
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            owner = self._assert_live_while_locked()
            if typed_text != CONFIRMATION_TEXT:
                self._state = ExactTargetConfirmationState.CANCELLED
                self._close_while_locked()
                _fail(ExactTargetConfirmationErrorCode.CONFIRMATION_REQUIRED)
            validation_failed = False
            interruption: BaseException | None = None
            try:
                owner.assert_unchanged()
                context = self._context
                if context is None:
                    _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
                context.assert_unchanged()
            except BaseException as error:
                if isinstance(error, Exception):
                    validation_failed = True
                else:
                    interruption = error
            if validation_failed or interruption is not None:
                self._close_while_locked()
            if interruption is not None:
                raise interruption
            if validation_failed:
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            self._state = ExactTargetConfirmationState.CONFIRMED

    def revalidate(self, stage: TargetRevalidationStage) -> None:
        """Fail closed at one explicitly named transaction boundary.

        Every stage must match the authorized target. The terminal stage runs
        against the newly rebound owner adopted after the exact runtime restart.
        """

        with self._lock:
            stages = tuple(TargetRevalidationStage)
            if (
                type(stage) is not TargetRevalidationStage
                or self._state is not ExactTargetConfirmationState.CONFIRMED
                or stage is TargetRevalidationStage.BEFORE_CONFIRMATION
                or stages.index(stage) != stages.index(self._stage) + 1
            ):
                self._close_while_locked()
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            owner = self._assert_live_while_locked()
            validation_failed = False
            interruption: BaseException | None = None
            try:
                owner.assert_unchanged()
                context = self._context
                if context is None:
                    _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
                context.assert_unchanged()
            except BaseException as error:
                if isinstance(error, Exception):
                    validation_failed = True
                else:
                    interruption = error
            if validation_failed or interruption is not None:
                self._close_while_locked()
            if interruption is not None:
                raise interruption
            if validation_failed:
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            self._stage = stage

    def _adopt_and_revalidate_terminal(
        self,
        owner: BoundResolvedRepairTarget,
    ) -> None:
        with self._lock:
            current = self._owner
            context = self._context
            invalid = (
                self._state is not ExactTargetConfirmationState.CONFIRMED
                or self._stage is not TargetRevalidationStage.BEFORE_RESTART
                or current is None
                or not current.closed
                or context is None
                or context.closed
                or not isinstance(owner, BoundResolvedRepairTarget)
                or owner.closed
                or owner.target.target_token.display != self._summary.target_token
            )
            if invalid:
                _discard_resources(owner)
                self._close_while_locked()
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            self._owner = owner
            self.revalidate(TargetRevalidationStage.TERMINAL)

    def _execute_authorized(
        self, executor: _RepairExecutor
    ) -> NativeRepairExecutionResult:
        with self._lock:
            if (
                not callable(executor)
                or self._state is not ExactTargetConfirmationState.CONFIRMED
                or self._stage is not TargetRevalidationStage.BEFORE_CONFIRMATION
            ):
                self._close_while_locked()
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            owner = self._assert_live_while_locked()
            context = self._context
            if context is None:
                self._close_while_locked()
                _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
            hooks = NativeRepairExecutionHooks(
                lambda: self.revalidate(TargetRevalidationStage.BEFORE_MUTATION),
                lambda: self.revalidate(TargetRevalidationStage.BEFORE_RESTART),
                self._adopt_and_revalidate_terminal,
            )
            return executor(
                cast(BoundResolvedRepairTarget, owner),
                cast(HeldWindowsTransactionContext, context),
                hooks,
            )

    def cancel(self) -> None:
        with self._lock:
            if self._state is ExactTargetConfirmationState.CLOSED:
                return
            self._state = ExactTargetConfirmationState.CANCELLED
            self._close_while_locked()

    def close(self) -> None:
        with self._lock:
            if self._state is ExactTargetConfirmationState.CLOSED:
                return
            self._close_while_locked()


class ExactTargetConfirmationCoordinator:
    """Production exact-target confirmation and native repair composition."""

    __slots__ = (
        "_capture",
        "_capture_context",
        "_clock",
        "_execute_repair",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        capture: Callable[[MapProvider], BoundResolvedRepairTarget] = (
            capture_native_windows_resolved_target
        ),
        capture_context: (
            Callable[[BoundResolvedRepairTarget], HeldWindowsTransactionContext] | None
        ) = None,
        execute_repair: _RepairExecutor = execute_native_windows_repair,
        timeout_seconds: float = DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            not callable(capture)
            or (capture_context is not None and not callable(capture_context))
            or not callable(execute_repair)
            or not callable(clock)
            or not 1.0 <= timeout_seconds <= 600.0
        ):
            raise ValueError("Exact-target confirmation configuration is invalid.")
        self._capture = capture
        self._capture_context = (
            capture_native_windows_transaction_context
            if capture_context is None
            else capture_context
        )
        self._timeout_seconds = timeout_seconds
        self._clock = clock
        self._execute_repair = execute_repair

    @property
    def mutation_enabled(self) -> bool:
        return True

    def prepare(self, provider: MapProvider) -> ExactTargetConfirmationTransaction:
        if type(provider) is not MapProvider:
            _fail(ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE)
        owner: BoundResolvedRepairTarget | None = None
        context: HeldWindowsTransactionContext | None = None
        capture_failed = False
        recovery_required = False
        interruption: BaseException | None = None
        try:
            owner = self._capture(provider)
            context = self._capture_context(owner)
            if (
                not isinstance(owner, BoundResolvedRepairTarget)
                or not isinstance(context, HeldWindowsTransactionContext)
                or owner.closed
                or context.closed
            ):
                raise ValueError("Exact transaction capture is invalid.")
            recovery_required = context.recovery_scan.repair_pending
        except BaseException as error:
            if isinstance(error, Exception):
                capture_failed = True
            else:
                interruption = error
        if capture_failed or interruption is not None:
            _discard_resources(owner, context)
        if interruption is not None:
            raise interruption
        if capture_failed or owner is None or context is None:
            _fail(ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE)
        if recovery_required:
            _discard_resources(owner, context)
            _fail(ExactTargetConfirmationErrorCode.RECOVERY_REQUIRED)
        return ExactTargetConfirmationTransaction(
            owner,
            context,
            timeout_seconds=self._timeout_seconds,
            clock=self._clock,
        )

    @staticmethod
    def confirm(
        transaction: ExactTargetConfirmationTransaction, typed_text: str
    ) -> None:
        if type(transaction) is not ExactTargetConfirmationTransaction:
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
        transaction.confirm(typed_text)

    @staticmethod
    def cancel(transaction: ExactTargetConfirmationTransaction) -> None:
        if type(transaction) is not ExactTargetConfirmationTransaction:
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
        transaction.cancel()

    def execute(
        self,
        transaction: ExactTargetConfirmationTransaction,
    ) -> NativeRepairExecutionResult:
        if type(transaction) is not ExactTargetConfirmationTransaction:
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
        failure: ExactTargetConfirmationErrorCode | None = None
        result: NativeRepairExecutionResult | None = None
        try:
            result = transaction._execute_authorized(self._execute_repair)
        except NativeRepairExecutionError as error:
            failure = {
                NativeRepairExecutionErrorCode.INPUT_INVALID: (
                    ExactTargetConfirmationErrorCode.TARGET_CHANGED
                ),
                NativeRepairExecutionErrorCode.EXECUTION_FAILED: (
                    ExactTargetConfirmationErrorCode.REPAIR_FAILED
                ),
                NativeRepairExecutionErrorCode.REPAIR_ROLLED_BACK: (
                    ExactTargetConfirmationErrorCode.REPAIR_ROLLED_BACK
                ),
                NativeRepairExecutionErrorCode.RECOVERY_PENDING: (
                    ExactTargetConfirmationErrorCode.RECOVERY_REQUIRED
                ),
            }[error.code]
        finally:
            transaction.close()
        if failure is not None:
            _fail(failure)
        if type(result) is not NativeRepairExecutionResult:
            _fail(ExactTargetConfirmationErrorCode.REPAIR_FAILED)
        return result


__all__ = [
    "CONFIRMATION_TEXT",
    "DEFAULT_CONFIRMATION_TIMEOUT_SECONDS",
    "ExactTargetConfirmationCoordinator",
    "ExactTargetConfirmationError",
    "ExactTargetConfirmationErrorCode",
    "ExactTargetConfirmationState",
    "ExactTargetConfirmationTransaction",
    "TargetRevalidationStage",
]
