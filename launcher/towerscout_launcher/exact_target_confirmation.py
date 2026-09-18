"""Fail-closed confirmation ownership for one exact native repair target.

This module remains repair-mutation-free. It connects the production exact-
target facade and retained Windows lock/recovery context to the launcher
confirmation lifetime, then exposes the ordered revalidation checkpoints that
the later repair transaction must use.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Callable, NoReturn, Protocol

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

CONFIRMATION_TEXT = "REPAIR TLS AND RESTART"
DEFAULT_CONFIRMATION_TIMEOUT_SECONDS = 120.0


class ExactTargetConfirmationErrorCode(str, Enum):
    TARGET_UNAVAILABLE = "target_unavailable"
    TARGET_CHANGED = "target_changed"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_EXPIRED = "confirmation_expired"
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

        Group 1 remains mutation-free, so every currently reachable stage must
        still match the original running target exactly.  Slice 7 will supply
        the authorized stop/recreation transition implementation behind these
        same ordered hooks before mutation can be enabled.
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
    """Production composition used by the launcher while mutation stays off."""

    __slots__ = ("_capture", "_capture_context", "_clock", "_timeout_seconds")

    def __init__(
        self,
        *,
        capture: Callable[[MapProvider], BoundResolvedRepairTarget] = (
            capture_native_windows_resolved_target
        ),
        capture_context: (
            Callable[[BoundResolvedRepairTarget], HeldWindowsTransactionContext] | None
        ) = None,
        timeout_seconds: float = DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            not callable(capture)
            or (capture_context is not None and not callable(capture_context))
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

    @property
    def mutation_enabled(self) -> bool:
        return False

    def prepare(self, provider: MapProvider) -> ExactTargetConfirmationTransaction:
        if type(provider) is not MapProvider:
            _fail(ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE)
        owner: BoundResolvedRepairTarget | None = None
        context: HeldWindowsTransactionContext | None = None
        capture_failed = False
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

    @staticmethod
    def execute(transaction: ExactTargetConfirmationTransaction) -> NoReturn:
        if type(transaction) is not ExactTargetConfirmationTransaction:
            _fail(ExactTargetConfirmationErrorCode.TARGET_CHANGED)
        try:
            transaction.revalidate(TargetRevalidationStage.BEFORE_MUTATION)
        finally:
            transaction.close()
        _fail(ExactTargetConfirmationErrorCode.MUTATION_DISABLED)


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
