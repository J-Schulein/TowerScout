"""Retained Windows authority for one exact Gate-A transaction.

The context duplicates the already-held package-root trust while the complete
resolved-target authority is active, acquires the environment mutex before the
target mutex, scans the protected recovery root between those acquisitions,
and retains every owner until explicit close.  Forward repair remains outside
this boundary; an authenticated pending rollback may be resumed explicitly.
"""

from __future__ import annotations

import threading
from enum import Enum
from typing import Any, Callable, NoReturn, Protocol, TypeVar, cast

from .runtime_target_resolution import BoundResolvedRepairTarget
from .target_contracts import ResolvedRepairTarget
from .windows_mutex import (
    HeldRuntimeTransactionLocks,
    RuntimeTransactionLockBinding,
    RuntimeTransactionLockError,
    RuntimeTransactionLockErrorCode,
    WindowsMutexApi,
    acquire_ordered_runtime_transaction_locks,
    runtime_transaction_lock_binding,
)
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_protected_state import (
    ProtectedStateRoot,
    capture_native_windows_protected_state_root,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_recovery_manager import resume_persisted_rollback_from_held_package_root
from .windows_recovery_manager_native import (
    build_native_windows_recovery_manager_ports,
    certificate_identity_from_recovery_chain,
)
from .windows_recovery_scan import (
    PackageRecoveryJournalScan,
    RecoveryJournalScanError,
    scan_package_recovery_journals_from_held_root,
)
from .windows_repair_transaction_journal import RepairTransactionState
from .windows_security import StableFileIdentity, WindowsSecurityError

_Result = TypeVar("_Result")


class WindowsTransactionContextErrorCode(str, Enum):
    INPUT_INVALID = "transaction_context_input_invalid"
    LOCK_UNAVAILABLE = "repair_lock_unavailable"
    BUSY = "repair_busy"
    TARGET_CHANGED = "target_changed"
    PROVIDER_RECOVERY_PENDING = "provider_recovery_pending"
    RECOVERY_STATE_AMBIGUOUS = "recovery_state_ambiguous"
    RECOVERY_FAILED = "repair_recovery_pending"
    WRONG_THREAD = "repair_lock_wrong_thread"
    RELEASE_FAILED = "repair_lock_release_failed"


class WindowsTransactionContextError(RuntimeError):
    """Sanitized transaction ownership failure."""

    _MESSAGES = {
        WindowsTransactionContextErrorCode.INPUT_INVALID: (
            "The Windows transaction context request is invalid."
        ),
        WindowsTransactionContextErrorCode.LOCK_UNAVAILABLE: (
            "The Windows repair locks are unavailable."
        ),
        WindowsTransactionContextErrorCode.BUSY: (
            "Another repair operation currently owns this environment or target."
        ),
        WindowsTransactionContextErrorCode.TARGET_CHANGED: (
            "The verified repair target changed while its locks were acquired."
        ),
        WindowsTransactionContextErrorCode.PROVIDER_RECOVERY_PENDING: (
            "Provider environment recovery must finish before runtime repair."
        ),
        WindowsTransactionContextErrorCode.RECOVERY_STATE_AMBIGUOUS: (
            "Protected recovery state is ambiguous."
        ),
        WindowsTransactionContextErrorCode.RECOVERY_FAILED: (
            "The prior repair still requires recovery."
        ),
        WindowsTransactionContextErrorCode.WRONG_THREAD: (
            "The Windows repair transaction must remain on its owning thread."
        ),
        WindowsTransactionContextErrorCode.RELEASE_FAILED: (
            "The Windows repair transaction could not be released safely."
        ),
    }

    def __init__(self, code: WindowsTransactionContextErrorCode) -> None:
        if type(code) is not WindowsTransactionContextErrorCode:
            raise ValueError("Unknown Windows transaction context error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"WindowsTransactionContextError(code={self.code.value!r})"


def _fail(code: WindowsTransactionContextErrorCode) -> NoReturn:
    raise WindowsTransactionContextError(code) from None


class _PackageRootOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    @property
    def root_snapshot(self) -> Any: ...

    @property
    def evidence(self) -> Any: ...

    def run_while_held(self, operation: Callable[[], _Result]) -> _Result: ...

    def assert_unchanged(self) -> object: ...

    def assert_unchanged_while_held(self) -> object: ...

    def close(self) -> None: ...


class _ProtectedRootOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    def assert_unchanged(self) -> object: ...

    def close(self) -> None: ...


class _LockOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    @property
    def environment_abandoned(self) -> bool: ...

    @property
    def target_abandoned(self) -> bool: ...

    def close(self) -> None: ...


_RecoveryRunner = Callable[
    [PathHierarchyTrust, _ProtectedRootOwner, PackageRecoveryJournalScan],
    PackageRecoveryJournalScan,
]
_RecoveryScanner = Callable[
    [PathHierarchyTrust, _ProtectedRootOwner],
    PackageRecoveryJournalScan,
]


def _recovery_unavailable(
    _package_root: PathHierarchyTrust,
    _protected_root: _ProtectedRootOwner,
    _scan: PackageRecoveryJournalScan,
) -> PackageRecoveryJournalScan:
    _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)


def _rescan_unavailable(
    _package_root: PathHierarchyTrust,
    _protected_root: _ProtectedRootOwner,
) -> PackageRecoveryJournalScan:
    _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)


class HeldWindowsTransactionContext:
    """Own a duplicated package-root lease, protected root, and lock pair."""

    __slots__ = (
        "_active",
        "_locks",
        "_mutex",
        "_owner_thread",
        "_package_root",
        "_protected_root",
        "_recovery_scan",
        "_rescan_recovery",
        "_resume_recovery",
        "_target_token",
    )

    def __init__(
        self,
        *,
        target_token_sha256: str,
        package_root: _PackageRootOwner,
        protected_root: _ProtectedRootOwner,
        locks: _LockOwner,
        recovery_scan: PackageRecoveryJournalScan,
        resume_recovery: _RecoveryRunner = _recovery_unavailable,
        rescan_recovery: _RecoveryScanner = _rescan_unavailable,
    ) -> None:
        valid = False
        try:
            identity = package_root.root_snapshot.identity
            valid = (
                type(target_token_sha256) is str
                and len(target_token_sha256) == 64
                and all(
                    character in "0123456789abcdef" for character in target_token_sha256
                )
                and package_root.closed is False
                and package_root.evidence.purpose is PathTrustPurpose.PACKAGE_ROOT
                and type(identity) is StableFileIdentity
                and protected_root.closed is False
                and locks.closed is False
                and type(recovery_scan) is PackageRecoveryJournalScan
                and recovery_scan.package_root_identity == identity
                and callable(resume_recovery)
                and callable(rescan_recovery)
                and (
                    recovery_scan.repair is None
                    or recovery_scan.repair.selection.tip.stream.target_token_sha256
                    == target_token_sha256
                )
            )
        except Exception:
            valid = False
        if not valid:
            _close_resources(locks, protected_root, package_root)
            _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
        self._mutex = threading.RLock()
        self._active = False
        self._owner_thread = threading.get_ident()
        self._target_token = target_token_sha256
        self._package_root: _PackageRootOwner | None = package_root
        self._protected_root: _ProtectedRootOwner | None = protected_root
        self._locks: _LockOwner | None = locks
        self._recovery_scan = recovery_scan
        self._resume_recovery = resume_recovery
        self._rescan_recovery = rescan_recovery

    @property
    def closed(self) -> bool:
        with self._mutex:
            return self._package_root is None

    @property
    def recovery_scan(self) -> PackageRecoveryJournalScan:
        with self._mutex:
            if self._package_root is None:
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            return self._recovery_scan

    @property
    def environment_abandoned(self) -> bool:
        with self._mutex:
            locks = self._locks
            if locks is None or locks.closed:
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            return locks.environment_abandoned

    @property
    def target_abandoned(self) -> bool:
        with self._mutex:
            locks = self._locks
            if locks is None or locks.closed:
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            return locks.target_abandoned

    def assert_target_binding(
        self,
        target_token_sha256: str,
        package_root_identity: StableFileIdentity,
    ) -> None:
        """Require the exact target/package binding retained at capture."""

        with self._mutex:
            package_root = self._package_root
            if (
                type(target_token_sha256) is not str
                or type(package_root_identity) is not StableFileIdentity
                or package_root is None
                or package_root.closed
                or self._target_token != target_token_sha256
                or package_root.root_snapshot.identity != package_root_identity
            ):
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)

    def assert_unchanged(self) -> PackageRecoveryJournalScan:
        """Revalidate every retained owner without rescanning mutable journals."""

        return self.run_with_package_root_held(
            lambda _package_root: self._recovery_scan
        )

    def resume_pending_recovery(self) -> PackageRecoveryJournalScan:
        """Resume one retained authenticated rollback under the held locks."""

        with self._mutex:
            protected_root = self._protected_root
            scan = self._recovery_scan
            if (
                protected_root is None
                or scan.repair is None
                or threading.get_ident() != self._owner_thread
            ):
                _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)

        failed = False
        interruption: BaseException | None = None
        recovered: PackageRecoveryJournalScan | None = None
        try:
            recovered = self.run_with_package_root_held(
                lambda package_root: self._resume_recovery(
                    package_root,
                    protected_root,
                    scan,
                )
            )
            if (
                type(recovered) is not PackageRecoveryJournalScan
                or recovered.package_root_identity != scan.package_root_identity
                or recovered.mutation_blocked
            ):
                failed = True
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            else:
                interruption = error
        if interruption is not None:
            raise interruption
        if failed or recovered is None:
            _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)
        with self._mutex:
            if self._package_root is None:
                _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)
            self._recovery_scan = recovered
        return recovered

    def refresh_and_resume_pending_recovery(self) -> PackageRecoveryJournalScan:
        """Rescan durable state written in this session, then resume it."""

        with self._mutex:
            protected_root = self._protected_root
            scan_before = self._recovery_scan
            if protected_root is None or threading.get_ident() != self._owner_thread:
                _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)

        candidate = self.run_with_package_root_held(
            lambda package_root: self._rescan_recovery(
                package_root,
                protected_root,
            )
        )
        if (
            type(candidate) is not PackageRecoveryJournalScan
            or candidate.package_root_identity != scan_before.package_root_identity
            or candidate.repair is None
            or candidate.repair.selection.tip.stream.target_token_sha256
            != self._target_token
        ):
            _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)
        with self._mutex:
            if self._package_root is None:
                _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)
            self._recovery_scan = candidate
        return self.resume_pending_recovery()

    def run_with_package_root_held(
        self,
        operation: Callable[[PathHierarchyTrust], _Result],
    ) -> _Result:
        if not callable(operation):
            _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
        return self.run_with_transaction_roots_held(
            lambda package_root, _protected_root: operation(package_root)
        )

    def run_with_transaction_roots_held(
        self,
        operation: Callable[[PathHierarchyTrust, ProtectedStateRoot], _Result],
    ) -> _Result:
        """Run one serialized operation while both retained roots stay valid."""

        if not callable(operation):
            _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
        with self._mutex:
            package_root = self._package_root
            protected_root = self._protected_root
            locks = self._locks
            if threading.get_ident() != self._owner_thread:
                _fail(WindowsTransactionContextErrorCode.WRONG_THREAD)
            if (
                self._active
                or package_root is None
                or protected_root is None
                or locks is None
                or package_root.closed
                or protected_root.closed
                or locks.closed
            ):
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            self._active = True
            operation_error: BaseException | None = None
            result: _Result | None = None
            try:
                protected_root.assert_unchanged()

                def invoke() -> None:
                    nonlocal operation_error, result
                    package_root.assert_unchanged_while_held()
                    try:
                        result = operation(
                            cast(PathHierarchyTrust, package_root),
                            cast(ProtectedStateRoot, protected_root),
                        )
                    except BaseException as error:
                        operation_error = error
                    package_root.assert_unchanged_while_held()

                package_root.run_while_held(invoke)
                protected_root.assert_unchanged()
                if locks.closed:
                    _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            except WindowsTransactionContextError:
                raise
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            finally:
                self._active = False
            if operation_error is not None:
                raise operation_error
            return cast(_Result, result)

    def run_with_transaction_roots(
        self,
        operation: Callable[[PathHierarchyTrust, ProtectedStateRoot], _Result],
    ) -> _Result:
        """Run one operation that manages its own package-root lease."""

        if not callable(operation):
            _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
        with self._mutex:
            package_root = self._package_root
            protected_root = self._protected_root
            locks = self._locks
            if threading.get_ident() != self._owner_thread:
                _fail(WindowsTransactionContextErrorCode.WRONG_THREAD)
            if (
                self._active
                or package_root is None
                or protected_root is None
                or locks is None
                or package_root.closed
                or protected_root.closed
                or locks.closed
            ):
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            self._active = True
            operation_error: BaseException | None = None
            result: _Result | None = None
            try:
                protected_root.assert_unchanged()
                package_root.assert_unchanged()
                try:
                    result = operation(
                        cast(PathHierarchyTrust, package_root),
                        cast(ProtectedStateRoot, protected_root),
                    )
                except BaseException as error:
                    operation_error = error
                package_root.assert_unchanged()
                protected_root.assert_unchanged()
                if locks.closed:
                    _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            except WindowsTransactionContextError:
                raise
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            finally:
                self._active = False
            if operation_error is not None:
                raise operation_error
            return cast(_Result, result)

    def close(self) -> None:
        with self._mutex:
            if threading.get_ident() != self._owner_thread:
                _fail(WindowsTransactionContextErrorCode.WRONG_THREAD)
            if self._active:
                _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
            package_root = self._package_root
            protected_root = self._protected_root
            locks = self._locks
            self._package_root = None
            self._protected_root = None
            self._locks = None
            if package_root is None:
                return
            if _close_resources(locks, protected_root, package_root):
                _fail(WindowsTransactionContextErrorCode.RELEASE_FAILED)

    def __enter__(self) -> HeldWindowsTransactionContext:
        if self.closed:
            _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "owned"
        return (
            "HeldWindowsTransactionContext("
            f"state={state!r}, repair_pending="
            f"{self._recovery_scan.repair_pending!r}, <redacted>)"
        )


def _close_resources(*resources: object | None) -> bool:
    failed = False
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
            failed = True
    return failed


def _map_lock_error(
    error: RuntimeTransactionLockError,
) -> WindowsTransactionContextErrorCode:
    return {
        RuntimeTransactionLockErrorCode.INVALID_BINDING: (
            WindowsTransactionContextErrorCode.INPUT_INVALID
        ),
        RuntimeTransactionLockErrorCode.LOCK_UNAVAILABLE: (
            WindowsTransactionContextErrorCode.LOCK_UNAVAILABLE
        ),
        RuntimeTransactionLockErrorCode.BUSY: WindowsTransactionContextErrorCode.BUSY,
        RuntimeTransactionLockErrorCode.BINDING_CHANGED: (
            WindowsTransactionContextErrorCode.TARGET_CHANGED
        ),
        RuntimeTransactionLockErrorCode.PROVIDER_RECOVERY_PENDING: (
            WindowsTransactionContextErrorCode.PROVIDER_RECOVERY_PENDING
        ),
        RuntimeTransactionLockErrorCode.WRONG_THREAD: (
            WindowsTransactionContextErrorCode.WRONG_THREAD
        ),
        RuntimeTransactionLockErrorCode.RELEASE_FAILED: (
            WindowsTransactionContextErrorCode.RELEASE_FAILED
        ),
    }[error.code]


def _capture_context(
    target: ResolvedRepairTarget,
    observed_package_root: _PackageRootOwner,
    *,
    capture_package_root: Callable[[], _PackageRootOwner],
    capture_protected_root: Callable[[], _ProtectedRootOwner],
    scan_recovery: Callable[
        [PathHierarchyTrust, _ProtectedRootOwner], PackageRecoveryJournalScan
    ],
    acquire_locks: Callable[
        [
            RuntimeTransactionLockBinding,
            Callable[[], RuntimeTransactionLockBinding],
            Callable[[], None],
        ],
        _LockOwner,
    ],
    resume_recovery: _RecoveryRunner = _recovery_unavailable,
) -> HeldWindowsTransactionContext:
    if (
        type(target) is not ResolvedRepairTarget
        or not callable(capture_package_root)
        or not callable(capture_protected_root)
        or not callable(scan_recovery)
        or not callable(acquire_locks)
        or not callable(resume_recovery)
    ):
        _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
    package_root: _PackageRootOwner | None = None
    protected_root: _ProtectedRootOwner | None = None
    locks: _LockOwner | None = None
    recovery_scan: PackageRecoveryJournalScan | None = None
    result: HeldWindowsTransactionContext | None = None
    failure: WindowsTransactionContextErrorCode | None = None
    interruption: BaseException | None = None
    try:
        if (
            observed_package_root.closed
            or observed_package_root.evidence.purpose
            is not PathTrustPurpose.PACKAGE_ROOT
        ):
            _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
        observed_package_root.assert_unchanged_while_held()
        observed_identity = observed_package_root.root_snapshot.identity
        package_root = capture_package_root()
        if (
            package_root.closed
            or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or package_root.root_snapshot.identity != observed_identity
        ):
            _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
        protected_root = capture_protected_root()
        if protected_root.closed:
            _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
        held_package_root = package_root
        held_protected_root = protected_root

        def revalidate() -> RuntimeTransactionLockBinding:
            held_protected_root.assert_unchanged()

            def bind() -> RuntimeTransactionLockBinding:
                held_package_root.assert_unchanged_while_held()
                return runtime_transaction_lock_binding(
                    target,
                    held_package_root.root_snapshot.identity,
                )

            return held_package_root.run_while_held(bind)

        binding = revalidate()

        def inspect_recovery() -> None:
            def scan() -> None:
                nonlocal recovery_scan
                held_package_root.assert_unchanged_while_held()
                candidate = scan_recovery(
                    cast(PathHierarchyTrust, held_package_root),
                    held_protected_root,
                )
                if (
                    type(candidate) is not PackageRecoveryJournalScan
                    or candidate.package_root_identity
                    != held_package_root.root_snapshot.identity
                ):
                    _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
                if (
                    candidate.repair is not None
                    and candidate.repair.selection.tip.stream.target_token_sha256
                    != target.target_token.digest_sha256
                ):
                    _fail(WindowsTransactionContextErrorCode.RECOVERY_STATE_AMBIGUOUS)
                if candidate.provider_environment_pending:
                    raise RuntimeTransactionLockError(
                        RuntimeTransactionLockErrorCode.PROVIDER_RECOVERY_PENDING
                    ) from None
                recovery_scan = candidate

            held_package_root.run_while_held(scan)

        locks = acquire_locks(binding, revalidate, inspect_recovery)
        if locks.closed or recovery_scan is None:
            _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
        observed_package_root.assert_unchanged_while_held()
        result = HeldWindowsTransactionContext(
            target_token_sha256=target.target_token.digest_sha256,
            package_root=held_package_root,
            protected_root=held_protected_root,
            locks=locks,
            recovery_scan=recovery_scan,
            resume_recovery=resume_recovery,
            rescan_recovery=scan_recovery,
        )
        package_root = None
        protected_root = None
        locks = None
    except WindowsTransactionContextError as error:
        failure = error.code
    except RuntimeTransactionLockError as error:
        failure = _map_lock_error(error)
    except RecoveryJournalScanError:
        failure = WindowsTransactionContextErrorCode.RECOVERY_STATE_AMBIGUOUS
    except (WindowsSecurityError, OSError, RuntimeError, TypeError, ValueError):
        failure = WindowsTransactionContextErrorCode.TARGET_CHANGED
    except BaseException as error:
        interruption = error
    cleanup_failed = _close_resources(locks, protected_root, package_root)
    if interruption is not None:
        raise interruption
    if cleanup_failed:
        _fail(WindowsTransactionContextErrorCode.RELEASE_FAILED)
    if failure is not None:
        _fail(failure)
    if result is None:
        _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
    return result


def resume_native_windows_pending_recovery(
    package_root: PathHierarchyTrust,
    protected_root: _ProtectedRootOwner,
    scan: PackageRecoveryJournalScan,
) -> PackageRecoveryJournalScan:
    """Run the native manager and reclassify protected state before return."""

    repair = scan.repair
    if repair is None:
        _fail(WindowsTransactionContextErrorCode.RECOVERY_FAILED)
    concrete_root = cast(ProtectedStateRoot, protected_root)
    forward = scan.forward
    if forward is not None and forward.selection.tip.state in {
        RepairTransactionState.COMMITTED,
        RepairTransactionState.RECOVERY_CLEANUP_PENDING,
    }:
        from .windows_repair_cleanup_execution_native import (
            resume_committed_native_windows_repair_cleanup,
        )

        resume_committed_native_windows_repair_cleanup(
            package_root,
            concrete_root,
            repair,
            forward,
        )
    else:
        certificate = certificate_identity_from_recovery_chain(repair)
        ports = build_native_windows_recovery_manager_ports(
            certificate,
            concrete_root,
        )
        provider_chain = scan.repair_provider_environment
        if provider_chain is None:
            provider_chain = scan.provider_environment
        provider_stream = (
            None if provider_chain is None else provider_chain.selection.tip.stream
        )
        resume_persisted_rollback_from_held_package_root(
            stream=repair.selection.tip.stream,
            provider_stream=provider_stream,
            package_root=package_root,
            initial_chain=repair,
            ports=ports,
        )
    return scan_package_recovery_journals_from_held_root(
        package_root,
        protected_root=concrete_root,
        generation_storage=NativeWindowsJournalGenerationStorage(),
        pointer_storage=NativeWindowsJournalPointerStorage(),
        protection=concrete_root,
    )


def capture_native_windows_transaction_context(
    owner: BoundResolvedRepairTarget,
    *,
    path_api: WindowsPathTrustApi | None = None,
    mutex_api: WindowsMutexApi | None = None,
    lock_timeout_ms: int = 0,
) -> HeldWindowsTransactionContext:
    """Capture the native lock/recovery context through one exact target owner."""

    if type(owner) is not BoundResolvedRepairTarget or owner.closed:
        _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)
    captured: HeldWindowsTransactionContext | None = None

    def capture(
        observed_package_root: PathHierarchyTrust,
        target: ResolvedRepairTarget,
    ) -> None:
        nonlocal captured
        if captured is not None:
            _fail(WindowsTransactionContextErrorCode.INPUT_INVALID)

        def scan(
            package_root: PathHierarchyTrust,
            protected_root: _ProtectedRootOwner,
        ) -> PackageRecoveryJournalScan:
            return scan_package_recovery_journals_from_held_root(
                package_root,
                protected_root=cast(ProtectedStateRoot, protected_root),
                generation_storage=NativeWindowsJournalGenerationStorage(),
                pointer_storage=NativeWindowsJournalPointerStorage(),
                protection=cast(ProtectedStateRoot, protected_root),
            )

        def acquire(
            binding: RuntimeTransactionLockBinding,
            revalidate: Callable[[], RuntimeTransactionLockBinding],
            inspect_recovery: Callable[[], None],
        ) -> HeldRuntimeTransactionLocks:
            return acquire_ordered_runtime_transaction_locks(
                binding,
                revalidate,
                before_target_acquisition=inspect_recovery,
                api=mutex_api,
                timeout_ms=lock_timeout_ms,
            )

        captured = _capture_context(
            target,
            observed_package_root,
            capture_package_root=lambda: capture_path_hierarchy(
                str(target.package_root.final_path),
                purpose=PathTrustPurpose.PACKAGE_ROOT,
                api=path_api,
            ),
            capture_protected_root=capture_native_windows_protected_state_root,
            scan_recovery=scan,
            acquire_locks=acquire,
            resume_recovery=resume_native_windows_pending_recovery,
        )

    try:
        owner.run_with_package_root_held(capture)
    except BaseException:
        if captured is not None:
            _close_resources(captured)
        raise
    if captured is None:
        _fail(WindowsTransactionContextErrorCode.TARGET_CHANGED)
    return captured


__all__ = [
    "HeldWindowsTransactionContext",
    "WindowsTransactionContextError",
    "WindowsTransactionContextErrorCode",
    "capture_native_windows_transaction_context",
    "resume_native_windows_pending_recovery",
]
