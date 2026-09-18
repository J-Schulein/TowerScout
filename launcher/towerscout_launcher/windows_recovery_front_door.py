"""Fresh-process admission for one authenticated Windows repair rollback.

The front door owns the fixed package root, protected recovery root, and
environment mutex before it trusts any pending journal. It then reconstructs
the persisted target without rerunning trust selection, acquires the target
mutex, and transfers every owner to the retained transaction context before
invoking the rollback manager.
"""

from __future__ import annotations

from enum import Enum
from typing import NoReturn

from .runtime_target_inputs import capture_native_windows_fixed_package_root_trust
from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_mutex import (
    HeldCrossSessionMutex,
    HeldRuntimeTransactionLocks,
    RuntimeTransactionLockBinding,
    absent_runtime_transaction_lock_binding,
    acquire_runtime_target_lock_after_environment,
    acquire_secured_cross_session_mutex,
    runtime_transaction_lock_binding,
)
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import (
    ProtectedStateRoot,
    capture_native_windows_protected_state_root,
)
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_recovery_manager_native import (
    certificate_identity_from_recovery_chain,
    rollback_runtime_authority_from_recovery_chain,
)
from .windows_recovery_runtime_authority import (
    derive_absent_rollback_runtime_recovery_authority,
    derive_rollback_runtime_recovery_authority,
)
from .windows_recovery_runtime_available_native import (
    BoundAbsentRollbackRuntimeTarget,
    capture_native_absent_rollback_runtime_target,
    capture_native_present_rollback_runtime_target,
)
from .windows_recovery_scan import (
    PackageRecoveryJournalScan,
    scan_package_recovery_journals_from_held_root,
)
from .windows_security import derive_environment_mutex_name
from .windows_transaction_context import (
    HeldWindowsTransactionContext,
    resume_native_windows_pending_recovery,
)


class WindowsRecoveryFrontDoorOutcome(str, Enum):
    NO_RECOVERY = "no_recovery"
    RECOVERED = "recovered"


class WindowsRecoveryFrontDoorErrorCode(str, Enum):
    RECOVERY_UNAVAILABLE = "repair_recovery_unavailable"
    PROVIDER_RECOVERY_PENDING = "provider_recovery_pending"
    RECOVERY_FAILED = "repair_recovery_pending"


class WindowsRecoveryFrontDoorError(RuntimeError):
    """Sanitized fresh-process recovery failure."""

    _MESSAGES = {
        WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE: (
            "Protected repair recovery is unavailable."
        ),
        WindowsRecoveryFrontDoorErrorCode.PROVIDER_RECOVERY_PENDING: (
            "Provider environment recovery must finish before repair recovery."
        ),
        WindowsRecoveryFrontDoorErrorCode.RECOVERY_FAILED: (
            "The prior repair still requires recovery."
        ),
    }

    def __init__(self, code: WindowsRecoveryFrontDoorErrorCode) -> None:
        if type(code) is not WindowsRecoveryFrontDoorErrorCode:
            raise ValueError("Unknown Windows recovery front-door error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"WindowsRecoveryFrontDoorError(code={self.code.value!r})"


def _fail(code: WindowsRecoveryFrontDoorErrorCode) -> NoReturn:
    raise WindowsRecoveryFrontDoorError(code) from None


_RecoveryTarget = BoundResolvedRepairTarget | BoundAbsentRollbackRuntimeTarget


def _close(resource: object | None) -> bool:
    if resource is None:
        return False
    try:
        close = getattr(resource, "close", None)
        if callable(close):
            close()
    except BaseException:
        return True
    return False


def _scan(
    package_root: PathHierarchyTrust,
    protected_root: ProtectedStateRoot,
) -> PackageRecoveryJournalScan:
    return scan_package_recovery_journals_from_held_root(
        package_root,
        protected_root=protected_root,
        generation_storage=NativeWindowsJournalGenerationStorage(),
        pointer_storage=NativeWindowsJournalPointerStorage(),
        protection=protected_root,
    )


def _capture_target(scan: PackageRecoveryJournalScan) -> _RecoveryTarget:
    repair = scan.repair
    if repair is None:
        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
    certificate = certificate_identity_from_recovery_chain(repair)
    authority = rollback_runtime_authority_from_recovery_chain(repair)
    present_unavailable = False
    try:
        return capture_native_present_rollback_runtime_target(
            certificate,
            authority,
        )
    except Exception:
        present_unavailable = True
    if not present_unavailable:
        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
    try:
        return capture_native_absent_rollback_runtime_target(
            certificate,
            authority,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)


def _target_binding(
    target: _RecoveryTarget,
    scan: PackageRecoveryJournalScan,
) -> RuntimeTransactionLockBinding:
    repair = scan.repair
    if repair is None:
        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
    stream = repair.selection.tip.stream
    authority = rollback_runtime_authority_from_recovery_chain(repair)
    package_identity = scan.package_root_identity
    if type(target) is BoundResolvedRepairTarget:
        target.assert_unchanged()
        if derive_rollback_runtime_recovery_authority(target.target) != authority:
            _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
        return runtime_transaction_lock_binding(target.target, package_identity)
    if type(target) is BoundAbsentRollbackRuntimeTarget:
        observation = target.assert_unchanged()
        if (
            derive_absent_rollback_runtime_recovery_authority(
                stream.target_token_sha256,
                observation,
            )
            != authority
        ):
            _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
        return absent_runtime_transaction_lock_binding(
            stream.target_token_sha256,
            observation,
            package_identity,
        )
    _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)


def recover_native_windows_pending_repair(
    *,
    lock_timeout_ms: int = 0,
) -> WindowsRecoveryFrontDoorOutcome:
    """Resume one pending repair without relying on a caller-selected provider."""

    package_root: PathHierarchyTrust | None = None
    protected_root: ProtectedStateRoot | None = None
    environment_mutex: HeldCrossSessionMutex | None = None
    locks: HeldRuntimeTransactionLocks | None = None
    target: _RecoveryTarget | None = None
    context: HeldWindowsTransactionContext | None = None
    outcome: WindowsRecoveryFrontDoorOutcome | None = None
    failure: WindowsRecoveryFrontDoorErrorCode | None = None
    interruption: BaseException | None = None
    try:
        package_root = capture_native_windows_fixed_package_root_trust()
        protected_root = capture_native_windows_protected_state_root()
        environment_mutex = acquire_secured_cross_session_mutex(
            derive_environment_mutex_name(package_root.root_snapshot.identity),
            timeout_ms=lock_timeout_ms,
        )
        held_package_root = package_root
        held_protected_root = protected_root
        initial_scan: PackageRecoveryJournalScan | None = None

        def inspect() -> None:
            nonlocal initial_scan
            initial_scan = _scan(held_package_root, held_protected_root)

        held_package_root.run_while_held(inspect)
        if initial_scan is None:
            _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
        if initial_scan.provider_environment_pending:
            _fail(WindowsRecoveryFrontDoorErrorCode.PROVIDER_RECOVERY_PENDING)
        if initial_scan.repair is None:
            outcome = WindowsRecoveryFrontDoorOutcome.NO_RECOVERY
        else:
            target = _capture_target(initial_scan)
            held_target = target

            def acquire_pair() -> None:
                nonlocal environment_mutex, locks
                binding = _target_binding(held_target, initial_scan)
                if (
                    environment_mutex is None
                    or binding.environment_mutex_name
                    != derive_environment_mutex_name(
                        held_package_root.root_snapshot.identity
                    )
                ):
                    _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)

                def revalidate() -> RuntimeTransactionLockBinding:
                    held_package_root.assert_unchanged_while_held()
                    held_protected_root.assert_unchanged()
                    if _scan(held_package_root, held_protected_root) != initial_scan:
                        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
                    return _target_binding(held_target, initial_scan)

                locks = acquire_runtime_target_lock_after_environment(
                    binding,
                    revalidate,
                    environment_mutex,
                    timeout_ms=lock_timeout_ms,
                )
                environment_mutex = None

            held_package_root.run_while_held(acquire_pair)
            if locks is None:
                _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
            if _close(target):
                _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_UNAVAILABLE)
            target = None
            stream = initial_scan.repair.selection.tip.stream
            context = HeldWindowsTransactionContext(
                target_token_sha256=stream.target_token_sha256,
                package_root=held_package_root,
                protected_root=held_protected_root,
                locks=locks,
                recovery_scan=initial_scan,
                resume_recovery=resume_native_windows_pending_recovery,
            )
            package_root = None
            protected_root = None
            locks = None
            context.resume_pending_recovery()
            outcome = WindowsRecoveryFrontDoorOutcome.RECOVERED
    except WindowsRecoveryFrontDoorError as error:
        failure = error.code
    except BaseException as error:
        if isinstance(error, Exception):
            failure = WindowsRecoveryFrontDoorErrorCode.RECOVERY_FAILED
        else:
            interruption = error

    cleanup_failed = False
    for resource in (
        context,
        target,
        locks,
        environment_mutex,
        protected_root,
        package_root,
    ):
        cleanup_failed = _close(resource) or cleanup_failed
    if interruption is not None:
        raise interruption
    if cleanup_failed:
        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_FAILED)
    if failure is not None:
        _fail(failure)
    if outcome is None:
        _fail(WindowsRecoveryFrontDoorErrorCode.RECOVERY_FAILED)
    return outcome


__all__ = [
    "WindowsRecoveryFrontDoorError",
    "WindowsRecoveryFrontDoorErrorCode",
    "WindowsRecoveryFrontDoorOutcome",
    "recover_native_windows_pending_repair",
]
