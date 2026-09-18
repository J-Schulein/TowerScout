from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
TEST_ROOT = Path(__file__).resolve().parent
for candidate in (LAUNCHER_ROOT, TEST_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from test_launcher_runtime_execution import _target  # noqa: E402
from test_launcher_windows_recovery_scan import (  # noqa: E402
    _chain as _recovery_chain,
    _forward_chain,
)
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_mutex import (  # noqa: E402
    RuntimeTransactionLockBinding,
    RuntimeTransactionLockError,
    RuntimeTransactionLockErrorCode,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    PathHierarchyTrust,
    PathTrustPurpose,
)
from towerscout_launcher.windows_recovery_scan import (  # noqa: E402
    PackageRecoveryJournalScan,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402
from towerscout_launcher.windows_transaction_context import (  # noqa: E402
    HeldWindowsTransactionContext,
    WindowsTransactionContextError,
    WindowsTransactionContextErrorCode,
    _capture_context,
)
import towerscout_launcher.windows_transaction_context as transaction_context  # noqa: E402


class _PathOwner:
    def __init__(
        self,
        identity: StableFileIdentity,
        events: list[str],
        name: str,
    ) -> None:
        self.root_snapshot = SimpleNamespace(identity=identity)
        self.evidence = SimpleNamespace(purpose=PathTrustPurpose.PACKAGE_ROOT)
        self.closed = False
        self.active = False
        self.events = events
        self.name = name

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert self.closed is False
        assert self.active is False
        self.active = True
        self.events.append(f"{self.name}:begin")
        try:
            self.assert_unchanged_while_held()
            result = operation()
            self.assert_unchanged_while_held()
            return result
        finally:
            self.events.append(f"{self.name}:end")
            self.active = False

    def assert_unchanged_while_held(self) -> object:
        assert self.closed is False
        assert self.active is True
        self.events.append(f"{self.name}:validate")
        return self.evidence

    def close(self) -> None:
        self.events.append(f"{self.name}:close")
        self.closed = True


class _ProtectedRoot:
    def __init__(self, events: list[str]) -> None:
        self.closed = False
        self.events = events

    def assert_unchanged(self) -> object:
        assert self.closed is False
        self.events.append("protected:validate")
        return self

    def close(self) -> None:
        self.events.append("protected:close")
        self.closed = True


class _Locks:
    def __init__(
        self,
        events: list[str],
        *,
        environment_abandoned: bool = False,
        target_abandoned: bool = False,
    ) -> None:
        self.closed = False
        self.environment_abandoned = environment_abandoned
        self.target_abandoned = target_abandoned
        self.events = events

    def close(self) -> None:
        self.events.append("locks:close")
        self.closed = True


def _identity(target: object) -> StableFileIdentity:
    package_root = getattr(target, "package_root")
    return StableFileIdentity(package_root.volume_serial, package_root.file_id)


def _capture(
    *,
    provider_pending: bool = False,
    environment_abandoned: bool = False,
    target_abandoned: bool = False,
    repair_pending: bool = False,
    resume_recovery: (
        Callable[
            [PathHierarchyTrust, object, PackageRecoveryJournalScan],
            PackageRecoveryJournalScan,
        ]
        | None
    ) = None,
) -> tuple[
    HeldWindowsTransactionContext,
    list[str],
    _PathOwner,
    _ProtectedRoot,
    _Locks,
]:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    identity = _identity(target)
    events: list[str] = []
    observed = _PathOwner(identity, events, "observed")
    retained = _PathOwner(identity, events, "retained")
    protected = _ProtectedRoot(events)
    locks = _Locks(
        events,
        environment_abandoned=environment_abandoned,
        target_abandoned=target_abandoned,
    )
    recovery_scan = PackageRecoveryJournalScan(
        1,
        identity,
        (
            _recovery_chain(
                journal_id="a" * 32,
                package_root_identity=identity,
                provider_environment=False,
                target_token_sha256=target.target_token.digest_sha256,
            )
            if repair_pending
            else None
        ),
    )

    def scan(
        package_root: PathHierarchyTrust,
        protected_root: object,
    ) -> PackageRecoveryJournalScan:
        assert package_root is retained
        assert retained.active is True
        assert protected_root is protected
        events.append("scan")
        if provider_pending:
            return PackageRecoveryJournalScan(
                1,
                identity,
                external_provider_environment_pending=True,
            )
        return recovery_scan

    def acquire(
        binding: RuntimeTransactionLockBinding,
        revalidate: Callable[[], RuntimeTransactionLockBinding],
        inspect: Callable[[], None],
    ) -> _Locks:
        events.append("lock:environment")
        assert revalidate() == binding
        inspect()
        events.append("lock:target")
        assert revalidate() == binding
        return locks

    capture_arguments: dict[str, object] = {}
    if resume_recovery is not None:
        capture_arguments["resume_recovery"] = resume_recovery
    context = observed.run_while_held(
        lambda: _capture_context(
            target,
            observed,  # type: ignore[arg-type]
            capture_package_root=lambda: retained,
            capture_protected_root=lambda: protected,
            scan_recovery=scan,
            acquire_locks=acquire,
            **capture_arguments,  # type: ignore[arg-type]
        )
    )
    return context, events, retained, protected, locks


def test_context_scans_between_ordered_locks_and_retains_every_owner() -> None:
    context, events, retained, protected, locks = _capture(
        environment_abandoned=True,
        target_abandoned=True,
    )

    assert context.recovery_scan.mutation_blocked is False
    assert context.environment_abandoned is True
    assert context.target_abandoned is True
    assert events.index("lock:environment") < events.index("scan")
    assert events.index("scan") < events.index("lock:target")
    assert retained.closed is protected.closed is locks.closed is False
    assert "PRIVATE" not in repr(context)

    result = context.run_with_package_root_held(
        lambda package_root: (package_root is retained, retained.active)
    )
    assert result == (True, True)

    context.close()
    assert context.closed is True
    assert events[-3:] == ["locks:close", "protected:close", "retained:close"]


def test_provider_recovery_pending_blocks_before_target_lock() -> None:
    with pytest.raises(WindowsTransactionContextError) as captured:
        _capture(provider_pending=True)

    assert (
        captured.value.code
        is WindowsTransactionContextErrorCode.PROVIDER_RECOVERY_PENDING
    )
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_native_recovery_uses_forward_owned_provider_stream(monkeypatch: Any) -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    identity = _identity(target)
    repair = _recovery_chain(
        journal_id="a" * 32,
        package_root_identity=identity,
        provider_environment=False,
        repair_armed=True,
        target_token_sha256=target.target_token.digest_sha256,
    )
    provider = _recovery_chain(
        journal_id="e" * 32,
        package_root_identity=identity,
        provider_environment=True,
        provider_applied=True,
        target_token_sha256=target.target_token.digest_sha256,
    )
    forward = _forward_chain(repair, count=8, provider=provider)
    recovery_scan = PackageRecoveryJournalScan(
        1,
        identity,
        repair,
        forward=forward,
        repair_provider_environment=provider,
    )
    calls: dict[str, object] = {}
    rescanned = PackageRecoveryJournalScan(1, identity)

    monkeypatch.setattr(
        transaction_context,
        "certificate_identity_from_recovery_chain",
        lambda selected: calls.setdefault("certificate_chain", selected),
    )
    monkeypatch.setattr(
        transaction_context,
        "build_native_windows_recovery_manager_ports",
        lambda certificate, root: calls.setdefault("ports", (certificate, root)),
    )

    def resume(**arguments: object) -> None:
        calls["resume"] = arguments

    monkeypatch.setattr(
        transaction_context,
        "resume_persisted_rollback_from_held_package_root",
        resume,
    )
    monkeypatch.setattr(
        transaction_context,
        "scan_package_recovery_journals_from_held_root",
        lambda *_args, **_kwargs: rescanned,
    )
    monkeypatch.setattr(
        transaction_context,
        "NativeWindowsJournalGenerationStorage",
        lambda: object(),
    )
    monkeypatch.setattr(
        transaction_context,
        "NativeWindowsJournalPointerStorage",
        lambda: object(),
    )

    package_root = object()
    protected_root = object()
    result = transaction_context.resume_native_windows_pending_recovery(
        package_root,  # type: ignore[arg-type]
        protected_root,  # type: ignore[arg-type]
        recovery_scan,
    )

    assert result is rescanned
    assert calls["certificate_chain"] is repair
    resume_arguments = calls["resume"]
    assert isinstance(resume_arguments, dict)
    assert resume_arguments["provider_stream"] == provider.selection.tip.stream
    assert resume_arguments["initial_chain"] is repair


def test_changed_duplicate_package_root_is_closed_without_lock_acquisition() -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    identity = _identity(target)
    different = StableFileIdentity(identity.volume_serial, b"x" * 16)
    events: list[str] = []
    observed = _PathOwner(identity, events, "observed")
    retained = _PathOwner(different, events, "retained")
    acquired = False

    def acquire(
        _binding: RuntimeTransactionLockBinding,
        _revalidate: Callable[[], RuntimeTransactionLockBinding],
        _inspect: Callable[[], None],
    ) -> _Locks:
        nonlocal acquired
        acquired = True
        return _Locks(events)

    with pytest.raises(WindowsTransactionContextError) as captured:
        observed.run_while_held(
            lambda: _capture_context(
                target,
                observed,  # type: ignore[arg-type]
                capture_package_root=lambda: retained,
                capture_protected_root=lambda: _ProtectedRoot(events),
                scan_recovery=lambda _path, _root: PackageRecoveryJournalScan(
                    1, identity
                ),
                acquire_locks=acquire,
            )
        )

    assert captured.value.code is WindowsTransactionContextErrorCode.TARGET_CHANGED
    assert acquired is False
    assert retained.closed is True


def test_busy_lock_failure_closes_both_captured_roots() -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    identity = _identity(target)
    events: list[str] = []
    observed = _PathOwner(identity, events, "observed")
    retained = _PathOwner(identity, events, "retained")
    protected = _ProtectedRoot(events)

    def acquire(
        _binding: RuntimeTransactionLockBinding,
        _revalidate: Callable[[], RuntimeTransactionLockBinding],
        _inspect: Callable[[], None],
    ) -> _Locks:
        raise RuntimeTransactionLockError(RuntimeTransactionLockErrorCode.BUSY)

    with pytest.raises(WindowsTransactionContextError) as captured:
        observed.run_while_held(
            lambda: _capture_context(
                target,
                observed,  # type: ignore[arg-type]
                capture_package_root=lambda: retained,
                capture_protected_root=lambda: protected,
                scan_recovery=lambda _path, _root: PackageRecoveryJournalScan(
                    1, identity
                ),
                acquire_locks=acquire,
            )
        )

    assert captured.value.code is WindowsTransactionContextErrorCode.BUSY
    assert protected.closed is True
    assert retained.closed is True


def test_context_rejects_use_and_close_from_another_thread() -> None:
    context, _events, _retained, _protected, _locks = _capture()
    errors: list[WindowsTransactionContextErrorCode] = []

    def close_elsewhere() -> None:
        try:
            context.close()
        except WindowsTransactionContextError as error:
            errors.append(error.code)

    worker = threading.Thread(target=close_elsewhere)
    worker.start()
    worker.join(timeout=5.0)

    assert worker.is_alive() is False
    assert errors == [WindowsTransactionContextErrorCode.WRONG_THREAD]
    assert context.closed is False
    context.close()


def test_context_preserves_callback_failure_after_revalidating_every_owner() -> None:
    context, events, _retained, _protected, _locks = _capture()

    def fail(_package_root: PathHierarchyTrust) -> None:
        raise RuntimeError("SANITIZED CALLBACK FAILURE")

    with pytest.raises(RuntimeError, match="SANITIZED CALLBACK FAILURE"):
        context.run_with_package_root_held(fail)

    assert events[-1] == "protected:validate"
    assert context.closed is False
    context.close()


def test_context_resumes_pending_recovery_under_retained_owners() -> None:
    recovered: list[PackageRecoveryJournalScan] = []

    def resume(
        package_root: PathHierarchyTrust,
        protected_root: object,
        scan: PackageRecoveryJournalScan,
    ) -> PackageRecoveryJournalScan:
        assert package_root.closed is False
        assert getattr(protected_root, "closed") is False
        assert scan.repair_pending is True
        result = PackageRecoveryJournalScan(1, scan.package_root_identity)
        recovered.append(result)
        return result

    context, _events, _retained, _protected, _locks = _capture(
        repair_pending=True,
        resume_recovery=resume,
    )

    result = context.resume_pending_recovery()

    assert result is recovered[0]
    assert result.mutation_blocked is False
    assert context.recovery_scan is result
    context.close()


def test_context_sanitizes_failed_pending_recovery() -> None:
    def fail(
        _package_root: PathHierarchyTrust,
        _protected_root: object,
        _scan: PackageRecoveryJournalScan,
    ) -> PackageRecoveryJournalScan:
        raise RuntimeError("PRIVATE RECOVERY DETAIL")

    context, _events, _retained, _protected, _locks = _capture(
        repair_pending=True,
        resume_recovery=fail,
    )

    with pytest.raises(WindowsTransactionContextError) as captured:
        context.resume_pending_recovery()

    assert captured.value.code is WindowsTransactionContextErrorCode.RECOVERY_FAILED
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "PRIVATE" not in str(captured.value)
    context.close()
