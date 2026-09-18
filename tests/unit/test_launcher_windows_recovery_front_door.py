from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
TEST_ROOT = Path(__file__).resolve().parent
for candidate in (LAUNCHER_ROOT, TEST_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from test_launcher_windows_recovery_scan import _chain  # noqa: E402
import towerscout_launcher.windows_recovery_front_door as front  # noqa: E402
from towerscout_launcher.windows_mutex import (  # noqa: E402
    RuntimeTransactionLockBinding,
)
from towerscout_launcher.windows_recovery_scan import (  # noqa: E402
    PackageRecoveryJournalScan,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _identity() -> StableFileIdentity:
    return StableFileIdentity(7, b"i" * 16)


class _Resource:
    def __init__(self, events: list[str], name: str) -> None:
        self.events = events
        self.name = name
        self.closed = False

    def close(self) -> None:
        self.events.append(f"{self.name}:close")
        self.closed = True


class _PackageRoot(_Resource):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, "package")
        self.root_snapshot = SimpleNamespace(identity=_identity())

    def run_while_held(self, operation):
        self.events.append("package:begin")
        result = operation()
        self.events.append("package:end")
        return result

    def assert_unchanged_while_held(self) -> object:
        self.events.append("package:validate")
        return self.root_snapshot


class _ProtectedRoot(_Resource):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, "protected")

    def assert_unchanged(self) -> object:
        self.events.append("protected:validate")
        return self


class _Target(_Resource):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events, "target")


class _Locks(_Resource):
    def __init__(self, events: list[str], environment: _Resource) -> None:
        super().__init__(events, "locks")
        self.environment = environment

    def close(self) -> None:
        super().close()
        self.environment.close()


class _Context(_Resource):
    def __init__(self, events: list[str], **arguments: object) -> None:
        super().__init__(events, "context")
        self.arguments = arguments
        self.recovery_scan = arguments["recovery_scan"]

    def resume_pending_recovery(self) -> PackageRecoveryJournalScan:
        self.events.append("context:resume")
        scan = self.recovery_scan
        assert isinstance(scan, PackageRecoveryJournalScan)
        return PackageRecoveryJournalScan(1, scan.package_root_identity)

    def abort_pending_prearm_recovery(self) -> PackageRecoveryJournalScan:
        self.events.append("context:abort")
        scan = self.recovery_scan
        assert isinstance(scan, PackageRecoveryJournalScan)
        return PackageRecoveryJournalScan(1, scan.package_root_identity)

    def close(self) -> None:
        if self.closed:
            return
        super().close()
        for name in ("locks", "protected_root", "package_root"):
            resource = self.arguments[name]
            close = getattr(resource, "close")
            close()


def _install_common(
    monkeypatch: pytest.MonkeyPatch,
    scan: PackageRecoveryJournalScan,
) -> tuple[list[str], _PackageRoot, _ProtectedRoot, _Resource]:
    events: list[str] = []
    package = _PackageRoot(events)
    protected = _ProtectedRoot(events)
    environment = _Resource(events, "environment")
    monkeypatch.setattr(
        front,
        "capture_native_windows_fixed_package_root_trust",
        lambda: package,
    )
    monkeypatch.setattr(
        front,
        "capture_native_windows_protected_state_root",
        lambda: protected,
    )
    monkeypatch.setattr(
        front,
        "derive_environment_mutex_name",
        lambda _identity: "Global\\TowerScoutEnv-v1-" + "a" * 64,
    )
    monkeypatch.setattr(
        front,
        "acquire_secured_cross_session_mutex",
        lambda _name, timeout_ms: environment,
    )
    monkeypatch.setattr(front, "_scan", lambda _package, _protected: scan)
    return events, package, protected, environment


def test_front_door_returns_cleanly_when_no_recovery_is_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = PackageRecoveryJournalScan(1, _identity())
    events, package, protected, environment = _install_common(monkeypatch, scan)

    outcome = front.recover_native_windows_pending_repair()

    assert outcome is front.WindowsRecoveryFrontDoorOutcome.NO_RECOVERY
    assert environment.closed
    assert protected.closed
    assert package.closed
    assert "package:begin" in events


def test_front_door_transfers_both_locks_and_resumes_pending_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "b" * 64
    repair = _chain(
        journal_id="a" * 32,
        package_root_identity=_identity(),
        provider_environment=False,
        repair_armed=True,
        target_token_sha256=token,
    )
    scan = PackageRecoveryJournalScan(1, _identity(), repair)
    events, package, protected, environment = _install_common(monkeypatch, scan)
    target = _Target(events)
    binding = RuntimeTransactionLockBinding(
        "Global\\TowerScoutEnv-v1-" + "a" * 64,
        "Global\\TowerScoutRepair-v1-" + "c" * 64,
        token,
        "d" * 64,
    )
    locks = _Locks(events, environment)
    monkeypatch.setattr(front, "_capture_target", lambda _scan: target)
    monkeypatch.setattr(front, "_target_binding", lambda _target, _scan: binding)

    def acquire(
        candidate: RuntimeTransactionLockBinding,
        revalidate,
        owned_environment: _Resource,
        *,
        timeout_ms: int,
    ) -> _Locks:
        assert candidate == binding
        assert owned_environment is environment
        assert timeout_ms == 0
        assert revalidate() == binding
        events.append("locks:acquired")
        return locks

    monkeypatch.setattr(front, "acquire_runtime_target_lock_after_environment", acquire)
    monkeypatch.setattr(
        front,
        "HeldWindowsTransactionContext",
        lambda **arguments: _Context(events, **arguments),
    )

    outcome = front.recover_native_windows_pending_repair()

    assert outcome is front.WindowsRecoveryFrontDoorOutcome.RECOVERED
    assert events.index("target:close") < events.index("context:resume")
    assert events.index("locks:acquired") < events.index("context:resume")
    assert locks.closed
    assert environment.closed
    assert protected.closed
    assert package.closed


@pytest.mark.parametrize(
    ("repair_verified", "repair_aborted_at"),
    ((False, None), (True, None), (False, 1), (False, 2)),
)
def test_front_door_aborts_fresh_process_prearm_recovery(
    monkeypatch: pytest.MonkeyPatch,
    repair_verified: bool,
    repair_aborted_at: int | None,
) -> None:
    token = "b" * 64
    repair = _chain(
        journal_id="9" * 32,
        package_root_identity=_identity(),
        provider_environment=False,
        repair_verified=repair_verified,
        repair_aborted_at=repair_aborted_at,
        abort_pointer_current=False,
        target_token_sha256=token,
    )
    scan = PackageRecoveryJournalScan(1, _identity(), repair)
    events, package, protected, environment = _install_common(monkeypatch, scan)
    target = _Target(events)
    binding = RuntimeTransactionLockBinding(
        "Global\\TowerScoutEnv-v1-" + "a" * 64,
        "Global\\TowerScoutRepair-v1-" + "c" * 64,
        token,
        "d" * 64,
    )
    locks = _Locks(events, environment)
    contexts: list[_Context] = []
    monkeypatch.setattr(front, "_capture_target", lambda _scan: target)
    monkeypatch.setattr(front, "_target_binding", lambda _target, _scan: binding)
    monkeypatch.setattr(
        front,
        "acquire_runtime_target_lock_after_environment",
        lambda _binding, _revalidate, _environment, timeout_ms: locks,
    )

    def context_factory(**arguments: object) -> _Context:
        context = _Context(events, **arguments)
        contexts.append(context)
        return context

    monkeypatch.setattr(front, "HeldWindowsTransactionContext", context_factory)

    outcome = front.recover_native_windows_pending_repair()

    assert outcome is front.WindowsRecoveryFrontDoorOutcome.RECOVERED
    assert events.count("context:abort") == 1
    assert "context:resume" not in events
    assert contexts[0].arguments["abort_recovery"] is (
        front.abort_native_windows_prearm_recovery
    )
    assert locks.closed
    assert environment.closed
    assert protected.closed
    assert package.closed


def test_front_door_blocks_provider_recovery_without_private_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = PackageRecoveryJournalScan(
        1,
        _identity(),
        external_provider_environment_pending=True,
    )
    _events, package, protected, environment = _install_common(monkeypatch, scan)

    with pytest.raises(front.WindowsRecoveryFrontDoorError) as captured:
        front.recover_native_windows_pending_repair()

    assert (
        captured.value.code
        is front.WindowsRecoveryFrontDoorErrorCode.PROVIDER_RECOVERY_PENDING
    )
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert environment.closed
    assert protected.closed
    assert package.closed


def test_target_capture_falls_back_only_after_present_capture_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = _chain(
        journal_id="a" * 32,
        package_root_identity=_identity(),
        provider_environment=False,
    )
    scan = PackageRecoveryJournalScan(1, _identity(), repair)
    certificate = object()
    authority = object()
    absent = object()
    events: list[str] = []
    monkeypatch.setattr(
        front,
        "certificate_identity_from_recovery_chain",
        lambda candidate: certificate if candidate is repair else None,
    )
    monkeypatch.setattr(
        front,
        "rollback_runtime_authority_from_recovery_chain",
        lambda candidate: authority if candidate is repair else None,
    )

    def capture_present(candidate_certificate: object, candidate_authority: object):
        assert candidate_certificate is certificate
        assert candidate_authority is authority
        events.append("present")
        raise RuntimeError("PRIVATE PRESENT DETAIL")

    def capture_absent(candidate_certificate: object, candidate_authority: object):
        assert candidate_certificate is certificate
        assert candidate_authority is authority
        events.append("absent")
        return absent

    monkeypatch.setattr(
        front,
        "capture_native_present_rollback_runtime_target",
        capture_present,
    )
    monkeypatch.setattr(
        front,
        "capture_native_absent_rollback_runtime_target",
        capture_absent,
    )

    assert front._capture_target(scan) is absent
    assert events == ["present", "absent"]


def test_target_capture_does_not_convert_process_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = _chain(
        journal_id="a" * 32,
        package_root_identity=_identity(),
        provider_environment=False,
    )
    scan = PackageRecoveryJournalScan(1, _identity(), repair)
    monkeypatch.setattr(
        front,
        "certificate_identity_from_recovery_chain",
        lambda _candidate: object(),
    )
    monkeypatch.setattr(
        front,
        "rollback_runtime_authority_from_recovery_chain",
        lambda _candidate: object(),
    )

    def interrupt(_certificate: object, _authority: object):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        front,
        "capture_native_present_rollback_runtime_target",
        interrupt,
    )

    with pytest.raises(KeyboardInterrupt):
        front._capture_target(scan)
