from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_windows_repair_cleanup_execution_native import (  # noqa: E402
    _Cleanup,
    _committed,
)
from test_launcher_windows_repair_runtime_start_native import (  # noqa: E402
    _fresh_owner,
)
from test_launcher_windows_recovery_scan import _chain as _recovery_chain  # noqa: E402
from towerscout_launcher.windows_recovery_scan import (  # noqa: E402
    PackageRecoveryJournalScan,
)
from towerscout_launcher.windows_repair_cleanup_execution_native import (  # noqa: E402
    cleanup_committed_native_windows_repair,
)
from towerscout_launcher.windows_repair_execution_native import (  # noqa: E402
    NativeRepairExecutionError,
    NativeRepairExecutionErrorCode,
    NativeRepairExecutionHooks,
    NativeRepairExecutionOutcome,
    execute_native_windows_repair,
)
from towerscout_launcher.windows_transaction_context import (  # noqa: E402
    HeldWindowsTransactionContext,
)
import towerscout_launcher.windows_repair_execution_native as execution_native  # noqa: E402,E501


def _hooks(events: list[str] | None = None) -> NativeRepairExecutionHooks:
    selected = [] if events is None else events
    return NativeRepairExecutionHooks(
        lambda: selected.append("before_mutation"),
        lambda: selected.append("before_restart"),
        lambda _owner: selected.append("terminal"),
    )


def _completed(monkeypatch: pytest.MonkeyPatch):
    context, committed, storage = _committed(monkeypatch)
    cleaned = cleanup_committed_native_windows_repair(
        context,  # type: ignore[arg-type]
        committed,
        cleanup=_Cleanup(),  # type: ignore[arg-type]
        journal_storage=storage,  # type: ignore[arg-type]
        pointer_storage=storage,  # type: ignore[arg-type]
    )
    started = committed.started
    stopped = started.stopped
    environment = stopped.environment
    certificates = environment.certificates
    forward = certificates.prepared
    rollback = forward.rollback
    return (
        context,
        rollback,
        forward,
        certificates,
        environment,
        stopped,
        started,
        committed,
        cleaned,
    )


def _patch_success_stages(monkeypatch: pytest.MonkeyPatch, values: tuple[object, ...]):
    (
        _context,
        rollback,
        forward,
        certificates,
        environment,
        stopped,
        started,
        committed,
        cleaned,
    ) = values
    for name, value in (
        ("prepare_native_windows_repair_rollback", rollback),
        ("prepare_native_windows_repair_forward", forward),
        ("apply_native_windows_repair_certificates", certificates),
        ("apply_native_windows_repair_environment", environment),
        ("stop_native_windows_repair_runtime", stopped),
        ("start_native_windows_repair_runtime", started),
        ("verify_and_commit_native_windows_repair", committed),
        ("cleanup_committed_native_windows_repair", cleaned),
    ):
        monkeypatch.setattr(
            execution_native,
            name,
            lambda *_args, _value=value, **_kwargs: _value,
        )


def test_coordinator_runs_every_stage_through_terminal_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _completed(monkeypatch)
    context = values[0]
    owner = _fresh_owner()
    events: list[str] = []
    _patch_success_stages(monkeypatch, values)

    result = execute_native_windows_repair(
        owner,
        context,  # type: ignore[arg-type]
        _hooks(events),
    )

    assert result.outcome is NativeRepairExecutionOutcome.REPAIR_SUCCEEDED
    assert result.cleanup_recovered is False
    assert events == ["before_mutation", "before_restart", "terminal"]
    owner.close()
    context.close()  # type: ignore[attr-defined]


def test_post_arm_failure_rescans_and_reports_verified_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _completed(monkeypatch)
    context = values[0]
    rollback = values[1]
    owner = _fresh_owner()
    monkeypatch.setattr(
        execution_native,
        "prepare_native_windows_repair_rollback",
        lambda *_args, **_kwargs: rollback,
    )
    monkeypatch.setattr(
        execution_native,
        "prepare_native_windows_repair_forward",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE")),
    )
    identity = rollback.stream.package_root_identity
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "refresh_recovery_scan",
        lambda _self: PackageRecoveryJournalScan(1, identity, rollback.activated),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "resume_pending_recovery",
        lambda _self: PackageRecoveryJournalScan(1, identity),
    )

    with pytest.raises(NativeRepairExecutionError) as captured:
        execute_native_windows_repair(
            owner,
            context,  # type: ignore[arg-type]
            _hooks(),
        )

    assert captured.value.code is NativeRepairExecutionErrorCode.REPAIR_ROLLED_BACK
    assert owner.closed
    context.close()  # type: ignore[attr-defined]


def test_committed_cleanup_failure_recovers_cleanup_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _completed(monkeypatch)
    context = values[0]
    rollback = values[1]
    owner = _fresh_owner()
    _patch_success_stages(monkeypatch, values)
    monkeypatch.setattr(
        execution_native,
        "cleanup_committed_native_windows_repair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE")),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "refresh_recovery_scan",
        lambda _self: PackageRecoveryJournalScan(
            1,
            rollback.stream.package_root_identity,
        ),
    )

    result = execute_native_windows_repair(
        owner,
        context,  # type: ignore[arg-type]
        _hooks(),
    )

    assert result.outcome is NativeRepairExecutionOutcome.REPAIR_SUCCEEDED
    assert result.cleanup_recovered is True
    owner.close()
    context.close()  # type: ignore[attr-defined]


def test_failure_before_durable_write_rescans_without_invoking_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _completed(monkeypatch)
    context = values[0]
    owner = _fresh_owner()
    monkeypatch.setattr(
        execution_native,
        "prepare_native_windows_repair_rollback",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE")),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "refresh_recovery_scan",
        lambda _self: PackageRecoveryJournalScan(
            1,
            context.recovery_scan.package_root_identity,
        ),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "resume_pending_recovery",
        lambda _self: pytest.fail("clear durable state must not recover"),
    )

    with pytest.raises(NativeRepairExecutionError) as captured:
        execute_native_windows_repair(
            owner,
            context,  # type: ignore[arg-type]
            _hooks(),
        )

    assert captured.value.code is NativeRepairExecutionErrorCode.EXECUTION_FAILED
    assert owner.closed
    context.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("repair_verified", "repair_aborted_at"),
    ((False, None), (True, None), (False, 1), (False, 2)),
)
def test_partial_rollback_preparation_is_aborted_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    repair_verified: bool,
    repair_aborted_at: int | None,
) -> None:
    values = _completed(monkeypatch)
    context = values[0]
    rollback = values[1]
    owner = _fresh_owner()
    partial = _recovery_chain(
        journal_id="9" * 32,
        package_root_identity=rollback.stream.package_root_identity,
        provider_environment=False,
        repair_verified=repair_verified,
        repair_aborted_at=repair_aborted_at,
        abort_pointer_current=False,
        target_token_sha256=owner.target.target_token.digest_sha256,
    )
    monkeypatch.setattr(
        execution_native,
        "prepare_native_windows_repair_rollback",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE")),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "refresh_recovery_scan",
        lambda _self: PackageRecoveryJournalScan(
            1,
            rollback.stream.package_root_identity,
            partial,
        ),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "abort_pending_prearm_recovery",
        lambda _self: PackageRecoveryJournalScan(
            1,
            rollback.stream.package_root_identity,
        ),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "resume_pending_recovery",
        lambda _self: pytest.fail("pre-arm recovery must not enter rollback"),
    )

    with pytest.raises(NativeRepairExecutionError) as captured:
        execute_native_windows_repair(
            owner,
            context,  # type: ignore[arg-type]
            _hooks(),
        )

    assert captured.value.code is NativeRepairExecutionErrorCode.EXECUTION_FAILED
    assert owner.closed
    context.close()  # type: ignore[attr-defined]


def test_partial_rollback_preparation_preserves_recovery_pending_on_abort_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _completed(monkeypatch)
    context = values[0]
    rollback = values[1]
    owner = _fresh_owner()
    partial = _recovery_chain(
        journal_id="8" * 32,
        package_root_identity=rollback.stream.package_root_identity,
        provider_environment=False,
        target_token_sha256=owner.target.target_token.digest_sha256,
    )
    monkeypatch.setattr(
        execution_native,
        "prepare_native_windows_repair_rollback",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE")),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "refresh_recovery_scan",
        lambda _self: PackageRecoveryJournalScan(
            1,
            rollback.stream.package_root_identity,
            partial,
        ),
    )
    monkeypatch.setattr(
        HeldWindowsTransactionContext,
        "abort_pending_prearm_recovery",
        lambda _self: (_ for _ in ()).throw(RuntimeError("PRIVATE")),
    )

    with pytest.raises(NativeRepairExecutionError) as captured:
        execute_native_windows_repair(
            owner,
            context,  # type: ignore[arg-type]
            _hooks(),
        )

    assert captured.value.code is NativeRepairExecutionErrorCode.RECOVERY_PENDING
    assert owner.closed
    context.close()  # type: ignore[attr-defined]
