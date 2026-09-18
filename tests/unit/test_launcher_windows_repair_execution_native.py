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
from towerscout_launcher.windows_recovery_scan import (  # noqa: E402
    PackageRecoveryJournalScan,
)
from towerscout_launcher.windows_repair_cleanup_execution_native import (  # noqa: E402
    cleanup_committed_native_windows_repair,
)
from towerscout_launcher.windows_repair_execution_native import (  # noqa: E402
    NativeRepairExecutionError,
    NativeRepairExecutionErrorCode,
    NativeRepairExecutionOutcome,
    execute_native_windows_repair,
)
from towerscout_launcher.windows_transaction_context import (  # noqa: E402
    HeldWindowsTransactionContext,
)
import towerscout_launcher.windows_repair_execution_native as execution_native  # noqa: E402,E501


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
    _patch_success_stages(monkeypatch, values)

    result = execute_native_windows_repair(
        owner,
        context,  # type: ignore[arg-type]
    )

    assert result.outcome is NativeRepairExecutionOutcome.REPAIR_SUCCEEDED
    assert result.cleanup_recovered is False
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
        "refresh_and_resume_pending_recovery",
        lambda _self: PackageRecoveryJournalScan(1, identity),
    )

    with pytest.raises(NativeRepairExecutionError) as captured:
        execute_native_windows_repair(owner, context)  # type: ignore[arg-type]

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
        "refresh_and_resume_pending_recovery",
        lambda _self: PackageRecoveryJournalScan(
            1,
            rollback.stream.package_root_identity,
        ),
    )

    result = execute_native_windows_repair(owner, context)  # type: ignore[arg-type]

    assert result.outcome is NativeRepairExecutionOutcome.REPAIR_SUCCEEDED
    assert result.cleanup_recovered is True
    owner.close()
    context.close()  # type: ignore[attr-defined]


def test_pre_arm_failure_never_invokes_recovery(
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
        "refresh_and_resume_pending_recovery",
        lambda _self: pytest.fail("pre-arm failure must not recover"),
    )

    with pytest.raises(NativeRepairExecutionError) as captured:
        execute_native_windows_repair(owner, context)  # type: ignore[arg-type]

    assert captured.value.code is NativeRepairExecutionErrorCode.EXECUTION_FAILED
    assert owner.closed
    context.close()  # type: ignore[attr-defined]
