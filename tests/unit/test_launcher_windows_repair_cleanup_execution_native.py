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

from test_launcher_windows_repair_terminal_verification_native import (  # noqa: E402
    _Certificates,
    _Environment,
    _started,
)
from test_launcher_windows_recovery_backup_storage import (  # noqa: E402
    _NativeCleanupApi,
)
from test_launcher_windows_recovery_verification_native import (  # noqa: E402
    _package_root_for_target,
)
from towerscout_launcher.windows_recovery import RecoveryCleanupEvidence  # noqa: E402
from towerscout_launcher.windows_recovery_cleanup_native import (  # noqa: E402
    NativeWindowsRecoveryCleanup,
)
from towerscout_launcher.windows_repair_cleanup_execution_native import (  # noqa: E402
    CleanedRepair,
    NativeRepairCleanupExecutionError,
    NativeRepairCleanupExecutionErrorCode,
    cleanup_committed_native_windows_repair,
)
from towerscout_launcher.windows_repair_terminal_verification_native import (  # noqa: E402
    verify_and_commit_native_windows_repair,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
)
import towerscout_launcher.windows_repair_cleanup_execution_native as cleanup_native  # noqa: E402,E501


class _Cleanup:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def cleanup_committed_repair_artifacts_while_package_root_held(
        self,
        package_root: object,
        protected_root_path: str,
        rollback: object,
        forward: object,
    ) -> RecoveryCleanupEvidence:
        self.calls += 1
        if self.fail:
            raise OSError("PRIVATE CLEANUP DETAIL")
        stream = getattr(forward, "selection").tip.stream
        assert getattr(package_root, "root_snapshot").identity == (
            stream.package_root_identity
        )
        assert protected_root_path
        assert getattr(rollback, "selection").tip.stream.journal_id == (
            stream.rollback_journal_id
        )
        return RecoveryCleanupEvidence(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            "a" * 64,
        )


def _committed(monkeypatch: pytest.MonkeyPatch):
    context, started, storage = _started(monkeypatch)
    committed = verify_and_commit_native_windows_repair(
        context,  # type: ignore[arg-type]
        started,
        environment=_Environment(started),  # type: ignore[arg-type]
        certificate_observer=_Certificates(started),  # type: ignore[arg-type]
        journal_storage=storage,  # type: ignore[arg-type]
        pointer_storage=storage,  # type: ignore[arg-type]
    )
    return context, committed, storage


def test_exact_backup_cleanup_advances_committed_directly_to_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, committed, storage = _committed(monkeypatch)
    cleanup = _Cleanup()

    cleaned = cleanup_committed_native_windows_repair(
        context,  # type: ignore[arg-type]
        committed,
        cleanup=cleanup,  # type: ignore[arg-type]
        journal_storage=storage,  # type: ignore[arg-type]
        pointer_storage=storage,  # type: ignore[arg-type]
    )

    assert isinstance(cleaned, CleanedRepair)
    assert cleanup.calls == 1
    assert cleaned.forward.selection.tip.state is RepairTransactionState.CLEANED
    assert len(cleaned.forward.selection.generations) == 15
    context.close()  # type: ignore[attr-defined]


def test_cleanup_failure_durably_records_pending_without_false_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, committed, storage = _committed(monkeypatch)
    appended: list[RepairTransactionState] = []
    real_append = cleanup_native._append

    def append(*args: object, **kwargs: object):
        appended.append(args[2])  # type: ignore[arg-type]
        return real_append(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(cleanup_native, "_append", append)

    with pytest.raises(NativeRepairCleanupExecutionError) as captured:
        cleanup_committed_native_windows_repair(
            context,  # type: ignore[arg-type]
            committed,
            cleanup=_Cleanup(fail=True),  # type: ignore[arg-type]
            journal_storage=storage,  # type: ignore[arg-type]
            pointer_storage=storage,  # type: ignore[arg-type]
        )

    assert captured.value.code is NativeRepairCleanupExecutionErrorCode.CLEANUP_PENDING
    assert appended == [RepairTransactionState.RECOVERY_CLEANUP_PENDING]
    context.close()  # type: ignore[attr-defined]


def test_native_cleanup_accepts_only_authenticated_committed_backup_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, committed, _storage = _committed(monkeypatch)
    api = _NativeCleanupApi({})
    adapter = NativeWindowsRecoveryCleanup(api=api)  # type: ignore[arg-type]
    rollback = committed.started.stopped.environment.certificates.prepared.rollback
    package_root = _package_root_for_target(rollback.target)

    evidence = package_root.run_while_held(
        lambda: adapter.cleanup_committed_repair_artifacts_while_package_root_held(
            package_root,
            r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
            rollback.activated,
            committed.forward,
        )
    )

    assert evidence.target_token_sha256 == rollback.stream.target_token_sha256
    assert len([event for event in api.events if event.startswith("delete-open:")]) == 2
    package_root.close()
    context.close()  # type: ignore[attr-defined]
