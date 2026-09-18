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

from test_launcher_runtime_target_observation_backend import _backend  # noqa: E402
from test_launcher_windows_recovery_backup_storage import (  # noqa: E402
    _BlobStorage,
    _GenerationStorage,
    _NameSource,
)
from test_launcher_windows_recovery_certificate_storage_native import (  # noqa: E402
    _Api,
)
from test_launcher_windows_repair_certificate_staging import _Names  # noqa: E402
from test_launcher_windows_repair_forward_preparation_native import (  # noqa: E402
    _ForwardIds,
)
from test_launcher_windows_repair_rollback_preparation_native import (  # noqa: E402
    _context,
    _JournalIds,
    _patch_exact_inputs,
    _ProtectedRoot,
)
from test_launcher_windows_repair_transaction_journal_storage import (  # noqa: E402
    _Storage,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.windows_recovery_certificate_storage_native import (  # noqa: E402
    NativeWindowsRepairCertificateTempStorage,
)
from towerscout_launcher.windows_repair_certificate_execution_native import (  # noqa: E402
    AppliedRepairCertificates,
    apply_native_windows_repair_certificates,
)
from towerscout_launcher.windows_repair_forward_preparation_native import (  # noqa: E402
    prepare_native_windows_repair_forward,
)
from towerscout_launcher.windows_repair_rollback_preparation_native import (  # noqa: E402
    prepare_native_windows_repair_rollback,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionGeneration,
    RepairTransactionState,
    RepairTransitionRecord,
    protect_repair_transaction_generation,
)
from towerscout_launcher.windows_repair_transaction_journal_storage import (  # noqa: E402
    append_persisted_repair_transaction_generation_from_held_root,
    ensure_persisted_repair_transaction_pointer_from_held_root,
)
import towerscout_launcher.windows_repair_certificate_execution_native as native  # noqa: E402


def _prepared(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, object, object, _ProtectedRoot, _Storage]:
    plan, _authority, _executor, backend = _backend()
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    protected = _ProtectedRoot()
    context = _context(owner, protected)
    rollback_storage = _GenerationStorage(protected)
    _patch_exact_inputs(monkeypatch, owner)
    rollback = prepare_native_windows_repair_rollback(
        owner,
        context,
        journal_id_source=_JournalIds(),
        backup_name_source=_NameSource(),
        journal_storage=rollback_storage,  # type: ignore[arg-type]
        pointer_storage=rollback_storage,  # type: ignore[arg-type]
        backup_storage=_BlobStorage(protected),  # type: ignore[arg-type]
    )
    forward_storage = _Storage()
    prepared = prepare_native_windows_repair_forward(
        owner,
        context,
        rollback,
        journal_id_source=_ForwardIds(),
        certificate_name_source=_Names(),
        journal_storage=forward_storage,  # type: ignore[arg-type]
        pointer_storage=forward_storage,  # type: ignore[arg-type]
        certificate_storage=NativeWindowsRepairCertificateTempStorage(api=_Api()),
    )
    return owner, context, prepared, protected, forward_storage


def _append_applied(prepared: object, protected: _ProtectedRoot, storage: _Storage):
    staged = getattr(prepared, "staged")
    stream = getattr(prepared, "stream")
    previous = staged.selection.tip_generation_sha256
    generation = RepairTransactionGeneration(
        1,
        stream,
        4,
        previous,
        RepairTransactionState.CERTIFICATES_APPLIED,
        RepairTransitionRecord(
            1,
            previous,
            stream.package_root_identity,
            "4" * 64,
        ),
    )
    sealed = protect_repair_transaction_generation(generation, protection=protected)
    append_persisted_repair_transaction_generation_from_held_root(
        r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
        sealed,
        stream=stream,
        storage=storage,
        protection=protected,
    )
    current = ensure_persisted_repair_transaction_pointer_from_held_root(
        r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
        stream,
        generation_storage=storage,
        pointer_storage=storage,
        protection=protected,
    )
    assert current is not None
    return current


def _applied_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, object, AppliedRepairCertificates, _ProtectedRoot, _Storage]:
    owner, context, prepared, protected, storage = _prepared(monkeypatch)
    applied = _append_applied(prepared, protected, storage)
    monkeypatch.setattr(native, "apply_repair_certificates", lambda *_a, **_k: applied)
    monkeypatch.setattr(
        native,
        "cleanup_applied_repair_certificate_candidates",
        lambda forward, *_a, **_k: forward,
    )
    result = apply_native_windows_repair_certificates(
        owner,  # type: ignore[arg-type]
        context,  # type: ignore[arg-type]
        prepared,  # type: ignore[arg-type]
        journal_storage=storage,
        pointer_storage=storage,
        certificate_storage=NativeWindowsRepairCertificateTempStorage(api=_Api()),
    )
    return owner, context, result, protected, storage


def test_composes_certificate_apply_and_exact_temp_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, context, applied, _protected, _storage = _applied_setup(monkeypatch)

    assert isinstance(applied, AppliedRepairCertificates)
    assert (
        applied.forward.selection.tip.state
        is RepairTransactionState.CERTIFICATES_APPLIED
    )
    assert getattr(owner, "closed") is getattr(context, "closed") is False
    context.close()
    owner.close()
