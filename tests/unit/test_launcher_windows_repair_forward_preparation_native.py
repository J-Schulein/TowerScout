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
from test_launcher_windows_repair_certificate_staging import (  # noqa: E402
    _Names,
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
from towerscout_launcher.windows_repair_forward_preparation_native import (  # noqa: E402
    NativeRepairForwardPreparationError,
    NativeRepairForwardPreparationErrorCode,
    PreparedRepairForward,
    prepare_native_windows_repair_forward,
)
from towerscout_launcher.windows_repair_rollback_preparation_native import (  # noqa: E402
    prepare_native_windows_repair_rollback,
)


class _ForwardIds:
    def new_forward_journal_id(self) -> str:
        return "b" * 32


class _SameForwardIds:
    def new_forward_journal_id(self) -> str:
        return "a" * 32


def test_stages_forward_certificate_candidates_after_rollback_is_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _authority, _executor, backend = _backend()
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    protected = _ProtectedRoot()
    context = _context(owner, protected)
    rollback_generations = _GenerationStorage(protected)
    _patch_exact_inputs(monkeypatch, owner)
    rollback = prepare_native_windows_repair_rollback(
        owner,
        context,
        journal_id_source=_JournalIds(),
        backup_name_source=_NameSource(),
        journal_storage=rollback_generations,  # type: ignore[arg-type]
        pointer_storage=rollback_generations,  # type: ignore[arg-type]
        backup_storage=_BlobStorage(protected),  # type: ignore[arg-type]
    )
    forward_storage = _Storage()
    certificate_api = _Api()

    forward = prepare_native_windows_repair_forward(
        owner,
        context,
        rollback,
        journal_id_source=_ForwardIds(),
        certificate_name_source=_Names(),
        journal_storage=forward_storage,  # type: ignore[arg-type]
        pointer_storage=forward_storage,  # type: ignore[arg-type]
        certificate_storage=NativeWindowsRepairCertificateTempStorage(
            api=certificate_api
        ),
    )

    assert isinstance(forward, PreparedRepairForward)
    assert forward.stream.journal_id == "b" * 32
    assert forward.stream.rollback_journal_id == "a" * 32
    assert len(forward.staged.selection.generations) == 3
    assert len(certificate_api.files) == 2
    context.close()
    owner.close()


def test_rejects_forward_id_equal_to_rollback_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _authority, _executor, backend = _backend()
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    protected = _ProtectedRoot()
    context = _context(owner, protected)
    rollback_generations = _GenerationStorage(protected)
    _patch_exact_inputs(monkeypatch, owner)
    rollback = prepare_native_windows_repair_rollback(
        owner,
        context,
        journal_id_source=_JournalIds(),
        backup_name_source=_NameSource(),
        journal_storage=rollback_generations,  # type: ignore[arg-type]
        pointer_storage=rollback_generations,  # type: ignore[arg-type]
        backup_storage=_BlobStorage(protected),  # type: ignore[arg-type]
    )

    with pytest.raises(NativeRepairForwardPreparationError) as caught:
        prepare_native_windows_repair_forward(
            owner,
            context,
            rollback,
            journal_id_source=_SameForwardIds(),
            certificate_name_source=_Names(),
            journal_storage=_Storage(),  # type: ignore[arg-type]
            pointer_storage=_Storage(),  # type: ignore[arg-type]
            certificate_storage=NativeWindowsRepairCertificateTempStorage(api=_Api()),
        )

    assert caught.value.code is NativeRepairForwardPreparationErrorCode.INPUT_INVALID
    assert caught.value.__cause__ is None
    context.close()
    owner.close()
