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

from test_launcher_windows_recovery_scan import (  # noqa: E402
    _chain as _provider_chain,
)
from test_launcher_windows_repair_certificate_execution_native import (  # noqa: E402
    _applied_setup,
)
from test_launcher_windows_repair_environment_execution_native import (  # noqa: E402
    _current_prefix,
    _ProviderIds,
)
from towerscout_launcher.windows_repair_environment_execution_native import (  # noqa: E402
    apply_native_windows_repair_environment,
)
from towerscout_launcher.windows_repair_runtime_stop_native import (  # noqa: E402
    StoppedRepairRuntime,
    stop_native_windows_repair_runtime,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
)
import towerscout_launcher.windows_repair_environment_execution_native as environment_native  # noqa: E402,E501


def test_persists_stop_intent_then_removes_only_exact_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, context, certificates, _protected, storage = _applied_setup(monkeypatch)
    stream = certificates.prepared.stream
    provider = _provider_chain(
        journal_id="c" * 32,
        package_root_identity=stream.package_root_identity,
        provider_environment=True,
        provider_applied=True,
        target_token_sha256=stream.target_token_sha256,
    )
    provider_staged = _current_prefix(provider, 3)
    provider_applied = _current_prefix(provider, 4)
    monkeypatch.setattr(
        environment_native,
        "stage_or_resume_persisted_environment_candidate",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        environment_native,
        "load_persisted_environment_journal_chain_from_held_root",
        lambda *_args, **_kwargs: provider_staged,
    )
    monkeypatch.setattr(
        environment_native,
        "persist_environment_applied_generation",
        lambda **_kwargs: provider_applied,
    )
    environment = apply_native_windows_repair_environment(
        owner,  # type: ignore[arg-type]
        context,  # type: ignore[arg-type]
        certificates,
        journal_id_source=_ProviderIds(),
        journal_storage=storage,
        pointer_storage=storage,
    )

    stopped = stop_native_windows_repair_runtime(
        owner,  # type: ignore[arg-type]
        context,  # type: ignore[arg-type]
        environment,
        journal_storage=storage,
        pointer_storage=storage,
    )

    assert isinstance(stopped, StoppedRepairRuntime)
    assert tuple(item.state for item in stopped.forward.selection.generations[-2:]) == (
        RepairTransactionState.RUNTIME_STOPPING,
        RepairTransactionState.RUNTIME_STOPPED,
    )
    assert getattr(owner, "closed") is True
    context.close()
