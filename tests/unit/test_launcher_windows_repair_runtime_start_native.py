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
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    BoundResolvedRepairTarget,
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.windows_repair_environment_execution_native import (  # noqa: E402
    apply_native_windows_repair_environment,
)
from towerscout_launcher.windows_repair_runtime_start_native import (  # noqa: E402
    NativeRepairRuntimeStartError,
    NativeRepairRuntimeStartErrorCode,
    StartedRepairRuntime,
    start_native_windows_repair_runtime,
)
from towerscout_launcher.windows_repair_runtime_stop_native import (  # noqa: E402
    StoppedRepairRuntime,
    stop_native_windows_repair_runtime,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
)
import towerscout_launcher.windows_repair_environment_execution_native as environment_native  # noqa: E402,E501
import towerscout_launcher.windows_repair_runtime_start_native as start_native  # noqa: E402,E501


class _Absent:
    def __init__(self, owner: BoundResolvedRepairTarget) -> None:
        self.closed = False
        self.owner = owner

    def start(self) -> tuple[BoundResolvedRepairTarget, int]:
        self.closed = True
        return self.owner, 0

    def close(self) -> None:
        self.closed = True


def _stopped_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, StoppedRepairRuntime, object]:
    owner, context, certificates, _protected, storage = _applied_setup(monkeypatch)
    stream = certificates.prepared.stream
    provider = _provider_chain(
        journal_id="c" * 32,
        package_root_identity=stream.package_root_identity,
        provider_environment=True,
        provider_applied=True,
        target_token_sha256=stream.target_token_sha256,
    )
    monkeypatch.setattr(
        environment_native,
        "stage_or_resume_persisted_environment_candidate",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        environment_native,
        "load_persisted_environment_journal_chain_from_held_root",
        lambda *_args, **_kwargs: _current_prefix(provider, 3),
    )
    monkeypatch.setattr(
        environment_native,
        "persist_environment_applied_generation",
        lambda **_kwargs: _current_prefix(provider, 4),
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
    return context, stopped, storage


def _fresh_owner() -> BoundResolvedRepairTarget:
    plan, _authority, _executor, backend = _backend()
    return capture_bound_resolved_repair_target(plan, backend=backend)


def test_persists_start_intent_then_returns_only_new_bound_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, stopped, storage = _stopped_setup(monkeypatch)
    owner = _fresh_owner()
    absent = _Absent(owner)

    started = start_native_windows_repair_runtime(
        context,  # type: ignore[arg-type]
        stopped,
        absent_capture=lambda _stopped: absent,  # type: ignore[arg-type,return-value]
        journal_storage=storage,  # type: ignore[arg-type]
        pointer_storage=storage,  # type: ignore[arg-type]
    )

    assert isinstance(started, StartedRepairRuntime)
    assert started.owner is owner
    assert not owner.closed
    assert absent.closed
    assert tuple(item.state for item in started.forward.selection.generations[-2:]) == (
        RepairTransactionState.RUNTIME_STARTING,
        RepairTransactionState.RUNTIME_STARTED,
    )
    owner.close()
    context.close()  # type: ignore[attr-defined]


def test_closes_new_owner_when_started_generation_cannot_be_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, stopped, storage = _stopped_setup(monkeypatch)
    owner = _fresh_owner()
    absent = _Absent(owner)
    real_append = start_native._append

    def append(*args: object, **kwargs: object):
        if args[2] is RepairTransactionState.RUNTIME_STARTED:
            raise NativeRepairRuntimeStartError(
                NativeRepairRuntimeStartErrorCode.START_FAILED
            )
        return real_append(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(start_native, "_append", append)

    with pytest.raises(NativeRepairRuntimeStartError) as captured:
        start_native_windows_repair_runtime(
            context,  # type: ignore[arg-type]
            stopped,
            absent_capture=lambda _stopped: absent,  # type: ignore[arg-type,return-value]
            journal_storage=storage,  # type: ignore[arg-type]
            pointer_storage=storage,  # type: ignore[arg-type]
        )

    assert captured.value.code is NativeRepairRuntimeStartErrorCode.START_FAILED
    assert owner.closed
    context.close()  # type: ignore[attr-defined]
