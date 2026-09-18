from __future__ import annotations

import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_runtime_target_observation_backend import _backend  # noqa: E402
from test_launcher_windows_repair_runtime_start_native import (  # noqa: E402
    _Absent,
    _stopped_setup,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    CertificateTargetDestination,
    ObservationOperation,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.runtime_target_observation_backend import (  # noqa: E402
    TargetObservationProcessResult,
)
from towerscout_launcher.windows_recovery import (  # noqa: E402
    CertificateDestinationRestoreEvidence,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_repair_runtime_start_native import (  # noqa: E402
    start_native_windows_repair_runtime,
)
from towerscout_launcher.windows_repair_terminal_verification_native import (  # noqa: E402
    CommittedRepair,
    NativeRepairTerminalVerificationError,
    NativeRepairTerminalVerificationErrorCode,
    verify_and_commit_native_windows_repair,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
)
import towerscout_launcher.windows_repair_terminal_verification_native as terminal_native  # noqa: E402,E501


class _Environment:
    def __init__(self, started: object) -> None:
        record = getattr(started, "stopped").environment.provider.selection.tip.record
        self.observation = EnvironmentDestinationObservation(
            True,
            record.candidate_identity,
            record.candidate_sha256,
            record.candidate_size,
            record.candidate_file_attributes,
            record.candidate_security_descriptor_sha256,
        )

    def observe_environment_while_package_root_held(
        self,
        package_root: object,
        package_root_identity: object,
    ) -> EnvironmentDestinationObservation:
        assert getattr(package_root, "root_snapshot").identity == package_root_identity
        return self.observation


class _Certificates:
    def __init__(self, started: object) -> None:
        plan = getattr(
            started, "stopped"
        ).environment.certificates.prepared.rollback.certificate_plan
        self.values = {
            CertificateTargetDestination.LOCAL_CA: CertificateDestinationRestoreEvidence(
                1,
                True,
                plan.local_ca_sha256,
                len(plan.local_ca_contents),
                plan.local_ca_mode,
                hashlib.sha256(b"local-ca-destination").hexdigest(),
            ),
            CertificateTargetDestination.CA_BUNDLE: CertificateDestinationRestoreEvidence(
                1,
                True,
                plan.ca_bundle_sha256,
                len(plan.ca_bundle_contents),
                plan.ca_bundle_mode,
                hashlib.sha256(b"ca-bundle-destination").hexdigest(),
            ),
        }

    def __call__(self, owner: object, destination: CertificateTargetDestination):
        assert getattr(owner, "closed") is False
        return self.values[destination]


class _ReadinessOwner:
    def __init__(self) -> None:
        self.target = SimpleNamespace(container=SimpleNamespace(container_id="d" * 64))
        self.calls = 0

    def execute_scoped_process(
        self,
        operation: str,
        arguments: tuple[object, ...],
    ) -> TargetObservationProcessResult:
        assert operation == "rollback_readiness_probe"
        assert arguments == ("d" * 64,)
        self.calls += 1
        return TargetObservationProcessResult(
            ObservationOperation.ROLLBACK_READINESS_PROBE,
            "a" * 64,
            b"" if self.calls == 1 else b"ready\n",
            "b" * 64,
            45 if self.calls == 1 else 0,
            False,
            None,
        )


def _started(monkeypatch: pytest.MonkeyPatch, *, provider: bytes = b"success\n"):
    context, stopped, storage = _stopped_setup(monkeypatch)
    plan, _authority, executor, backend = _backend()
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    container_id = owner.target.container.container_id
    executor.overrides[
        (ObservationOperation.ROLLBACK_READINESS_PROBE, container_id)
    ] = b"ready\n"
    executor.overrides[(ObservationOperation.ROLLBACK_PROVIDER_PROBE, container_id)] = (
        provider
    )
    started = start_native_windows_repair_runtime(
        context,  # type: ignore[arg-type]
        stopped,
        absent_capture=lambda _stopped: _Absent(owner),  # type: ignore[arg-type,return-value]
        journal_storage=storage,  # type: ignore[arg-type]
        pointer_storage=storage,  # type: ignore[arg-type]
    )
    return context, started, storage


def test_verifies_every_terminal_condition_then_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, started, storage = _started(monkeypatch)

    committed = verify_and_commit_native_windows_repair(
        context,  # type: ignore[arg-type]
        started,
        environment=_Environment(started),  # type: ignore[arg-type]
        certificate_observer=_Certificates(started),  # type: ignore[arg-type]
        journal_storage=storage,  # type: ignore[arg-type]
        pointer_storage=storage,  # type: ignore[arg-type]
    )

    assert isinstance(committed, CommittedRepair)
    assert started.owner.closed
    assert tuple(
        item.state for item in committed.forward.selection.generations[-2:]
    ) == (
        RepairTransactionState.SUCCESS_VERIFYING,
        RepairTransactionState.COMMITTED,
    )
    context.close()  # type: ignore[attr-defined]


def test_provider_failure_leaves_verifying_state_and_closes_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, started, storage = _started(
        monkeypatch,
        provider=b"repairable_tls_failure\n",
    )
    appended: list[RepairTransactionState] = []
    real_append = terminal_native._append

    def append(*args: object, **kwargs: object):
        appended.append(args[2])  # type: ignore[arg-type]
        return real_append(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(terminal_native, "_append", append)

    with pytest.raises(NativeRepairTerminalVerificationError) as captured:
        verify_and_commit_native_windows_repair(
            context,  # type: ignore[arg-type]
            started,
            environment=_Environment(started),  # type: ignore[arg-type]
            certificate_observer=_Certificates(started),  # type: ignore[arg-type]
            journal_storage=storage,  # type: ignore[arg-type]
            pointer_storage=storage,  # type: ignore[arg-type]
        )

    assert (
        captured.value.code is NativeRepairTerminalVerificationErrorCode.VERIFY_FAILED
    )
    assert appended == [RepairTransactionState.SUCCESS_VERIFYING]
    assert started.owner.closed
    context.close()  # type: ignore[attr-defined]


def test_readiness_wait_is_bounded_and_retries_only_empty_process_failure() -> None:
    owner = _ReadinessOwner()
    moments = iter((0.0, 1.0, 2.0))
    sleeps: list[float] = []

    result = terminal_native._wait_for_readiness(
        owner,  # type: ignore[arg-type]
        clock=lambda: next(moments),
        sleeper=sleeps.append,
    )

    assert result.stdout == b"ready\n"
    assert owner.calls == 2
    assert sleeps == [2.0]
