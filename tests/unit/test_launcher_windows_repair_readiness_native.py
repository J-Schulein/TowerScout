from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_runtime_target_observation_backend import (  # noqa: E402
    _CONTAINER_ID,
    _backend,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    ObservationOperation,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from towerscout_launcher.windows_repair_readiness_native import (  # noqa: E402
    NativeRepairReadinessError,
    NativeRepairReadinessErrorCode,
    capture_repair_readiness_authority_while_target_held,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        (b"setup_required\n", RollbackReadinessCondition.SETUP_REQUIRED),
        (b"degraded\n", RollbackReadinessCondition.DEGRADED),
        (b"ready\n", RollbackReadinessCondition.READY),
    ),
)
def test_captures_exact_repairable_pre_mutation_authority(
    product: RuntimeProduct,
    raw: bytes,
    expected: RollbackReadinessCondition,
) -> None:
    plan, _native, executor, backend = _backend(product)
    executor.overrides[
        (ObservationOperation.ROLLBACK_READINESS_PROBE, _CONTAINER_ID)
    ] = raw
    executor.overrides[
        (ObservationOperation.ROLLBACK_PROVIDER_PROBE, _CONTAINER_ID)
    ] = b"repairable_tls_failure\n"
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    authority = capture_repair_readiness_authority_while_target_held(owner)

    assert authority.condition is expected
    assert authority.provider_outcome is RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE
    assert authority.target_token_sha256 == owner.target.target_token.digest_sha256
    assert authority.package_root_identity == StableFileIdentity(
        owner.target.package_root.volume_serial,
        owner.target.package_root.file_id,
    )
    owner.close()


@pytest.mark.parametrize(
    "outcome",
    (b"success\n", b"provider_recheck_indeterminate\n"),
)
def test_rejects_nonrepairable_provider_outcome(outcome: bytes) -> None:
    plan, _native, executor, backend = _backend()
    executor.overrides[
        (ObservationOperation.ROLLBACK_READINESS_PROBE, _CONTAINER_ID)
    ] = b"degraded\n"
    executor.overrides[
        (ObservationOperation.ROLLBACK_PROVIDER_PROBE, _CONTAINER_ID)
    ] = outcome
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(NativeRepairReadinessError) as caught:
        capture_repair_readiness_authority_while_target_held(owner)

    assert caught.value.code is NativeRepairReadinessErrorCode.NOT_REPAIRABLE
    owner.close()


@pytest.mark.parametrize(
    ("operation", "raw"),
    (
        (ObservationOperation.ROLLBACK_READINESS_PROBE, b"unknown\n"),
        (ObservationOperation.ROLLBACK_PROVIDER_PROBE, b"unknown\n"),
    ),
)
def test_rejects_malformed_probe_output(
    operation: ObservationOperation,
    raw: bytes,
) -> None:
    plan, _native, executor, backend = _backend()
    executor.overrides[
        (ObservationOperation.ROLLBACK_READINESS_PROBE, _CONTAINER_ID)
    ] = b"degraded\n"
    executor.overrides[
        (ObservationOperation.ROLLBACK_PROVIDER_PROBE, _CONTAINER_ID)
    ] = b"repairable_tls_failure\n"
    executor.overrides[(operation, _CONTAINER_ID)] = raw
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(NativeRepairReadinessError) as caught:
        capture_repair_readiness_authority_while_target_held(owner)

    assert caught.value.code is NativeRepairReadinessErrorCode.PROBE_FAILED
    assert caught.value.__cause__ is None
    owner.close()
