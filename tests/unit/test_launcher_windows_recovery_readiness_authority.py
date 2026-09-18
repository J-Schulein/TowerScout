from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from towerscout_launcher.windows_recovery_readiness_authority import (  # noqa: E402
    derive_rollback_readiness_authority,
    rollback_readiness_evidence_sha256,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _identity() -> StableFileIdentity:
    return StableFileIdentity(7, (8).to_bytes(16, "big"))


@pytest.mark.parametrize("condition", tuple(RollbackReadinessCondition))
def test_readiness_authority_binds_sanitized_pre_mutation_condition(
    condition: RollbackReadinessCondition,
) -> None:
    authority = derive_rollback_readiness_authority(
        target_token_sha256="a" * 64,
        package_root_identity=_identity(),
        condition=condition,
        provider_outcome=RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
    )

    assert authority.condition is condition
    assert authority.evidence_sha256 == rollback_readiness_evidence_sha256(
        "a" * 64,
        condition,
    )
    assert "a" * 64 not in repr(authority)


@pytest.mark.parametrize(
    "outcome",
    [
        RollbackProviderOutcome.SUCCESS,
        RollbackProviderOutcome.PROVIDER_RECHECK_INDETERMINATE,
    ],
)
def test_readiness_authority_rejects_nonrepairable_precondition(
    outcome: RollbackProviderOutcome,
) -> None:
    with pytest.raises(ValueError):
        derive_rollback_readiness_authority(
            target_token_sha256="a" * 64,
            package_root_identity=_identity(),
            condition=RollbackReadinessCondition.DEGRADED,
            provider_outcome=outcome,
        )


def test_readiness_authority_rejects_forged_evidence() -> None:
    authority = derive_rollback_readiness_authority(
        target_token_sha256="a" * 64,
        package_root_identity=_identity(),
        condition=RollbackReadinessCondition.DEGRADED,
        provider_outcome=RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
    )

    with pytest.raises(ValueError):
        replace(authority, evidence_sha256="b" * 64)


def test_readiness_evidence_is_target_and_condition_specific() -> None:
    degraded = rollback_readiness_evidence_sha256(
        "a" * 64,
        RollbackReadinessCondition.DEGRADED,
    )

    assert degraded != rollback_readiness_evidence_sha256(
        "b" * 64,
        RollbackReadinessCondition.DEGRADED,
    )
    assert degraded != rollback_readiness_evidence_sha256(
        "a" * 64,
        RollbackReadinessCondition.READY,
    )
