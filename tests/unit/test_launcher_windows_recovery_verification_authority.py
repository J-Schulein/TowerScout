from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.target_contracts import MapProvider  # noqa: E402
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from towerscout_launcher.windows_recovery_readiness_authority import (  # noqa: E402
    rollback_readiness_evidence_sha256,
)
from towerscout_launcher.windows_recovery_verification_authority import (  # noqa: E402
    RollbackCertificateExpectation,
    RollbackEnvironmentExpectation,
    RollbackVerificationAuthority,
    rollback_certificate_evidence_sha256,
    rollback_environment_evidence_sha256,
    rollback_readiness_condition_restored,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _identity(value: int = 7) -> StableFileIdentity:
    return StableFileIdentity(value, value.to_bytes(16, "big"))


def _environment() -> RollbackEnvironmentExpectation:
    return RollbackEnvironmentExpectation(
        True,
        "1" * 64,
        42,
        0x20,
        "2" * 64,
        _identity(8),
    )


def _certificate(value: str) -> RollbackCertificateExpectation:
    return RollbackCertificateExpectation(True, value * 64, "3" * 64, 128, 0o644)


def _authority() -> RollbackVerificationAuthority:
    target_token = "a" * 64
    environment = _environment()
    local_ca = _certificate("4")
    ca_bundle = _certificate("5")
    readiness = RollbackReadinessCondition.DEGRADED
    return RollbackVerificationAuthority(
        1,
        target_token,
        _identity(),
        MapProvider.GOOGLE,
        "6" * 64,
        environment,
        local_ca,
        ca_bundle,
        rollback_environment_evidence_sha256(target_token, environment),
        rollback_certificate_evidence_sha256(
            target_token,
            MapProvider.GOOGLE,
            "6" * 64,
            local_ca,
            ca_bundle,
        ),
        "7" * 64,
        "8" * 64,
        tuple(f"{value:x}" * 64 for value in range(1, 9)),
        readiness,
        rollback_readiness_evidence_sha256(target_token, readiness),
        RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
    )


def test_environment_evidence_binds_destination_identity() -> None:
    environment = _environment()

    assert rollback_environment_evidence_sha256(
        "a" * 64,
        environment,
    ) != rollback_environment_evidence_sha256(
        "a" * 64,
        replace(environment, identity=_identity(9)),
    )


def test_certificate_evidence_binds_both_destination_observations() -> None:
    authority = _authority()

    assert (
        authority.certificate_evidence_sha256
        != rollback_certificate_evidence_sha256(
            authority.target_token_sha256,
            authority.provider,
            authority.windows_root_fingerprint_sha256,
            replace(authority.local_ca, destination_evidence_sha256="9" * 64),
            authority.ca_bundle,
        )
    )


def test_verification_authority_rejects_forged_readiness_evidence() -> None:
    with pytest.raises(ValueError):
        replace(_authority(), prior_readiness_evidence_sha256="9" * 64)


@pytest.mark.parametrize(
    ("observed", "outcome", "expected"),
    (
        (
            RollbackReadinessCondition.DEGRADED,
            RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
            True,
        ),
        (
            RollbackReadinessCondition.DEGRADED,
            RollbackProviderOutcome.PROVIDER_RECHECK_INDETERMINATE,
            True,
        ),
        (
            RollbackReadinessCondition.READY,
            RollbackProviderOutcome.SUCCESS,
            True,
        ),
        (
            RollbackReadinessCondition.READY,
            RollbackProviderOutcome.PROVIDER_RECHECK_INDETERMINATE,
            False,
        ),
        (
            RollbackReadinessCondition.SETUP_REQUIRED,
            RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
            False,
        ),
    ),
)
def test_readiness_restoration_accepts_only_exact_or_success_equivalent(
    observed: RollbackReadinessCondition,
    outcome: RollbackProviderOutcome,
    expected: bool,
) -> None:
    assert (
        rollback_readiness_condition_restored(_authority(), observed, outcome)
        is expected
    )


def test_verification_authority_repr_redacts_evidence() -> None:
    authority = _authority()
    rendered = repr(authority)

    assert authority.target_token_sha256 not in rendered
    assert authority.environment_evidence_sha256 not in rendered
    assert authority.certificate_evidence_sha256 not in rendered
