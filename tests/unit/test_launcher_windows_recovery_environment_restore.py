from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_environment_restore as restore  # noqa: E402
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _authority(
    *,
    original_present: bool = True,
    candidate_applied: bool = True,
) -> restore.EnvironmentRestoreAuthority:
    return restore.EnvironmentRestoreAuthority(
        schema_version=1,
        package_root_identity=_identity(7),
        original_present=original_present,
        original_identity=_identity(8) if original_present else None,
        original_sha256="a" * 64 if original_present else None,
        original_size=11 if original_present else None,
        original_file_attributes=0x20 if original_present else None,
        original_security_descriptor_sha256=("b" * 64 if original_present else None),
        candidate_sha256="c" * 64,
        candidate_size=23,
        candidate_identity=_identity(9) if candidate_applied else None,
        candidate_file_attributes=0x20 if candidate_applied else None,
        candidate_security_descriptor_sha256=("d" * 64 if candidate_applied else None),
        restore_temp_identity=_identity(10) if original_present else None,
    )


def _original_observation(
    *,
    identity: StableFileIdentity | None = None,
) -> restore.EnvironmentDestinationObservation:
    return restore.EnvironmentDestinationObservation(
        True,
        identity or _identity(8),
        "a" * 64,
        11,
        0x20,
        "b" * 64,
    )


def _candidate_observation() -> restore.EnvironmentDestinationObservation:
    return restore.EnvironmentDestinationObservation(
        True,
        _identity(9),
        "c" * 64,
        23,
        0x20,
        "d" * 64,
    )


def test_present_original_accepts_original_or_promoted_restore_identity() -> None:
    authority = _authority()

    for observed in (
        _original_observation(),
        _original_observation(identity=_identity(10)),
    ):
        decision = restore.decide_environment_restore(authority, observed)
        assert decision.content_state is restore.EnvironmentRestoreContentState.ORIGINAL
        assert decision.action is restore.EnvironmentRestoreAction.ALREADY_RESTORED


def test_present_original_restores_only_exact_recorded_candidate() -> None:
    decision = restore.decide_environment_restore(
        _authority(),
        _candidate_observation(),
    )

    assert decision.content_state is restore.EnvironmentRestoreContentState.CANDIDATE
    assert decision.action is restore.EnvironmentRestoreAction.RESTORE_ORIGINAL


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("identity", _identity(99)),
        ("sha256", "e" * 64),
        ("size", 12),
        ("file_attributes", 0x21),
        ("security_descriptor_sha256", "f" * 64),
    ),
)
def test_original_drift_is_preserved_as_third_state(
    field: str,
    value: object,
) -> None:
    values = {
        "present": True,
        "identity": _identity(8),
        "sha256": "a" * 64,
        "size": 11,
        "file_attributes": 0x20,
        "security_descriptor_sha256": "b" * 64,
    }
    values[field] = value

    decision = restore.decide_environment_restore(
        _authority(),
        restore.EnvironmentDestinationObservation(**values),
    )

    assert decision.content_state is restore.EnvironmentRestoreContentState.THIRD_STATE
    assert decision.action is restore.EnvironmentRestoreAction.BLOCK


def test_absent_original_accepts_absence_or_removes_exact_candidate() -> None:
    authority = _authority(original_present=False)

    absent = restore.decide_environment_restore(
        authority,
        restore.EnvironmentDestinationObservation(False),
    )
    candidate = restore.decide_environment_restore(
        authority,
        _candidate_observation(),
    )

    assert absent.content_state is restore.EnvironmentRestoreContentState.ABSENT
    assert absent.action is restore.EnvironmentRestoreAction.ALREADY_RESTORED
    assert candidate.content_state is restore.EnvironmentRestoreContentState.CANDIDATE
    assert candidate.action is restore.EnvironmentRestoreAction.REMOVE_CANDIDATE


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("identity", _identity(99)),
        ("sha256", "e" * 64),
        ("size", 24),
        ("file_attributes", 0x21),
        ("security_descriptor_sha256", "f" * 64),
    ),
)
def test_candidate_drift_is_preserved_as_third_state(
    field: str,
    value: object,
) -> None:
    values = {
        "present": True,
        "identity": _identity(9),
        "sha256": "c" * 64,
        "size": 23,
        "file_attributes": 0x20,
        "security_descriptor_sha256": "d" * 64,
    }
    values[field] = value
    observed = restore.EnvironmentDestinationObservation(**values)

    decision = restore.decide_environment_restore(_authority(), observed)

    assert decision.content_state is restore.EnvironmentRestoreContentState.THIRD_STATE
    assert decision.action is restore.EnvironmentRestoreAction.BLOCK


def test_candidate_without_durable_applied_identity_is_never_authorized() -> None:
    decision = restore.decide_environment_restore(
        _authority(candidate_applied=False),
        _candidate_observation(),
    )

    assert decision.content_state is restore.EnvironmentRestoreContentState.THIRD_STATE
    assert decision.action is restore.EnvironmentRestoreAction.BLOCK


def test_present_original_rejects_absence() -> None:
    decision = restore.decide_environment_restore(
        _authority(),
        restore.EnvironmentDestinationObservation(False),
    )

    assert decision.content_state is restore.EnvironmentRestoreContentState.ABSENT
    assert decision.action is restore.EnvironmentRestoreAction.BLOCK


def test_models_reject_mixed_authority_and_observation_shapes() -> None:
    with pytest.raises(ValueError):
        restore.EnvironmentDestinationObservation(False, identity=_identity(8))
    with pytest.raises(ValueError):
        restore.EnvironmentDestinationObservation(
            True,
            _identity(8),
            "not-a-hash",
            11,
            0x20,
            "b" * 64,
        )
    with pytest.raises(ValueError):
        restore.EnvironmentRestoreAuthority(
            1,
            _identity(7),
            False,
            original_identity=_identity(8),
            candidate_sha256="c" * 64,
            candidate_size=23,
        )
    with pytest.raises(ValueError):
        restore.EnvironmentRestoreAuthority(
            1,
            _identity(7),
            False,
            candidate_sha256="c" * 64,
            candidate_size=23,
            candidate_identity=_identity(9),
        )


def test_public_boundary_is_sanitized_and_repr_redacts_authority() -> None:
    authority = _authority()
    observed = _candidate_observation()
    rendered = repr(authority) + repr(observed)

    assert authority.candidate_sha256 not in rendered
    assert repr(authority.candidate_identity) not in rendered
    assert observed.sha256 not in rendered
    with pytest.raises(restore.EnvironmentRestoreDecisionError) as failure:
        restore.decide_environment_restore(
            cast(restore.EnvironmentRestoreAuthority, object()),
            observed,
        )
    assert (
        failure.value.code is restore.EnvironmentRestoreDecisionErrorCode.INPUT_INVALID
    )
    assert "private" not in str(failure.value)
