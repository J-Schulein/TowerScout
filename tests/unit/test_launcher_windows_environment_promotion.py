from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_environment_promotion as promotion  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _destination(
    *,
    identity: StableFileIdentity = _identity(8),
    sha256: str = "a" * 64,
    size: int = 11,
    attributes: int = 0x20,
    descriptor: str = "b" * 64,
) -> EnvironmentDestinationObservation:
    return EnvironmentDestinationObservation(
        True,
        identity,
        sha256,
        size,
        attributes,
        descriptor,
    )


def _verified() -> EnvironmentTempVerifiedRecord:
    return EnvironmentTempVerifiedRecord(
        1,
        "1" * 64,
        _identity(7),
        _identity(9),
        "c" * 64,
        23,
        0x80,
        "d" * 64,
        ".towerscout-env-0123456789abcdef0123456789abcdef.tmp",
    )


def _authority(
    *, original_present: bool = True
) -> promotion.EnvironmentPromotionAuthority:
    return promotion.EnvironmentPromotionAuthority(
        1,
        _identity(7),
        (
            _destination()
            if original_present
            else EnvironmentDestinationObservation(False)
        ),
        _verified(),
    )


def _temp(**changes: object) -> EnvironmentDestinationObservation:
    values: dict[str, object] = {
        "present": True,
        "identity": _identity(9),
        "sha256": "c" * 64,
        "size": 23,
        "file_attributes": 0x80,
        "security_descriptor_sha256": "d" * 64,
    }
    values.update(changes)
    return EnvironmentDestinationObservation(**values)  # type: ignore[arg-type]


def test_existing_original_and_exact_temp_authorize_replace() -> None:
    decision = promotion.decide_environment_promotion(
        _authority(),
        promotion.EnvironmentPromotionObservation(_destination(), _temp()),
    )

    assert decision.state is promotion.EnvironmentPromotionState.READY_EXISTING
    assert decision.action is promotion.EnvironmentPromotionAction.REPLACE_EXISTING


def test_absent_original_and_exact_temp_authorize_write_through_move() -> None:
    decision = promotion.decide_environment_promotion(
        _authority(original_present=False),
        promotion.EnvironmentPromotionObservation(
            EnvironmentDestinationObservation(False),
            _temp(),
        ),
    )

    assert decision.state is promotion.EnvironmentPromotionState.READY_ABSENT
    assert decision.action is promotion.EnvironmentPromotionAction.MOVE_NEW


def test_applied_existing_file_requires_replacement_identity_and_original_metadata() -> (
    None
):
    authority = _authority()
    expected = authority.expected_applied

    decision = promotion.decide_environment_promotion(
        authority,
        promotion.EnvironmentPromotionObservation(
            expected,
            EnvironmentDestinationObservation(False),
        ),
    )

    assert expected.identity == authority.verified.temp_identity
    assert expected.file_attributes == authority.original.file_attributes
    assert (
        expected.security_descriptor_sha256
        == authority.original.security_descriptor_sha256
    )
    assert decision.action is promotion.EnvironmentPromotionAction.ALREADY_APPLIED


def test_applied_new_file_retains_staged_metadata() -> None:
    authority = _authority(original_present=False)

    assert authority.expected_applied == _temp()
    decision = promotion.decide_environment_promotion(
        authority,
        promotion.EnvironmentPromotionObservation(
            authority.expected_applied,
            EnvironmentDestinationObservation(False),
        ),
    )
    assert decision.action is promotion.EnvironmentPromotionAction.ALREADY_APPLIED


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
def test_any_temp_drift_blocks_promotion(field: str, value: object) -> None:
    decision = promotion.decide_environment_promotion(
        _authority(),
        promotion.EnvironmentPromotionObservation(
            _destination(),
            _temp(**{field: value}),
        ),
    )

    assert decision.state is promotion.EnvironmentPromotionState.THIRD_STATE
    assert decision.action is promotion.EnvironmentPromotionAction.BLOCK


@pytest.mark.parametrize(
    ("destination", "temp"),
    (
        (_destination(identity=_identity(99)), _temp()),
        (EnvironmentDestinationObservation(False), _temp()),
        (_destination(), EnvironmentDestinationObservation(False)),
        (_destination(identity=_identity(9), sha256="c" * 64, size=23), _temp()),
    ),
)
def test_ambiguous_combinations_block_or_reject(
    destination: EnvironmentDestinationObservation,
    temp: EnvironmentDestinationObservation,
) -> None:
    if destination.identity == temp.identity:
        with pytest.raises(ValueError):
            promotion.EnvironmentPromotionObservation(destination, temp)
        return
    decision = promotion.decide_environment_promotion(
        _authority(),
        promotion.EnvironmentPromotionObservation(destination, temp),
    )
    assert decision.action is promotion.EnvironmentPromotionAction.BLOCK


def test_authority_rejects_cross_volume_or_colliding_identity() -> None:
    verified = _verified()
    with pytest.raises(ValueError):
        promotion.EnvironmentPromotionAuthority(
            1,
            _identity(7),
            _destination(identity=verified.temp_identity),
            verified,
        )
    with pytest.raises(ValueError):
        promotion.EnvironmentPromotionAuthority(
            1,
            _identity(99),
            _destination(),
            verified,
        )


def test_public_boundary_is_sanitized_and_repr_redacts() -> None:
    authority = _authority()
    observation = promotion.EnvironmentPromotionObservation(
        _destination(),
        _temp(),
    )
    rendered = repr(authority) + repr(observation)

    assert authority.verified.candidate_sha256 not in rendered
    assert repr(authority.verified.temp_identity) not in rendered
    with pytest.raises(promotion.EnvironmentPromotionDecisionError) as failure:
        promotion.decide_environment_promotion(
            cast(promotion.EnvironmentPromotionAuthority, object()),
            observation,
        )
    assert (
        failure.value.code
        is promotion.EnvironmentPromotionDecisionErrorCode.INPUT_INVALID
    )
