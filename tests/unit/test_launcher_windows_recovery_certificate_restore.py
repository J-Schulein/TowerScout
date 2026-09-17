from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.windows_recovery_certificate_restore import (  # noqa: E402
    CertificateDestinationObservation,
    CertificateDestinationRestoreAuthority,
    CertificateRestoreAction,
    decide_certificate_restore,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

ORIGINAL_SHA256 = "1" * 64
CANDIDATE_SHA256 = "2" * 64


def _authority(
    *,
    original_present: bool = True,
) -> CertificateDestinationRestoreAuthority:
    return CertificateDestinationRestoreAuthority(
        original_present=original_present,
        original_sha256=ORIGINAL_SHA256 if original_present else None,
        original_size=11 if original_present else None,
        original_mode=0o600 if original_present else None,
        candidate_sha256=CANDIDATE_SHA256,
        candidate_size=12,
        candidate_mode=0o644,
        restore_temp_name=(
            f"recovery-certificate-{1:032x}.tmp" if original_present else None
        ),
        restore_temp_identity=(
            StableFileIdentity(7, (1).to_bytes(16, "big")) if original_present else None
        ),
    )


def test_exact_original_is_already_restored() -> None:
    decision = decide_certificate_restore(
        _authority(),
        CertificateDestinationObservation(True, ORIGINAL_SHA256, 11, 0o600),
    )

    assert decision.action is CertificateRestoreAction.ALREADY_RESTORED


def test_exact_candidate_restores_present_original() -> None:
    decision = decide_certificate_restore(
        _authority(),
        CertificateDestinationObservation(True, CANDIDATE_SHA256, 12, 0o644),
    )

    assert decision.action is CertificateRestoreAction.RESTORE_ORIGINAL


def test_exact_candidate_removes_originally_absent_destination() -> None:
    decision = decide_certificate_restore(
        _authority(original_present=False),
        CertificateDestinationObservation(True, CANDIDATE_SHA256, 12, 0o644),
    )

    assert decision.action is CertificateRestoreAction.REMOVE_CANDIDATE


@pytest.mark.parametrize(
    "observation",
    [
        CertificateDestinationObservation(False),
        CertificateDestinationObservation(True, "3" * 64, 12, 0o644),
        CertificateDestinationObservation(True, CANDIDATE_SHA256, 13, 0o644),
        CertificateDestinationObservation(True, CANDIDATE_SHA256, 12, 0o600),
    ],
)
def test_third_state_blocks(observation: CertificateDestinationObservation) -> None:
    decision = decide_certificate_restore(_authority(), observation)

    assert decision.action is CertificateRestoreAction.BLOCK


def test_candidate_equal_to_original_is_already_restored() -> None:
    authority = CertificateDestinationRestoreAuthority(
        original_present=True,
        original_sha256=CANDIDATE_SHA256,
        original_size=12,
        original_mode=0o644,
        candidate_sha256=CANDIDATE_SHA256,
        candidate_size=12,
        candidate_mode=0o644,
        restore_temp_name=f"recovery-certificate-{1:032x}.tmp",
        restore_temp_identity=StableFileIdentity(7, (1).to_bytes(16, "big")),
    )

    decision = decide_certificate_restore(
        authority,
        CertificateDestinationObservation(True, CANDIDATE_SHA256, 12, 0o644),
    )

    assert decision.action is CertificateRestoreAction.ALREADY_RESTORED


@pytest.mark.parametrize(
    "observation",
    [
        {"present": False, "sha256": ORIGINAL_SHA256},
        {"present": True, "sha256": "bad", "size": 1, "mode": 0o644},
        {"present": True, "sha256": ORIGINAL_SHA256, "size": -1, "mode": 0o644},
        {"present": True, "sha256": ORIGINAL_SHA256, "size": 1, "mode": -1},
    ],
)
def test_invalid_observation_is_rejected(observation: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="observation is invalid"):
        CertificateDestinationObservation(**observation)  # type: ignore[arg-type]
