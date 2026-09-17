from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.target_contracts import MapProvider  # noqa: E402
from towerscout_launcher.trust_policy import (  # noqa: E402
    SelectedWindowsRootMaterial,
)
from towerscout_launcher.windows_certificate_replacement import (  # noqa: E402
    CERTIFICATE_FILE_MODE,
    MAX_CA_BUNDLE_BYTES,
    CertificateReplacementPlan,
    plan_certificate_replacement,
)


def _selected() -> SelectedWindowsRootMaterial:
    return SelectedWindowsRootMaterial(MapProvider.GOOGLE, b"private-root-der")


def test_plan_binds_exact_root_and_combined_bundle_without_repr_bytes():
    selected = _selected()

    plan = plan_certificate_replacement(selected, b"private-system-bundle\r\n")

    assert plan.provider is MapProvider.GOOGLE
    assert plan.local_ca_contents == selected.pem_bytes
    assert plan.ca_bundle_contents == b"private-system-bundle\n" + selected.pem_bytes
    assert plan.local_ca_sha256 == selected.pem_sha256
    assert plan.ca_bundle_sha256 == hashlib.sha256(plan.ca_bundle_contents).hexdigest()
    assert plan.local_ca_mode == CERTIFICATE_FILE_MODE
    assert plan.ca_bundle_mode == CERTIFICATE_FILE_MODE
    rendered = repr(plan)
    assert "private" not in rendered
    assert "CERTIFICATE" not in rendered


@pytest.mark.parametrize(
    "bundle",
    [
        b"",
        b"\r\n",
        b"private\x00bundle",
        b"x" * MAX_CA_BUNDLE_BYTES,
    ],
    ids=("empty", "newlines-only", "nul", "combined-oversize"),
)
def test_plan_rejects_empty_unsafe_or_oversized_combined_bundle(bundle: bytes):
    with pytest.raises(ValueError, match="Certificate replacement plan is invalid"):
        plan_certificate_replacement(
            _selected(),
            bundle,
        )


def test_plan_requires_selected_windows_root_material():
    invalid_selected = object()
    with pytest.raises(ValueError, match="Certificate replacement plan is invalid"):
        plan_certificate_replacement(
            invalid_selected,  # type: ignore[arg-type]
            b"system bundle",
        )


@pytest.mark.parametrize(
    "local,bundle",
    [
        (b"candidate", b"candidate"),
        (b"candidate", b"candidate-system"),
        (b"candidate\x00", b"system\ncandidate\x00"),
        (
            _selected().pem_bytes,
            b"system-without-separator" + _selected().pem_bytes,
        ),
    ],
)
def test_direct_plan_rejects_unbound_or_unsafe_contents(
    local: bytes,
    bundle: bytes,
):
    with pytest.raises(ValueError, match="Certificate replacement plan is invalid"):
        CertificateReplacementPlan(MapProvider.GOOGLE, local, bundle)


def test_direct_plan_requires_fixed_regular_file_modes():
    selected = _selected()
    contents = b"system-bundle\n" + selected.pem_bytes

    with pytest.raises(ValueError, match="Certificate replacement plan is invalid"):
        CertificateReplacementPlan(
            MapProvider.GOOGLE,
            selected.pem_bytes,
            contents,
            local_ca_mode=0o600,
        )
    with pytest.raises(ValueError, match="Certificate replacement plan is invalid"):
        CertificateReplacementPlan(
            MapProvider.GOOGLE,
            selected.pem_bytes,
            contents,
            ca_bundle_mode=0o600,
        )
