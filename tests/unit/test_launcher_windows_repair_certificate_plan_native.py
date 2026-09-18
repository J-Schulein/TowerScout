from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_runtime_target_observation import _plan  # noqa: E402
from test_launcher_runtime_target_observation_backend import (  # noqa: E402
    _CONTAINER_ID,
    _backend_for_plan,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    ObservationOperation,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    CertificateIdentity,
    RuntimeProduct,
)
from towerscout_launcher.trust_policy import (  # noqa: E402
    SelectedWindowsRootMaterial,
)
from towerscout_launcher.windows_certificate_replacement import (  # noqa: E402
    MAX_CA_BUNDLE_BYTES,
)
from towerscout_launcher.windows_repair_certificate_plan_native import (  # noqa: E402
    NativeRepairCertificatePlanError,
    NativeRepairCertificatePlanErrorCode,
    build_repair_certificate_plan_while_target_held,
)


def _owner(
    product: RuntimeProduct,
) -> tuple[object, object, SelectedWindowsRootMaterial]:
    selected = SelectedWindowsRootMaterial(_plan(product).provider, b"reviewed-root")
    plan = replace(
        _plan(product),
        certificate=CertificateIdentity(
            provider=selected.provider,
            windows_root_fingerprint_sha256=selected.fingerprint_sha256,
            candidate_content_sha256=selected.pem_sha256,
        ),
    )
    _plan_value, _authority, executor, backend = _backend_for_plan(plan)
    owner = capture_bound_resolved_repair_target(
        plan,
        backend=backend,
        certificate_material=selected,
    )
    return owner, executor, selected


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
def test_builds_exact_replacement_plan_from_held_bundle_and_reviewed_root(
    product: RuntimeProduct,
) -> None:
    owner, executor, selected = _owner(product)
    executor.overrides[
        (ObservationOperation.CERTIFICATE_READ_SYSTEM_BUNDLE, _CONTAINER_ID)
    ] = b"private-system-bundle\r\n"

    replacement = build_repair_certificate_plan_while_target_held(owner)

    assert replacement.provider is selected.provider
    assert replacement.windows_root_fingerprint_sha256 == selected.fingerprint_sha256
    assert replacement.local_ca_contents == selected.pem_bytes
    assert replacement.ca_bundle_contents == (
        b"private-system-bundle\n" + selected.pem_bytes
    )
    assert (
        executor.calls.count(
            (ObservationOperation.CERTIFICATE_READ_SYSTEM_BUNDLE, _CONTAINER_ID)
        )
        == 1
    )
    owner.close()


@pytest.mark.parametrize(
    ("configure", "expected"),
    [
        (
            lambda executor: executor.exit_codes.__setitem__(
                ObservationOperation.CERTIFICATE_READ_SYSTEM_BUNDLE, 47
            ),
            NativeRepairCertificatePlanErrorCode.READ_FAILED,
        ),
        (
            lambda executor: executor.overrides.__setitem__(
                (ObservationOperation.CERTIFICATE_READ_SYSTEM_BUNDLE, _CONTAINER_ID),
                b"x" * MAX_CA_BUNDLE_BYTES,
            ),
            NativeRepairCertificatePlanErrorCode.PLAN_INVALID,
        ),
    ],
)
def test_fails_closed_for_unreadable_or_unplannable_bundle(
    configure: object,
    expected: NativeRepairCertificatePlanErrorCode,
) -> None:
    owner, executor, _selected = _owner(RuntimeProduct.DOCKER)
    assert callable(configure)
    configure(executor)

    with pytest.raises(NativeRepairCertificatePlanError) as caught:
        build_repair_certificate_plan_while_target_held(owner)

    assert caught.value.code is expected
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "private" not in repr(caught.value).casefold()
    owner.close()


def test_requires_retained_reviewed_root_material() -> None:
    plan, _authority, _executor, backend = _backend_for_plan(_plan())
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(NativeRepairCertificatePlanError) as caught:
        build_repair_certificate_plan_while_target_held(owner)

    assert caught.value.code is NativeRepairCertificatePlanErrorCode.READ_FAILED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    owner.close()
