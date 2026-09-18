from __future__ import annotations

import hashlib
import json
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
    CertificateRuntimeSelector,
    CertificateTargetDestination,
    ObservationOperation,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    BoundResolvedRepairTarget,
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_recovery_backup import (  # noqa: E402
    CertificateBackupDestination,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
)
from towerscout_launcher.windows_repair_certificate_backup_native import (  # noqa: E402
    NativeRepairCertificateBackupError,
    NativeRepairCertificateBackupErrorCode,
    capture_repair_certificate_backup_while_target_held,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _owner(
    product: RuntimeProduct = RuntimeProduct.DOCKER,
) -> tuple[BoundResolvedRepairTarget, object, JournalStreamIdentity]:
    plan, _authority, executor, backend = _backend(product)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    stream = JournalStreamIdentity(
        1,
        "a" * 32,
        owner.target.target_token.digest_sha256,
        StableFileIdentity(
            owner.target.package_root.volume_serial,
            owner.target.package_root.file_id,
        ),
    )
    return owner, executor, stream


def _observation(contents: bytes, mode: int) -> bytes:
    return json.dumps(
        {
            "present": True,
            "sha256": hashlib.sha256(contents).hexdigest(),
            "size": len(contents),
            "mode": mode,
        },
        separators=(",", ":"),
    ).encode("ascii")


def _set_destination(
    executor: object,
    destination: CertificateTargetDestination,
    contents: bytes,
    mode: int,
) -> None:
    selector = CertificateRuntimeSelector(_CONTAINER_ID, destination)
    executor.overrides[(ObservationOperation.CERTIFICATE_OBSERVE, selector)] = (
        _observation(contents, mode)
    )
    executor.overrides[
        (ObservationOperation.CERTIFICATE_READ_DESTINATION, selector)
    ] = contents


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
def test_captures_both_exact_certificate_destinations(product: RuntimeProduct) -> None:
    owner, executor, stream = _owner(product)
    local_ca = b"private-local-ca"
    ca_bundle = b"private-ca-bundle"
    _set_destination(
        executor,
        CertificateTargetDestination.LOCAL_CA,
        local_ca,
        0o640,
    )
    _set_destination(
        executor,
        CertificateTargetDestination.CA_BUNDLE,
        ca_bundle,
        0o644,
    )

    backup = capture_repair_certificate_backup_while_target_held(owner, stream)

    assert backup.local_ca.destination is CertificateBackupDestination.LOCAL_CA
    assert backup.local_ca.contents == local_ca
    assert backup.local_ca.mode == 0o640
    assert backup.ca_bundle.destination is CertificateBackupDestination.CA_BUNDLE
    assert backup.ca_bundle.contents == ca_bundle
    assert backup.ca_bundle.mode == 0o644
    assert (
        sum(
            operation is ObservationOperation.CERTIFICATE_READ_DESTINATION
            for operation, _selector in executor.calls
        )
        == 2
    )
    owner.close()


def test_captures_exact_absence_without_reading_a_destination() -> None:
    owner, executor, stream = _owner()

    backup = capture_repair_certificate_backup_while_target_held(owner, stream)

    assert backup.local_ca.existed is False
    assert backup.ca_bundle.existed is False
    assert all(
        operation is not ObservationOperation.CERTIFICATE_READ_DESTINATION
        for operation, _selector in executor.calls
    )
    owner.close()


def test_rejects_destination_bytes_that_do_not_match_observation() -> None:
    owner, executor, stream = _owner()
    _set_destination(
        executor,
        CertificateTargetDestination.LOCAL_CA,
        b"private-local-ca",
        0o644,
    )
    selector = CertificateRuntimeSelector(
        _CONTAINER_ID,
        CertificateTargetDestination.LOCAL_CA,
    )
    executor.overrides[
        (ObservationOperation.CERTIFICATE_READ_DESTINATION, selector)
    ] = b"substituted"

    with pytest.raises(NativeRepairCertificateBackupError) as caught:
        capture_repair_certificate_backup_while_target_held(owner, stream)

    assert caught.value.code is NativeRepairCertificateBackupErrorCode.VERIFY_FAILED
    assert "private" not in repr(caught.value).casefold()
    owner.close()


def test_rejects_stream_for_another_exact_target() -> None:
    owner, _executor, stream = _owner()
    wrong = JournalStreamIdentity(
        1,
        stream.journal_id,
        "b" * 64,
        stream.package_root_identity,
    )

    with pytest.raises(NativeRepairCertificateBackupError) as caught:
        capture_repair_certificate_backup_while_target_held(owner, wrong)

    assert caught.value.code is NativeRepairCertificateBackupErrorCode.INPUT_INVALID
    owner.close()
