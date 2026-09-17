from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = Path(__file__).resolve().parent
for item in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from test_launcher_runtime_execution import _target  # noqa: E402
from test_launcher_windows_recovery_runtime_available_native import (  # noqa: E402
    _package_root_for_target,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    CertificateTargetDestination,
    ObservationOperation,
)
from towerscout_launcher.runtime_target_observation_backend import (  # noqa: E402
    TargetObservationProcessResult,
)
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_recovery_certificate_restore import (  # noqa: E402
    CertificateDestinationObservation,
    CertificateDestinationRestoreAuthority,
    CertificateRestorationAuthority,
)
from towerscout_launcher.windows_recovery_certificate_restore_native import (  # noqa: E402
    NativeCertificateRestorationError,
    NativeCertificateRestorationErrorCode,
    NativeWindowsCertificateRestoration,
)
from towerscout_launcher.windows_recovery_certificate_storage_native import (  # noqa: E402
    HeldCertificateRestoreTempPaths,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
)
from towerscout_launcher.windows_recovery_runtime_available_native import (  # noqa: E402
    observe_rollback_runtime_target,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_LOCAL_NAME = f"recovery-certificate-{1:032x}.tmp"
_LOCAL_PATH = PureWindowsPath(
    rf"C:\Users\private\AppData\Local\TowerScout\Recovery\v1\{_LOCAL_NAME}"
)
_ORIGINAL_LOCAL = CertificateDestinationObservation(True, "1" * 64, 11, 0o600)
_CANDIDATE_LOCAL = CertificateDestinationObservation(True, "2" * 64, 12, 0o644)
_CANDIDATE_BUNDLE = CertificateDestinationObservation(True, "3" * 64, 13, 0o644)


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _stream(target) -> JournalStreamIdentity:
    return JournalStreamIdentity(
        1,
        "a" * 32,
        target.target_token.digest_sha256,
        StableFileIdentity(
            target.package_root.volume_serial,
            target.package_root.file_id,
        ),
    )


def _authority(target) -> CertificateRestorationAuthority:
    observed = observe_rollback_runtime_target(target)
    return CertificateRestorationAuthority(
        observed.target_token_sha256,
        observed.package_root_identity,
        observed.runtime_evidence_sha256,
        observed.container_evidence_sha256,
        observed.volume_evidence_sha256s,
        CertificateDestinationRestoreAuthority(
            True,
            _ORIGINAL_LOCAL.sha256,
            _ORIGINAL_LOCAL.size,
            _ORIGINAL_LOCAL.mode,
            _CANDIDATE_LOCAL.sha256 or "",
            _CANDIDATE_LOCAL.size or 0,
            _CANDIDATE_LOCAL.mode or 0,
            _LOCAL_NAME,
            _identity(40),
        ),
        CertificateDestinationRestoreAuthority(
            False,
            candidate_sha256=_CANDIDATE_BUNDLE.sha256 or "",
            candidate_size=_CANDIDATE_BUNDLE.size or 0,
            candidate_mode=_CANDIDATE_BUNDLE.mode or 0,
        ),
    )


def _raw(observation: CertificateDestinationObservation) -> bytes:
    value: dict[str, object] = {"present": observation.present}
    if observation.present:
        value.update(
            sha256=observation.sha256,
            size=observation.size,
            mode=observation.mode,
        )
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class _Owner:
    def __init__(self, target) -> None:
        self.target = target
        self.closed = False
        self.assertions = 0
        self.calls: list[str] = []
        self.states = {
            CertificateTargetDestination.LOCAL_CA: _CANDIDATE_LOCAL,
            CertificateTargetDestination.CA_BUNDLE: _CANDIDATE_BUNDLE,
        }
        self.stages = {
            CertificateTargetDestination.LOCAL_CA: CertificateDestinationObservation(
                False
            ),
            CertificateTargetDestination.CA_BUNDLE: CertificateDestinationObservation(
                False
            ),
        }
        self.exit_codes: dict[str, int] = {}
        self.apply_effects = True

    def assert_unchanged(self):
        self.assertions += 1

    def execute_scoped_process(self, operation: str, arguments: tuple[object, ...]):
        self.calls.append(operation)
        destination = arguments[1]
        assert isinstance(destination, CertificateTargetDestination)
        operation_kind = {
            "certificate_observe": ObservationOperation.CERTIFICATE_OBSERVE,
            "certificate_stage_original": (
                ObservationOperation.CERTIFICATE_STAGE_ORIGINAL
            ),
            "certificate_apply_original": (
                ObservationOperation.CERTIFICATE_APPLY_ORIGINAL
            ),
            "certificate_remove_candidate": (
                ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE
            ),
            "certificate_remove_staged_original": (
                ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL
            ),
        }[operation]
        stdout = b""
        if operation == "certificate_observe":
            stdout = _raw(
                self.stages[destination]
                if arguments[2] is not None
                else self.states[destination]
            )
        elif operation == "certificate_stage_original" and self.apply_effects:
            self.stages[destination] = _ORIGINAL_LOCAL
        elif operation == "certificate_apply_original" and self.apply_effects:
            self.states[destination] = _ORIGINAL_LOCAL
            self.stages[destination] = CertificateDestinationObservation(False)
        elif operation == "certificate_remove_candidate" and self.apply_effects:
            self.states[destination] = CertificateDestinationObservation(False)
        elif operation == "certificate_remove_staged_original" and self.apply_effects:
            self.stages[destination] = CertificateDestinationObservation(False)
        return TargetObservationProcessResult(
            operation_kind,
            "f" * 64,
            stdout,
            hashlib.sha256(b"").hexdigest(),
            self.exit_codes.get(operation, 0),
            False,
            None,
        )

    def close(self) -> None:
        self.closed = True


class _Temps:
    def __init__(self) -> None:
        self.closed = False
        self.calls = 0

    def run_while_held(self, operation):
        self.calls += 1
        return operation(HeldCertificateRestoreTempPaths(_LOCAL_PATH, None))

    def close(self) -> None:
        self.closed = True


def _adapter(target, owner: _Owner, temps: _Temps):
    return NativeWindowsCertificateRestoration(
        target.certificate,
        target_capture=lambda _provider: owner,
        temp_capture=lambda _root, _authority: temps,
    )


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
def test_native_certificate_restore_applies_present_and_absent_originals(
    product: RuntimeProduct,
) -> None:
    target, _python, _identity_key = _target(product)
    owner = _Owner(target)
    temps = _Temps()
    package_root = _package_root_for_target(target)
    try:
        evidence = package_root.run_while_held(
            lambda: _adapter(
                target,
                owner,
                temps,
            ).restore_certificates_while_package_root_held(
                package_root,
                r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
                _stream(target),
                _authority(target),
            )
        )
    finally:
        package_root.close()

    assert evidence.local_ca.present
    assert evidence.local_ca.contents_sha256 == _ORIGINAL_LOCAL.sha256
    assert evidence.local_ca.mode == _ORIGINAL_LOCAL.mode
    assert evidence.ca_bundle.present is False
    assert owner.calls.count("certificate_stage_original") == 1
    assert owner.calls.count("certificate_apply_original") == 1
    assert owner.calls.count("certificate_remove_candidate") == 1
    assert owner.closed and temps.closed


def test_native_certificate_restore_reconciles_nonzero_completed_commands() -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    owner = _Owner(target)
    owner.exit_codes = {
        "certificate_stage_original": 17,
        "certificate_apply_original": 18,
        "certificate_remove_candidate": 19,
    }
    temps = _Temps()
    package_root = _package_root_for_target(target)
    try:
        evidence = package_root.run_while_held(
            lambda: _adapter(
                target,
                owner,
                temps,
            ).restore_certificates_while_package_root_held(
                package_root,
                r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
                _stream(target),
                _authority(target),
            )
        )
    finally:
        package_root.close()

    assert evidence.local_ca.contents_sha256 == _ORIGINAL_LOCAL.sha256
    assert evidence.ca_bundle.present is False


def test_native_certificate_restore_removes_exact_stage_residue_when_already_done() -> (
    None
):
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    owner = _Owner(target)
    owner.states[CertificateTargetDestination.LOCAL_CA] = _ORIGINAL_LOCAL
    owner.states[CertificateTargetDestination.CA_BUNDLE] = (
        CertificateDestinationObservation(False)
    )
    owner.stages[CertificateTargetDestination.LOCAL_CA] = _ORIGINAL_LOCAL
    owner.exit_codes["certificate_remove_staged_original"] = 17
    temps = _Temps()
    package_root = _package_root_for_target(target)
    try:
        evidence = package_root.run_while_held(
            lambda: _adapter(
                target,
                owner,
                temps,
            ).restore_certificates_while_package_root_held(
                package_root,
                r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
                _stream(target),
                _authority(target),
            )
        )
    finally:
        package_root.close()

    assert evidence.local_ca.contents_sha256 == _ORIGINAL_LOCAL.sha256
    assert owner.calls.count("certificate_remove_staged_original") == 1
    assert owner.stages[CertificateTargetDestination.LOCAL_CA].present is False


def test_native_certificate_restore_blocks_third_state_and_closes_owners() -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    owner = _Owner(target)
    owner.states[CertificateTargetDestination.LOCAL_CA] = (
        CertificateDestinationObservation(True, "9" * 64, 12, 0o644)
    )
    temps = _Temps()
    package_root = _package_root_for_target(target)
    try:
        with pytest.raises(NativeCertificateRestorationError) as failure:
            package_root.run_while_held(
                lambda: _adapter(
                    target,
                    owner,
                    temps,
                ).restore_certificates_while_package_root_held(
                    package_root,
                    r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
                    _stream(target),
                    _authority(target),
                )
            )
    finally:
        package_root.close()

    assert failure.value.code is NativeCertificateRestorationErrorCode.TARGET_MISMATCH
    assert owner.closed and temps.closed
    assert "certificate_stage_original" not in owner.calls


def test_native_certificate_restore_rejects_nonzero_without_exact_post_state() -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    owner = _Owner(target)
    owner.apply_effects = False
    owner.exit_codes["certificate_stage_original"] = 17
    temps = _Temps()
    package_root = _package_root_for_target(target)
    try:
        with pytest.raises(NativeCertificateRestorationError) as failure:
            package_root.run_while_held(
                lambda: _adapter(
                    target,
                    owner,
                    temps,
                ).restore_certificates_while_package_root_held(
                    package_root,
                    r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1",
                    _stream(target),
                    _authority(target),
                )
            )
    finally:
        package_root.close()

    assert failure.value.code is NativeCertificateRestorationErrorCode.VERIFY_FAILED
    assert owner.closed and temps.closed
