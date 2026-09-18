from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

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
from towerscout_launcher.windows_recovery import (  # noqa: E402
    CertificateDestinationRestoreEvidence,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from towerscout_launcher.windows_recovery_readiness_authority import (  # noqa: E402
    rollback_readiness_evidence_sha256,
)
from towerscout_launcher.windows_recovery_runtime_available_native import (  # noqa: E402
    observe_rollback_runtime_target,
)
from towerscout_launcher.windows_recovery_verification_authority import (  # noqa: E402
    RollbackCertificateExpectation,
    RollbackEnvironmentExpectation,
    RollbackVerificationAuthority,
    rollback_certificate_evidence_sha256,
    rollback_environment_evidence_sha256,
)
from towerscout_launcher.windows_recovery_verification_native import (  # noqa: E402
    NativeRollbackVerificationError,
    NativeRollbackVerificationErrorCode,
    NativeWindowsRollbackVerification,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _stream(target) -> JournalStreamIdentity:
    observed = observe_rollback_runtime_target(target)
    return JournalStreamIdentity(
        1,
        "a" * 32,
        observed.target_token_sha256,
        observed.package_root_identity,
    )


def _certificate_expectation(
    marker: str,
    *,
    present: bool,
) -> RollbackCertificateExpectation:
    return RollbackCertificateExpectation(
        present,
        marker * 64,
        "c" * 64 if present else None,
        128 if present else None,
        0o644 if present else None,
    )


def _authority(target) -> RollbackVerificationAuthority:
    stream = _stream(target)
    observed = observe_rollback_runtime_target(target, stream.target_token_sha256)
    environment = RollbackEnvironmentExpectation(
        True,
        "1" * 64,
        42,
        0x20,
        "2" * 64,
        _identity(8),
    )
    local_ca = _certificate_expectation("3", present=True)
    ca_bundle = _certificate_expectation("4", present=False)
    readiness = RollbackReadinessCondition.DEGRADED
    return RollbackVerificationAuthority(
        1,
        stream.target_token_sha256,
        stream.package_root_identity,
        target.provider,
        target.certificate.windows_root_fingerprint_sha256,
        environment,
        local_ca,
        ca_bundle,
        rollback_environment_evidence_sha256(
            stream.target_token_sha256,
            environment,
        ),
        rollback_certificate_evidence_sha256(
            stream.target_token_sha256,
            target.provider,
            target.certificate.windows_root_fingerprint_sha256,
            local_ca,
            ca_bundle,
        ),
        observed.runtime_evidence_sha256,
        observed.container_evidence_sha256,
        observed.volume_evidence_sha256s,
        readiness,
        rollback_readiness_evidence_sha256(stream.target_token_sha256, readiness),
        RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
    )


def _environment(authority: RollbackVerificationAuthority):
    expected = authority.environment
    return EnvironmentDestinationObservation(
        expected.present,
        expected.identity,
        expected.sha256,
        expected.size,
        expected.file_attributes,
        expected.security_descriptor_sha256,
    )


def _certificate_evidence(
    expected: RollbackCertificateExpectation,
) -> CertificateDestinationRestoreEvidence:
    return CertificateDestinationRestoreEvidence(
        1,
        expected.present,
        expected.sha256,
        expected.size,
        expected.mode,
        expected.destination_evidence_sha256,
    )


class _Environment:
    def __init__(self, observation: EnvironmentDestinationObservation) -> None:
        self.observation = observation
        self.calls = 0

    def observe_environment_while_package_root_held(
        self,
        package_root,
        package_root_identity,
    ) -> EnvironmentDestinationObservation:
        package_root.assert_unchanged_while_held()
        assert package_root.root_snapshot.identity == package_root_identity
        self.calls += 1
        return self.observation


class _Certificates:
    def __init__(self, authority: RollbackVerificationAuthority) -> None:
        self.values = {
            CertificateTargetDestination.LOCAL_CA: _certificate_evidence(
                authority.local_ca
            ),
            CertificateTargetDestination.CA_BUNDLE: _certificate_evidence(
                authority.ca_bundle
            ),
        }
        self.calls: list[CertificateTargetDestination] = []

    def __call__(self, owner, destination):
        assert owner.closed is False
        self.calls.append(destination)
        return self.values[destination]


class _Owner:
    def __init__(
        self,
        target,
        *,
        readiness: bytes = b"degraded\n",
        provider: bytes = b"repairable_tls_failure\n",
        exit_code: int = 0,
        close_error: bool = False,
    ) -> None:
        self.target = target
        self.readiness = readiness
        self.provider = provider
        self.exit_code = exit_code
        self.close_error = close_error
        self.closed = False
        self.assertions = 0
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def assert_unchanged(self) -> object:
        self.assertions += 1
        return object()

    def execute_scoped_process(
        self,
        operation: str,
        arguments: tuple[object, ...],
    ) -> TargetObservationProcessResult:
        self.calls.append((operation, arguments))
        if operation == "rollback_readiness_probe":
            selected = ObservationOperation.ROLLBACK_READINESS_PROBE
            stdout = self.readiness
        elif operation == "rollback_provider_probe":
            selected = ObservationOperation.ROLLBACK_PROVIDER_PROBE
            stdout = self.provider
        else:
            raise AssertionError("unexpected operation")
        return TargetObservationProcessResult(
            selected,
            "d" * 64,
            stdout,
            hashlib.sha256(b"PRIVATE STDERR").hexdigest(),
            self.exit_code,
            False,
            None,
        )

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise OSError("PRIVATE CLOSE DETAIL")


def _adapter(target, authority, owner, environment=None, certificates=None):
    selected_environment = environment or _Environment(_environment(authority))
    selected_certificates = certificates or _Certificates(authority)
    return (
        NativeWindowsRollbackVerification(
            target.certificate,
            target_capture=lambda provider: owner,
            environment=selected_environment,
            certificate_observer=selected_certificates,
        ),
        selected_environment,
        selected_certificates,
    )


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
def test_native_verification_proves_every_exact_state(product: RuntimeProduct) -> None:
    target = _target(product)[0]
    authority = _authority(target)
    owner = _Owner(target)
    adapter, environment, certificates = _adapter(target, authority, owner)
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.verify_rollback_while_package_root_held(
            package_root,
            _stream(target),
            authority,
        )
    )

    assert evidence.environment_evidence_sha256 == authority.environment_evidence_sha256
    assert evidence.certificate_evidence_sha256 == authority.certificate_evidence_sha256
    assert evidence.runtime_evidence_sha256 == authority.runtime_evidence_sha256
    assert evidence.container_evidence_sha256 == authority.container_evidence_sha256
    assert evidence.volume_evidence_sha256s == authority.volume_evidence_sha256s
    assert evidence.readiness_condition is RollbackReadinessCondition.DEGRADED
    assert evidence.provider_outcome is RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE
    assert environment.calls == 1
    assert certificates.calls == list(CertificateTargetDestination)
    assert owner.calls == [
        (
            "rollback_readiness_probe",
            (target.container.container_id,),
        ),
        (
            "rollback_provider_probe",
            (target.container.container_id,),
        ),
    ]
    assert owner.closed is True
    package_root.close()


@pytest.mark.parametrize(
    ("provider", "readiness", "expected"),
    (
        (
            b"provider_recheck_indeterminate\n",
            b"degraded\n",
            RollbackProviderOutcome.PROVIDER_RECHECK_INDETERMINATE,
        ),
        (b"success\n", b"ready\n", RollbackProviderOutcome.SUCCESS),
    ),
)
def test_native_verification_records_indeterminate_or_success_equivalent(
    provider: bytes,
    readiness: bytes,
    expected: RollbackProviderOutcome,
) -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    authority = _authority(target)
    owner = _Owner(target, readiness=readiness, provider=provider)
    adapter, _environment_port, _certificates = _adapter(target, authority, owner)
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.verify_rollback_while_package_root_held(
            package_root,
            _stream(target),
            authority,
        )
    )

    assert evidence.provider_outcome is expected
    assert owner.closed is True
    package_root.close()


def test_native_verification_rejects_readiness_improvement_when_indeterminate() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    authority = _authority(target)
    owner = _Owner(
        target,
        readiness=b"ready\n",
        provider=b"provider_recheck_indeterminate\n",
    )
    adapter, _environment_port, _certificates = _adapter(target, authority, owner)
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackVerificationError) as caught:
        package_root.run_while_held(
            lambda: adapter.verify_rollback_while_package_root_held(
                package_root,
                _stream(target),
                authority,
            )
        )

    assert caught.value.code is NativeRollbackVerificationErrorCode.READINESS_MISMATCH
    assert owner.closed is True
    assert caught.value.__cause__ is None
    package_root.close()


def test_native_verification_rejects_environment_drift_before_container_probes() -> (
    None
):
    target = _target(RuntimeProduct.DOCKER)[0]
    authority = _authority(target)
    owner = _Owner(target)
    environment = _Environment(replace(_environment(authority), sha256="f" * 64))
    adapter, _environment_port, certificates = _adapter(
        target,
        authority,
        owner,
        environment=environment,
    )
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackVerificationError) as caught:
        package_root.run_while_held(
            lambda: adapter.verify_rollback_while_package_root_held(
                package_root,
                _stream(target),
                authority,
            )
        )

    assert caught.value.code is NativeRollbackVerificationErrorCode.LOCAL_STATE_MISMATCH
    assert certificates.calls == []
    assert owner.calls == []
    assert owner.closed is True
    package_root.close()


def test_native_verification_rejects_certificate_evidence_drift() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    authority = _authority(target)
    owner = _Owner(target)
    certificates = _Certificates(authority)
    certificates.values[CertificateTargetDestination.CA_BUNDLE] = replace(
        certificates.values[CertificateTargetDestination.CA_BUNDLE],
        destination_evidence_sha256="f" * 64,
    )
    adapter, _environment_port, _certificates = _adapter(
        target,
        authority,
        owner,
        certificates=certificates,
    )
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackVerificationError) as caught:
        package_root.run_while_held(
            lambda: adapter.verify_rollback_while_package_root_held(
                package_root,
                _stream(target),
                authority,
            )
        )

    assert caught.value.code is NativeRollbackVerificationErrorCode.LOCAL_STATE_MISMATCH
    assert owner.calls == []
    assert owner.closed is True
    package_root.close()


@pytest.mark.parametrize(
    "owner",
    (
        _Owner(_target(RuntimeProduct.DOCKER)[0], readiness=b"PRIVATE OUTPUT\n"),
        _Owner(_target(RuntimeProduct.DOCKER)[0], exit_code=17),
    ),
)
def test_native_verification_rejects_malformed_or_failed_probe(owner: _Owner) -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    authority = _authority(target)
    owner.target = target
    adapter, _environment_port, _certificates = _adapter(target, authority, owner)
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackVerificationError) as caught:
        package_root.run_while_held(
            lambda: adapter.verify_rollback_while_package_root_held(
                package_root,
                _stream(target),
                authority,
            )
        )

    assert caught.value.code is NativeRollbackVerificationErrorCode.VERIFY_FAILED
    assert "PRIVATE" not in str(caught.value)
    assert owner.closed is True
    package_root.close()


def test_native_verification_close_failure_is_sanitized() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    authority = _authority(target)
    owner = _Owner(target, close_error=True)
    adapter, _environment_port, _certificates = _adapter(target, authority, owner)
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackVerificationError) as caught:
        package_root.run_while_held(
            lambda: adapter.verify_rollback_while_package_root_held(
                package_root,
                _stream(target),
                authority,
            )
        )

    assert caught.value.code is NativeRollbackVerificationErrorCode.VERIFY_FAILED
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__cause__ is None
    package_root.close()


def test_native_verification_rejects_certificate_authority_drift_before_capture() -> (
    None
):
    target = _target(RuntimeProduct.DOCKER)[0]
    base = _authority(target)
    fingerprint = "f" * 64
    authority = replace(
        base,
        windows_root_fingerprint_sha256=fingerprint,
        certificate_evidence_sha256=rollback_certificate_evidence_sha256(
            base.target_token_sha256,
            base.provider,
            fingerprint,
            base.local_ca,
            base.ca_bundle,
        ),
    )
    captures = 0

    def capture(provider):
        nonlocal captures
        captures += 1
        return _Owner(target)

    adapter = NativeWindowsRollbackVerification(
        target.certificate,
        target_capture=capture,
        environment=_Environment(_environment(_authority(target))),
        certificate_observer=_Certificates(_authority(target)),
    )
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackVerificationError) as caught:
        package_root.run_while_held(
            lambda: adapter.verify_rollback_while_package_root_held(
                package_root,
                _stream(target),
                authority,
            )
        )

    assert caught.value.code is NativeRollbackVerificationErrorCode.INPUT_INVALID
    assert captures == 0
    package_root.close()
