"""Native exact-state terminal verification for Windows rollback recovery."""

from __future__ import annotations

from enum import Enum
from typing import NoReturn, Protocol

from .runtime_target_factory import capture_native_windows_resolved_target
from .runtime_target_observation import (
    CertificateTargetDestination,
    ObservationOperation,
)
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .target_contracts import CertificateIdentity, MapProvider, ResolvedRepairTarget
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery import (
    CertificateDestinationRestoreEvidence,
    RollbackVerificationEvidence,
)
from .windows_recovery_certificate_restore_native import (
    observe_certificate_destination_while_target_held,
)
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_recovery_environment_restore_native import (
    NativeWindowsEnvironmentRestoreStorage,
)
from .windows_recovery_journal import (
    JournalStreamIdentity,
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from .windows_recovery_readiness_authority import (
    rollback_readiness_evidence_sha256,
)
from .windows_recovery_runtime_available_native import (
    ExistingRollbackRuntimeObservation,
    observe_rollback_runtime_target,
)
from .windows_recovery_verification_authority import (
    RollbackCertificateExpectation,
    RollbackEnvironmentExpectation,
    RollbackVerificationAuthority,
    rollback_readiness_condition_restored,
)
from .windows_security import StableFileIdentity


class NativeRollbackVerificationErrorCode(str, Enum):
    INPUT_INVALID = "rollback_verification_input_invalid"
    CAPTURE_UNAVAILABLE = "rollback_verification_capture_unavailable"
    TARGET_MISMATCH = "rollback_verification_target_mismatch"
    LOCAL_STATE_MISMATCH = "rollback_verification_local_state_mismatch"
    READINESS_MISMATCH = "rollback_verification_readiness_mismatch"
    VERIFY_FAILED = "rollback_verification_failed"


class NativeRollbackVerificationError(RuntimeError):
    """Sanitized terminal rollback-verification failure."""

    _MESSAGES = {
        NativeRollbackVerificationErrorCode.INPUT_INVALID: (
            "The rollback verification request is invalid."
        ),
        NativeRollbackVerificationErrorCode.CAPTURE_UNAVAILABLE: (
            "The rollback target could not be inspected."
        ),
        NativeRollbackVerificationErrorCode.TARGET_MISMATCH: (
            "The rollback runtime no longer matches its authenticated authority."
        ),
        NativeRollbackVerificationErrorCode.LOCAL_STATE_MISMATCH: (
            "The exact local rollback state could not be verified."
        ),
        NativeRollbackVerificationErrorCode.READINESS_MISMATCH: (
            "The prior readiness condition was not restored."
        ),
        NativeRollbackVerificationErrorCode.VERIFY_FAILED: (
            "Rollback verification could not be completed safely."
        ),
    }

    def __init__(self, code: NativeRollbackVerificationErrorCode) -> None:
        if type(code) is not NativeRollbackVerificationErrorCode:
            raise ValueError("Unknown rollback verification error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRollbackVerificationError(code={self.code.value!r})"


class _ResolvedTargetOwner(Protocol):
    @property
    def target(self) -> ResolvedRepairTarget: ...

    @property
    def closed(self) -> bool: ...

    def assert_unchanged(self) -> object: ...

    def execute_scoped_process(
        self,
        operation: str,
        arguments: tuple[object, ...],
    ) -> object: ...

    def close(self) -> None: ...


class ResolvedTargetCapture(Protocol):
    def __call__(self, provider: MapProvider) -> _ResolvedTargetOwner: ...


class EnvironmentObservationPort(Protocol):
    def observe_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        package_root_identity: StableFileIdentity,
    ) -> EnvironmentDestinationObservation: ...


class CertificateObservationPort(Protocol):
    def __call__(
        self,
        owner: _ResolvedTargetOwner,
        destination: CertificateTargetDestination,
    ) -> CertificateDestinationRestoreEvidence: ...


def _fail(code: NativeRollbackVerificationErrorCode) -> NoReturn:
    raise NativeRollbackVerificationError(code) from None


def _assert_package_root(
    package_root: PathHierarchyTrust,
    stream: JournalStreamIdentity,
) -> None:
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.root_snapshot.identity != stream.package_root_identity
    ):
        _fail(NativeRollbackVerificationErrorCode.TARGET_MISMATCH)
    try:
        package_root.assert_unchanged_while_held()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(NativeRollbackVerificationErrorCode.TARGET_MISMATCH)


def _runtime_matches(
    observation: ExistingRollbackRuntimeObservation,
    authority: RollbackVerificationAuthority,
) -> bool:
    return (
        type(observation) is ExistingRollbackRuntimeObservation
        and observation.target_token_sha256 == authority.target_token_sha256
        and observation.package_root_identity == authority.package_root_identity
        and observation.runtime_evidence_sha256 == authority.runtime_evidence_sha256
        and observation.container_evidence_sha256 == authority.container_evidence_sha256
        and observation.volume_evidence_sha256s == authority.volume_evidence_sha256s
    )


def _environment_matches(
    observation: EnvironmentDestinationObservation,
    expected: RollbackEnvironmentExpectation,
) -> bool:
    return (
        type(observation) is EnvironmentDestinationObservation
        and observation.present is expected.present
        and observation.identity == expected.identity
        and observation.sha256 == expected.sha256
        and observation.size == expected.size
        and observation.file_attributes == expected.file_attributes
        and observation.security_descriptor_sha256
        == expected.security_descriptor_sha256
    )


def _certificate_matches(
    observation: CertificateDestinationRestoreEvidence,
    expected: RollbackCertificateExpectation,
) -> bool:
    return (
        type(observation) is CertificateDestinationRestoreEvidence
        and observation.present is expected.present
        and observation.contents_sha256 == expected.sha256
        and observation.size == expected.size
        and observation.mode == expected.mode
        and observation.destination_evidence_sha256
        == expected.destination_evidence_sha256
    )


def _process_result(
    value: object,
    operation: ObservationOperation,
) -> TargetObservationProcessResult:
    if not isinstance(value, TargetObservationProcessResult):
        _fail(NativeRollbackVerificationErrorCode.VERIFY_FAILED)
    if (
        type(value) is not TargetObservationProcessResult
        or value.operation is not operation
        or value.exit_code != 0
    ):
        _fail(NativeRollbackVerificationErrorCode.VERIFY_FAILED)
    return value


def _readiness(owner: _ResolvedTargetOwner) -> RollbackReadinessCondition:
    result = _process_result(
        owner.execute_scoped_process(
            "rollback_readiness_probe",
            (owner.target.container.container_id,),
        ),
        ObservationOperation.ROLLBACK_READINESS_PROBE,
    )
    values = {
        b"setup_required\n": RollbackReadinessCondition.SETUP_REQUIRED,
        b"degraded\n": RollbackReadinessCondition.DEGRADED,
        b"ready\n": RollbackReadinessCondition.READY,
    }
    condition = values.get(result.stdout)
    if condition is None:
        _fail(NativeRollbackVerificationErrorCode.VERIFY_FAILED)
    return condition


def _provider_outcome(owner: _ResolvedTargetOwner) -> RollbackProviderOutcome:
    result = _process_result(
        owner.execute_scoped_process(
            "rollback_provider_probe",
            (owner.target.container.container_id,),
        ),
        ObservationOperation.ROLLBACK_PROVIDER_PROBE,
    )
    values = {
        b"success\n": RollbackProviderOutcome.SUCCESS,
        b"repairable_tls_failure\n": (RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE),
        b"provider_recheck_indeterminate\n": (
            RollbackProviderOutcome.PROVIDER_RECHECK_INDETERMINATE
        ),
    }
    outcome = values.get(result.stdout)
    if outcome is None:
        _fail(NativeRollbackVerificationErrorCode.VERIFY_FAILED)
    return outcome


def _default_certificate_observer(
    owner: _ResolvedTargetOwner,
    destination: CertificateTargetDestination,
) -> CertificateDestinationRestoreEvidence:
    if type(owner) is not BoundResolvedRepairTarget:
        _fail(NativeRollbackVerificationErrorCode.CAPTURE_UNAVAILABLE)
    return observe_certificate_destination_while_target_held(
        owner,
        destination,
    )


def _close(owner: _ResolvedTargetOwner | None) -> bool:
    if owner is None or owner.closed:
        return False
    failed = False
    try:
        owner.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        return failed or owner.closed is not True
    except Exception:
        return True


class NativeWindowsRollbackVerification:
    """Verify exact rollback state through one retained runtime target."""

    __slots__ = (
        "_certificate",
        "_certificate_observer",
        "_environment",
        "_target_capture",
    )

    def __init__(
        self,
        certificate: CertificateIdentity,
        *,
        target_capture: ResolvedTargetCapture = capture_native_windows_resolved_target,
        environment: EnvironmentObservationPort | None = None,
        certificate_observer: CertificateObservationPort | None = None,
    ) -> None:
        if (
            type(certificate) is not CertificateIdentity
            or not callable(target_capture)
            or (
                environment is not None
                and not callable(
                    getattr(
                        environment,
                        "observe_environment_while_package_root_held",
                        None,
                    )
                )
            )
            or (certificate_observer is not None and not callable(certificate_observer))
        ):
            raise ValueError("Rollback verification configuration is invalid.")
        self._certificate = certificate
        self._target_capture = target_capture
        self._environment = (
            NativeWindowsEnvironmentRestoreStorage()
            if environment is None
            else environment
        )
        self._certificate_observer = (
            _default_certificate_observer
            if certificate_observer is None
            else certificate_observer
        )

    def verify_rollback_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        authority: RollbackVerificationAuthority,
    ) -> RollbackVerificationEvidence:
        if (
            type(stream) is not JournalStreamIdentity
            or type(authority) is not RollbackVerificationAuthority
            or authority.target_token_sha256 != stream.target_token_sha256
            or authority.package_root_identity != stream.package_root_identity
            or self._certificate.provider is not authority.provider
            or self._certificate.windows_root_fingerprint_sha256
            != authority.windows_root_fingerprint_sha256
        ):
            _fail(NativeRollbackVerificationErrorCode.INPUT_INVALID)
        _assert_package_root(package_root, stream)
        owner: _ResolvedTargetOwner | None = None
        result: RollbackVerificationEvidence | None = None
        primary: BaseException | None = None
        try:
            owner = self._target_capture(authority.provider)
            if owner.closed:
                _fail(NativeRollbackVerificationErrorCode.CAPTURE_UNAVAILABLE)
            owner.assert_unchanged()
            runtime = observe_rollback_runtime_target(
                owner.target,
                authority.target_token_sha256,
            )
            owner.assert_unchanged()
            if not _runtime_matches(runtime, authority):
                _fail(NativeRollbackVerificationErrorCode.TARGET_MISMATCH)
            environment = self._environment.observe_environment_while_package_root_held(
                package_root,
                authority.package_root_identity,
            )
            if not _environment_matches(environment, authority.environment):
                _fail(NativeRollbackVerificationErrorCode.LOCAL_STATE_MISMATCH)
            local_ca = self._certificate_observer(
                owner,
                CertificateTargetDestination.LOCAL_CA,
            )
            ca_bundle = self._certificate_observer(
                owner,
                CertificateTargetDestination.CA_BUNDLE,
            )
            if not _certificate_matches(
                local_ca,
                authority.local_ca,
            ) or not _certificate_matches(ca_bundle, authority.ca_bundle):
                _fail(NativeRollbackVerificationErrorCode.LOCAL_STATE_MISMATCH)
            readiness = _readiness(owner)
            provider_outcome = _provider_outcome(owner)
            readiness_restored = rollback_readiness_condition_restored(
                authority,
                readiness,
                provider_outcome,
            )
            if not readiness_restored:
                _fail(NativeRollbackVerificationErrorCode.READINESS_MISMATCH)
            owner.assert_unchanged()
            _assert_package_root(package_root, stream)
            result = RollbackVerificationEvidence(
                1,
                authority.target_token_sha256,
                authority.package_root_identity,
                authority.environment_evidence_sha256,
                authority.certificate_evidence_sha256,
                authority.runtime_evidence_sha256,
                authority.container_evidence_sha256,
                authority.volume_evidence_sha256s,
                rollback_readiness_evidence_sha256(
                    authority.target_token_sha256,
                    readiness,
                ),
                readiness,
                provider_outcome,
                True,
                True,
                True,
                readiness_restored,
            )
        except BaseException as error:
            primary = error
        cleanup_failed = _close(owner)
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup_failed:
            _fail(NativeRollbackVerificationErrorCode.VERIFY_FAILED)
        if isinstance(primary, NativeRollbackVerificationError):
            raise primary from None
        if primary is not None or result is None:
            _fail(NativeRollbackVerificationErrorCode.CAPTURE_UNAVAILABLE)
        return result

    def __repr__(self) -> str:
        return (
            "NativeWindowsRollbackVerification("
            f"provider={self._certificate.provider.value!r}, <redacted>)"
        )


__all__ = [
    "CertificateObservationPort",
    "EnvironmentObservationPort",
    "NativeRollbackVerificationError",
    "NativeRollbackVerificationErrorCode",
    "NativeWindowsRollbackVerification",
    "ResolvedTargetCapture",
]
