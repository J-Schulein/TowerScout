"""Native retained-runtime attestation for fresh-process Windows rollback.

The retained-container adapter recaptures the complete resolved target.  The
absent-container owner reconstructs the original plan from authenticated
certificate identity, retains every native authority, and proves exact
Compose/image/all-volume state without rerunning Windows trust selection.
Container recreation remains a separate mutation boundary. No runtime mutation
command is issued here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
import threading
from typing import Any, Callable, NoReturn, Protocol

from .runtime_target_factory import capture_native_windows_resolved_target
from .runtime_target_inputs import (
    capture_native_windows_target_resolution_plan_inputs,
)
from .runtime_target_observation_native import (
    capture_native_windows_target_observation_backend,
)
from .runtime_target_observation_backend import RecreatedTargetResolutionSnapshots
from .runtime_target_plan import (
    TargetResolutionPlanInputs,
    assemble_target_resolution_plan,
)
from .runtime_target_resolution import (
    AbsentResolvedRuntimeTarget,
    AbsentTargetResolutionSnapshot,
    BoundResolvedRepairTarget,
    TargetResolutionPlan,
    TargetResolutionSnapshot,
    capture_bound_resolved_repair_target,
    resolve_absent_runtime_target,
    resolve_present_runtime_target,
)
from .target_contracts import (
    CertificateIdentity,
    MapProvider,
    ResolvedRepairTarget,
)
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_recovery import RollbackRuntimeAvailabilityEvidence
from .windows_recovery_journal import JournalStreamIdentity
from .windows_recovery_runtime_authority import (
    RollbackRuntimeRecoveryAuthority,
    derive_absent_rollback_runtime_recovery_authority,
    derive_recreated_rollback_runtime_recovery_authority,
    derive_rollback_runtime_recovery_authority,
)
from .windows_security import StableFileIdentity

_CONTAINER_EVIDENCE_DOMAIN = b"TowerScout.RollbackRuntimeAvailability.Container.v1"


class NativeRollbackRuntimeAvailabilityErrorCode(str, Enum):
    INPUT_INVALID = "rollback_runtime_availability_input_invalid"
    CAPTURE_UNAVAILABLE = "rollback_runtime_availability_capture_unavailable"
    TARGET_MISMATCH = "rollback_runtime_availability_target_mismatch"
    VERIFY_FAILED = "rollback_runtime_availability_verify_failed"


class NativeRollbackRuntimeAvailabilityError(RuntimeError):
    """Sanitized retained-runtime attestation failure."""

    _MESSAGES = {
        NativeRollbackRuntimeAvailabilityErrorCode.INPUT_INVALID: (
            "The rollback runtime availability request is invalid."
        ),
        NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE: (
            "The exact rollback runtime could not be inspected."
        ),
        NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH: (
            "The inspected rollback runtime does not match the recovery " "target."
        ),
        NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED: (
            "The rollback runtime could not be verified safely."
        ),
    }

    def __init__(self, code: NativeRollbackRuntimeAvailabilityErrorCode) -> None:
        if type(code) is not NativeRollbackRuntimeAvailabilityErrorCode:
            raise ValueError("Unknown rollback runtime availability error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        code = self.code.value
        return f"NativeRollbackRuntimeAvailabilityError(code={code!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ExistingRollbackRuntimeObservation:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        try:
            RollbackRuntimeAvailabilityEvidence(
                self.schema_version,
                self.target_token_sha256,
                self.package_root_identity,
                self.runtime_evidence_sha256,
                self.container_evidence_sha256,
                self.volume_evidence_sha256s,
                True,
            )
        except ValueError:
            raise ValueError(
                "Existing rollback runtime observation is invalid."
            ) from None

    def __repr__(self) -> str:
        return "ExistingRollbackRuntimeObservation(<redacted>)"


class _ResolvedTargetOwner(Protocol):
    @property
    def target(self) -> ResolvedRepairTarget: ...

    @property
    def closed(self) -> bool: ...

    def assert_unchanged(self) -> object: ...

    def close(self) -> None: ...


class ExistingRollbackRuntimeCapture(Protocol):
    def __call__(self, provider: MapProvider) -> ExistingRollbackRuntimeObservation: ...


class _PlanInputOwner(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture(self) -> TargetResolutionPlanInputs: ...

    def close(self) -> None: ...


class _AbsentObservationBackend(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture_absent(
        self,
        plan: TargetResolutionPlan,
    ) -> AbsentTargetResolutionSnapshot: ...

    def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot: ...

    def recreate_absent(
        self,
        plan: TargetResolutionPlan,
        expected: AbsentResolvedRuntimeTarget,
    ) -> RecreatedTargetResolutionSnapshots: ...

    def close(self) -> None: ...


class AbsentPlanInputCapture(Protocol):
    def __call__(self, provider: MapProvider) -> _PlanInputOwner: ...


class AbsentObservationBackendCapture(Protocol):
    def __call__(self, plan: TargetResolutionPlan) -> _AbsentObservationBackend: ...


class ResolvedTargetCapture(Protocol):
    def __call__(self, provider: MapProvider) -> BoundResolvedRepairTarget: ...


class AbsentRollbackRuntimeCapture(Protocol):
    def __call__(
        self,
        certificate: CertificateIdentity,
        authority: RollbackRuntimeRecoveryAuthority,
    ) -> BoundAbsentRollbackRuntimeTarget: ...


def _fail(code: NativeRollbackRuntimeAvailabilityErrorCode) -> NoReturn:
    raise NativeRollbackRuntimeAvailabilityError(code) from None


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _evidence_sha256(domain: bytes, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    _add(digest, domain)
    for value in values:
        _add(digest, value.encode("utf-8", errors="strict"))
    return digest.hexdigest()


def _container_evidence(
    target: ResolvedRepairTarget,
    target_token_sha256: str,
) -> str:
    container = target.container
    return _evidence_sha256(
        _CONTAINER_EVIDENCE_DOMAIN,
        (
            target_token_sha256,
            container.container_id,
            container.daemon_image_id,
            container.private_inspect_sha256,
        ),
    )


def observe_rollback_runtime_target(
    target: ResolvedRepairTarget,
    target_token_sha256: str | None = None,
) -> ExistingRollbackRuntimeObservation:
    if type(target) is not ResolvedRepairTarget:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    try:
        authority = (
            derive_rollback_runtime_recovery_authority(target)
            if target_token_sha256 is None
            else derive_recreated_rollback_runtime_recovery_authority(
                target_token_sha256,
                target,
            )
        )
        return ExistingRollbackRuntimeObservation(
            1,
            authority.target_token_sha256,
            authority.package_root_identity,
            authority.runtime_evidence_sha256,
            _container_evidence(target, authority.target_token_sha256),
            authority.volume_evidence_sha256s,
        )
    except NativeRollbackRuntimeAvailabilityError:
        raise
    except (AttributeError, TypeError, UnicodeError, ValueError):
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)


def capture_native_existing_rollback_runtime(
    provider: MapProvider,
    *,
    capture: Callable[[MapProvider], BoundResolvedRepairTarget] = (
        capture_native_windows_resolved_target
    ),
) -> ExistingRollbackRuntimeObservation:
    """Recapture one still-existing exact target and close its native owner."""

    if type(provider) is not MapProvider or not callable(capture):
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.INPUT_INVALID)
    owner: _ResolvedTargetOwner | None = None
    primary: BaseException | None = None
    result: ExistingRollbackRuntimeObservation | None = None
    try:
        owner = capture(provider)
        if owner.closed:
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
        owner.assert_unchanged()
        result = observe_rollback_runtime_target(owner.target)
        owner.assert_unchanged()
    except BaseException as error:
        primary = error
    cleanup_failed = False
    if owner is not None:
        try:
            owner.close()
            cleanup_failed = not owner.closed
        except BaseException as error:
            if not isinstance(error, Exception) and primary is None:
                primary = error
            cleanup_failed = True
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    if cleanup_failed:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    if primary is not None:
        if isinstance(primary, NativeRollbackRuntimeAvailabilityError):
            raise primary from None
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
    if type(result) is not ExistingRollbackRuntimeObservation:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    return result


def capture_native_present_rollback_runtime_target(
    certificate: CertificateIdentity,
    authority: RollbackRuntimeRecoveryAuthority,
    *,
    input_capture: AbsentPlanInputCapture = (
        capture_native_windows_target_resolution_plan_inputs
    ),
    backend_capture: AbsentObservationBackendCapture = (
        capture_native_windows_target_observation_backend
    ),
) -> BoundResolvedRepairTarget:
    """Capture a present recovery target without rerunning trust selection."""

    if (
        type(certificate) is not CertificateIdentity
        or type(authority) is not RollbackRuntimeRecoveryAuthority
        or not callable(input_capture)
        or not callable(backend_capture)
    ):
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.INPUT_INVALID)
    inputs: _PlanInputOwner | None = None
    backend: _AbsentObservationBackend | None = None
    result: BoundResolvedRepairTarget | None = None
    primary: BaseException | None = None
    transferred = False
    try:
        inputs = input_capture(certificate.provider)
        if inputs.supported is not True or inputs.closed is not False:
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
        first_inputs = inputs.capture()
        second_inputs = inputs.capture()
        first_plan = assemble_target_resolution_plan(
            first_inputs,
            certificate=certificate,
        )
        second_plan = assemble_target_resolution_plan(
            second_inputs,
            certificate=certificate,
        )
        if (
            first_plan.authority_sha256 != second_plan.authority_sha256
            or first_plan.provider is not certificate.provider
            or StableFileIdentity(
                first_plan.package_root.volume_serial,
                first_plan.package_root.file_id,
            )
            != authority.package_root_identity
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        backend = backend_capture(second_plan)
        if _close_absent_resource(inputs):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
        inputs = None
        result = capture_bound_resolved_repair_target(
            second_plan,
            backend=backend,
        )
        backend = None
        transferred = True
        if (
            result.closed
            or derive_rollback_runtime_recovery_authority(result.target) != authority
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
    except BaseException as error:
        primary = error
    cleanup_failed = False
    if primary is not None and result is not None:
        try:
            result.close()
        except BaseException as error:
            if not isinstance(error, Exception) and primary is None:
                primary = error
            cleanup_failed = True
        result = None
    if not transferred:
        for resource in (backend, inputs):
            if resource is None:
                continue
            try:
                cleanup_failed = _close_absent_resource(resource) or cleanup_failed
            except BaseException as error:
                if not isinstance(error, Exception) and primary is None:
                    primary = error
                cleanup_failed = True
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    if cleanup_failed:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    if isinstance(primary, NativeRollbackRuntimeAvailabilityError):
        raise primary from None
    if primary is not None or result is None:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
    return result


def _close_absent_resource(
    resource: _PlanInputOwner | _AbsentObservationBackend,
) -> bool:
    failed = False
    try:
        resource.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        closed = resource.closed is True
    except Exception:
        closed = False
    return failed or not closed


class BoundAbsentRollbackRuntimeTarget:
    """Retain native authorities for a repeatedly attestable absent target."""

    __slots__ = (
        "_authority",
        "_backend",
        "_closed",
        "_lock",
        "_observation",
        "_plan",
    )

    def __init__(
        self,
        *,
        plan: TargetResolutionPlan,
        backend: _AbsentObservationBackend,
        authority: RollbackRuntimeRecoveryAuthority,
        observation: AbsentResolvedRuntimeTarget,
    ) -> None:
        valid = False
        try:
            valid = (
                type(plan) is TargetResolutionPlan
                and type(authority) is RollbackRuntimeRecoveryAuthority
                and type(observation) is AbsentResolvedRuntimeTarget
                and observation.plan is plan
                and backend.supported is True
                and backend.closed is False
                and callable(backend.capture_absent)
                and callable(backend.close)
                and derive_absent_rollback_runtime_recovery_authority(
                    authority.target_token_sha256,
                    observation,
                )
                == authority
            )
        except Exception:
            valid = False
        if not valid:
            _close_absent_resource(backend)
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        self._lock = threading.RLock()
        self._closed = False
        self._plan = plan
        self._backend: _AbsentObservationBackend | None = backend
        self._authority = authority
        self._observation = observation

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def observation(self) -> AbsentResolvedRuntimeTarget:
        with self._lock:
            if self._closed:
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
            return self._observation

    def assert_unchanged(self) -> AbsentResolvedRuntimeTarget:
        with self._lock:
            backend = self._backend
            if self._closed or backend is None:
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
            try:
                snapshot = backend.capture_absent(self._plan)
                observed = resolve_absent_runtime_target(self._plan, snapshot)
                authority = derive_absent_rollback_runtime_recovery_authority(
                    self._authority.target_token_sha256,
                    observed,
                )
            except BaseException as error:
                self._poison()
                if not isinstance(error, Exception):
                    raise
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
            if (
                authority != self._authority
                or observed.observation_binding_sha256
                != self._observation.observation_binding_sha256
            ):
                self._poison()
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
            self._observation = observed
            return observed

    def recreate_prior_profile(self) -> BoundResolvedRepairTarget:
        """Recreate once, prove the exact profile, and transfer present authority."""

        with self._lock:
            backend = self._backend
            if self._closed or backend is None:
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
            mismatch = False
            transferred = False
            cleanup_failed = False
            present: BoundResolvedRepairTarget | None = None
            try:
                recreated = backend.recreate_absent(
                    self._plan,
                    self._observation,
                )
                first = resolve_present_runtime_target(
                    self._plan,
                    recreated.first,
                )
                second = resolve_present_runtime_target(
                    self._plan,
                    recreated.second,
                )
                mismatch = (
                    first != second
                    or first.target_token != second.target_token
                    or derive_recreated_rollback_runtime_recovery_authority(
                        self._authority.target_token_sha256,
                        first,
                    )
                    != self._authority
                    or derive_recreated_rollback_runtime_recovery_authority(
                        self._authority.target_token_sha256,
                        second,
                    )
                    != self._authority
                )
                if mismatch:
                    raise ValueError("Recreated target authority changed.")
                self._backend = None
                self._closed = True
                present = capture_bound_resolved_repair_target(
                    self._plan,
                    backend=backend,
                )
                transferred = True
                if (
                    derive_recreated_rollback_runtime_recovery_authority(
                        self._authority.target_token_sha256,
                        present.target,
                    )
                    != self._authority
                ):
                    mismatch = True
                    present.close()
                    present = None
                    _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
            except BaseException as error:
                if present is not None:
                    try:
                        present.close()
                    except BaseException as cleanup_error:
                        if not isinstance(cleanup_error, Exception):
                            raise
                        cleanup_failed = True
                    present = None
                elif not transferred:
                    self._poison()
                if not isinstance(error, Exception):
                    raise
                if cleanup_failed:
                    _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
                if mismatch or isinstance(
                    error,
                    NativeRollbackRuntimeAvailabilityError,
                ):
                    _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
            if present is None:
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
            return present

    def _poison(self) -> None:
        backend = self._backend
        self._backend = None
        self._closed = True
        if backend is not None:
            try:
                backend.close()
            except BaseException:
                pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            backend = self._backend
            self._backend = None
            self._closed = True
            if backend is not None and _close_absent_resource(backend):
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)

    def __repr__(self) -> str:
        return (
            "BoundAbsentRollbackRuntimeTarget("
            f"state={'closed' if self.closed else 'open'!r}, <redacted>)"
        )


def capture_native_absent_rollback_runtime_target(
    certificate: CertificateIdentity,
    authority: RollbackRuntimeRecoveryAuthority,
    *,
    input_capture: AbsentPlanInputCapture = (
        capture_native_windows_target_resolution_plan_inputs
    ),
    backend_capture: AbsentObservationBackendCapture = (
        capture_native_windows_target_observation_backend
    ),
) -> BoundAbsentRollbackRuntimeTarget:
    """Capture a trust-stable absent target without issuing runtime mutation."""

    if (
        type(certificate) is not CertificateIdentity
        or type(authority) is not RollbackRuntimeRecoveryAuthority
        or not callable(input_capture)
        or not callable(backend_capture)
    ):
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.INPUT_INVALID)
    inputs: _PlanInputOwner | None = None
    backend: _AbsentObservationBackend | None = None
    result: BoundAbsentRollbackRuntimeTarget | None = None
    primary: BaseException | None = None
    transferred = False
    try:
        inputs = input_capture(certificate.provider)
        if inputs.supported is not True or inputs.closed is not False:
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
        first_inputs = inputs.capture()
        second_inputs = inputs.capture()
        first_plan = assemble_target_resolution_plan(
            first_inputs,
            certificate=certificate,
        )
        second_plan = assemble_target_resolution_plan(
            second_inputs,
            certificate=certificate,
        )
        if (
            first_plan.authority_sha256 != second_plan.authority_sha256
            or first_plan.provider is not certificate.provider
            or StableFileIdentity(
                first_plan.package_root.volume_serial,
                first_plan.package_root.file_id,
            )
            != authority.package_root_identity
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        backend = backend_capture(second_plan)
        if _close_absent_resource(inputs):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
        inputs = None
        first = resolve_absent_runtime_target(
            second_plan,
            backend.capture_absent(second_plan),
        )
        second = resolve_absent_runtime_target(
            second_plan,
            backend.capture_absent(second_plan),
        )
        first_authority = derive_absent_rollback_runtime_recovery_authority(
            authority.target_token_sha256,
            first,
        )
        second_authority = derive_absent_rollback_runtime_recovery_authority(
            authority.target_token_sha256,
            second,
        )
        if (
            first_authority != authority
            or second_authority != authority
            or first.observation_binding_sha256 != second.observation_binding_sha256
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        result = BoundAbsentRollbackRuntimeTarget(
            plan=second_plan,
            backend=backend,
            authority=authority,
            observation=second,
        )
        backend = None
        transferred = True
    except BaseException as error:
        primary = error
    cleanup_failed = False
    if not transferred:
        for resource in (backend, inputs):
            if resource is not None:
                try:
                    cleanup_failed = _close_absent_resource(resource) or cleanup_failed
                except BaseException as error:
                    if not isinstance(error, Exception) and primary is None:
                        primary = error
                    cleanup_failed = True
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    if isinstance(primary, NativeRollbackRuntimeAvailabilityError):
        raise primary from None
    if cleanup_failed:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    if primary is not None or result is None:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
    return result


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
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
    try:
        package_root.assert_unchanged_while_held()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)


class NativeWindowsExistingRollbackRuntimeAvailability:
    """Attest a retained exact runtime without issuing a mutation command."""

    __slots__ = ("_capture", "_provider")

    def __init__(
        self,
        provider: MapProvider,
        *,
        capture: ExistingRollbackRuntimeCapture = (
            capture_native_existing_rollback_runtime
        ),
    ) -> None:
        if type(provider) is not MapProvider or not callable(capture):
            raise ValueError("Rollback runtime availability configuration is invalid.")
        self._provider = provider
        self._capture = capture

    def establish_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        authority: RollbackRuntimeRecoveryAuthority,
    ) -> RollbackRuntimeAvailabilityEvidence:
        if (
            type(stream) is not JournalStreamIdentity
            or type(authority) is not RollbackRuntimeRecoveryAuthority
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.INPUT_INVALID)
        _assert_package_root(package_root, stream)
        if (
            authority.target_token_sha256 != stream.target_token_sha256
            or authority.package_root_identity != stream.package_root_identity
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        try:
            observed = self._capture(self._provider)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            if isinstance(error, NativeRollbackRuntimeAvailabilityError):
                raise error from None
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
        _assert_package_root(package_root, stream)
        if (
            type(observed) is not ExistingRollbackRuntimeObservation
            or observed.target_token_sha256 != stream.target_token_sha256
            or observed.package_root_identity != stream.package_root_identity
            or observed.runtime_evidence_sha256 != authority.runtime_evidence_sha256
            or observed.volume_evidence_sha256s != authority.volume_evidence_sha256s
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        return RollbackRuntimeAvailabilityEvidence(
            1,
            observed.target_token_sha256,
            observed.package_root_identity,
            observed.runtime_evidence_sha256,
            observed.container_evidence_sha256,
            observed.volume_evidence_sha256s,
            True,
        )

    def __repr__(self) -> str:
        return (
            "NativeWindowsExistingRollbackRuntimeAvailability("
            f"provider={self._provider.value!r}, <redacted>)"
        )


def _close_resolved_target(owner: _ResolvedTargetOwner) -> bool:
    failed = False
    try:
        owner.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        closed = owner.closed is True
    except Exception:
        closed = False
    return failed or not closed


def _consume_resolved_target(
    owner: _ResolvedTargetOwner,
    stream: JournalStreamIdentity,
    authority: RollbackRuntimeRecoveryAuthority,
    *,
    existing_container_retained: bool,
) -> RollbackRuntimeAvailabilityEvidence:
    primary: BaseException | None = None
    result: RollbackRuntimeAvailabilityEvidence | None = None
    try:
        if owner.closed:
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
        owner.assert_unchanged()
        observed = observe_rollback_runtime_target(
            owner.target,
            authority.target_token_sha256,
        )
        if (
            observed.target_token_sha256 != stream.target_token_sha256
            or observed.package_root_identity != stream.package_root_identity
            or observed.runtime_evidence_sha256 != authority.runtime_evidence_sha256
            or observed.volume_evidence_sha256s != authority.volume_evidence_sha256s
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH)
        owner.assert_unchanged()
        result = RollbackRuntimeAvailabilityEvidence(
            1,
            observed.target_token_sha256,
            observed.package_root_identity,
            observed.runtime_evidence_sha256,
            observed.container_evidence_sha256,
            observed.volume_evidence_sha256s,
            existing_container_retained,
        )
    except BaseException as error:
        primary = error
    cleanup_failed = _close_resolved_target(owner)
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    if cleanup_failed:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    if isinstance(primary, NativeRollbackRuntimeAvailabilityError):
        raise primary from None
    if primary is not None or result is None:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
    return result


class NativeWindowsRollbackRuntimeAvailability:
    """Attest an existing target or exactly recreate a proven absent target."""

    __slots__ = ("_absent_capture", "_certificate", "_existing_capture")

    def __init__(
        self,
        certificate: CertificateIdentity,
        *,
        existing_capture: ResolvedTargetCapture = capture_native_windows_resolved_target,
        absent_capture: AbsentRollbackRuntimeCapture = (
            capture_native_absent_rollback_runtime_target
        ),
    ) -> None:
        if (
            type(certificate) is not CertificateIdentity
            or not callable(existing_capture)
            or not callable(absent_capture)
        ):
            raise ValueError("Rollback runtime availability configuration is invalid.")
        self._certificate = certificate
        self._existing_capture = existing_capture
        self._absent_capture = absent_capture

    def establish_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        authority: RollbackRuntimeRecoveryAuthority,
    ) -> RollbackRuntimeAvailabilityEvidence:
        if (
            type(stream) is not JournalStreamIdentity
            or type(authority) is not RollbackRuntimeRecoveryAuthority
            or authority.target_token_sha256 != stream.target_token_sha256
            or authority.package_root_identity != stream.package_root_identity
        ):
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.INPUT_INVALID)
        _assert_package_root(package_root, stream)
        present: BoundResolvedRepairTarget | None = None
        try:
            present = self._existing_capture(self._certificate.provider)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
        if present is not None:
            result = _consume_resolved_target(
                present,
                stream,
                authority,
                existing_container_retained=True,
            )
            _assert_package_root(package_root, stream)
            return result

        absent: BoundAbsentRollbackRuntimeTarget | None = None
        absent_result: RollbackRuntimeAvailabilityEvidence | None = None
        primary: BaseException | None = None
        try:
            absent = self._absent_capture(self._certificate, authority)
            if absent.closed:
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
            absent.assert_unchanged()
            present = absent.recreate_prior_profile()
            if absent.closed is not True:
                _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
            absent_result = _consume_resolved_target(
                present,
                stream,
                authority,
                existing_container_retained=False,
            )
            present = None
        except BaseException as error:
            primary = error
        cleanup_failed = False
        if present is not None:
            cleanup_failed = _close_resolved_target(present)
        if absent is not None and not absent.closed:
            try:
                absent.close()
                cleanup_failed = absent.closed is not True or cleanup_failed
            except BaseException as error:
                if not isinstance(error, Exception) and primary is None:
                    primary = error
                cleanup_failed = True
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup_failed:
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
        if isinstance(primary, NativeRollbackRuntimeAvailabilityError):
            raise primary from None
        if primary is not None or absent_result is None:
            _fail(NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE)
        _assert_package_root(package_root, stream)
        return absent_result

    def __repr__(self) -> str:
        return (
            "NativeWindowsRollbackRuntimeAvailability("
            f"provider={self._certificate.provider.value!r}, <redacted>)"
        )


__all__ = [
    "AbsentRollbackRuntimeCapture",
    "AbsentObservationBackendCapture",
    "AbsentPlanInputCapture",
    "BoundAbsentRollbackRuntimeTarget",
    "ExistingRollbackRuntimeObservation",
    "NativeRollbackRuntimeAvailabilityError",
    "NativeRollbackRuntimeAvailabilityErrorCode",
    "NativeWindowsExistingRollbackRuntimeAvailability",
    "NativeWindowsRollbackRuntimeAvailability",
    "ResolvedTargetCapture",
    "capture_native_existing_rollback_runtime",
    "capture_native_present_rollback_runtime_target",
    "capture_native_absent_rollback_runtime_target",
    "observe_rollback_runtime_target",
]
