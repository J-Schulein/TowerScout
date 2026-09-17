"""Native retained-runtime attestation for fresh-process Windows rollback.

This adapter is deliberately limited to the safest rollback-availability
case: the exact pre-repair container still exists and the complete resolved
target can be recaptured through the native read-only target facade. Missing-
container
recreation remains a separate mutation boundary.  No runtime command is issued
here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
from typing import Any, Callable, NoReturn, Protocol

from .runtime_target_factory import capture_native_windows_resolved_target
from .runtime_target_resolution import BoundResolvedRepairTarget
from .target_contracts import (
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


def _container_evidence(target: ResolvedRepairTarget) -> str:
    container = target.container
    return _evidence_sha256(
        _CONTAINER_EVIDENCE_DOMAIN,
        (
            target.target_token.digest_sha256,
            container.container_id,
            container.daemon_image_id,
            container.private_inspect_sha256,
        ),
    )


def _observation_from_target(
    target: ResolvedRepairTarget,
) -> ExistingRollbackRuntimeObservation:
    if type(target) is not ResolvedRepairTarget:
        _fail(NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED)
    try:
        authority = derive_rollback_runtime_recovery_authority(target)
        return ExistingRollbackRuntimeObservation(
            1,
            authority.target_token_sha256,
            authority.package_root_identity,
            authority.runtime_evidence_sha256,
            _container_evidence(target),
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
        result = _observation_from_target(owner.target)
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


__all__ = [
    "ExistingRollbackRuntimeObservation",
    "NativeRollbackRuntimeAvailabilityError",
    "NativeRollbackRuntimeAvailabilityErrorCode",
    "NativeWindowsExistingRollbackRuntimeAvailability",
    "capture_native_existing_rollback_runtime",
]
