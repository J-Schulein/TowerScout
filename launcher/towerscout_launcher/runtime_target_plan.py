"""Assemble one exact target plan and hand it to the native resolver.

This module is the ownership boundary between authenticated input discovery and
the already-reviewed native observation bridge.  It performs no discovery,
process execution, certificate-store access, repair, or mutation itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .runtime_target_observation_native import (
    capture_native_windows_resolved_repair_target,
)
from .runtime_target_resolution import (
    BoundResolvedRepairTarget,
    TargetResolutionError,
    TargetResolutionErrorCode,
    TargetResolutionPlan,
)
from .target_contracts import (
    AccelerationPlan,
    CertificateIdentity,
    ComposeProviderIdentity,
    EndpointIdentity,
    FileIdentity,
    MapProvider,
    RuntimeIdentity,
    SecurityArtifactInventory,
    WindowsProcessEnvironment,
)


@dataclass(frozen=True, slots=True, repr=False)
class TargetResolutionPlanInputs:
    """One immutable snapshot emitted by an authenticated input owner."""

    package_root: FileIdentity
    process_environment: WindowsProcessEnvironment
    release_identity: str
    security_artifacts: SecurityArtifactInventory
    runtime: RuntimeIdentity
    endpoint: EndpointIdentity
    compose_provider: ComposeProviderIdentity
    ordered_compose_files: tuple[FileIdentity, ...]
    environment_sha256: str = field(repr=False)
    planned_environment_sha256: str = field(repr=False)
    environment_source: FileIdentity = field(repr=False)
    environment_file: FileIdentity | None = field(repr=False)
    compose_project: str
    acceleration: AccelerationPlan
    provider: MapProvider
    port: int
    configured_image_reference: str = field(repr=False)
    pinned_image_digest: str = field(repr=False)
    certificate: CertificateIdentity = field(repr=False)

    def __repr__(self) -> str:
        return "TargetResolutionPlanInputs(<redacted>)"


class TargetResolutionPlanInputOwner(Protocol):
    """Retained authority that can recapture one coherent input snapshot."""

    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture(self) -> TargetResolutionPlanInputs: ...

    def close(self) -> None: ...


def assemble_target_resolution_plan(
    inputs: TargetResolutionPlanInputs,
) -> TargetResolutionPlan:
    """Construct the strict plan without leaking invalid private input data."""

    plan: TargetResolutionPlan | None = None
    if type(inputs) is TargetResolutionPlanInputs:
        try:
            plan = TargetResolutionPlan(
                package_root=inputs.package_root,
                process_environment=inputs.process_environment,
                release_identity=inputs.release_identity,
                security_artifacts=inputs.security_artifacts,
                runtime=inputs.runtime,
                endpoint=inputs.endpoint,
                compose_provider=inputs.compose_provider,
                ordered_compose_files=inputs.ordered_compose_files,
                environment_sha256=inputs.environment_sha256,
                planned_environment_sha256=inputs.planned_environment_sha256,
                environment_source=inputs.environment_source,
                environment_file=inputs.environment_file,
                compose_project=inputs.compose_project,
                acceleration=inputs.acceleration,
                provider=inputs.provider,
                port=inputs.port,
                configured_image_reference=inputs.configured_image_reference,
                pinned_image_digest=inputs.pinned_image_digest,
                certificate=inputs.certificate,
            )
        except (OverflowError, TypeError, UnicodeError, ValueError):
            pass
    if plan is None:
        raise TargetResolutionError(
            TargetResolutionErrorCode.AUTHORITY_MISMATCH
        ) from None
    return plan


def _capture_plan(
    owner: TargetResolutionPlanInputOwner,
) -> TargetResolutionPlan:
    inputs: TargetResolutionPlanInputs | None = None
    failure: TargetResolutionErrorCode | None = None
    try:
        inputs = owner.capture()
    except TargetResolutionError as error:
        failure = error.code
    except Exception:
        failure = TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
    if failure is not None:
        raise TargetResolutionError(failure) from None
    if type(inputs) is not TargetResolutionPlanInputs:
        raise TargetResolutionError(
            TargetResolutionErrorCode.AUTHORITY_MISMATCH
        ) from None
    return assemble_target_resolution_plan(inputs)


def _recapture_plan(
    owner: TargetResolutionPlanInputOwner,
) -> TargetResolutionPlan:
    plan: TargetResolutionPlan | None = None
    interrupted: BaseException | None = None
    try:
        plan = _capture_plan(owner)
    except BaseException as error:
        if not isinstance(error, Exception):
            interrupted = error
    if interrupted is not None:
        raise interrupted from None
    if plan is None:
        raise TargetResolutionError(TargetResolutionErrorCode.TARGET_CHANGED) from None
    return plan


def _owner_is_available(owner: TargetResolutionPlanInputOwner) -> bool:
    try:
        return bool(
            owner.supported is True
            and owner.closed is False
            and callable(owner.capture)
            and callable(owner.close)
        )
    except Exception:
        return False


def _close_owner(owner: TargetResolutionPlanInputOwner) -> bool:
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


def _suppress_resolved_close(owner: Any) -> None:
    try:
        owner.close()
    except BaseException:
        pass


def capture_native_windows_resolved_target_from_inputs(
    owner: TargetResolutionPlanInputOwner,
) -> BoundResolvedRepairTarget:
    """Consume stable inputs, transfer to native ownership, then close inputs.

    The input owner remains open through both stable captures and until the
    native bridge has independently recaptured every plan authority.  After a
    successful handoff, only the returned resolved-target owner remains live.
    """

    resolved: BoundResolvedRepairTarget | None = None
    primary_error: BaseException | None = None
    cleanup_interruption: BaseException | None = None
    cleanup_failed = False
    try:
        if not _owner_is_available(owner):
            raise TargetResolutionError(
                TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
            ) from None
        first = _capture_plan(owner)
        second = _recapture_plan(owner)
        if first.authority_sha256 != second.authority_sha256:
            raise TargetResolutionError(
                TargetResolutionErrorCode.TARGET_CHANGED
            ) from None
        resolved = capture_native_windows_resolved_repair_target(second)
        if type(resolved) is not BoundResolvedRepairTarget or resolved.closed:
            raise TargetResolutionError(
                TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
            ) from None
    except BaseException as error:
        if isinstance(error, TargetResolutionError) or not isinstance(error, Exception):
            primary_error = error
        else:
            primary_error = TargetResolutionError(
                TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
            )

    try:
        cleanup_failed = _close_owner(owner)
    except BaseException as error:
        cleanup_interruption = error

    if primary_error is not None:
        if resolved is not None:
            _suppress_resolved_close(resolved)
        raise primary_error from None
    if cleanup_interruption is not None:
        if resolved is not None:
            _suppress_resolved_close(resolved)
        raise cleanup_interruption from None
    if cleanup_failed or resolved is None:
        if resolved is not None:
            _suppress_resolved_close(resolved)
        raise TargetResolutionError(TargetResolutionErrorCode.TARGET_CHANGED) from None
    return resolved


__all__ = [
    "TargetResolutionPlanInputOwner",
    "TargetResolutionPlanInputs",
    "assemble_target_resolution_plan",
    "capture_native_windows_resolved_target_from_inputs",
]
