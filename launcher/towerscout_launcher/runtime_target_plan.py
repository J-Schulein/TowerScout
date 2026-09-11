"""Assemble one exact target plan and hand it to the native resolver.

This module is the ownership boundary between authenticated input discovery and
the already-reviewed native observation bridge.  It performs fixed-host,
read-only Windows certificate-store verification, but no input discovery,
process execution, certificate-store mutation, repair, or other mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import threading
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
from .trust_policy import SelectedWindowsRootMaterial, TrustPolicyError
from .trust_windows_native import capture_selected_windows_root


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


class _WindowsTrustedPlanInputOwner:
    """Bind every captured plan snapshot to fresh native Windows trust.

    The wrapped owner remains responsible for retaining the package, runtime,
    endpoint, and file authorities.  This owner deliberately ignores its
    caller-provided certificate field and replaces it with the identity of the
    root selected through the fixed, non-injectable Windows trust provider.
    """

    __slots__ = ("_active_owner", "_closed", "_lifetime_lock", "_owner")

    def __init__(self, owner: TargetResolutionPlanInputOwner) -> None:
        self._owner = owner
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._closed = False

    @property
    def supported(self) -> bool:
        with self._lifetime_lock:
            return bool(not self._closed and _owner_is_available(self._owner))

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            if self._closed:
                return True
            try:
                return self._owner.closed is True
            except Exception:
                return True

    def capture(self) -> TargetResolutionPlanInputs:
        self._lifetime_lock.acquire()
        if self._active_owner is not None or self._closed:
            self._lifetime_lock.release()
            raise TargetResolutionError(
                TargetResolutionErrorCode.TARGET_CHANGED
            ) from None
        self._active_owner = threading.get_ident()
        try:
            if not _owner_is_available(self._owner):
                raise TargetResolutionError(
                    TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
                ) from None
            inputs = self._owner.capture()
            if type(inputs) is not TargetResolutionPlanInputs:
                raise TargetResolutionError(
                    TargetResolutionErrorCode.AUTHORITY_MISMATCH
                ) from None
            provider = inputs.provider
            if type(provider) is not MapProvider:
                raise TargetResolutionError(
                    TargetResolutionErrorCode.AUTHORITY_MISMATCH
                ) from None
            try:
                selected = capture_selected_windows_root(provider)
            except TrustPolicyError:
                raise TargetResolutionError(
                    TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
                ) from None
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise TargetResolutionError(
                    TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
                ) from None
            if (
                type(selected) is not SelectedWindowsRootMaterial
                or selected.provider is not provider
            ):
                raise TargetResolutionError(
                    TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
                ) from None
            try:
                certificate = CertificateIdentity(
                    provider=provider,
                    windows_root_fingerprint_sha256=selected.fingerprint_sha256,
                    candidate_content_sha256=selected.pem_sha256,
                )
                return replace(inputs, certificate=certificate)
            except (OverflowError, TypeError, UnicodeError, ValueError):
                raise TargetResolutionError(
                    TargetResolutionErrorCode.AUTHORITY_MISMATCH
                ) from None
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                raise TargetResolutionError(
                    TargetResolutionErrorCode.TARGET_CHANGED
                ) from None
            if self._closed:
                return
            error: BaseException | None = None
            try:
                self._owner.close()
            except BaseException as caught:
                error = caught
            try:
                closed = self._owner.closed is True
            except Exception:
                closed = False
            if closed:
                self._closed = True
            if error is not None:
                raise error
            if not closed:
                raise TargetResolutionError(
                    TargetResolutionErrorCode.TARGET_CHANGED
                ) from None

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"_WindowsTrustedPlanInputOwner(state={state!r}, <redacted>)"


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
    """Bind native Windows trust, transfer stable inputs, then close them.

    Caller-provided certificate identity is never authoritative.  An internal
    owner replaces it with fresh fixed-host Windows-store evidence on both
    stable captures.  The input owner remains open until the native bridge has
    independently recaptured every plan authority.  After a successful
    handoff, only the returned resolved-target owner remains live.
    """

    trusted_owner = _WindowsTrustedPlanInputOwner(owner)
    resolved: BoundResolvedRepairTarget | None = None
    primary_error: BaseException | None = None
    cleanup_interruption: BaseException | None = None
    cleanup_failed = False
    try:
        if not _owner_is_available(trusted_owner):
            raise TargetResolutionError(
                TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
            ) from None
        first = _capture_plan(trusted_owner)
        second = _recapture_plan(trusted_owner)
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
        cleanup_failed = _close_owner(trusted_owner)
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
