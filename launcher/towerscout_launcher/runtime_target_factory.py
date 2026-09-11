"""Create one retained exact native target before launcher confirmation.

This is the production composition boundary between authenticated native input
capture and the already-reviewed Windows-trust/target-observation bridge.  It
performs read-only resolution and returns a still-held target owner.  It does
not display confirmation, invoke repair, or perform mutation.
"""

from __future__ import annotations

from typing import NoReturn, Protocol

from .runtime_target_inputs import (
    BoundNativeTargetResolutionPlanInputs,
    TargetInputError,
    TargetInputErrorCode,
    capture_native_windows_target_resolution_plan_inputs,
)
from .runtime_target_plan import capture_native_windows_resolved_target_from_inputs
from .runtime_target_resolution import (
    BoundResolvedRepairTarget,
    TargetResolutionError,
    TargetResolutionErrorCode,
)
from .target_contracts import MapProvider


class _CloseableOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


def _fail(code: TargetResolutionErrorCode) -> NoReturn:
    raise TargetResolutionError(code)


def _input_error_code(error: TargetInputError) -> TargetResolutionErrorCode:
    return {
        TargetInputErrorCode.INPUTS_INVALID: (
            TargetResolutionErrorCode.AUTHORITY_MISMATCH
        ),
        TargetInputErrorCode.INPUTS_CHANGED: TargetResolutionErrorCode.TARGET_CHANGED,
        TargetInputErrorCode.VERIFICATION_UNAVAILABLE: (
            TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
        ),
    }[error.code]


def _close_owners(owners: tuple[_CloseableOwner, ...]) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(3):
        for owner in owners:
            try:
                closed = owner.closed
            except Exception:
                closed = False
            if closed:
                continue
            try:
                owner.close()
            except BaseException as error:
                if not isinstance(error, Exception) and interruption is None:
                    interruption = error
        try:
            if all(owner.closed for owner in owners):
                break
        except Exception:
            pass
    try:
        incomplete = any(not owner.closed for owner in owners)
    except Exception:
        incomplete = True
    if interruption is not None:
        return interruption
    if incomplete:
        return TargetResolutionError(TargetResolutionErrorCode.TARGET_CHANGED)
    return None


def capture_native_windows_resolved_target(
    provider: MapProvider,
) -> BoundResolvedRepairTarget:
    """Resolve and retain one exact target using only fixed native authorities.

    The sole public input is the approved map-provider selection.  Runtime,
    endpoint, package, environment, acceleration, Windows trust, Compose model,
    container, image, mount, and volume identities are captured internally.
    The returned owner remains responsible for revalidation and cleanup.
    """

    if type(provider) is not MapProvider:
        _fail(TargetResolutionErrorCode.AUTHORITY_MISMATCH)
    inputs: BoundNativeTargetResolutionPlanInputs | None = None
    resolved: BoundResolvedRepairTarget | None = None
    primary: BaseException | None = None
    try:
        inputs = capture_native_windows_target_resolution_plan_inputs(provider)
        resolved = capture_native_windows_resolved_target_from_inputs(inputs)
        if (
            type(resolved) is not BoundResolvedRepairTarget
            or resolved.closed
            or not inputs.closed
            or resolved.target.provider is not provider
            or resolved.evidence.target_token != resolved.target.target_token.display
        ):
            _fail(TargetResolutionErrorCode.AUTHORITY_MISMATCH)
        evidence = resolved.assert_unchanged()
        if evidence.target_token != resolved.target.target_token.display:
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        return resolved
    except BaseException as error:
        primary = error

    closeables: tuple[_CloseableOwner, ...] = tuple(
        owner for owner in (resolved, inputs) if owner is not None
    )
    cleanup = _close_owners(closeables)
    if primary is not None and not isinstance(primary, Exception):
        raise primary from None
    if cleanup is not None and not isinstance(cleanup, Exception):
        raise cleanup from None
    if cleanup is not None:
        raise TargetResolutionError(TargetResolutionErrorCode.TARGET_CHANGED) from None
    if isinstance(primary, TargetInputError):
        raise TargetResolutionError(_input_error_code(primary)) from None
    if isinstance(primary, TargetResolutionError):
        raise primary from None
    raise TargetResolutionError(
        TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
    ) from None


__all__ = ["capture_native_windows_resolved_target"]
