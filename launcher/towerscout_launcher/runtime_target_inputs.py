"""Retained native source owner for one complete target-resolution plan.

This source-only boundary composes the package, runtime, endpoint, process
directory, and acceleration authorities already retained by
``BoundEngineAccelerationEvidence``.  It performs no launcher confirmation,
repair, mutation, PATH discovery, or ambient-environment discovery.
"""

from __future__ import annotations

import sys
import threading
from enum import Enum
from pathlib import PureWindowsPath
from typing import NoReturn, Protocol

from .runtime_acceleration_inputs import (
    AuthenticatedAccelerationPackageValues,
    PackageComputeFlavor,
    RuntimeAccelerationInputError,
    construct_runtime_acceleration_inputs,
)
from .runtime_acceleration_probe import (
    AccelerationProbeError,
    BoundEngineAccelerationEvidence,
    EngineAccelerationSnapshot,
    capture_native_windows_engine_acceleration_evidence,
)
from .runtime_docker_inputs import (
    BoundDockerTargetSourceInputs,
    DockerInputError,
    DockerTargetSourceInputs,
    capture_native_windows_docker_target_source_inputs,
)
from .runtime_package_inputs import (
    BoundPackageEnvironmentInputs,
    PackageInputError,
    capture_native_windows_package_environment_inputs,
)
from .runtime_process_environment import (
    BoundWindowsProcessEnvironment,
    ProcessEnvironmentInputError,
    capture_native_windows_process_environment,
)
from .runtime_podman_inputs import (
    BoundPodmanTargetSourceInputs,
    PodmanInputError,
    PodmanTargetSourceInputs,
    capture_native_windows_podman_target_source_inputs,
)
from .runtime_target_plan import TargetResolutionPlanInputs
from .target_contracts import (
    EffectiveProfile,
    FileIdentity,
    MapProvider,
    RuntimeProduct,
    WindowsProcessEnvironment,
)


class TargetInputErrorCode(str, Enum):
    """Stable, non-sensitive failure categories for the source owner."""

    INPUTS_INVALID = "inputs_invalid"
    INPUTS_CHANGED = "inputs_changed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class TargetInputError(RuntimeError):
    """Sanitized complete-target input failure."""

    _MESSAGES = {
        TargetInputErrorCode.INPUTS_INVALID: (
            "The authenticated target-plan inputs are invalid."
        ),
        TargetInputErrorCode.INPUTS_CHANGED: (
            "The authenticated target-plan inputs changed during verification."
        ),
        TargetInputErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure target-plan input verification is unavailable."
        ),
    }

    def __init__(self, code: TargetInputErrorCode) -> None:
        if type(code) is not TargetInputErrorCode:
            raise ValueError("Unknown target input error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"TargetInputError(code={self.code.value!r})"


def _fail(code: TargetInputErrorCode) -> NoReturn:
    raise TargetInputError(code)


class _CloseableOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


def _process_environment_items(
    environment: WindowsProcessEnvironment,
) -> tuple[tuple[str, FileIdentity], ...]:
    return (
        ("SYSTEMROOT", environment.system_root),
        ("WINDIR", environment.system_root),
        ("TEMP", environment.temp_directory),
        ("TMP", environment.temp_directory),
        ("USERPROFILE", environment.user_profile),
        ("LOCALAPPDATA", environment.local_app_data),
        ("APPDATA", environment.roaming_app_data),
    )


def _compose_files(
    snapshot: EngineAccelerationSnapshot,
    logical_names: tuple[str, ...],
) -> tuple[FileIdentity, ...]:
    package_files = snapshot.package.compose_files
    if tuple(item.logical_name for item in package_files) != (
        "compose.yaml",
        "compose.gpu.yaml",
        "compose.gpu.podman.yaml",
    ) or len({(item.volume_serial, item.file_id) for item in package_files}) != len(
        package_files
    ):
        _fail(TargetInputErrorCode.INPUTS_INVALID)
    by_name = {item.logical_name: item for item in package_files}
    try:
        selected = tuple(by_name[name] for name in logical_names)
    except KeyError:
        _fail(TargetInputErrorCode.INPUTS_INVALID)
    if tuple(item.logical_name for item in selected) != logical_names:
        _fail(TargetInputErrorCode.INPUTS_INVALID)
    return selected


def _compose_plan_inputs(
    snapshot: EngineAccelerationSnapshot,
    provider: MapProvider,
) -> TargetResolutionPlanInputs:
    """Construct every plan field from one authenticated aggregate snapshot."""

    if (
        type(snapshot) is not EngineAccelerationSnapshot
        or type(provider) is not MapProvider
    ):
        _fail(TargetInputErrorCode.INPUTS_INVALID)
    package = snapshot.package
    source = snapshot.target_source
    runtime = source.runtime
    endpoint = source.endpoint
    product = runtime.product
    expected_source = {
        RuntimeProduct.DOCKER: DockerTargetSourceInputs,
        RuntimeProduct.PODMAN: PodmanTargetSourceInputs,
    }.get(product)
    if (
        expected_source is None
        or type(source) is not expected_source
        or endpoint.product is not product
        or package.engine_hint != product.value
    ):
        # An empty engine hint is deliberately not an auto-discovery request.
        _fail(TargetInputErrorCode.INPUTS_INVALID)
    try:
        flavor = PackageComputeFlavor(package.pytorch_flavor)
        acceleration_inputs = construct_runtime_acceleration_inputs(
            package=AuthenticatedAccelerationPackageValues(
                runtime_product=product,
                requested_mode=package.requested_gpu_mode,
                compute_flavor=flavor,
                auto_overlay_enabled=(
                    package.gpu_auto_overlay
                    if product is RuntimeProduct.DOCKER
                    else package.podman_gpu_overlay
                ),
                package_binding_sha256=package.package_binding_sha256,
            ),
            capability=snapshot.attestation,
            runtime=runtime,
            endpoint=endpoint,
            process_environment_items=_process_environment_items(
                snapshot.process_environment
            ),
        )
        ordered_compose_files = _compose_files(
            snapshot,
            acceleration_inputs.ordered_compose_logical_names,
        )
        allowed_profiles = {
            RuntimeProduct.DOCKER: {
                EffectiveProfile.CPU,
                EffectiveProfile.DOCKER_GPU,
            },
            RuntimeProduct.PODMAN: {
                EffectiveProfile.CPU,
                EffectiveProfile.PODMAN_GPU,
            },
        }
        if acceleration_inputs.acceleration.effective not in allowed_profiles[product]:
            _fail(TargetInputErrorCode.INPUTS_INVALID)
        return TargetResolutionPlanInputs(
            package_root=package.package_root,
            process_environment=acceleration_inputs.process_environment,
            release_identity=package.release_identity,
            security_artifacts=package.security_artifacts,
            runtime=runtime,
            endpoint=endpoint,
            compose_provider=source.compose_provider,
            ordered_compose_files=ordered_compose_files,
            environment_sha256=package.environment_sha256,
            planned_environment_sha256=package.planned_environment_sha256,
            environment_source=package.environment_source,
            environment_file=package.environment_file,
            compose_project=package.compose_project,
            acceleration=acceleration_inputs.acceleration,
            provider=provider,
            port=package.port,
            configured_image_reference=package.configured_image_reference,
            pinned_image_digest=package.pinned_image_digest,
        )
    except TargetInputError:
        raise
    except RuntimeAccelerationInputError:
        raise TargetInputError(TargetInputErrorCode.INPUTS_INVALID) from None
    except (KeyError, TypeError, UnicodeError, ValueError):
        raise TargetInputError(TargetInputErrorCode.INPUTS_INVALID) from None


class BoundNativeTargetResolutionPlanInputs:
    """Sole owner of the retained aggregate source used by target resolution."""

    __slots__ = ("_active_owner", "_evidence", "_lock", "_provider")

    def __init__(
        self,
        *,
        evidence: BoundEngineAccelerationEvidence,
        provider: MapProvider,
    ) -> None:
        if (
            type(evidence) is not BoundEngineAccelerationEvidence
            or evidence.closed
            or not evidence.supported
            or type(provider) is not MapProvider
        ):
            raise ValueError("Bound native target-plan inputs are invalid.")
        self._lock = threading.RLock()
        self._active_owner: int | None = None
        self._evidence: BoundEngineAccelerationEvidence | None = evidence
        self._provider = provider

    @property
    def supported(self) -> bool:
        with self._lock:
            evidence = self._evidence
            try:
                return bool(
                    evidence is not None and not evidence.closed and evidence.supported
                )
            except Exception:
                return False

    @property
    def closed(self) -> bool:
        with self._lock:
            evidence = self._evidence
            return evidence is None or evidence.closed

    def capture(self) -> TargetResolutionPlanInputs:
        self._lock.acquire()
        if self._active_owner is not None:
            self._lock.release()
            _fail(TargetInputErrorCode.INPUTS_CHANGED)
        evidence = self._evidence
        if evidence is None or evidence.closed:
            self._lock.release()
            _fail(TargetInputErrorCode.INPUTS_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            first = evidence.capture()
            second = evidence.capture()
            if (
                type(first) is not EngineAccelerationSnapshot
                or type(second) is not EngineAccelerationSnapshot
                or first != second
                or first.authority_sha256 != second.authority_sha256
            ):
                _fail(TargetInputErrorCode.INPUTS_CHANGED)
            first_inputs = _compose_plan_inputs(first, self._provider)
            second_inputs = _compose_plan_inputs(second, self._provider)
            if first_inputs != second_inputs:
                _fail(TargetInputErrorCode.INPUTS_CHANGED)
            return second_inputs
        except TargetInputError:
            raise
        except AccelerationProbeError:
            raise TargetInputError(TargetInputErrorCode.INPUTS_CHANGED) from None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TargetInputError(
                TargetInputErrorCode.VERIFICATION_UNAVAILABLE
            ) from None
        finally:
            self._active_owner = None
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                _fail(TargetInputErrorCode.INPUTS_CHANGED)
            evidence = self._evidence
            if evidence is None:
                return
            interruption: BaseException | None = None
            for _attempt in range(3):
                if evidence.closed:
                    self._evidence = None
                    break
                try:
                    evidence.close()
                except BaseException as error:
                    if not isinstance(error, Exception) and interruption is None:
                        interruption = error
                if evidence.closed:
                    self._evidence = None
                    break
            if interruption is not None:
                raise interruption
            if self._evidence is not None:
                _fail(TargetInputErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundNativeTargetResolutionPlanInputs":
        if self.closed:
            _fail(TargetInputErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundNativeTargetResolutionPlanInputs(state={state!r}, <redacted>)"


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
        return TargetInputError(TargetInputErrorCode.INPUTS_CHANGED)
    return None


def _fixed_package_root() -> PureWindowsPath:
    """Derive one fixed package root without searching the host or ``cwd``."""

    try:
        if getattr(sys, "frozen", False):
            executable = PureWindowsPath(sys.executable)
            if executable.name.casefold() != "towerscoutlauncher.exe":
                _fail(TargetInputErrorCode.VERIFICATION_UNAVAILABLE)
            # Release layout: <package>\launcher\TowerScoutLauncher.exe.
            root = executable.parent.parent
        else:
            module = PureWindowsPath(__file__)
            if module.name != "runtime_target_inputs.py":
                _fail(TargetInputErrorCode.VERIFICATION_UNAVAILABLE)
            # Source layout: <package>\launcher\towerscout_launcher\<module>.
            root = module.parents[2]
    except TargetInputError:
        raise
    except (IndexError, TypeError, ValueError, UnicodeError):
        raise TargetInputError(TargetInputErrorCode.VERIFICATION_UNAVAILABLE) from None
    if not root.is_absolute() or not root.name or "\x00" in str(root):
        _fail(TargetInputErrorCode.VERIFICATION_UNAVAILABLE)
    return root


def capture_native_windows_target_resolution_plan_inputs(
    provider: MapProvider,
) -> BoundNativeTargetResolutionPlanInputs:
    """Open the complete fixed native source owner for one approved provider.

    The public API accepts no caller path, backend, endpoint, command,
    attestation, or environment.  Package location uses one fixed
    executable/module-relative derivation and is then authenticated by the
    retained package owner before it contributes any plan input.
    """

    if type(provider) is not MapProvider:
        _fail(TargetInputErrorCode.INPUTS_INVALID)
    package_root = _fixed_package_root()
    package_owner: BoundPackageEnvironmentInputs | None = None
    runtime_owner: (
        BoundDockerTargetSourceInputs | BoundPodmanTargetSourceInputs | None
    ) = None
    environment_owner: BoundWindowsProcessEnvironment | None = None
    evidence: BoundEngineAccelerationEvidence | None = None
    complete: BoundNativeTargetResolutionPlanInputs | None = None
    primary: BaseException | None = None
    try:
        package_owner = capture_native_windows_package_environment_inputs(package_root)
        package = package_owner.capture()
        if package.engine_hint == RuntimeProduct.DOCKER.value:
            runtime_owner = capture_native_windows_docker_target_source_inputs()
        elif package.engine_hint == RuntimeProduct.PODMAN.value:
            runtime_owner = capture_native_windows_podman_target_source_inputs(
                package_root
            )
        else:
            _fail(TargetInputErrorCode.INPUTS_INVALID)
        environment_owner = capture_native_windows_process_environment()
        evidence = capture_native_windows_engine_acceleration_evidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=environment_owner,
        )
        # The acceleration owner now sole-owns all three retained authorities.
        package_owner = None
        runtime_owner = None
        environment_owner = None
        complete = BoundNativeTargetResolutionPlanInputs(
            evidence=evidence,
            provider=provider,
        )
        complete.capture()
        evidence = None
        return complete
    except BaseException as error:
        primary = error

    closeables: tuple[_CloseableOwner, ...]
    if complete is not None:
        closeables = (complete,)
    elif evidence is not None:
        closeables = (evidence,)
    else:
        closeables = tuple(
            owner
            for owner in (environment_owner, runtime_owner, package_owner)
            if owner is not None
        )
    cleanup = _close_owners(closeables)
    if primary is not None and not isinstance(primary, Exception):
        raise primary from None
    if cleanup is not None and not isinstance(cleanup, Exception):
        raise cleanup from None
    if isinstance(cleanup, TargetInputError):
        raise cleanup from None
    if isinstance(primary, TargetInputError):
        raise primary from None
    if isinstance(
        primary,
        (
            AccelerationProbeError,
            DockerInputError,
            PackageInputError,
            PodmanInputError,
            ProcessEnvironmentInputError,
        ),
    ):
        raise TargetInputError(TargetInputErrorCode.INPUTS_CHANGED) from None
    raise TargetInputError(TargetInputErrorCode.VERIFICATION_UNAVAILABLE) from None


__all__ = [
    "BoundNativeTargetResolutionPlanInputs",
    "TargetInputError",
    "TargetInputErrorCode",
    "capture_native_windows_target_resolution_plan_inputs",
]
