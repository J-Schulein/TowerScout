"""Pure policy boundary for exact process-environment and acceleration inputs.

This module performs no discovery, environment reads, path resolution, or
command execution.  It consumes identities retained by other authenticated
owners plus engine capability evidence produced by the attested probe. The
result is joined into the exact target-plan owner, but that composed source
boundary intentionally remains unwired from launcher confirmation and repair.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn

from .target_contracts import (
    AccelerationPlan,
    EffectiveProfile,
    EndpointIdentity,
    FileIdentity,
    GpuMode,
    RuntimeIdentity,
    RuntimeProduct,
    WindowsProcessEnvironment,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROCESS_ENVIRONMENT_NAMES = (
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
)


class RuntimeAccelerationInputErrorCode(str, Enum):
    """Stable, non-sensitive failure categories for this policy boundary."""

    PACKAGE_INVALID = "package_invalid"
    CAPABILITY_INVALID = "capability_invalid"
    PROCESS_ENVIRONMENT_INVALID = "process_environment_invalid"
    ACCELERATION_UNAVAILABLE = "acceleration_unavailable"
    ENGINE_MISMATCH = "engine_mismatch"


class RuntimeAccelerationInputError(RuntimeError):
    """Sanitized failure from deterministic acceleration construction."""

    _MESSAGES = {
        RuntimeAccelerationInputErrorCode.PACKAGE_INVALID: (
            "The authenticated package acceleration inputs are invalid."
        ),
        RuntimeAccelerationInputErrorCode.CAPABILITY_INVALID: (
            "The attested engine acceleration evidence is invalid."
        ),
        RuntimeAccelerationInputErrorCode.PROCESS_ENVIRONMENT_INVALID: (
            "The authenticated Windows process environment is invalid."
        ),
        RuntimeAccelerationInputErrorCode.ACCELERATION_UNAVAILABLE: (
            "The requested acceleration profile is unavailable."
        ),
        RuntimeAccelerationInputErrorCode.ENGINE_MISMATCH: (
            "The acceleration engine bindings do not match."
        ),
    }

    def __init__(self, code: RuntimeAccelerationInputErrorCode) -> None:
        if type(code) is not RuntimeAccelerationInputErrorCode:
            raise ValueError("Unknown runtime acceleration input error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeAccelerationInputError(code={self.code.value!r})"


def _fail(code: RuntimeAccelerationInputErrorCode) -> NoReturn:
    raise RuntimeAccelerationInputError(code)


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


class PackageComputeFlavor(str, Enum):
    """Reviewed release-package compute flavors accepted by Gate A."""

    CPU = "cpu"
    CUDA126 = "cuda126"


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedAccelerationPackageValues:
    """Normalized values emitted by an authenticated package owner.

    ``auto_overlay_enabled`` is the already-normalized engine-specific package
    gate: Docker's reviewed auto-overlay gate or Podman's reviewed Podman GPU
    overlay gate.  This class does not read or interpret ``.env`` itself.
    """

    runtime_product: RuntimeProduct
    requested_mode: GpuMode
    compute_flavor: PackageComputeFlavor
    auto_overlay_enabled: bool
    package_binding_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.runtime_product) is not RuntimeProduct
            or type(self.requested_mode) is not GpuMode
            or type(self.compute_flavor) is not PackageComputeFlavor
            or type(self.auto_overlay_enabled) is not bool
            or not _is_sha256(self.package_binding_sha256)
        ):
            raise ValueError("Authenticated package acceleration values are invalid.")

    def __repr__(self) -> str:
        return "AuthenticatedAccelerationPackageValues(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AttestedEngineAccelerationEvidence:
    """Capability claims bound to one authenticated runtime and endpoint.

    The producer of this value is responsible for executing the fixed,
    endpoint-bound capability probe while the runtime authority is retained.
    This pure policy module validates that binding; it is not an attestation
    source and deliberately provides no native factory.
    """

    runtime_product: RuntimeProduct
    runtime_executable_sha256: str = field(repr=False)
    runtime_publisher_policy_sha256: str = field(repr=False)
    endpoint_private_metadata_sha256: str = field(repr=False)
    probe_evidence_sha256: str = field(repr=False)
    docker_gpu_ready: bool
    podman_cdi_ready: bool

    def __post_init__(self) -> None:
        if (
            type(self.runtime_product) is not RuntimeProduct
            or not _is_sha256(self.runtime_executable_sha256)
            or not _is_sha256(self.runtime_publisher_policy_sha256)
            or not _is_sha256(self.endpoint_private_metadata_sha256)
            or not _is_sha256(self.probe_evidence_sha256)
            or type(self.docker_gpu_ready) is not bool
            or type(self.podman_cdi_ready) is not bool
            or (self.runtime_product is RuntimeProduct.DOCKER and self.podman_cdi_ready)
            or (self.runtime_product is RuntimeProduct.PODMAN and self.docker_gpu_ready)
        ):
            raise ValueError("Attested engine acceleration evidence is invalid.")

    def __repr__(self) -> str:
        return "AttestedEngineAccelerationEvidence(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeAccelerationInputs:
    """Exact deterministic inputs for the retained target-plan owner."""

    process_environment: WindowsProcessEnvironment = field(repr=False)
    acceleration: AccelerationPlan
    ordered_compose_logical_names: tuple[str, ...]
    package_binding_sha256: str = field(repr=False)
    capability_evidence_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        expected_names = {
            EffectiveProfile.CPU: ("compose.yaml",),
            EffectiveProfile.DOCKER_GPU: ("compose.yaml", "compose.gpu.yaml"),
            EffectiveProfile.PODMAN_GPU: (
                "compose.yaml",
                "compose.gpu.podman.yaml",
            ),
        }
        expected_overlays = {
            EffectiveProfile.CPU: "",
            EffectiveProfile.DOCKER_GPU: "compose.gpu.yaml",
            EffectiveProfile.PODMAN_GPU: "compose.gpu.podman.yaml",
        }
        if (
            type(self.process_environment) is not WindowsProcessEnvironment
            or type(self.acceleration) is not AccelerationPlan
            or type(self.acceleration.requested) is not GpuMode
            or type(self.acceleration.effective) is not EffectiveProfile
            or self.acceleration.overlay_logical_name
            != expected_overlays.get(self.acceleration.effective)
            or type(self.ordered_compose_logical_names) is not tuple
            or self.ordered_compose_logical_names
            != expected_names.get(self.acceleration.effective)
            or not _is_sha256(self.package_binding_sha256)
            or not _is_sha256(self.capability_evidence_sha256)
        ):
            raise ValueError("Runtime acceleration inputs are invalid.")

    def __repr__(self) -> str:
        return "RuntimeAccelerationInputs(<redacted>)"


def construct_windows_process_environment(
    items: tuple[tuple[str, FileIdentity], ...],
) -> WindowsProcessEnvironment:
    """Construct the exact seven-alias, five-directory Windows environment.

    The tuple form intentionally rejects mappings that can hide duplicate or
    case-colliding names.  Every path comes from an authenticated directory
    identity; raw strings, ambient variables, ``PATH``, proxy values, and other
    child-process redirection inputs have no representation in this API.
    """

    if (
        type(items) is not tuple
        or len(items) != len(_PROCESS_ENVIRONMENT_NAMES)
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not FileIdentity
            or not item[1].is_directory
            for item in items
        )
        or tuple(item[0] for item in items) != _PROCESS_ENVIRONMENT_NAMES
    ):
        _fail(RuntimeAccelerationInputErrorCode.PROCESS_ENVIRONMENT_INVALID)
    identities = tuple(item[1] for item in items)
    if identities[0] != identities[1] or identities[2] != identities[3]:
        _fail(RuntimeAccelerationInputErrorCode.PROCESS_ENVIRONMENT_INVALID)
    try:
        return WindowsProcessEnvironment(
            system_root=identities[0],
            temp_directory=identities[2],
            user_profile=identities[4],
            local_app_data=identities[5],
            roaming_app_data=identities[6],
        )
    except (TypeError, ValueError, UnicodeError):
        raise RuntimeAccelerationInputError(
            RuntimeAccelerationInputErrorCode.PROCESS_ENVIRONMENT_INVALID
        ) from None


def _attestation_matches(
    evidence: AttestedEngineAccelerationEvidence,
    runtime: RuntimeIdentity,
    endpoint: EndpointIdentity,
) -> bool:
    return bool(
        evidence.runtime_product is runtime.product
        and evidence.runtime_executable_sha256 == runtime.executable.sha256
        and evidence.runtime_publisher_policy_sha256 == runtime.publisher_policy_sha256
        and evidence.endpoint_private_metadata_sha256
        == endpoint.private_metadata_sha256
    )


def _resolve_acceleration(
    package: AuthenticatedAccelerationPackageValues,
    evidence: AttestedEngineAccelerationEvidence,
) -> AccelerationPlan:
    requested = package.requested_mode
    if requested is GpuMode.OFF:
        return AccelerationPlan(
            requested=requested,
            effective=EffectiveProfile.CPU,
        )
    is_cuda_package = package.compute_flavor is PackageComputeFlavor.CUDA126
    capability_ready = (
        evidence.docker_gpu_ready
        if package.runtime_product is RuntimeProduct.DOCKER
        else evidence.podman_cdi_ready
    )
    use_gpu = bool(
        is_cuda_package
        and capability_ready
        and (requested is GpuMode.ON or package.auto_overlay_enabled)
    )
    if requested is GpuMode.ON and not use_gpu:
        _fail(RuntimeAccelerationInputErrorCode.ACCELERATION_UNAVAILABLE)
    if not use_gpu:
        return AccelerationPlan(
            requested=requested,
            effective=EffectiveProfile.CPU,
        )
    effective, overlay = {
        RuntimeProduct.DOCKER: (
            EffectiveProfile.DOCKER_GPU,
            "compose.gpu.yaml",
        ),
        RuntimeProduct.PODMAN: (
            EffectiveProfile.PODMAN_GPU,
            "compose.gpu.podman.yaml",
        ),
    }[package.runtime_product]
    return AccelerationPlan(
        requested=requested,
        effective=effective,
        overlay_logical_name=overlay,
    )


def construct_runtime_acceleration_inputs(
    *,
    package: AuthenticatedAccelerationPackageValues,
    capability: AttestedEngineAccelerationEvidence,
    runtime: RuntimeIdentity,
    endpoint: EndpointIdentity,
    process_environment_items: tuple[tuple[str, FileIdentity], ...],
) -> RuntimeAccelerationInputs:
    """Bind authenticated package, runtime, endpoint, and capability inputs."""

    if type(package) is not AuthenticatedAccelerationPackageValues:
        _fail(RuntimeAccelerationInputErrorCode.PACKAGE_INVALID)
    if type(capability) is not AttestedEngineAccelerationEvidence:
        _fail(RuntimeAccelerationInputErrorCode.CAPABILITY_INVALID)
    if (
        type(runtime) is not RuntimeIdentity
        or type(endpoint) is not EndpointIdentity
        or runtime.product is not endpoint.product
        or package.runtime_product is not runtime.product
        or capability.runtime_product is not runtime.product
    ):
        _fail(RuntimeAccelerationInputErrorCode.ENGINE_MISMATCH)
    if not _attestation_matches(capability, runtime, endpoint):
        _fail(RuntimeAccelerationInputErrorCode.CAPABILITY_INVALID)
    environment = construct_windows_process_environment(process_environment_items)
    acceleration = _resolve_acceleration(package, capability)
    names = {
        EffectiveProfile.CPU: ("compose.yaml",),
        EffectiveProfile.DOCKER_GPU: ("compose.yaml", "compose.gpu.yaml"),
        EffectiveProfile.PODMAN_GPU: (
            "compose.yaml",
            "compose.gpu.podman.yaml",
        ),
    }[acceleration.effective]
    try:
        return RuntimeAccelerationInputs(
            process_environment=environment,
            acceleration=acceleration,
            ordered_compose_logical_names=names,
            package_binding_sha256=package.package_binding_sha256,
            capability_evidence_sha256=capability.probe_evidence_sha256,
        )
    except (TypeError, ValueError, UnicodeError):
        raise RuntimeAccelerationInputError(
            RuntimeAccelerationInputErrorCode.CAPABILITY_INVALID
        ) from None


__all__ = [
    "AttestedEngineAccelerationEvidence",
    "AuthenticatedAccelerationPackageValues",
    "PackageComputeFlavor",
    "RuntimeAccelerationInputError",
    "RuntimeAccelerationInputErrorCode",
    "RuntimeAccelerationInputs",
    "construct_runtime_acceleration_inputs",
    "construct_windows_process_environment",
]
