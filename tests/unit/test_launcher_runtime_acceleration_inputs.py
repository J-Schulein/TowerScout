"""Gate A tests for pure process-environment and acceleration construction."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path, PureWindowsPath

import pytest

LAUNCHER_ROOT = Path(__file__).resolve().parents[2] / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_acceleration_inputs import (  # noqa: E402
    AttestedEngineAccelerationEvidence,
    AuthenticatedAccelerationPackageValues,
    PackageComputeFlavor,
    RuntimeAccelerationInputError,
    RuntimeAccelerationInputErrorCode,
    RuntimeAccelerationInputs,
    construct_runtime_acceleration_inputs,
    construct_windows_process_environment,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    AccelerationPlan,
    EffectiveProfile,
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    GpuMode,
    RuntimeIdentity,
    RuntimeProduct,
)

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_DIGEST_D = "d" * 64
_DIGEST_E = "e" * 64


def _directory(logical_name: str, path: str, identifier: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=10,
        file_id=identifier.to_bytes(8, "big"),
        is_directory=True,
    )


def _file(logical_name: str, path: str, identifier: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=10,
        file_id=identifier.to_bytes(8, "big"),
        sha256=_DIGEST_A,
        size_bytes=200,
    )


def _environment_items() -> tuple[tuple[str, FileIdentity], ...]:
    system = _directory("system_root", r"C:\Windows", 1)
    temporary = _directory("temp_directory", r"C:\Users\operator\AppData\Local\Temp", 2)
    profile = _directory("user_profile", r"C:\Users\operator", 3)
    local = _directory("local_app_data", r"C:\Users\operator\AppData\Local", 4)
    roaming = _directory("roaming_app_data", r"C:\Users\operator\AppData\Roaming", 5)
    return (
        ("SYSTEMROOT", system),
        ("WINDIR", system),
        ("TEMP", temporary),
        ("TMP", temporary),
        ("USERPROFILE", profile),
        ("LOCALAPPDATA", local),
        ("APPDATA", roaming),
    )


def _runtime(product: RuntimeProduct) -> RuntimeIdentity:
    leaf = f"{product.value}.exe"
    return RuntimeIdentity(
        product=product,
        executable=_file(leaf, rf"C:\Runtime\{leaf}", 20),
        version="5.4.2",
        publisher_policy_sha256=_DIGEST_B,
    )


def _endpoint(product: RuntimeProduct) -> EndpointIdentity:
    if product is RuntimeProduct.DOCKER:
        return EndpointIdentity(
            product=product,
            kind=EndpointKind.DOCKER_NAMED_PIPE,
            canonical_endpoint="npipe:////./pipe/dockerDesktopLinuxEngine",
            private_metadata_sha256=_DIGEST_C,
        )
    return EndpointIdentity(
        product=product,
        kind=EndpointKind.PODMAN_ROOTLESS_WSL,
        canonical_endpoint="ssh://operator@127.0.0.1:50222/run/user/1000/podman/podman.sock",
        private_metadata_sha256=_DIGEST_C,
        identity_key=_file(
            "podman_identity_key",
            r"C:\Users\operator\.local\share\containers\podman\key",
            21,
        ),
        rootless=True,
    )


def _package(
    product: RuntimeProduct,
    requested: GpuMode,
    *,
    flavor: PackageComputeFlavor = PackageComputeFlavor.CUDA126,
    auto_overlay_enabled: bool = True,
) -> AuthenticatedAccelerationPackageValues:
    return AuthenticatedAccelerationPackageValues(
        runtime_product=product,
        requested_mode=requested,
        compute_flavor=flavor,
        auto_overlay_enabled=auto_overlay_enabled,
        package_binding_sha256=_DIGEST_D,
    )


def _capability(
    product: RuntimeProduct,
    runtime: RuntimeIdentity,
    endpoint: EndpointIdentity,
    *,
    ready: bool,
) -> AttestedEngineAccelerationEvidence:
    return AttestedEngineAccelerationEvidence(
        runtime_product=product,
        runtime_executable_sha256=runtime.executable.sha256,
        runtime_publisher_policy_sha256=runtime.publisher_policy_sha256,
        endpoint_private_metadata_sha256=endpoint.private_metadata_sha256,
        probe_evidence_sha256=_DIGEST_E,
        docker_gpu_ready=ready if product is RuntimeProduct.DOCKER else False,
        podman_cdi_ready=ready if product is RuntimeProduct.PODMAN else False,
    )


def _construct(
    product: RuntimeProduct,
    requested: GpuMode,
    *,
    flavor: PackageComputeFlavor = PackageComputeFlavor.CUDA126,
    gate: bool = True,
    ready: bool = True,
) -> RuntimeAccelerationInputs:
    runtime = _runtime(product)
    endpoint = _endpoint(product)
    return construct_runtime_acceleration_inputs(
        package=_package(
            product,
            requested,
            flavor=flavor,
            auto_overlay_enabled=gate,
        ),
        capability=_capability(product, runtime, endpoint, ready=ready),
        runtime=runtime,
        endpoint=endpoint,
        process_environment_items=_environment_items(),
    )


def test_constructs_exact_minimal_windows_process_environment() -> None:
    items = _environment_items()
    result = construct_windows_process_environment(items)

    assert result.system_root == items[0][1]
    assert result.temp_directory == items[2][1]
    assert result.user_profile == items[4][1]
    assert result.local_app_data == items[5][1]
    assert result.roaming_app_data == items[6][1]
    assert repr(result) == "WindowsProcessEnvironment(<redacted>)"


@pytest.mark.parametrize("name", ["PATH", "PATHEXT", "DOCKER_HOST", "HTTP_PROXY"])
def test_rejects_extra_or_redirection_process_variables(name: str) -> None:
    items = (*_environment_items(), (name, _environment_items()[0][1]))

    with pytest.raises(RuntimeAccelerationInputError) as raised:
        construct_windows_process_environment(items)

    assert (
        raised.value.code
        is RuntimeAccelerationInputErrorCode.PROCESS_ENVIRONMENT_INVALID
    )
    assert name not in str(raised.value)


def test_rejects_aliases_that_do_not_refer_to_the_same_directory() -> None:
    items = list(_environment_items())
    items[1] = ("WINDIR", _directory("system_root", r"D:\Windows", 30))

    with pytest.raises(RuntimeAccelerationInputError) as raised:
        construct_windows_process_environment(tuple(items))

    assert (
        raised.value.code
        is RuntimeAccelerationInputErrorCode.PROCESS_ENVIRONMENT_INVALID
    )


@pytest.mark.parametrize("product", list(RuntimeProduct))
def test_off_always_selects_cpu_and_base_compose(product: RuntimeProduct) -> None:
    result = _construct(product, GpuMode.OFF, ready=True)

    assert result.acceleration == AccelerationPlan(
        requested=GpuMode.OFF,
        effective=EffectiveProfile.CPU,
    )
    assert result.ordered_compose_logical_names == ("compose.yaml",)


def test_docker_on_selects_exact_docker_overlay() -> None:
    result = _construct(RuntimeProduct.DOCKER, GpuMode.ON)

    assert result.acceleration.effective is EffectiveProfile.DOCKER_GPU
    assert result.acceleration.overlay_logical_name == "compose.gpu.yaml"
    assert result.ordered_compose_logical_names == (
        "compose.yaml",
        "compose.gpu.yaml",
    )


def test_podman_on_selects_exact_podman_overlay() -> None:
    result = _construct(RuntimeProduct.PODMAN, GpuMode.ON)

    assert result.acceleration.effective is EffectiveProfile.PODMAN_GPU
    assert result.acceleration.overlay_logical_name == "compose.gpu.podman.yaml"
    assert result.ordered_compose_logical_names == (
        "compose.yaml",
        "compose.gpu.podman.yaml",
    )


@pytest.mark.parametrize("product", list(RuntimeProduct))
def test_on_rejects_cpu_package(product: RuntimeProduct) -> None:
    with pytest.raises(RuntimeAccelerationInputError) as raised:
        _construct(
            product,
            GpuMode.ON,
            flavor=PackageComputeFlavor.CPU,
            ready=True,
        )

    assert (
        raised.value.code is RuntimeAccelerationInputErrorCode.ACCELERATION_UNAVAILABLE
    )


@pytest.mark.parametrize("product", list(RuntimeProduct))
def test_on_rejects_missing_engine_gpu_capability(product: RuntimeProduct) -> None:
    with pytest.raises(RuntimeAccelerationInputError) as raised:
        _construct(product, GpuMode.ON, ready=False)

    assert (
        raised.value.code is RuntimeAccelerationInputErrorCode.ACCELERATION_UNAVAILABLE
    )


@pytest.mark.parametrize(
    ("flavor", "gate", "ready", "gpu_expected"),
    [
        (PackageComputeFlavor.CUDA126, True, True, True),
        (PackageComputeFlavor.CUDA126, False, True, False),
        (PackageComputeFlavor.CUDA126, True, False, False),
        (PackageComputeFlavor.CPU, True, True, False),
    ],
)
@pytest.mark.parametrize("product", list(RuntimeProduct))
def test_auto_requires_package_gate_cuda_and_capability(
    product: RuntimeProduct,
    flavor: PackageComputeFlavor,
    gate: bool,
    ready: bool,
    gpu_expected: bool,
) -> None:
    result = _construct(
        product,
        GpuMode.AUTO,
        flavor=flavor,
        gate=gate,
        ready=ready,
    )

    assert (result.acceleration.effective is not EffectiveProfile.CPU) is gpu_expected


def test_rejects_engine_mismatch_before_selecting_overlay() -> None:
    docker_runtime = _runtime(RuntimeProduct.DOCKER)
    docker_endpoint = _endpoint(RuntimeProduct.DOCKER)
    podman_runtime = _runtime(RuntimeProduct.PODMAN)
    podman_endpoint = _endpoint(RuntimeProduct.PODMAN)

    with pytest.raises(RuntimeAccelerationInputError) as raised:
        construct_runtime_acceleration_inputs(
            package=_package(RuntimeProduct.DOCKER, GpuMode.ON),
            capability=_capability(
                RuntimeProduct.PODMAN,
                podman_runtime,
                podman_endpoint,
                ready=True,
            ),
            runtime=docker_runtime,
            endpoint=docker_endpoint,
            process_environment_items=_environment_items(),
        )

    assert raised.value.code is RuntimeAccelerationInputErrorCode.ENGINE_MISMATCH


def test_rejects_capability_bound_to_different_runtime_or_endpoint() -> None:
    runtime = _runtime(RuntimeProduct.DOCKER)
    endpoint = _endpoint(RuntimeProduct.DOCKER)
    capability = replace(
        _capability(RuntimeProduct.DOCKER, runtime, endpoint, ready=True),
        endpoint_private_metadata_sha256=_DIGEST_A,
    )

    with pytest.raises(RuntimeAccelerationInputError) as raised:
        construct_runtime_acceleration_inputs(
            package=_package(RuntimeProduct.DOCKER, GpuMode.ON),
            capability=capability,
            runtime=runtime,
            endpoint=endpoint,
            process_environment_items=_environment_items(),
        )

    assert raised.value.code is RuntimeAccelerationInputErrorCode.CAPABILITY_INVALID


def test_rejects_direct_engine_overlay_mismatch() -> None:
    environment = construct_windows_process_environment(_environment_items())

    with pytest.raises(ValueError, match="Runtime acceleration inputs are invalid"):
        RuntimeAccelerationInputs(
            process_environment=environment,
            acceleration=AccelerationPlan(
                requested=GpuMode.ON,
                effective=EffectiveProfile.DOCKER_GPU,
                overlay_logical_name="compose.gpu.podman.yaml",
            ),
            ordered_compose_logical_names=(
                "compose.yaml",
                "compose.gpu.yaml",
            ),
            package_binding_sha256=_DIGEST_D,
            capability_evidence_sha256=_DIGEST_E,
        )


def test_private_paths_and_hashes_do_not_reflect_in_representations() -> None:
    product = RuntimeProduct.PODMAN
    runtime = _runtime(product)
    endpoint = _endpoint(product)
    package = _package(product, GpuMode.AUTO)
    capability = _capability(product, runtime, endpoint, ready=True)
    result = construct_runtime_acceleration_inputs(
        package=package,
        capability=capability,
        runtime=runtime,
        endpoint=endpoint,
        process_environment_items=_environment_items(),
    )

    rendered = " ".join((repr(package), repr(capability), repr(result), str(result)))
    assert "operator" not in rendered
    assert _DIGEST_D not in rendered
    assert _DIGEST_E not in rendered


def test_module_is_source_only_and_does_not_read_ambient_state() -> None:
    source = Path(
        "launcher/towerscout_launcher/runtime_acceleration_inputs.py"
    ).read_text(encoding="utf-8")

    assert "import os" not in source
    assert "subprocess" not in source
    assert "runtime_execution" not in source
    assert "runtime_target_plan" not in source
    assert "runtime_target_observation" not in source
    assert "from .repair import" not in source
