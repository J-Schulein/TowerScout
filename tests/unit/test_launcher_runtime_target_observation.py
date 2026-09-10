from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    OBSERVATION_CA_DESTINATION,
    OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES,
    OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES,
    OBSERVATION_LIST_STDOUT_LIMIT_BYTES,
    ObservationOperation,
    TargetObservationBindingError,
    TargetObservationBindingErrorCode,
    TargetObservationExecutionBinding,
    TargetObservationProcessPlan,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    TargetResolutionPlan,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    CONTAINER_BUNDLE_DESTINATION,
    EXPECTED_VOLUME_DESTINATIONS,
    AccelerationPlan,
    CertificateIdentity,
    ComposeInvocationKind,
    ComposeProviderIdentity,
    EffectiveProfile,
    EndpointBindingKind,
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    GpuMode,
    MapProvider,
    RuntimeIdentity,
    RuntimeProduct,
    SecurityArtifactInventory,
    WindowsProcessEnvironment,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _directory(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=1000 + marker,
        file_id=marker.to_bytes(16, "big"),
        is_directory=True,
    )


def _file(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=2000 + marker,
        file_id=marker.to_bytes(16, "big"),
        sha256=_digest(f"file-{marker}"),
        size_bytes=100 + marker,
    )


def _plan(product: RuntimeProduct = RuntimeProduct.DOCKER) -> TargetResolutionPlan:
    root = PureWindowsPath(r"C:\Users\PRIVATE-PATH\TowerScout")
    package_root = _directory("package_root", str(root), 1)
    process_environment = WindowsProcessEnvironment(
        system_root=_directory("system_root", r"C:\Windows", 50),
        temp_directory=_directory(
            "temp_directory", r"C:\Users\PRIVATE-PATH\AppData\Local\Temp", 51
        ),
        user_profile=_directory("user_profile", r"C:\Users\PRIVATE-PATH", 52),
        local_app_data=_directory(
            "local_app_data", r"C:\Users\PRIVATE-PATH\AppData\Local", 53
        ),
        roaming_app_data=_directory(
            "roaming_app_data", r"C:\Users\PRIVATE-PATH\AppData\Roaming", 54
        ),
    )
    runtime_leaf = "docker.exe" if product is RuntimeProduct.DOCKER else "podman.exe"
    runtime = RuntimeIdentity(
        product=product,
        executable=_file(runtime_leaf, rf"C:\Program Files\Runtime\{runtime_leaf}", 2),
        version="29.5.3" if product is RuntimeProduct.DOCKER else "6.0.2",
        publisher_policy_sha256=_digest("runtime-policy"),
    )
    if product is RuntimeProduct.DOCKER:
        endpoint = EndpointIdentity(
            product=product,
            kind=EndpointKind.DOCKER_NAMED_PIPE,
            canonical_endpoint="npipe:////./pipe/dockerDesktopLinuxEngine",
            private_metadata_sha256=_digest("docker-daemon"),
            discovery_artifacts=(
                _file(
                    "docker_context_metadata",
                    r"C:\Users\PRIVATE-PATH\.docker\contexts\meta.json",
                    7,
                ),
            ),
        )
        provider = ComposeProviderIdentity(
            provider_id="docker-compose-v2",
            invocation_kind=ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE,
            endpoint_binding=EndpointBindingKind.DOCKER_HOST_ARGUMENT,
            artifacts=(
                _file(
                    "docker-compose.exe",
                    r"C:\Program Files\Docker\docker-compose.exe",
                    3,
                ),
            ),
            integrity_sha256=_digest("docker-compose-integrity"),
        )
    else:
        key = _file(
            "podman_identity_key",
            r"C:\Users\PRIVATE-PATH\.ssh\podman-machine-default",
            4,
        )
        endpoint = EndpointIdentity(
            product=product,
            kind=EndpointKind.PODMAN_ROOTLESS_WSL,
            canonical_endpoint=(
                "ssh://core@127.0.0.1:54321/run/user/1000/podman/podman.sock"
            ),
            private_metadata_sha256=_digest("podman-endpoint"),
            identity_key=key,
            discovery_artifacts=(
                _file(
                    "podman_connections_config",
                    r"C:\Users\PRIVATE-PATH\.config\containers\connections.json",
                    7,
                ),
            ),
            rootless=True,
        )
        provider = ComposeProviderIdentity(
            provider_id="podman-compose-pypi-1.5.0",
            invocation_kind=ComposeInvocationKind.PODMAN_PYTHON_MODULE,
            endpoint_binding=EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
            artifacts=(
                _file(
                    "python.exe",
                    r"C:\TowerScoutProvider\.venv\Scripts\python.exe",
                    5,
                ),
                _file(
                    "podman_compose_module",
                    (
                        r"C:\TowerScoutProvider\.venv\Lib\site-packages"
                        r"\podman_compose.py"
                    ),
                    6,
                ),
            ),
            integrity_sha256=_digest("podman-compose-integrity"),
        )
    environment = _file(".env", str(root / ".env"), 12)
    security = SecurityArtifactInventory(
        release_manifest=_file(
            "release-manifest.v1.json", str(root / "release-manifest.v1.json"), 20
        ),
        runtime_policy=_file(
            "runtime-policy.v1.json",
            str(root / "launcher" / "towerscout_launcher" / "runtime-policy.v1.json"),
            21,
        ),
        runtime_dependency_policy=_file(
            "runtime-dependency-policy.v1.json",
            str(
                root
                / "launcher"
                / "towerscout_launcher"
                / "runtime-dependency-policy.v1.json"
            ),
            22,
        ),
    )
    return TargetResolutionPlan(
        package_root=package_root,
        process_environment=process_environment,
        release_identity="v0.1.3-preview.test",
        security_artifacts=security,
        runtime=runtime,
        endpoint=endpoint,
        compose_provider=provider,
        ordered_compose_files=(_file("compose.yaml", str(root / "compose.yaml"), 10),),
        environment_sha256=environment.sha256,
        planned_environment_sha256=_digest("planned environment"),
        environment_source=environment,
        environment_file=environment,
        compose_project="towerscout-private",
        acceleration=AccelerationPlan(GpuMode.OFF, EffectiveProfile.CPU, ""),
        provider=MapProvider.GOOGLE,
        port=5000,
        configured_image_reference=("ghcr.io/j-schulein/towerscout@sha256:" + "a" * 64),
        pinned_image_digest="sha256:" + "a" * 64,
        certificate=CertificateIdentity(
            provider=MapProvider.GOOGLE,
            windows_root_fingerprint_sha256="b" * 64,
            candidate_content_sha256="c" * 64,
        ),
    )


def _keys(plan: TargetResolutionPlan) -> tuple[str, ...]:
    return tuple(
        identity.logical_name
        for identity in (
            plan.runtime.executable,
            *plan.compose_provider.artifacts,
            *plan.ordered_compose_files,
            plan.environment_source,
            *plan.security_artifacts.ordered_files,
            plan.package_root,
            plan.process_environment.system_root,
            plan.process_environment.temp_directory,
            plan.process_environment.user_profile,
            plan.process_environment.local_app_data,
            plan.process_environment.roaming_app_data,
            *((plan.endpoint.identity_key,) if plan.endpoint.identity_key else ()),
            *plan.endpoint.discovery_artifacts,
        )
    )


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_compose_reads_bind_exact_provider_files_endpoint_and_environment(
    product: RuntimeProduct,
) -> None:
    plan = _plan(product)
    binding = TargetObservationExecutionBinding(plan)

    current = binding.compose_model(planned=False)
    planned = binding.compose_model(planned=True)

    assert current.operation is ObservationOperation.COMPOSE_MODEL_CURRENT
    assert planned.operation is ObservationOperation.COMPOSE_MODEL_PLANNED
    assert current.shell is False
    assert current.stdin_closed is True
    assert current.working_directory == plan.package_root.final_path
    assert current.authority_sha256 == plan.authority_sha256
    assert tuple(item.logical_name for item in current.authenticated_files) == tuple(
        dict.fromkeys(_keys(plan))
    )
    assert "PATH" not in current.environment
    assert "PATHEXT" not in current.environment
    assert "HTTP_PROXY" not in current.environment
    assert "DOCKER_HOST" not in current.environment
    assert "REQUESTS_CA_BUNDLE" not in current.environment
    assert "SSL_CERT_FILE" not in current.environment
    assert planned.environment["REQUESTS_CA_BUNDLE"] == OBSERVATION_CA_DESTINATION
    assert planned.environment["SSL_CERT_FILE"] == OBSERVATION_CA_DESTINATION
    assert OBSERVATION_CA_DESTINATION == CONTAINER_BUNDLE_DESTINATION
    assert set(planned.environment) - set(current.environment) == {
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    }
    command = current.command
    assert command[0] == str(plan.compose_provider.artifacts[0].final_path)
    if product is RuntimeProduct.DOCKER:
        assert str(plan.package_root.final_path) in command
    else:
        assert current.environment["COMPOSE_PROJECT_DIR"] == str(
            plan.package_root.final_path
        )
    assert str(plan.environment_source.final_path) in command
    assert all(str(item.final_path) in command for item in plan.ordered_compose_files)
    if product is RuntimeProduct.DOCKER:
        assert command[1:3] == ("--host", plan.endpoint.canonical_endpoint)
        assert command[-3:] == ("config", "--format", "json")
    else:
        assert command[1:4] == ("-I", "-m", "podman_compose")
        assert current.environment["CONTAINER_HOST"] == plan.endpoint.canonical_endpoint
        assert current.environment["CONTAINER_SSHKEY"] == str(
            plan.endpoint.identity_key.final_path  # type: ignore[union-attr]
        )
        assert command[-1] == "config"


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_container_list_is_exact_read_only_and_endpoint_bound(
    product: RuntimeProduct,
) -> None:
    plan = _plan(product)
    request = TargetObservationExecutionBinding(plan).container_list()

    assert request.operation is ObservationOperation.CONTAINER_LIST
    assert request.selector is None
    assert request.command[0] == str(plan.runtime.executable.final_path)
    assert "--all" in request.command
    assert "--quiet" in request.command
    assert "towerscout-private" in " ".join(request.command)
    assert not (
        {"start", "stop", "restart", "rm", "create", "run"} & set(request.command)
    )
    if product is RuntimeProduct.DOCKER:
        assert request.command[1:3] == ("--host", plan.endpoint.canonical_endpoint)
        assert "label=com.docker.compose.project=towerscout-private" in request.command
    else:
        assert request.command[1:5] == (
            "--url",
            plan.endpoint.canonical_endpoint,
            "--identity",
            str(plan.endpoint.identity_key.final_path),  # type: ignore[union-attr]
        )
        assert "label=io.podman.compose.project=towerscout-private" in request.command


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_exact_container_image_and_all_volume_inspection_plans(
    product: RuntimeProduct,
) -> None:
    plan = _plan(product)
    binding = TargetObservationExecutionBinding(plan)
    container_id = "d" * 64
    image_id = "sha256:" + "e" * 64

    container = binding.container_inspect(container_id)
    image = binding.image_inspect(image_id)
    volumes = binding.volume_inspects()

    assert container.operation is ObservationOperation.CONTAINER_INSPECT
    assert container.command[-3:] == ("container", "inspect", container_id)
    assert image.operation is ObservationOperation.IMAGE_INSPECT
    assert image.command[-3:] == ("image", "inspect", image_id)
    assert tuple(item.operation for item in volumes) == (
        ObservationOperation.VOLUME_INSPECT,
    ) * len(EXPECTED_VOLUME_DESTINATIONS)
    assert tuple(item.selector for item in volumes) == tuple(
        f"{plan.compose_project}_{logical_name}"
        for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
    )
    assert all(item.command[-3:-1] == ("volume", "inspect") for item in volumes)
    assert container.stdout_limit_bytes == OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    assert image.stdout_limit_bytes == OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    assert all(
        item.stdout_limit_bytes == OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
        for item in volumes
    )


def test_compose_plan_copies_are_immutable_and_planned_arguments_do_not_change() -> (
    None
):
    binding = TargetObservationExecutionBinding(_plan(RuntimeProduct.PODMAN))
    current = binding.compose_model(planned=False)
    planned = binding.compose_model(planned=True)

    current_environment = current.environment
    current_environment["PATH"] = r"C:\attacker"

    assert current.arguments == planned.arguments
    assert current.authenticated_files == planned.authenticated_files
    assert current.stdout_limit_bytes == OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES
    assert "PATH" not in current.environment
    assert "PATH" not in planned.environment


def test_container_list_uses_the_smaller_output_budget() -> None:
    request = TargetObservationExecutionBinding(_plan()).container_list()

    assert request.stdout_limit_bytes == OBSERVATION_LIST_STDOUT_LIMIT_BYTES
    assert request.stdout_limit_bytes < OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES


def test_compose_plan_rejects_aggregate_windows_command_over_limit() -> None:
    plan = _plan()
    long_root = PureWindowsPath("C:\\" + "x" * 11_000)
    package_root = _directory("package_root", str(long_root), 60)
    compose_file = _file("compose.yaml", str(long_root / "compose.yaml"), 61)
    environment = _file(".env", str(long_root / ".env"), 62)
    plan = replace(
        plan,
        package_root=package_root,
        ordered_compose_files=(compose_file,),
        environment_sha256=environment.sha256,
        environment_source=environment,
        environment_file=environment,
    )

    with pytest.raises(TargetObservationBindingError) as caught:
        TargetObservationExecutionBinding(plan).compose_model(planned=False)

    assert caught.value.code is TargetObservationBindingErrorCode.PLAN_REJECTED


def test_engine_plan_rejects_aggregate_windows_environment_over_limit() -> None:
    plan = _plan()
    process_environment = WindowsProcessEnvironment(
        system_root=_directory("system_root", "C:\\" + "s" * 5_000, 70),
        temp_directory=_directory("temp_directory", "C:\\" + "t" * 5_000, 71),
        user_profile=_directory("user_profile", "C:\\" + "u" * 5_000, 72),
        local_app_data=_directory("local_app_data", "C:\\" + "l" * 5_000, 73),
        roaming_app_data=_directory("roaming_app_data", "C:\\" + "r" * 5_000, 74),
    )
    plan = replace(plan, process_environment=process_environment)

    with pytest.raises(TargetObservationBindingError) as caught:
        TargetObservationExecutionBinding(plan).container_list()

    assert caught.value.code is TargetObservationBindingErrorCode.PLAN_REJECTED


def test_compose_planned_flag_requires_an_exact_boolean() -> None:
    binding = TargetObservationExecutionBinding(_plan())

    with pytest.raises(TargetObservationBindingError) as caught:
        binding.compose_model(planned=1)  # type: ignore[arg-type]

    assert caught.value.code is TargetObservationBindingErrorCode.OPERATION_REJECTED


@pytest.mark.parametrize(
    ("factory", "selector"),
    [
        ("container_inspect", "short-id"),
        ("container_inspect", "d" * 63),
        ("container_inspect", "d" * 64 + "x"),
        ("image_inspect", "e" * 64),
        ("image_inspect", "sha256:" + "E" * 64),
        ("image_inspect", "sha256:" + "e" * 63),
    ],
)
def test_dynamic_engine_selectors_are_strict(factory: str, selector: str) -> None:
    binding = TargetObservationExecutionBinding(_plan())

    with pytest.raises(TargetObservationBindingError) as caught:
        getattr(binding, factory)(selector)

    assert caught.value.code is TargetObservationBindingErrorCode.SELECTOR_REJECTED


def test_volume_inspection_rejects_noncanonical_logical_name() -> None:
    binding = TargetObservationExecutionBinding(_plan())

    with pytest.raises(TargetObservationBindingError) as caught:
        binding.volume_inspect("../towerscout_config")

    assert caught.value.code is TargetObservationBindingErrorCode.SELECTOR_REJECTED


def test_process_plan_rejects_argument_environment_and_identity_tampering() -> None:
    request = TargetObservationExecutionBinding(_plan()).container_list()
    baseline = {
        "operation": request.operation,
        "target": request.target,
        "executable": request.executable,
        "arguments": request.arguments,
        "environment_items": request.environment_items,
        "authenticated_files": request.authenticated_files,
        "selector": request.selector,
        "timeout_ms": request.timeout_ms,
        "stdout_limit_bytes": request.stdout_limit_bytes,
        "stderr_limit_bytes": request.stderr_limit_bytes,
        "stdin_closed": request.stdin_closed,
        "shell": request.shell,
    }
    cases = (
        {"arguments": (*request.arguments, "--latest")},
        {"arguments": ("safe",) * 129},
        {"environment_items": (*request.environment_items, ("PATH", "C:\\x"))},
        {"environment_items": tuple((f"SAFE_{index}", "x") for index in range(33))},
        {"authenticated_files": request.authenticated_files[:-1]},
        {"executable": request.authenticated_files[-1]},
        {"stdout_limit_bytes": request.stdout_limit_bytes + 1},
        {"stdin_closed": False},
        {"shell": True},
    )

    for changes in cases:
        with pytest.raises(TargetObservationBindingError) as caught:
            TargetObservationProcessPlan(**(baseline | changes))  # type: ignore[arg-type]
        assert caught.value.code is TargetObservationBindingErrorCode.PLAN_REJECTED


def test_binding_and_process_plan_repr_hide_private_values() -> None:
    plan = _plan(RuntimeProduct.PODMAN)
    binding = TargetObservationExecutionBinding(plan)
    request = binding.compose_model(planned=True)

    combined = repr(binding) + repr(request)
    assert "PRIVATE-PATH" not in combined
    assert plan.endpoint.canonical_endpoint not in combined
    assert plan.authority_sha256 not in combined
    assert OBSERVATION_CA_DESTINATION not in combined
    assert "<redacted>" in combined


def test_binding_rejects_non_plan_and_does_not_import_live_launcher_modules() -> None:
    with pytest.raises(TargetObservationBindingError) as caught:
        TargetObservationExecutionBinding(object())  # type: ignore[arg-type]

    assert caught.value.code is TargetObservationBindingErrorCode.TARGET_MISMATCH
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_target_observation.py"
    ).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "from .repair" not in source
    assert "from .discovery" not in source
    assert "from .app" not in source
