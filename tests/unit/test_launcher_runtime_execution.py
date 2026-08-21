from __future__ import annotations

import hashlib
import inspect
import sys
from types import SimpleNamespace
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_execution as runtime_execution  # noqa: E402
from towerscout_launcher.runtime_execution import (  # noqa: E402
    BindingErrorCode,
    CommandKind,
    ComposeReadOperation,
    EngineReadOperation,
    ProcessCommandPlan,
    RuntimeExecutionBinding,
    RuntimeExecutionBindingError,
    sanitized_environment,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    ABSENT_FILE_SHA256,
    EXPECTED_VOLUME_DESTINATIONS,
    AccelerationPlan,
    CertificateIdentity,
    ComposeInvocationKind,
    ComposePlan,
    ComposeProviderIdentity,
    ContainerIdentity,
    EffectiveProfile,
    EndpointBindingKind,
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    GpuMode,
    ImageIdentity,
    MapProvider,
    ResolvedRepairTarget,
    RuntimeIdentity,
    RuntimeProduct,
    VolumeIdentity,
    WindowsProcessEnvironment,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=Path(path),
        volume_serial=4000 + marker,
        file_id=marker.to_bytes(16, "big"),
        sha256=_digest(f"file-{marker}"),
        size_bytes=1000 + marker,
    )


def _directory(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=Path(path),
        volume_serial=5000 + marker,
        file_id=marker.to_bytes(16, "big"),
        is_directory=True,
    )


def _target(
    product: RuntimeProduct,
    *,
    endpoint_override: str | None = None,
    runtime_file: FileIdentity | None = None,
    provider_artifacts: tuple[FileIdentity, ...] | None = None,
) -> tuple[ResolvedRepairTarget, FileIdentity | None, FileIdentity | None]:
    private_root = r"C:\Users\PRIVATE-USER\TowerScout"
    package_root = _directory("package_root", private_root, 1)
    process_environment = WindowsProcessEnvironment(
        system_root=_directory("system_root", r"C:\Windows", 30),
        temp_directory=_directory(
            "temp_directory", r"C:\Users\PRIVATE-USER\AppData\Local\Temp", 31
        ),
        user_profile=_directory("user_profile", r"C:\Users\PRIVATE-USER", 32),
        local_app_data=_directory(
            "local_app_data", r"C:\Users\PRIVATE-USER\AppData\Local", 33
        ),
        roaming_app_data=_directory(
            "roaming_app_data", r"C:\Users\PRIVATE-USER\AppData\Roaming", 34
        ),
    )
    compose_file = _file("compose.yaml", private_root + r"\compose.yaml", 2)

    if product is RuntimeProduct.DOCKER:
        runtime_file = runtime_file or _file(
            "docker.exe", r"C:\Program Files\Docker\bin\docker.exe", 3
        )
        endpoint_value = endpoint_override or "npipe:////./pipe/docker_engine"
        endpoint_kind = EndpointKind.DOCKER_NAMED_PIPE
        provider_artifacts = provider_artifacts or (
            _file(
                "docker-compose.exe",
                r"C:\Program Files\Docker\bin\docker-compose.exe",
                4,
            ),
        )
        invocation_kind = ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE
        endpoint_binding = EndpointBindingKind.DOCKER_HOST_ARGUMENT
        python = None
        identity_key = None
        discovery_artifacts = (
            _file(
                "docker_context_metadata",
                r"C:\Users\PRIVATE-USER\.docker\contexts\meta.json",
                40,
            ),
        )
    else:
        runtime_file = runtime_file or _file(
            "podman.exe", r"C:\Program Files\RedHat\Podman\podman.exe", 5
        )
        endpoint_value = endpoint_override or (
            "ssh://core@127.0.0.1:51999/run/user/1000/podman/podman.sock"
        )
        endpoint_kind = EndpointKind.PODMAN_ROOTLESS_WSL
        python = _file(
            "python.exe",
            r"C:\TowerScout\providers\.venv\Scripts\python.exe",
            6,
        )
        module = _file(
            "podman_compose_module",
            r"C:\TowerScout\providers\.venv\Lib\site-packages\podman_compose.py",
            7,
        )
        provider_artifacts = provider_artifacts or (python, module)
        invocation_kind = ComposeInvocationKind.PODMAN_PYTHON_MODULE
        endpoint_binding = EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT
        identity_key = _file(
            "podman_identity_key",
            r"C:\Users\PRIVATE-USER\.local\share\containers\podman\machine\machine",
            8,
        )
        discovery_artifacts = (
            _file(
                "podman_connection_metadata",
                r"C:\Users\PRIVATE-USER\.config\containers\connections.json",
                41,
            ),
        )

    runtime = RuntimeIdentity(
        product=product,
        executable=runtime_file,
        version="6.0.2" if product is RuntimeProduct.PODMAN else "29.7.2",
        publisher_policy_sha256=_digest("runtime publisher policy"),
    )
    endpoint = EndpointIdentity(
        product=product,
        kind=endpoint_kind,
        canonical_endpoint=endpoint_value,
        private_metadata_sha256=_digest("private endpoint metadata"),
        identity_key=identity_key,
        discovery_artifacts=discovery_artifacts,
        rootless=product is RuntimeProduct.PODMAN,
    )
    compose_provider = ComposeProviderIdentity(
        provider_id=(
            "podman-compose@1.5.0"
            if product is RuntimeProduct.PODMAN
            else "docker-compose@5.3.1"
        ),
        invocation_kind=invocation_kind,
        endpoint_binding=endpoint_binding,
        artifacts=provider_artifacts,
        integrity_sha256=_digest("provider integrity"),
    )
    environment_file = _file(".env", private_root + r"\.env", 9)
    environment_file = replace(
        environment_file,
        sha256=_digest("environment"),
    )
    compose = ComposePlan(
        ordered_files=(compose_file,),
        environment_sha256=_digest("environment"),
        planned_environment_sha256=_digest("planned environment"),
        pre_model_sha256=_digest("pre model"),
        post_model_sha256=_digest("post model"),
        environment_source=environment_file,
        environment_file=environment_file,
    )
    image_digest = "sha256:" + "a" * 64
    image = ImageIdentity(
        configured_reference="ghcr.io/example/towerscout@" + image_digest,
        pinned_digest=image_digest,
        repository_digest="ghcr.io/example/towerscout@" + image_digest,
        daemon_image_id=image_digest,
        private_inspect_sha256=_digest("image inspect"),
    )
    container = ContainerIdentity(
        container_id="7" * 64,
        container_name="towerscout-runtime-binding",
        daemon_image_id=image_digest,
        private_inspect_sha256=_digest("container inspect"),
    )
    volumes = tuple(
        VolumeIdentity(
            logical_name=logical_name,
            runtime_name=f"runtime-binding-{logical_name}",
            destination=destination,
            private_inspect_sha256=_digest(f"volume-{index}"),
        )
        for index, (logical_name, destination) in enumerate(
            EXPECTED_VOLUME_DESTINATIONS, start=1
        )
    )
    target = ResolvedRepairTarget(
        package_root=package_root,
        process_environment=process_environment,
        release_identity="v0.1.3-test",
        runtime=runtime,
        endpoint=endpoint,
        compose_provider=compose_provider,
        compose=compose,
        compose_project="towerscout-test",
        service="towerscout",
        acceleration=AccelerationPlan(
            requested=GpuMode.OFF,
            effective=EffectiveProfile.CPU,
        ),
        provider=MapProvider.GOOGLE,
        port=5000,
        image=image,
        container=container,
        volumes=volumes,
        certificate=CertificateIdentity(
            provider=MapProvider.GOOGLE,
            windows_root_fingerprint_sha256=_digest("root fingerprint"),
            candidate_content_sha256=_digest("candidate content"),
        ),
    )
    return target, python, identity_key


def test_docker_plans_bind_direct_executables_and_exact_named_pipe():
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    assert target.compose.environment_file is not None
    binding = RuntimeExecutionBinding(target)

    engine = binding.engine_command(EngineReadOperation.VERSION_JSON)
    compose = binding.compose_command(ComposeReadOperation.CONFIG)

    assert engine.kind is CommandKind.DOCKER_ENGINE
    assert engine.command == (
        str(target.runtime.executable.final_path),
        "--host",
        target.endpoint.canonical_endpoint,
        "version",
        "--format",
        "json",
    )
    assert compose.kind is CommandKind.DOCKER_COMPOSE
    assert compose.command == (
        str(target.compose_provider.artifacts[0].final_path),
        "--host",
        target.endpoint.canonical_endpoint,
        "--project-name",
        target.compose_project,
        "--project-directory",
        str(target.package_root.final_path),
        "--file",
        str(target.compose.ordered_files[0].final_path),
        "--env-file",
        str(target.compose.environment_file.final_path),
        "config",
        "--format",
        "json",
    )
    assert Path(compose.command[0]).name.casefold() == "docker-compose.exe"
    assert "docker.exe" not in tuple(
        Path(argument).name.casefold() for argument in compose.command
    )
    assert engine.environment == compose.environment
    assert set(engine.environment) == {
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    }
    assert engine.shell is compose.shell is False
    assert engine.working_directory == target.package_root.final_path
    assert compose.working_directory == target.package_root.final_path
    assert all(
        artifact in engine.authenticated_files
        and artifact in compose.authenticated_files
        for artifact in target.endpoint.discovery_artifacts
    )


def test_podman_plans_bind_exact_url_key_python_module_and_child_endpoint():
    target, python, identity_key = _target(RuntimeProduct.PODMAN)
    assert (
        python is not None
        and identity_key is not None
        and target.compose.environment_file is not None
    )
    binding = RuntimeExecutionBinding(target)

    engine = binding.engine_command(EngineReadOperation.INFO_JSON)
    compose = binding.compose_command(ComposeReadOperation.CONFIG)

    assert engine.kind is CommandKind.PODMAN_ENGINE
    assert engine.command == (
        str(target.runtime.executable.final_path),
        "--url",
        target.endpoint.canonical_endpoint,
        "--identity",
        str(identity_key.final_path),
        "info",
        "--format",
        "json",
    )
    assert compose.kind is CommandKind.PODMAN_COMPOSE
    assert compose.command == (
        str(python.final_path),
        "-I",
        "-m",
        "podman_compose",
        "--podman-path",
        str(target.runtime.executable.final_path),
        "-p",
        target.compose_project,
        "-f",
        str(target.compose.ordered_files[0].final_path),
        "--env-file",
        str(target.compose.environment_file.final_path),
        "config",
    )
    assert compose.environment == {
        "SYSTEMROOT": str(target.process_environment.system_root.final_path),
        "WINDIR": str(target.process_environment.system_root.final_path),
        "TEMP": str(target.process_environment.temp_directory.final_path),
        "TMP": str(target.process_environment.temp_directory.final_path),
        "USERPROFILE": str(target.process_environment.user_profile.final_path),
        "LOCALAPPDATA": str(target.process_environment.local_app_data.final_path),
        "APPDATA": str(target.process_environment.roaming_app_data.final_path),
        "COMPOSE_PROJECT_DIR": str(target.package_root.final_path),
        "CONTAINER_HOST": target.endpoint.canonical_endpoint,
        "CONTAINER_SSHKEY": str(identity_key.final_path),
    }
    assert compose.environment["CONTAINER_HOST"] == engine.command[2]
    assert compose.environment["CONTAINER_SSHKEY"] == engine.command[4]
    assert compose.command[5] == engine.command[0]
    assert "connection" not in compose.command
    assert compose.command[compose.command.index("--env-file") + 1] == str(
        target.compose.environment_file.final_path
    )
    assert compose.shell is False
    assert compose.working_directory == target.package_root.final_path
    assert identity_key in engine.authenticated_files
    assert identity_key in compose.authenticated_files
    assert all(
        artifact in engine.authenticated_files
        and artifact in compose.authenticated_files
        for artifact in target.endpoint.discovery_artifacts
    )


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_absent_root_env_uses_authenticated_template_instead_of_auto_discovery(
    product: RuntimeProduct,
):
    target, _python, _identity_key = _target(product)
    template = _file(
        ".env.example",
        str(target.package_root.final_path / ".env.example"),
        42,
    )
    absent = replace(
        target,
        compose=replace(
            target.compose,
            environment_file=None,
            environment_sha256=ABSENT_FILE_SHA256,
            environment_source=template,
        ),
    )

    plan = RuntimeExecutionBinding(absent).compose_command(ComposeReadOperation.CONFIG)

    assert "--env-file" in plan.command
    assert plan.command[plan.command.index("--env-file") + 1] == str(
        template.final_path
    )
    assert template in plan.authenticated_files


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_ambient_redirect_environment_is_discarded(product: RuntimeProduct):
    target, python, identity_key = _target(product)
    binding = RuntimeExecutionBinding(target)
    plan = binding.compose_command(ComposeReadOperation.CONFIG)
    hostile_ambient = {
        "PATH": r"C:\attacker",
        "DOCKER_HOST": "tcp://attacker.invalid:2375",
        "DOCKER_CONTEXT": "attacker",
        "COMPOSE_FILE": r"C:\attacker\compose.yaml",
        "COMPOSE_PATH_SEPARATOR": ";",
        "PODMAN_CONNECTIONS_CONF": r"C:\attacker\connections.json",
        "PODMAN_COMPOSE_PROVIDER": r"C:\attacker\provider.cmd",
        "CONTAINER_HOST": "ssh://root@attacker.invalid/run/podman.sock",
        "CONTAINER_SSHKEY": r"C:\attacker\key",
        "PYTHONPATH": r"C:\attacker\python",
        "PYTHONHOME": r"C:\attacker\home",
        "SSL_CERT_FILE": r"C:\attacker\root.pem",
        "REQUESTS_CA_BUNDLE": r"C:\attacker\root.pem",
    }

    sanitized = sanitized_environment(plan, hostile_ambient)

    assert sanitized == plan.environment
    for key, hostile_value in hostile_ambient.items():
        if key in sanitized:
            assert sanitized[key] != hostile_value
    if product is RuntimeProduct.PODMAN:
        assert set(sanitized) == {
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            "COMPOSE_PROJECT_DIR",
            "CONTAINER_HOST",
            "CONTAINER_SSHKEY",
        }
        assert sanitized["CONTAINER_HOST"] == target.endpoint.canonical_endpoint
        assert sanitized["CONTAINER_SSHKEY"] == str(identity_key.final_path)
    else:
        assert set(sanitized) == {
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        }


def test_endpoint_switching_requires_a_new_bound_target():
    first, python, identity_key = _target(RuntimeProduct.PODMAN)
    second_endpoint = "ssh://core@127.0.0.1:52000/run/user/1000/podman/podman.sock"
    second, second_python, second_key = _target(
        RuntimeProduct.PODMAN, endpoint_override=second_endpoint
    )
    assert python is not None and identity_key is not None
    assert second_python is not None and second_key is not None

    first_plan = RuntimeExecutionBinding(first).compose_command(
        ComposeReadOperation.CONFIG
    )
    second_plan = RuntimeExecutionBinding(second).compose_command(
        ComposeReadOperation.CONFIG
    )

    assert first_plan.environment["CONTAINER_HOST"] == first.endpoint.canonical_endpoint
    assert second_plan.environment["CONTAINER_HOST"] == second_endpoint
    assert first_plan.target_token != second_plan.target_token
    assert second_endpoint not in first_plan.command
    assert second_endpoint not in first_plan.environment.values()

    tampered_environment = tuple(
        (key, second_endpoint if key == "CONTAINER_HOST" else value)
        for key, value in first_plan.environment_items
    )
    with pytest.raises(RuntimeExecutionBindingError) as plan_error:
        replace(first_plan, environment_items=tampered_environment)
    assert plan_error.value.code is BindingErrorCode.PLAN_REJECTED


def test_podman_identity_key_path_and_content_are_target_token_inputs() -> None:
    target, _python, identity_key = _target(RuntimeProduct.PODMAN)
    assert identity_key is not None
    changed_key = replace(
        identity_key,
        final_path=Path(r"C:\Users\OTHER\.local\share\containers\podman\key"),
        sha256=_digest("changed identity key"),
    )
    changed = replace(
        target,
        endpoint=replace(target.endpoint, identity_key=changed_key),
    )

    assert changed.target_token != target.target_token


def test_plan_reconstruction_cannot_restore_an_ambient_redirect_variable():
    target, python, identity_key = _target(RuntimeProduct.PODMAN)
    assert python is not None and identity_key is not None
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)

    with pytest.raises(RuntimeExecutionBindingError) as exc_info:
        replace(
            plan,
            environment_items=plan.environment_items
            + (("DOCKER_HOST", "tcp://attacker.invalid:2375"),),
        )

    assert exc_info.value.code is BindingErrorCode.PLAN_REJECTED
    assert "attacker" not in str(exc_info.value)


def test_environment_sanitizer_rejects_duck_typed_hostile_object() -> None:
    hostile = SimpleNamespace(environment={"PATH": r"C:\attacker"})

    with pytest.raises(RuntimeExecutionBindingError) as failure:
        sanitized_environment(hostile)  # type: ignore[arg-type]
    assert failure.value.code is BindingErrorCode.PLAN_REJECTED


def test_plan_reconstruction_rejects_string_subclass_with_hostile_value() -> None:
    class HostileArgument(str):
        def __new__(cls):
            return super().__new__(cls, "--attacker-switch")

        def __eq__(self, _other):
            return True

        __hash__ = str.__hash__

    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    plan = RuntimeExecutionBinding(target).engine_command(
        EngineReadOperation.VERSION_JSON
    )

    with pytest.raises(RuntimeExecutionBindingError) as failure:
        replace(plan, arguments=(HostileArgument(), *plan.arguments[1:]))

    assert failure.value.code is BindingErrorCode.PLAN_REJECTED


def test_plan_reconstruction_rejects_environment_tuple_subclass() -> None:
    class HostileEnvironment(tuple):
        pass

    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    plan = RuntimeExecutionBinding(target).engine_command(
        EngineReadOperation.VERSION_JSON
    )

    with pytest.raises(RuntimeExecutionBindingError) as failure:
        replace(
            plan,
            environment_items=HostileEnvironment(plan.environment_items),
        )

    assert failure.value.code is BindingErrorCode.PLAN_REJECTED


def test_environment_sanitizer_rejects_process_plan_subclass() -> None:
    class HostilePlan(ProcessCommandPlan):
        @property
        def environment(self):
            return {"PATH": r"C:\attacker"}

    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    plan = RuntimeExecutionBinding(target).engine_command(
        EngineReadOperation.VERSION_JSON
    )
    hostile = HostilePlan(
        kind=plan.kind,
        target=plan.target,
        executable=plan.executable,
        arguments=plan.arguments,
        environment_items=plan.environment_items,
        authenticated_files=plan.authenticated_files,
    )

    with pytest.raises(RuntimeExecutionBindingError) as failure:
        sanitized_environment(hostile)

    assert failure.value.code is BindingErrorCode.PLAN_REJECTED


def test_plan_reconstruction_cannot_drop_or_replace_authenticated_input() -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)

    with pytest.raises(RuntimeExecutionBindingError) as missing:
        replace(plan, authenticated_files=plan.authenticated_files[:-1])
    assert missing.value.code is BindingErrorCode.PLAN_REJECTED

    replacement = replace(
        plan.authenticated_files[-1],
        file_id=(999).to_bytes(16, "big"),
    )
    with pytest.raises(RuntimeExecutionBindingError) as changed:
        replace(
            plan,
            authenticated_files=(*plan.authenticated_files[:-1], replacement),
        )
    assert changed.value.code is BindingErrorCode.PLAN_REJECTED


@pytest.mark.parametrize(
    "operation",
    [
        ("ps", "--host=tcp://attacker.invalid:2375"),
        ("ps", "-Htcp://attacker.invalid:2375"),
        ("ps", "--context", "attacker"),
        ("ps", "--connection=attacker"),
        ("info", "--url", "ssh://root@attacker.invalid/run/podman.sock"),
        ("info", "--identity=C:\\attacker\\key"),
        ("config", "--podman-path", r"C:\attacker\podman.exe"),
        ("config", "--project-directory", r"C:\attacker"),
        ("config", "--file", r"C:\attacker\compose.yaml"),
        ("config", r"-fC:\attacker\compose.yaml"),
        ("config", "-p", "attacker"),
        ("config", "-pattacker"),
        ("-c", "attacker", "version"),
        ("--podman-args=-c attacker", "config"),
        ("--podman-volume-args=--url ssh://root@attacker", "config"),
        ("down", "--volumes"),
    ],
)
def test_operation_cannot_override_bound_endpoint_provider_or_compose_inputs(
    operation: tuple[str, ...],
):
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    binding = RuntimeExecutionBinding(target)

    with pytest.raises(RuntimeExecutionBindingError) as exc_info:
        binding.compose_command(operation)  # type: ignore[arg-type]

    assert exc_info.value.code is BindingErrorCode.OPERATION_REJECTED
    assert "attacker" not in str(exc_info.value)
    assert "attacker" not in repr(exc_info.value)


@pytest.mark.parametrize(
    "operation",
    [
        ("exec", "cmd.exe"),
        ("exec", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        ("exec", "pwsh"),
        ("exec", "/bin/sh"),
        ("ps", "value|malicious"),
        ("ps", "$(malicious)"),
        ("ps", "`malicious`"),
    ],
)
def test_operation_cannot_delegate_to_shell_cmd_or_powershell(
    operation: tuple[str, ...],
):
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)

    with pytest.raises(RuntimeExecutionBindingError) as exc_info:
        RuntimeExecutionBinding(target).engine_command(operation)  # type: ignore[arg-type]

    assert exc_info.value.code is BindingErrorCode.OPERATION_REJECTED


def test_podman_python_and_module_must_be_distinct_bound_provider_artifacts():
    target, python, identity_key = _target(RuntimeProduct.PODMAN)
    assert python is not None and identity_key is not None
    duplicate_module = replace(
        python,
        logical_name="podman_compose_module",
    )

    with pytest.raises(ValueError, match="distinct"):
        replace(
            target.compose_provider,
            artifacts=(python, duplicate_module),
        )


def test_command_wrappers_and_indirect_compose_entrypoints_are_rejected():
    bad_runtime = _file("podman.exe", r"C:\Program Files\RedHat\Podman\podman.cmd", 90)
    target, python, identity_key = _target(
        RuntimeProduct.PODMAN, runtime_file=bad_runtime
    )
    assert python is not None and identity_key is not None
    with pytest.raises(RuntimeExecutionBindingError) as runtime_error:
        RuntimeExecutionBinding(target)
    assert runtime_error.value.code is BindingErrorCode.EXECUTABLE_REJECTED

    bad_compose = _file(
        "docker-compose.exe", r"C:\Program Files\Docker\docker-compose.cmd", 91
    )
    docker, _python, _key = _target(
        RuntimeProduct.DOCKER, provider_artifacts=(bad_compose,)
    )
    with pytest.raises(RuntimeExecutionBindingError) as provider_error:
        RuntimeExecutionBinding(docker)
    assert provider_error.value.code is BindingErrorCode.EXECUTABLE_REJECTED


def test_plans_and_bindings_are_immutable_and_repr_is_sanitized():
    target, python, identity_key = _target(RuntimeProduct.PODMAN)
    assert python is not None and identity_key is not None
    binding = RuntimeExecutionBinding(target)
    plan = binding.compose_command(ComposeReadOperation.CONFIG)

    with pytest.raises(FrozenInstanceError):
        plan.arguments = ("malicious",)  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        binding.target = target  # type: ignore[misc]

    rendered = repr(binding) + repr(plan)
    for private_value in (
        str(target.package_root.final_path),
        target.endpoint.canonical_endpoint,
        str(target.runtime.executable.final_path),
        str(python.final_path),
        str(identity_key.final_path),
    ):
        assert private_value not in rendered
    assert target.target_token.display in rendered


def test_module_is_plan_only_and_has_no_process_or_path_resolution_calls():
    source = inspect.getsource(runtime_execution)

    assert "import subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
    assert ".resolve(" not in source
    assert "Path.cwd" not in source
    assert "shutil.which" not in source
