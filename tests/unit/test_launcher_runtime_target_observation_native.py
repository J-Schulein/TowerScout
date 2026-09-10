from __future__ import annotations

import hashlib
import ntpath
import struct
import sys
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, Callable

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_command_native import (  # noqa: E402
    NativeWindowsTargetObservationCommandBackend,
    _NativeProcess,
)
import towerscout_launcher.runtime_target_observation_native as native_module  # noqa: E402
from towerscout_launcher.runtime_command_version import (  # noqa: E402
    CommandExecutionError,
    CommandExecutionErrorCode,
)
from towerscout_launcher.runtime_dynamic_load import (  # noqa: E402
    ProviderChildEnforcementEvidence,
    TargetObservationProviderChildCommandResult,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.runtime_provider_child import (  # noqa: E402
    ProcessImageBinding,
    ProcessImagePolicy,
    ProcessImageRole,
    TargetObservationProviderChildProcessRequest,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    OBSERVATION_CA_DESTINATION,
    ObservationOperation,
    TargetObservationExecutionBinding,
    TargetObservationProcessPlan,
    TargetObservationProcessRequest,
)
from towerscout_launcher.runtime_target_observation_backend import (  # noqa: E402
    TargetObservationAdapterError,
    TargetObservationAdapterErrorCode,
    TargetObservationProcessResult,
)
from towerscout_launcher.runtime_target_observation_native import (  # noqa: E402
    HeldTargetObservationAuthority,
    NativeWindowsTargetObservationExecutor,
    TargetObservationNativeError,
    TargetObservationNativeErrorCode,
    capture_native_windows_target_observation_backend,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    TargetResolutionPlan,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
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
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    PathTrustPurpose,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    FileSnapshot,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
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


def _plan(product: RuntimeProduct) -> TargetResolutionPlan:
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
        configured_image_reference=("ghcr.io/example/towerscout@sha256:" + "a" * 64),
        pinned_image_digest="sha256:" + "a" * 64,
        certificate=CertificateIdentity(
            provider=MapProvider.GOOGLE,
            windows_root_fingerprint_sha256="b" * 64,
            candidate_content_sha256="c" * 64,
        ),
    )


def _snapshot(identity: FileIdentity) -> FileSnapshot:
    return FileSnapshot(
        identity=StableFileIdentity(identity.volume_serial, identity.file_id),
        sha256=identity.sha256,
        size=identity.size_bytes,
        attributes=0,
        creation_time=1,
        last_write_time=2,
        reparse_tag=0,
        final_path=str(identity.final_path),
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=True,
            regular_file=True,
            single_link=True,
        ),
    )


class _HeldFile:
    def __init__(self, identity: FileIdentity) -> None:
        self.snapshot = _snapshot(identity)
        self.closed = False
        self.active = False
        self.close_calls = 0

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert self.closed is False
        assert self.active is False
        self.active = True
        try:
            return operation()
        finally:
            self.active = False

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


class _HeldPath:
    def __init__(self, identity: FileIdentity, purpose: PathTrustPurpose) -> None:
        self.root_snapshot = SimpleNamespace(
            identity=StableFileIdentity(identity.volume_serial, identity.file_id),
            final_path=str(identity.final_path),
        )
        self.evidence = SimpleNamespace(purpose=purpose)
        self.closed = False
        self.active = False
        self.close_calls = 0

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert self.closed is False
        assert self.active is False
        self.active = True
        try:
            return operation()
        finally:
            self.active = False

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


class _RuntimeInventory:
    def __init__(self, executable: _HeldFile) -> None:
        self.executable = executable
        self.closed = False
        self.active = False
        self.close_calls = 0

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert self.closed is False
        assert self.active is False
        self.active = True
        try:
            return self.executable.run_while_held(operation)
        finally:
            self.active = False

    def active_process_image_policy(self, role: ProcessImageRole) -> ProcessImagePolicy:
        assert self.active is True
        return ProcessImagePolicy(
            role,
            (
                ProcessImageBinding.from_snapshot(
                    self.executable.snapshot, entrypoint=True
                ),
            ),
            ("kernel32.dll",),
        )

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


class _ProviderInventory:
    def __init__(self, entrypoint: _HeldFile) -> None:
        self.entrypoint = entrypoint
        self.closed = False
        self.active = False
        self.close_calls = 0

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert self.closed is False
        assert self.active is False
        self.active = True
        try:
            return self.entrypoint.run_while_held(operation)
        finally:
            self.active = False

    def active_process_image_policy(
        self,
        role: ProcessImageRole,
        *,
        entrypoint: _HeldFile,
    ) -> ProcessImagePolicy:
        assert self.active is True
        return ProcessImagePolicy(
            role,
            (ProcessImageBinding.from_snapshot(entrypoint.snapshot, entrypoint=True),),
            ("kernel32.dll",),
        )

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


def _resources(plan: TargetResolutionPlan) -> tuple[
    HeldTargetObservationAuthority,
    list[_HeldFile],
    list[_HeldPath],
    list[_RuntimeInventory],
    _ProviderInventory | None,
]:
    identities = (
        TargetObservationExecutionBinding(plan).container_list().authenticated_files
    )
    entrypoint_identities = (
        plan.runtime.executable,
        plan.compose_provider.artifacts[0],
    )
    entrypoints = [_HeldFile(identity) for identity in entrypoint_identities]
    general_identities = tuple(
        identity
        for identity in identities
        if not identity.is_directory and identity not in entrypoint_identities
    )
    files = [_HeldFile(identity) for identity in general_identities]
    directory_identities = tuple(
        identity for identity in identities if identity.is_directory
    )
    paths = [
        _HeldPath(
            identity,
            (
                PathTrustPurpose.PACKAGE_ROOT
                if identity is plan.package_root
                else PathTrustPurpose.PROCESS_ENVIRONMENT
            ),
        )
        for identity in directory_identities
    ]
    inventories = [_RuntimeInventory(entrypoints[0])]
    provider: _ProviderInventory | None = None
    if plan.runtime.product is RuntimeProduct.DOCKER:
        inventories.append(_RuntimeInventory(entrypoints[1]))
    else:
        provider_base = _HeldFile(_file("python.exe", r"C:\Python312\python.exe", 88))
        entrypoints.append(provider_base)
        provider = _ProviderInventory(provider_base)
    authority = HeldTargetObservationAuthority(
        plan=plan,
        general_file_identities=general_identities,
        general_files=tuple(files),
        directory_identities=directory_identities,
        directory_paths=tuple(paths),
        entrypoint_handles=tuple(entrypoints),
        runtime_inventories=tuple(inventories),
        provider_inventory=provider,
        provider_entrypoint=(
            entrypoints[1] if plan.runtime.product is RuntimeProduct.PODMAN else None
        ),
    )
    return authority, [*entrypoints, *files], paths, inventories, provider


class _CommandBackend:
    supported = True

    def __init__(self) -> None:
        self.calls: list[TargetObservationProcessRequest] = []

    def execute(
        self, request: TargetObservationProcessRequest
    ) -> TargetObservationProcessResult:
        self.calls.append(request)
        return TargetObservationProcessResult.from_plan(
            request.plan,
            stdout=b"{}",
            stderr=b"private",
            exit_code=0,
            provider_child_claimed=False,
        )


class _ProviderBackend:
    supported = True

    def __init__(self) -> None:
        self.calls: list[TargetObservationProcessPlan] = []

    def execute_observation(
        self,
        plan: TargetObservationProcessPlan,
        provider_policy: ProcessImagePolicy,
        child_policy: ProcessImagePolicy,
    ) -> TargetObservationProviderChildCommandResult:
        self.calls.append(plan)
        request = TargetObservationProviderChildProcessRequest.from_plan(plan)
        enforcement = ProviderChildEnforcementEvidence(
            request_binding_sha256=request.binding_sha256,
            provider_policy_sha256=provider_policy.content_sha256,
            child_policy_sha256=child_policy.content_sha256,
            system_directory_identity=StableFileIdentity(99, b"s" * 16),
            provider_image_count=1,
            child_image_count=1,
            child_process_count=1,
            exact_inventory_image_count=2,
            system32_image_count=0,
            active_process_limit=2,
            debug_process_tree=True,
            provider_dynamic_code_prohibited=True,
            root_alive_during_child=True,
            unexpected_processes_denied=True,
            event_file_handles_closed=True,
            arbitrary_dynamic_destinations_denied=True,
            image_sequence_sha256=_digest("images"),
        )
        command = TargetObservationProcessResult.from_plan(
            plan,
            stdout=b"services: {}",
            stderr=b"private",
            exit_code=0,
            provider_child_claimed=True,
            provider_child_claim_sha256=enforcement.evidence_sha256,
        )
        return TargetObservationProviderChildCommandResult(command, enforcement)


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_process_request_wraps_only_the_validated_plan(product: RuntimeProduct) -> None:
    process = TargetObservationExecutionBinding(
        product_plan := _plan(product)
    ).container_list()
    request = TargetObservationProcessRequest.from_plan(process)

    assert request.plan is process
    assert request.executable_path == process.executable.final_path
    assert request.arguments == process.arguments
    assert request.environment == tuple(
        sorted(process.environment_items, key=lambda item: item[0].casefold())
    )
    assert request.working_directory == product_plan.package_root.final_path
    assert "PRIVATE-PATH" not in repr(request)

    with pytest.raises(Exception):
        TargetObservationProcessRequest(object())  # type: ignore[arg-type]


def test_provider_request_is_bound_to_each_exact_podman_compose_plan() -> None:
    binding = TargetObservationExecutionBinding(_plan(RuntimeProduct.PODMAN))
    current = TargetObservationProviderChildProcessRequest.from_plan(
        binding.compose_model(planned=False)
    )
    planned = TargetObservationProviderChildProcessRequest.from_plan(
        binding.compose_model(planned=True)
    )

    assert current.binding_sha256 != planned.binding_sha256
    assert current.authority_sha256 == planned.authority_sha256
    assert "REQUESTS_CA_BUNDLE" not in dict(current.environment)
    assert dict(planned.environment)["REQUESTS_CA_BUNDLE"] == OBSERVATION_CA_DESTINATION
    assert "PRIVATE-PATH" not in repr(current)

    docker = TargetObservationExecutionBinding(
        _plan(RuntimeProduct.DOCKER)
    ).compose_model(planned=False)
    engine = binding.container_list()
    for rejected in (docker, engine):
        with pytest.raises(ValueError):
            TargetObservationProviderChildProcessRequest.from_plan(rejected)


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_authority_holds_every_owner_for_the_complete_callback(
    product: RuntimeProduct,
) -> None:
    plan = _plan(product)
    authority, files, paths, inventories, provider = _resources(plan)

    def inspect() -> str:
        assert authority.active is True
        assert all(item.active for item in files)
        assert all(item.active for item in paths)
        assert all(item.active for item in inventories)
        if provider is not None:
            assert provider.active is True
        return "complete"

    assert authority.run_while_held(inspect) == "complete"
    assert authority.active is False
    authority.close()
    assert authority.closed is True
    assert all(
        getattr(item, "closed") is True for item in (*files, *paths, *inventories)
    )
    if provider is not None:
        assert provider.closed is True


def test_authority_preserves_a_process_failure_after_revalidation() -> None:
    authority, *_resources_value = _resources(_plan(RuntimeProduct.DOCKER))

    def fail() -> None:
        raise TargetObservationAdapterError(
            TargetObservationAdapterErrorCode.PROCESS_FAILED
        )

    with pytest.raises(TargetObservationAdapterError) as captured:
        authority.run_while_held(fail)
    assert captured.value.code is TargetObservationAdapterErrorCode.PROCESS_FAILED
    authority.close()


def test_executor_routes_podman_compose_only_through_provider_child_evidence() -> None:
    plan = _plan(RuntimeProduct.PODMAN)
    authority, *_resources_value = _resources(plan)
    command = _CommandBackend()
    provider = _ProviderBackend()
    executor = NativeWindowsTargetObservationExecutor(
        plan=plan,
        authority=authority,
        command_backend=command,
        provider_backend=provider,
    )
    binding = TargetObservationExecutionBinding(plan)

    compose_result, engine_result = authority.run_while_held(
        lambda: (
            executor.execute(binding.compose_model(planned=True)),
            executor.execute(binding.container_list()),
        )
    )

    assert compose_result.provider_child_claimed is True
    assert engine_result.provider_child_claimed is False
    assert len(provider.calls) == 1
    assert len(command.calls) == 1
    executor.close()
    authority.close()


def test_executor_rejects_use_outside_the_authority_lease() -> None:
    plan = _plan(RuntimeProduct.DOCKER)
    authority, *_resources_value = _resources(plan)
    executor = NativeWindowsTargetObservationExecutor(
        plan=plan,
        authority=authority,
        command_backend=_CommandBackend(),
        provider_backend=_ProviderBackend(),
    )

    with pytest.raises(TargetObservationNativeError) as captured:
        executor.execute(TargetObservationExecutionBinding(plan).container_list())
    assert captured.value.code is TargetObservationNativeErrorCode.AUTHORITY_CHANGED
    executor.close()
    authority.close()


class _ProcessApi:
    supported = True

    def __init__(self, stdout: bytes) -> None:
        self.streams = {3: bytearray(stdout), 4: bytearray(b"private stderr")}
        self.request: Any = None
        self.closed = 0

    def start(self, request: Any, **_kwargs: Any) -> _NativeProcess:
        self.request = request
        return _NativeProcess(1, 2, 3, 4)

    def read_file(self, handle: int, maximum: int) -> bytes:
        stream = self.streams[handle]
        chunk = bytes(stream[:maximum])
        del stream[:maximum]
        return chunk

    def wait_process(self, _process: int, _milliseconds: int) -> bool:
        return True

    def exit_code(self, _process: int) -> int:
        return 0

    def active_processes(self, _job: int) -> int:
        return 0

    def terminate_job(self, _job: int) -> None:
        return None

    def close_process(self, _process: _NativeProcess) -> None:
        self.closed += 1

    def windows_directory(self) -> str:
        return r"C:\Windows"

    def system_directory(self) -> str:
        return r"C:\Windows\System32"

    def user_profile_directory(self) -> str:
        return r"C:\Users\PRIVATE-PATH"


class _Clock:
    def monotonic(self) -> float:
        return 0.0

    def wait(self, _seconds: float) -> None:
        return None


def test_native_command_backend_preserves_observation_output_budget() -> None:
    plan = _plan(RuntimeProduct.DOCKER)
    process = TargetObservationExecutionBinding(plan).compose_model(planned=False)
    stdout = b"x" * (70 * 1024)
    api = _ProcessApi(stdout)
    backend = NativeWindowsTargetObservationCommandBackend(api=api, clock=_Clock())

    result = backend.execute(TargetObservationProcessRequest.from_plan(process))

    assert result.stdout == stdout
    assert result.provider_child_claimed is False
    assert api.request.plan is process
    assert api.closed == 1


def test_native_command_backend_denies_podman_compose_bypass() -> None:
    plan = _plan(RuntimeProduct.PODMAN)
    process = TargetObservationExecutionBinding(plan).compose_model(planned=False)
    api = _ProcessApi(b"services: {}")
    backend = NativeWindowsTargetObservationCommandBackend(api=api, clock=_Clock())

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(TargetObservationProcessRequest.from_plan(process))
    assert captured.value.code is CommandExecutionErrorCode.UNAVAILABLE
    assert api.request is None


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_factory_captures_each_plan_identity_and_transfers_cleanup(
    product: RuntimeProduct,
) -> None:
    plan = _plan(product)
    files: list[tuple[FileIdentity, bool, _HeldFile]] = []
    paths: list[_HeldPath] = []
    inventories: list[tuple[RuntimeProductId, _RuntimeInventory]] = []
    provider_inventories: list[_ProviderInventory] = []
    provider_bases: list[_HeldFile] = []
    verified_entrypoints: list[
        tuple[RuntimeProductId, FileIdentity, str | None, _HeldFile]
    ] = []

    def capture_file(identity: FileIdentity, entrypoint: bool) -> _HeldFile:
        held = _HeldFile(identity)
        files.append((identity, entrypoint, held))
        return held

    def capture_path(identity: FileIdentity, purpose: PathTrustPurpose) -> _HeldPath:
        held = _HeldPath(identity, purpose)
        paths.append(held)
        return held

    def capture_runtime(
        product_id: RuntimeProductId, handle: _HeldFile
    ) -> _RuntimeInventory:
        held = _RuntimeInventory(handle)
        inventories.append((product_id, held))
        return held

    def capture_provider(_handle: _HeldFile) -> _ProviderInventory:
        held = _ProviderInventory(_handle)
        provider_inventories.append(held)
        return held

    def capture_provider_base() -> _HeldFile:
        held = _HeldFile(_file("python.exe", r"C:\Python312\python.exe", 88))
        provider_bases.append(held)
        return held

    def capture_verified_entrypoint(
        product_id: RuntimeProductId,
        identity: FileIdentity,
        expected_version: str | None,
    ) -> _HeldFile:
        held = _HeldFile(identity)
        verified_entrypoints.append((product_id, identity, expected_version, held))
        return held

    backend = capture_native_windows_target_observation_backend(
        plan,
        command_backend=_CommandBackend(),
        provider_backend=_ProviderBackend(),
        _file_capture=capture_file,
        _path_capture=capture_path,
        _runtime_capture=capture_runtime,
        _provider_capture=capture_provider,
        _provider_base_capture=capture_provider_base,
        _verified_entrypoint_capture=capture_verified_entrypoint,
    )

    expected = (
        TargetObservationExecutionBinding(plan).container_list().authenticated_files
    )
    assert len(files) + len(paths) + len(verified_entrypoints) == len(expected)
    assert sum(entrypoint for _identity, entrypoint, _held in files) == 0
    assert [item[0] for item in verified_entrypoints] == (
        [RuntimeProductId.DOCKER_CLI, RuntimeProductId.DOCKER_COMPOSE]
        if product is RuntimeProduct.DOCKER
        else [RuntimeProductId.PODMAN_CLI]
    )
    assert verified_entrypoints[0][2] == plan.runtime.version
    if product is RuntimeProduct.DOCKER:
        assert verified_entrypoints[1][2] is None
    assert [item[0] for item in inventories] == (
        [RuntimeProductId.DOCKER_CLI, RuntimeProductId.DOCKER_COMPOSE]
        if product is RuntimeProduct.DOCKER
        else [RuntimeProductId.PODMAN_CLI]
    )
    assert len(provider_inventories) == (0 if product is RuntimeProduct.DOCKER else 1)
    assert len(provider_bases) == (0 if product is RuntimeProduct.DOCKER else 1)

    backend.close()
    assert backend.closed is True
    assert all(held.closed for _identity, _entrypoint, held in files)
    assert all(path.closed for path in paths)
    assert all(inventory.closed for _product, inventory in inventories)
    assert all(inventory.closed for inventory in provider_inventories)
    assert all(handle.closed for handle in provider_bases)
    assert all(item[3].closed for item in verified_entrypoints)


def test_factory_rejects_a_verified_entrypoint_that_does_not_match_plan() -> None:
    plan = _plan(RuntimeProduct.DOCKER)
    wrong = _HeldFile(_file("docker.exe", r"C:\Unapproved\docker.exe", 99))

    with pytest.raises(TargetObservationNativeError) as captured:
        capture_native_windows_target_observation_backend(
            plan,
            command_backend=_CommandBackend(),
            provider_backend=_ProviderBackend(),
            _verified_entrypoint_capture=(lambda _product, _identity, _version: wrong),
        )

    assert captured.value.code is TargetObservationNativeErrorCode.BINDING_INVALID
    assert wrong.closed is True


def test_default_capture_accepts_an_empty_env_with_a_positive_read_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_env = FileIdentity(
        logical_name=".env",
        final_path=PureWindowsPath(r"C:\Users\PRIVATE-PATH\TowerScout\.env"),
        volume_serial=2099,
        file_id=(99).to_bytes(16, "big"),
        sha256=hashlib.sha256(b"").hexdigest(),
        size_bytes=0,
    )
    captured: list[tuple[Path, Any, Any]] = []

    def capture(path: Path, *, api: Any, policy: Any) -> _HeldFile:
        captured.append((path, api, policy))
        return _HeldFile(empty_env)

    monkeypatch.setattr(native_module, "capture_handle_bound_file", capture)

    held = native_module._capture_file_default(  # noqa: SLF001
        empty_env,
        entrypoint=False,
        file_api=None,
    )

    assert held.snapshot.size == 0
    assert captured[0][0] == Path(str(empty_env.final_path))
    assert captured[0][2].max_bytes == 1
    assert captured[0][2].require_single_link is True


def test_provider_request_path_digest_is_canonical_and_private() -> None:
    plan = _plan(RuntimeProduct.PODMAN)
    process = TargetObservationExecutionBinding(plan).compose_model(planned=False)
    request = TargetObservationProviderChildProcessRequest.from_plan(process)
    digest = hashlib.sha256()
    canonical = ntpath.normcase(ntpath.normpath(str(process.executable.final_path)))
    for value in (
        b"TowerScout.ProviderChildImagePath.v1",
        canonical.encode("utf-16-le"),
    ):
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)

    assert len(request.binding_sha256) == 64
    assert digest.hexdigest() not in repr(request)
    assert str(process.executable.final_path) not in repr(request)


def test_native_observation_remains_unwired_and_yaml_is_hash_locked() -> None:
    for relative in ("app.py", "discovery.py", "repair.py"):
        source = (LAUNCHER_ROOT / "towerscout_launcher" / relative).read_text(
            encoding="utf-8"
        )
        assert "runtime_target_observation_native" not in source

    requirements = (LAUNCHER_ROOT / "requirements-build.txt").read_text(
        encoding="utf-8"
    )
    assert "pyyaml-6.0.3-cp312-cp312-win_amd64.whl" in requirements
    assert (
        "sha256=5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b"
        in requirements
    )
    spec = (LAUNCHER_ROOT / "TowerScoutLauncher.spec").read_text(encoding="utf-8")
    assert '"yaml"' in spec
