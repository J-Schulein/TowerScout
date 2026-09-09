from __future__ import annotations

import hashlib
import sys
import threading
from dataclasses import FrozenInstanceError, replace
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_dynamic_load as dynamic_module  # noqa: E402
import towerscout_launcher.runtime_dependency_capture as dependency_module  # noqa: E402
from towerscout_launcher.runtime_command_native import _NativeProcess  # noqa: E402
from towerscout_launcher.runtime_dependency_capture import (  # noqa: E402
    HeldCpythonDependencyInventory,
)
from towerscout_launcher.runtime_dynamic_load import (  # noqa: E402
    DebugEvent,
    DebugEventKind,
    DynamicLoadEnforcementError,
    DynamicLoadEnforcementErrorCode,
    NativeWindowsProviderChildDynamicLoadBackend,
)
from towerscout_launcher.runtime_execution import (  # noqa: E402
    ComposeReadOperation,
    RuntimeExecutionBinding,
)
from towerscout_launcher.runtime_load_trust import (  # noqa: E402
    RuntimeLoadPrerequisites,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.runtime_provider_child import (  # noqa: E402
    ProcessImageBinding,
    ProcessImagePolicy,
    ProcessImageRole,
    ProviderChildProcessRequest,
)
from towerscout_launcher.runtime_provider_inventory import (  # noqa: E402
    HeldProviderChildInventory,
    ProviderChildInventoryError,
    ProviderChildInventoryErrorCode,
)
from towerscout_launcher.runtime_transaction_inventory import (  # noqa: E402
    HeldRuntimeTransactionInventory,
    RuntimeTransactionInventoryError,
    RuntimeTransactionInventoryErrorCode,
    capture_runtime_transaction_inventory,
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
    SecurityArtifactInventory,
    VolumeIdentity,
    WindowsProcessEnvironment,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    KNOWN_CLOUD_REPARSE_TAGS,
    NativeFileFacts,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
    WindowsSecurityError,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    DirectoryTrustSnapshot,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathHierarchyEvidence,
    PathHierarchyTrust,
    PathTrustPurpose,
)

_SYSTEM32 = PureWindowsPath(r"C:\Windows\System32")
_PROVIDER = PureWindowsPath(r"C:\TowerScout\tools\provider\.venv\Scripts\python.exe")
_BASE_PYTHON = PureWindowsPath(r"C:\Python312\python.exe")
_PROVIDER_DLL = PureWindowsPath(r"C:\Python312\python312.dll")
_PODMAN = PureWindowsPath(r"C:\Program Files\RedHat\Podman\podman.exe")
_PODMAN_DLL = PureWindowsPath(r"C:\Program Files\RedHat\Podman\helper.dll")
_KERNEL32 = _SYSTEM32 / "kernel32.dll"
_NTDLL = _SYSTEM32 / "ntdll.dll"
_ATTACKER = PureWindowsPath(r"C:\Users\Public\attacker.exe")


def _snapshot(path: str, marker: int) -> FileSnapshot:
    content = path.encode("utf-8")
    return FileSnapshot(
        identity=StableFileIdentity(71, marker.to_bytes(16, "big")),
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        attributes=0x80,
        creation_time=1,
        last_write_time=2,
        reparse_tag=0,
        final_path=rf"\\?\{path}",
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=True,
            regular_file=True,
            single_link=False,
        ),
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file(logical_name: str, path: PureWindowsPath, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=path,
        volume_serial=71,
        file_id=marker.to_bytes(16, "big"),
        sha256=_digest(str(path)),
        size_bytes=len(str(path).encode("utf-8")),
    )


def _directory(logical_name: str, path: str, marker: int) -> FileIdentity:
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(path),
        volume_serial=71,
        file_id=marker.to_bytes(16, "big"),
        is_directory=True,
    )


def _podman_target() -> ResolvedRepairTarget:
    package_root = _directory("package_root", r"C:\TowerScout", 20)
    python = _file("python.exe", _PROVIDER, 1)
    module = _file(
        "podman_compose_module",
        PureWindowsPath(
            r"C:\TowerScout\tools\provider\.venv\Lib\site-packages\podman_compose.py"
        ),
        8,
    )
    runtime = _file("podman.exe", _PODMAN, 3)
    identity_key = _file(
        "podman_identity_key",
        PureWindowsPath(r"C:\Users\private\.config\containers\podman-machine-key"),
        4,
    )
    compose_file = _file(
        "compose.yaml", PureWindowsPath(r"C:\TowerScout\compose.yaml"), 5
    )
    environment_file = _file(".env", PureWindowsPath(r"C:\TowerScout\.env"), 6)
    image_digest = "sha256:" + "a" * 64
    return ResolvedRepairTarget(
        package_root=package_root,
        process_environment=WindowsProcessEnvironment(
            system_root=_directory("system_root", r"C:\Windows", 21),
            temp_directory=_directory(
                "temp_directory", r"C:\Users\private\AppData\Local\Temp", 22
            ),
            user_profile=_directory("user_profile", r"C:\Users\private", 23),
            local_app_data=_directory(
                "local_app_data", r"C:\Users\private\AppData\Local", 24
            ),
            roaming_app_data=_directory(
                "roaming_app_data", r"C:\Users\private\AppData\Roaming", 25
            ),
        ),
        release_identity="v0.1.3-test",
        security_artifacts=SecurityArtifactInventory(
            release_manifest=_file(
                "release-manifest.v1.json",
                PureWindowsPath(r"C:\TowerScout\release-manifest.v1.json"),
                26,
            ),
            runtime_policy=_file(
                "runtime-policy.v1.json",
                PureWindowsPath(
                    r"C:\TowerScout\launcher\_internal\towerscout_launcher\runtime-policy.v1.json"
                ),
                27,
            ),
            runtime_dependency_policy=_file(
                "runtime-dependency-policy.v1.json",
                PureWindowsPath(
                    r"C:\TowerScout\launcher\_internal\towerscout_launcher\runtime-dependency-policy.v1.json"
                ),
                28,
            ),
        ),
        runtime=RuntimeIdentity(
            RuntimeProduct.PODMAN,
            runtime,
            "6.0.2",
            _digest("runtime-policy"),
        ),
        endpoint=EndpointIdentity(
            product=RuntimeProduct.PODMAN,
            kind=EndpointKind.PODMAN_ROOTLESS_WSL,
            canonical_endpoint=(
                "ssh://core@127.0.0.1:51999/run/user/1000/podman/podman.sock"
            ),
            private_metadata_sha256=_digest("endpoint"),
            identity_key=identity_key,
            rootless=True,
        ),
        compose_provider=ComposeProviderIdentity(
            provider_id="podman-compose@1.5.0",
            invocation_kind=ComposeInvocationKind.PODMAN_PYTHON_MODULE,
            endpoint_binding=EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
            artifacts=(python, module),
            integrity_sha256=_digest("provider"),
        ),
        compose=ComposePlan(
            ordered_files=(compose_file,),
            environment_sha256=environment_file.sha256,
            planned_environment_sha256=_digest("planned-environment"),
            pre_model_sha256=_digest("pre-model"),
            post_model_sha256=_digest("post-model"),
            environment_source=environment_file,
            environment_file=environment_file,
        ),
        compose_project="towerscout-test",
        service="towerscout",
        acceleration=AccelerationPlan(GpuMode.OFF, EffectiveProfile.CPU),
        provider=MapProvider.GOOGLE,
        port=5000,
        image=ImageIdentity(
            configured_reference="ghcr.io/example/towerscout@" + image_digest,
            pinned_digest=image_digest,
            repository_digest="ghcr.io/example/towerscout@" + image_digest,
            daemon_image_id=image_digest,
            private_inspect_sha256=_digest("image"),
        ),
        container=ContainerIdentity(
            container_id="7" * 64,
            container_name="towerscout-test",
            daemon_image_id=image_digest,
            private_inspect_sha256=_digest("container"),
        ),
        volumes=tuple(
            VolumeIdentity(
                logical_name=name,
                runtime_name=f"towerscout-test-{name}",
                destination=destination,
                private_inspect_sha256=_digest(name),
            )
            for name, destination in EXPECTED_VOLUME_DESTINATIONS
        ),
        certificate=CertificateIdentity(
            provider=MapProvider.GOOGLE,
            windows_root_fingerprint_sha256=_digest("root"),
            candidate_content_sha256=_digest("candidate"),
        ),
    )


def _plan_and_policies() -> tuple[
    ProviderChildProcessRequest,
    ProcessImagePolicy,
    ProcessImagePolicy,
]:
    target = _podman_target()
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)
    request = ProviderChildProcessRequest.from_plan(plan)
    provider_policy = ProcessImagePolicy(
        ProcessImageRole.PROVIDER,
        (
            ProcessImageBinding.from_snapshot(
                _snapshot(str(_PROVIDER), 1), entrypoint=True
            ),
            ProcessImageBinding.from_snapshot(
                _snapshot(str(_PROVIDER_DLL), 2), entrypoint=False
            ),
        ),
        ("kernel32.dll", "ntdll.dll"),
    )
    child_policy = ProcessImagePolicy(
        ProcessImageRole.RUNTIME_CHILD,
        (
            ProcessImageBinding.from_snapshot(
                _snapshot(str(_PODMAN), 3), entrypoint=True
            ),
            ProcessImageBinding.from_snapshot(
                _snapshot(str(_PODMAN_DLL), 4), entrypoint=False
            ),
        ),
        ("kernel32.dll", "ntdll.dll"),
    )
    return request, provider_policy, child_policy


def test_provider_and_child_image_policies_are_distinct_immutable_bindings() -> None:
    provider = ProcessImageBinding.from_snapshot(
        _snapshot(r"C:\TowerScout\provider\.venv\Scripts\python.exe", 1),
        entrypoint=True,
    )
    child = ProcessImageBinding.from_snapshot(
        _snapshot(r"C:\Program Files\RedHat\Podman\podman.exe", 2),
        entrypoint=True,
    )
    provider_policy = ProcessImagePolicy(
        ProcessImageRole.PROVIDER,
        (provider,),
        ("kernel32.dll", "ntdll.dll"),
    )
    child_policy = ProcessImagePolicy(
        ProcessImageRole.RUNTIME_CHILD,
        (child,),
        ("kernel32.dll", "ntdll.dll"),
    )

    assert provider_policy.role is ProcessImageRole.PROVIDER
    assert child_policy.role is ProcessImageRole.RUNTIME_CHILD
    assert provider_policy.content_sha256 != child_policy.content_sha256
    assert "TowerScout" not in repr(provider_policy)
    assert "Program Files" not in repr(child_policy)
    with pytest.raises(FrozenInstanceError):
        provider_policy.role = ProcessImageRole.RUNTIME_CHILD  # type: ignore[misc]


def test_image_policy_rejects_unsorted_or_nested_system_image_names() -> None:
    binding = ProcessImageBinding.from_snapshot(
        _snapshot(r"C:\TowerScout\provider\python.exe", 1),
        entrypoint=True,
    )

    with pytest.raises(ValueError):
        ProcessImagePolicy(
            ProcessImageRole.PROVIDER,
            (binding,),
            ("ntdll.dll", "kernel32.dll"),
        )
    with pytest.raises(ValueError):
        ProcessImagePolicy(
            ProcessImageRole.PROVIDER,
            (binding,),
            (r"nested\kernel32.dll",),
        )


def test_provider_and_child_policies_cannot_share_an_exact_image() -> None:
    request, provider_policy, child_policy = _plan_and_policies()
    child_image = child_policy.entrypoint
    shared_dependency = ProcessImageBinding(
        identity=child_image.identity,
        sha256=child_image.sha256,
        final_path_sha256=child_image.final_path_sha256,
        entrypoint=False,
    )
    overlapping_provider_policy = ProcessImagePolicy(
        ProcessImageRole.PROVIDER,
        provider_policy.exact_files + (shared_dependency,),
        provider_policy.system_image_names,
    )
    backend = NativeWindowsProviderChildDynamicLoadBackend()

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._validate_policies(
            RuntimeExecutionBinding(_podman_target()).compose_command(
                ComposeReadOperation.CONFIG
            ),
            overlapping_provider_policy,
            child_policy,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.PLAN_REJECTED
    assert request.target_token not in str(failure.value)


def test_process_request_binds_exact_provider_endpoint_and_discards_ambient_state() -> (
    None
):
    target = _podman_target()
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)

    request = ProviderChildProcessRequest.from_plan(plan)

    assert request.executable_path == target.compose_provider.artifacts[0].final_path
    assert request.arguments == plan.arguments
    assert dict(request.environment) == plan.environment
    assert request.working_directory == target.package_root.final_path
    assert request.target_token == target.target_token.display
    assert len(request.binding_sha256) == 64
    assert tuple(name for name, _ in request.environment) == tuple(
        sorted(plan.environment, key=str.casefold)
    )
    rendered = repr(request)
    assert target.endpoint.canonical_endpoint not in rendered
    assert str(target.endpoint.identity_key.final_path) not in rendered
    assert str(target.package_root.final_path) not in rendered

    with pytest.raises(ValueError):
        ProviderChildProcessRequest(
            executable_path=request.executable_path,
            arguments=request.arguments,
            environment=request.environment + (("PATH", r"C:\attacker"),),
            working_directory=request.working_directory,
            timeout_ms=request.timeout_ms,
            stdout_limit_bytes=request.stdout_limit_bytes,
            stderr_limit_bytes=request.stderr_limit_bytes,
            target_token=request.target_token,
            binding_sha256=request.binding_sha256,
        )


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def wait(self, seconds: float) -> None:
        self.value += seconds


class _ProcessApi:
    supported = True

    def __init__(self) -> None:
        self.active = 2
        self.terminated = 0
        self.closed = 0
        self.starts: list[tuple[object, bool, int]] = []
        self.streams = {31: bytearray(b"{}\n"), 32: bytearray()}

    def system_directory(self) -> str:
        return str(_SYSTEM32)

    def start(
        self,
        request: object,
        *,
        debug_process_tree: bool = False,
        active_process_limit: int = 1,
    ) -> _NativeProcess:
        self.starts.append((request, debug_process_tree, active_process_limit))
        return _NativeProcess(
            11,
            12,
            31,
            32,
            process_id=101,
            debug_process_tree=debug_process_tree,
            dynamic_code_prohibited=debug_process_tree,
            child_processes_restricted=False,
            active_process_limit=active_process_limit,
        )

    def read_file(self, handle: int, maximum: int) -> bytes:
        result = bytes(self.streams[handle][:maximum])
        del self.streams[handle][:maximum]
        return result

    def active_processes(self, job: int) -> int:
        del job
        return self.active

    def terminate_job(self, job: int) -> None:
        del job
        self.terminated += 1
        self.active = 0

    def exit_code(self, process: int) -> int:
        del process
        return 0

    def close_process(self, process: _NativeProcess) -> None:
        del process
        self.closed += 1


class _DebugApi:
    supported = True

    def __init__(
        self,
        process_api: _ProcessApi,
        events: tuple[DebugEvent, ...],
        images: dict[object, FileSnapshot],
    ) -> None:
        self.process_api = process_api
        self.events = list(events)
        self.images = images
        self.prepared = 0
        self.closed: list[object] = []
        self.continued: list[tuple[DebugEventKind, int, int]] = []

    def prepare_kill_on_exit(self) -> None:
        self.prepared += 1

    def wait_event(self, milliseconds: int) -> DebugEvent | None:
        assert 0 <= milliseconds <= 25
        return self.events.pop(0) if self.events else None

    def inspect_image(self, handle: object) -> FileSnapshot:
        return self.images[handle]

    def close_image_handle(self, handle: object) -> None:
        self.closed.append(handle)

    def continue_event(self, event: DebugEvent, status: int) -> None:
        assert event.image_handle is None or event.image_handle in self.closed
        self.continued.append((event.kind, event.process_id, status))
        if event.kind is DebugEventKind.EXIT_PROCESS:
            self.process_api.active = 0 if event.process_id == 101 else 1


def _events(
    *,
    child_image: object = "podman",
    child_load: object = "podman-dll",
) -> tuple[DebugEvent, ...]:
    return (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="provider"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="provider-dll"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="kernel32"),
        DebugEvent(
            DebugEventKind.EXCEPTION,
            101,
            201,
            exception_code=0x80000003,
            first_chance=True,
        ),
        DebugEvent(DebugEventKind.CREATE_PROCESS, 102, 202, image_handle=child_image),
        DebugEvent(DebugEventKind.LOAD_DLL, 102, 202, image_handle=child_load),
        DebugEvent(DebugEventKind.LOAD_DLL, 102, 202, image_handle="ntdll"),
        DebugEvent(
            DebugEventKind.EXCEPTION,
            102,
            202,
            exception_code=0x80000003,
            first_chance=True,
        ),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 102, 202, exit_code=0),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=0),
    )


def _backend(events: tuple[DebugEvent, ...] | None = None):
    process_api = _ProcessApi()
    images = {
        "provider": _snapshot(str(_PROVIDER), 1),
        "provider-dll": _snapshot(str(_PROVIDER_DLL), 2),
        "podman": _snapshot(str(_PODMAN), 3),
        "podman-dll": _snapshot(str(_PODMAN_DLL), 4),
        "kernel32": _snapshot(str(_KERNEL32), 5),
        "ntdll": _snapshot(str(_NTDLL), 6),
        "attacker": _snapshot(str(_ATTACKER), 7),
    }
    debug_api = _DebugApi(process_api, events or _events(), images)
    backend = NativeWindowsProviderChildDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )
    return backend, process_api, debug_api


class _HeldFileApi:
    supported = True

    def __init__(self, snapshot: FileSnapshot, content: bytes) -> None:
        self.snapshot = snapshot
        self.content = content
        self.cursor = 0
        self.closed = False

    def query_file(self, handle: object) -> NativeFileFacts:
        del handle
        return NativeFileFacts(
            final_path=self.snapshot.final_path,
            volume_serial=self.snapshot.identity.volume_serial,
            file_id=self.snapshot.identity.file_id,
            attributes=self.snapshot.attributes,
            link_count=1 if self.snapshot.classification.single_link else 2,
            size=len(self.content),
            creation_time=self.snapshot.creation_time,
            last_write_time=self.snapshot.last_write_time,
            drive_type=3,
            file_type=1,
            reparse_tag=self.snapshot.reparse_tag,
        )

    def rewind_file(self, handle: object) -> None:
        del handle
        self.cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        del handle
        chunk = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        del handle
        self.closed = True


def _held_file(
    path: PureWindowsPath, marker: int
) -> tuple[HandleBoundFile, _HeldFileApi]:
    snapshot = _snapshot(str(path), marker)
    api = _HeldFileApi(snapshot, str(path).encode("utf-8"))
    return (
        HandleBoundFile(
            api,
            object(),
            FileCapturePolicy(max_bytes=1024 * 1024, require_single_link=False),
            snapshot,
        ),
        api,
    )


def _provider_runtime_inventory(
    base_python: HandleBoundFile, base_dll: HandleBoundFile
) -> HeldCpythonDependencyInventory:
    inventory = object.__new__(HeldCpythonDependencyInventory)
    inventory._lifetime_lock = threading.RLock()  # noqa: SLF001
    inventory._active_owner = None  # noqa: SLF001
    inventory._executable = base_python  # noqa: SLF001
    inventory._directories = ()  # noqa: SLF001
    inventory._files = (  # noqa: SLF001
        dependency_module._HeldDependency(  # noqa: SLF001
            "python.exe", base_python, True, True
        ),
        dependency_module._HeldDependency(  # noqa: SLF001
            "python312.dll", base_dll, False, True
        ),
    )
    inventory._system_image_names = ("kernel32.dll", "ntdll.dll")  # noqa: SLF001
    inventory._evidence = SimpleNamespace(  # noqa: SLF001
        dependency=SimpleNamespace(amd64_loadable_count=2)
    )
    return inventory


def _held_inventory_owner(
    monkeypatch: pytest.MonkeyPatch,
    target: ResolvedRepairTarget | None = None,
) -> tuple[
    HeldProviderChildInventory,
    NativeWindowsProviderChildDynamicLoadBackend,
    _HeldFileApi,
    HandleBoundFile,
]:
    target = _podman_target() if target is None else target
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)
    provider, _provider_api = _held_file(_PROVIDER, 1)
    provider_module, _module_api = _held_file(
        target.compose_provider.artifacts[1].final_path, 8
    )
    base_python, _base_api = _held_file(_BASE_PYTHON, 9)
    base_dll, _base_dll_api = _held_file(_PROVIDER_DLL, 2)
    child_executable, _child_api = _held_file(_PODMAN, 3)
    child_dll, _child_dll_api = _held_file(_PODMAN_DLL, 10)
    identity_key, identity_key_api = _held_file(
        target.endpoint.identity_key.final_path, 4  # type: ignore[union-attr]
    )
    provider_inventory = _provider_runtime_inventory(base_python, base_dll)
    child_inventory = object.__new__(RuntimeLoadPrerequisites)
    child_inventory._evidence = SimpleNamespace(  # noqa: SLF001
        product_id=RuntimeProductId.PODMAN_CLI
    )

    def run_child(_self, operation):  # noqa: ANN001, ANN202
        return child_executable.run_while_held(
            lambda: child_dll.run_while_held(operation)
        )

    def child_policy(_self, role):  # noqa: ANN001, ANN202
        return ProcessImagePolicy(
            role,
            (
                ProcessImageBinding.from_snapshot(
                    child_executable.snapshot, entrypoint=True
                ),
                ProcessImageBinding.from_snapshot(child_dll.snapshot, entrypoint=False),
            ),
            ("kernel32.dll", "ntdll.dll"),
        )

    monkeypatch.setattr(RuntimeLoadPrerequisites, "run_while_held", run_child)
    monkeypatch.setattr(
        RuntimeLoadPrerequisites, "active_process_image_policy", child_policy
    )
    monkeypatch.setattr(
        RuntimeLoadPrerequisites, "close", lambda _self: child_dll.close()
    )

    def execute(
        backend_self,
        command_plan,
        provider_policy,
        runtime_policy,
    ):  # noqa: ANN001, ANN202
        assert provider_policy.entrypoint.matches(debug_api.images["provider"])
        assert any(
            binding.matches(debug_api.images["provider-dll"])
            for binding in provider_policy.exact_files
        )
        assert runtime_policy.entrypoint.matches(debug_api.images["podman"])
        assert any(
            binding.matches(debug_api.images["podman-dll"])
            for binding in runtime_policy.exact_files
        )
        backend_self._validate_policies(  # noqa: SLF001
            command_plan, provider_policy, runtime_policy
        )
        return backend_self._execute_provider_request(  # noqa: SLF001
            ProviderChildProcessRequest.from_plan(command_plan),
            provider_policy,
            runtime_policy,
            system_directory=_SYSTEM32,
            system_directory_identity=StableFileIdentity(71, (99).to_bytes(16, "big")),
        )

    monkeypatch.setattr(
        NativeWindowsProviderChildDynamicLoadBackend, "execute", execute
    )
    backend, _process_api, debug_api = _backend()
    debug_api.images["podman-dll"] = _snapshot(str(_PODMAN_DLL), 10)
    owner = HeldProviderChildInventory(
        plan=plan,
        provider_runtime_inventory=provider_inventory,
        child_runtime_inventory=child_inventory,
        provider_base_executable=base_python,
        child_executable=child_executable,
        provider_artifacts=(provider, provider_module),
        endpoint_artifacts=(identity_key,),
    )
    return owner, backend, identity_key_api, identity_key


def test_held_provider_child_inventory_binds_endpoint_and_both_image_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend, _identity_key_api, _identity_key = _held_inventory_owner(
        monkeypatch
    )

    result = owner.execute(backend)

    assert owner.target_token == result.evidence.target_token
    assert owner.request_binding_sha256 == result.evidence.request_binding_sha256
    assert result.command.command.stdout == b"{}\n"
    assert result.evidence.target_token == _podman_target().target_token.display
    assert (
        result.evidence.request_binding_sha256
        == result.command.enforcement.request_binding_sha256
    )
    assert (
        result.evidence.provider_policy_sha256
        == result.command.enforcement.provider_policy_sha256
    )
    assert (
        result.evidence.child_policy_sha256
        == result.command.enforcement.child_policy_sha256
    )
    assert result.evidence.constructed_endpoint_environment
    assert result.evidence.provider_rediscovery_denied_by_policy
    assert result.evidence.endpoint_artifacts_held_through_execution
    assert not result.evidence.live_network_peer_observed
    assert "127.0.0.1" not in repr(result)
    assert "private" not in repr(result.evidence)
    owner.close()


class _HeldPathApi:
    supported = True

    def __init__(self, identity: FileIdentity) -> None:
        self.identity = StableFileIdentity(identity.volume_serial, identity.file_id)
        self.final_path = rf"\\?\{identity.final_path}"
        self.security = NativeSecurityFacts("S-1-5-21-1000", True, ())
        self.query_count = 0
        self.drift_after_queries: int | None = None
        self.closed = 0

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        del handle
        self.query_count += 1
        identity = self.identity
        if (
            self.drift_after_queries is not None
            and self.query_count > self.drift_after_queries
        ):
            identity = StableFileIdentity(
                identity.volume_serial, (999).to_bytes(16, "big")
            )
        return NativeDirectoryFacts(
            final_path=self.final_path,
            volume_serial=identity.volume_serial,
            file_id=identity.file_id,
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        del handle
        return self.security

    def close_handle(self, handle: object) -> None:
        del handle
        self.closed += 1


def _held_path(
    identity: FileIdentity, purpose: PathTrustPurpose
) -> tuple[PathHierarchyTrust, _HeldPathApi]:
    api = _HeldPathApi(identity)
    snapshot = DirectoryTrustSnapshot(
        identity=api.identity,
        final_path=api.final_path,
        attributes=0x10,
        reparse_tag=0,
        security=api.security,
        is_trusted_root=True,
    )
    evidence = PathHierarchyEvidence(
        purpose=purpose,
        lexical_depth=1,
        resolved_depth=1,
        root_identity=api.identity,
    )
    return (
        PathHierarchyTrust(
            api,
            "S-1-5-21-1000",
            (object(), object()),
            (snapshot, snapshot),
            evidence,
        ),
        api,
    )


def _held_target_file(
    identity: FileIdentity,
) -> tuple[HandleBoundFile, _HeldFileApi]:
    content = str(identity.final_path).encode("utf-8")
    snapshot = FileSnapshot(
        identity=StableFileIdentity(identity.volume_serial, identity.file_id),
        sha256=identity.sha256,
        size=identity.size_bytes,
        attributes=0x80,
        creation_time=1,
        last_write_time=2,
        reparse_tag=0,
        final_path=rf"\\?\{identity.final_path}",
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=True,
            regular_file=True,
            single_link=True,
        ),
    )
    assert len(content) == snapshot.size
    assert hashlib.sha256(content).hexdigest() == snapshot.sha256
    api = _HeldFileApi(snapshot, content)
    return (
        HandleBoundFile(
            api,
            object(),
            FileCapturePolicy(max_bytes=1024 * 1024, require_single_link=True),
            snapshot,
        ),
        api,
    )


def _transaction_components(
    monkeypatch: pytest.MonkeyPatch,
    target: ResolvedRepairTarget | None = None,
):  # noqa: ANN202
    provider_owner, backend, _key_api, _key = _held_inventory_owner(monkeypatch, target)
    plan = provider_owner._plan  # noqa: SLF001
    covered = {
        (identity.volume_serial, identity.file_id)
        for identity in (
            plan.target.runtime.executable,
            *plan.target.compose_provider.artifacts,
            *(
                ()
                if plan.target.endpoint.identity_key is None
                else (plan.target.endpoint.identity_key,)
            ),
            *plan.target.endpoint.discovery_artifacts,
        )
    }
    outer_identities = tuple(
        identity
        for identity in plan.authenticated_files
        if not identity.is_directory
        and (identity.volume_serial, identity.file_id) not in covered
    )
    held_files_with_apis = tuple(
        _held_target_file(identity) for identity in outer_identities
    )
    directory_identities = tuple(
        identity for identity in plan.authenticated_files if identity.is_directory
    )
    held_paths_with_apis = tuple(
        _held_path(
            identity,
            (
                PathTrustPurpose.PACKAGE_ROOT
                if index == 0
                else PathTrustPurpose.PROCESS_ENVIRONMENT
            ),
        )
        for index, identity in enumerate(directory_identities)
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.load_package_bound_runtime_policy",
        lambda: SimpleNamespace(
            content_sha256=plan.target.security_artifacts.runtime_policy.sha256
        ),
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.package_bound_runtime_policy_path",
        lambda: Path(str(plan.target.security_artifacts.runtime_policy.final_path)),
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.load_package_bound_runtime_dependency_policy",
        lambda: SimpleNamespace(
            content_sha256=(
                plan.target.security_artifacts.runtime_dependency_policy.sha256
            )
        ),
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.package_bound_runtime_dependency_policy_path",
        lambda: Path(
            str(plan.target.security_artifacts.runtime_dependency_policy.final_path)
        ),
    )
    return (
        provider_owner,
        backend,
        plan,
        tuple(item[0] for item in held_files_with_apis),
        tuple(item[1] for item in held_files_with_apis),
        tuple(item[0] for item in held_paths_with_apis),
        tuple(item[1] for item in held_paths_with_apis),
    )


def _capture_transaction_owner(
    monkeypatch: pytest.MonkeyPatch,
    provider_owner: HeldProviderChildInventory,
    plan,
    held_files: tuple[HandleBoundFile, ...],
    held_paths: tuple[PathHierarchyTrust, ...],
):  # noqa: ANN202
    opened_files: list[tuple[str, FileCapturePolicy, object]] = []
    opened_paths: list[tuple[str, PathTrustPurpose, object]] = []
    pending_files = iter(held_files)
    pending_paths = iter(held_paths)
    file_api = object()
    path_api = object()

    def capture_file(path, *, api=None, policy=None):  # noqa: ANN001, ANN202
        assert type(policy) is FileCapturePolicy
        opened_files.append((str(path), policy, api))
        return next(pending_files)

    def capture_path(path, *, purpose, api=None):  # noqa: ANN001, ANN202
        opened_paths.append((path, purpose, api))
        return next(pending_paths)

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        capture_file,
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_path_hierarchy",
        capture_path,
    )
    owner = capture_runtime_transaction_inventory(
        plan,
        provider_owner,
        file_api=file_api,  # type: ignore[arg-type]
        path_api=path_api,  # type: ignore[arg-type]
    )
    return owner, opened_files, opened_paths


def test_runtime_transaction_capture_opens_exact_inputs_in_plan_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )

    owner, opened_files, opened_paths = _capture_transaction_owner(
        monkeypatch, provider, plan, files, paths
    )

    assert tuple(item[0] for item in opened_files) == tuple(
        str(identity.final_path)
        for identity in (
            *plan.target.compose.ordered_files,
            plan.target.compose.environment_source,
            *plan.target.security_artifacts.ordered_files,
        )
    )
    assert all(item[1].require_single_link for item in opened_files)
    assert all(item[1].allow_hydrated_cloud_placeholder for item in opened_files)
    assert len({id(item[2]) for item in opened_files}) == 1
    assert tuple(item[0] for item in opened_paths) == tuple(
        str(identity.final_path)
        for identity in (
            plan.target.package_root,
            plan.target.process_environment.system_root,
            plan.target.process_environment.temp_directory,
            plan.target.process_environment.user_profile,
            plan.target.process_environment.local_app_data,
            plan.target.process_environment.roaming_app_data,
        )
    )
    assert tuple(item[1] for item in opened_paths) == (
        PathTrustPurpose.PACKAGE_ROOT,
        *(PathTrustPurpose.PROCESS_ENVIRONMENT for _ in range(5)),
    )
    assert len({id(item[2]) for item in opened_paths}) == 1
    owner.close()


def test_runtime_transaction_capture_uses_env_example_when_env_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _podman_target()
    template = _file(
        ".env.example", original.package_root.final_path / ".env.example", 106
    )
    target = replace(
        original,
        compose=replace(
            original.compose,
            environment_sha256=ABSENT_FILE_SHA256,
            environment_source=template,
            environment_file=None,
        ),
    )
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch, target
    )

    owner, opened_files, _opened_paths = _capture_transaction_owner(
        monkeypatch, provider, plan, files, paths
    )

    assert opened_files[1][0].endswith(r"\TowerScout\.env.example")
    assert all(not item[0].endswith(r"\TowerScout\.env") for item in opened_files)
    owner.close()


def test_runtime_transaction_capture_preserves_podman_gpu_overlay_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _podman_target()
    overlay = _file(
        "compose.gpu.podman.yaml",
        original.package_root.final_path / "compose.gpu.podman.yaml",
        107,
    )
    target = replace(
        original,
        compose=replace(
            original.compose,
            ordered_files=(*original.compose.ordered_files, overlay),
        ),
        acceleration=AccelerationPlan(
            GpuMode.ON,
            EffectiveProfile.PODMAN_GPU,
            "compose.gpu.podman.yaml",
        ),
    )
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch, target
    )

    owner, opened_files, _opened_paths = _capture_transaction_owner(
        monkeypatch, provider, plan, files, paths
    )

    assert [PureWindowsPath(item[0]).name for item in opened_files[:3]] == [
        "compose.yaml",
        "compose.gpu.podman.yaml",
        ".env",
    ]
    owner.close()


def test_runtime_transaction_capture_accepts_hydrated_cloud_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )
    original = files[0]
    cloud_tag = min(KNOWN_CLOUD_REPARSE_TAGS)
    cloud_snapshot = replace(
        original.snapshot,
        attributes=0x480,
        reparse_tag=cloud_tag,
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.KNOWN_CLOUD_PLACEHOLDER,
            hydrated=True,
            regular_file=True,
            single_link=True,
        ),
    )
    cloud_api = _HeldFileApi(
        cloud_snapshot,
        str(plan.target.compose.ordered_files[0].final_path).encode("utf-8"),
    )
    cloud_file = HandleBoundFile(
        cloud_api,
        object(),
        FileCapturePolicy(
            max_bytes=1024 * 1024,
            require_single_link=True,
            allow_hydrated_cloud_placeholder=True,
        ),
        cloud_snapshot,
    )
    original.close()
    files = (cloud_file, *files[1:])

    owner, opened_files, _opened_paths = _capture_transaction_owner(
        monkeypatch, provider, plan, files, paths
    )

    assert opened_files[0][1].allow_hydrated_cloud_placeholder
    owner.close()


def test_runtime_transaction_capture_closes_partial_capture_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )
    capture_count = 0

    def fail_second_file(path, *, api=None, policy=None):  # noqa: ANN001, ANN202
        del path, api, policy
        nonlocal capture_count
        capture_count += 1
        if capture_count == 1:
            return files[0]
        raise WindowsSecurityError("file_open_failed", "sanitized")

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        fail_second_file,
    )

    with pytest.raises(RuntimeTransactionInventoryError) as failure:
        capture_runtime_transaction_inventory(plan, provider)

    assert failure.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    assert files[0].closed
    assert not provider.closed
    provider.close()
    for item in files[1:]:
        item.close()
    for path in paths:
        path.close()


def test_runtime_transaction_capture_accepts_exact_input_size_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _podman_target()
    compose_file = replace(
        target.compose.ordered_files[0],
        size_bytes=16 * 1024 * 1024,
    )
    target = replace(
        target,
        compose=replace(target.compose, ordered_files=(compose_file,)),
    )
    provider, _backend, _key_api, _key = _held_inventory_owner(monkeypatch, target)
    plan = provider._plan  # noqa: SLF001
    observed_maximum = None

    def observe_boundary(path, *, api=None, policy=None):  # noqa: ANN001, ANN202
        del path, api
        nonlocal observed_maximum
        observed_maximum = policy.max_bytes
        raise WindowsSecurityError("file_open_failed", "sanitized")

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        observe_boundary,
    )

    with pytest.raises(RuntimeTransactionInventoryError) as failure:
        capture_runtime_transaction_inventory(plan, provider)

    assert failure.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    assert observed_maximum == 16 * 1024 * 1024
    assert not provider.closed
    provider.close()


def test_runtime_transaction_capture_rejects_input_above_size_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _podman_target()
    compose_file = replace(
        target.compose.ordered_files[0],
        size_bytes=(16 * 1024 * 1024) + 1,
    )
    target = replace(
        target,
        compose=replace(target.compose, ordered_files=(compose_file,)),
    )
    provider, _backend, _key_api, _key = _held_inventory_owner(monkeypatch, target)
    plan = provider._plan  # noqa: SLF001

    def unexpected_capture(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("oversized input must be rejected before capture")

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        unexpected_capture,
    )

    with pytest.raises(RuntimeTransactionInventoryError) as failure:
        capture_runtime_transaction_inventory(plan, provider)

    assert failure.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    assert not provider.closed
    provider.close()


def test_runtime_transaction_capture_fails_closed_when_partial_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )
    capture_count = 0
    original_close = HandleBoundFile.close

    def fail_second_file(path, *, api=None, policy=None):  # noqa: ANN001, ANN202
        del path, api, policy
        nonlocal capture_count
        capture_count += 1
        if capture_count == 1:
            return files[0]
        raise WindowsSecurityError("file_open_failed", "sanitized")

    def fail_captured_close(self):  # noqa: ANN001, ANN202
        if self is files[0]:
            raise WindowsSecurityError("file_handle_in_use", "sanitized")
        return original_close(self)

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        fail_second_file,
    )
    monkeypatch.setattr(HandleBoundFile, "close", fail_captured_close)

    with pytest.raises(RuntimeTransactionInventoryError) as failure:
        capture_runtime_transaction_inventory(plan, provider)

    assert failure.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED
    assert not provider.closed
    original_close(files[0])
    provider.close()
    for item in files[1:]:
        item.close()
    for path in paths:
        path.close()


def test_runtime_transaction_capture_constructor_failure_retains_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )

    def fail_constructor(**kwargs):  # noqa: ANN003, ANN202
        del kwargs
        raise ValueError("constructor failure")

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.HeldRuntimeTransactionInventory",
        fail_constructor,
    )
    pending_files = iter(files)
    pending_paths = iter(paths)
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        lambda *args, **kwargs: next(pending_files),
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_path_hierarchy",
        lambda *args, **kwargs: next(pending_paths),
    )

    with pytest.raises(RuntimeTransactionInventoryError) as failure:
        capture_runtime_transaction_inventory(plan, provider)

    assert failure.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    assert not provider.closed
    assert all(item.closed for item in files)
    assert all(path.closed for path in paths)
    provider.close()


def test_runtime_transaction_capture_rejects_wrong_provider_before_opening_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _backend, _key_api, _key = _held_inventory_owner(monkeypatch)
    original = _podman_target()
    other_target = replace(original, release_identity="v0.1.3-other")
    other_plan = RuntimeExecutionBinding(other_target).compose_command(
        ComposeReadOperation.CONFIG
    )

    def unexpected_capture(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("capture must not run for a mismatched provider")

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_handle_bound_file",
        unexpected_capture,
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.capture_path_hierarchy",
        unexpected_capture,
    )

    with pytest.raises(RuntimeTransactionInventoryError) as failure:
        capture_runtime_transaction_inventory(other_plan, provider)

    assert failure.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    assert not provider.closed
    provider.close()


def test_runtime_transaction_owner_rejects_same_thread_reentry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )
    owner = HeldRuntimeTransactionInventory(
        plan=plan,
        provider_inventory=provider,
        input_files=files,
        directory_paths=paths,
    )
    original_execute = HeldProviderChildInventory.execute
    nested_code = None

    def execute_with_reentry(
        self, selected_backend, *, pre_execute_validator=None
    ):  # noqa: ANN001, ANN202
        nonlocal nested_code
        with pytest.raises(RuntimeTransactionInventoryError) as nested:
            owner.execute(selected_backend)
        nested_code = nested.value.code
        return original_execute(
            self,
            selected_backend,
            pre_execute_validator=pre_execute_validator,
        )

    monkeypatch.setattr(HeldProviderChildInventory, "execute", execute_with_reentry)

    result = owner.execute(backend)

    assert result.provider_result.command.command.exit_code == 0
    assert nested_code is RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED
    owner.close()


def test_runtime_transaction_owner_serializes_concurrent_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, backend, plan, files, _apis, paths, _path_apis = _transaction_components(
        monkeypatch
    )
    owner = HeldRuntimeTransactionInventory(
        plan=plan,
        provider_inventory=provider,
        input_files=files,
        directory_paths=paths,
    )
    original_execute = HeldProviderChildInventory.execute
    entered = threading.Event()
    release = threading.Event()
    close_started = threading.Event()
    close_complete = threading.Event()
    failures: list[BaseException] = []

    def blocked_execute(
        self, selected_backend, *, pre_execute_validator=None
    ):  # noqa: ANN001, ANN202
        entered.set()
        if not release.wait(2):
            raise AssertionError("test release timed out")
        return original_execute(
            self,
            selected_backend,
            pre_execute_validator=pre_execute_validator,
        )

    def execute_owner() -> None:
        try:
            owner.execute(backend)
        except BaseException as error:
            failures.append(error)

    def close_owner() -> None:
        try:
            close_started.set()
            owner.close()
        except BaseException as error:
            failures.append(error)
        finally:
            close_complete.set()

    monkeypatch.setattr(HeldProviderChildInventory, "execute", blocked_execute)
    execute_thread = threading.Thread(target=execute_owner)
    close_thread = threading.Thread(target=close_owner)
    execute_thread.start()
    assert entered.wait(1)
    close_thread.start()
    assert close_started.wait(1)
    assert not close_complete.wait(0.1)

    release.set()
    execute_thread.join(2)
    close_thread.join(2)

    assert not execute_thread.is_alive()
    assert not close_thread.is_alive()
    assert failures == []
    assert owner.closed


def test_runtime_transaction_owner_holds_all_outer_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        provider_owner,
        backend,
        plan,
        held_files,
        _file_apis,
        held_paths,
        _path_apis,
    ) = _transaction_components(monkeypatch)
    owner = HeldRuntimeTransactionInventory(
        plan=plan,
        provider_inventory=provider_owner,
        input_files=held_files,
        directory_paths=held_paths,
    )

    result = owner.execute(backend)

    assert result.provider_result.command.command.stdout == b"{}\n"
    assert result.evidence.target_token == plan.target_token
    assert result.evidence.input_file_count == 5
    assert result.evidence.directory_path_count == 6
    assert result.evidence.compose_inputs_held_through_execution
    assert result.evidence.security_artifacts_held_through_execution
    assert result.evidence.process_environment_held_through_execution
    assert not result.evidence.live_network_peer_observed
    assert "TowerScout" not in repr(result)
    assert "private" not in repr(result.evidence)
    owner.close()
    assert all(bound.closed for bound in held_files)
    assert all(path.closed for path in held_paths)
    assert provider_owner.closed


def test_runtime_transaction_owner_rejects_missing_or_wrong_policy_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_owner, _backend, plan, held_files, _apis, held_paths, _path_apis = (
        _transaction_components(monkeypatch)
    )

    with pytest.raises(RuntimeTransactionInventoryError) as missing:
        HeldRuntimeTransactionInventory(
            plan=plan,
            provider_inventory=provider_owner,
            input_files=held_files[:-1],
            directory_paths=held_paths,
        )
    assert missing.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    provider_owner.close()
    for bound_file in held_files:
        bound_file.close()
    for path in held_paths:
        path.close()


def test_runtime_transaction_owner_rejects_policy_hash_or_path_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_owner, _backend, plan, held_files, _apis, held_paths, _path_apis = (
        _transaction_components(monkeypatch)
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.load_package_bound_runtime_policy",
        lambda: SimpleNamespace(content_sha256="0" * 64),
    )

    with pytest.raises(RuntimeTransactionInventoryError) as wrong_hash:
        HeldRuntimeTransactionInventory(
            plan=plan,
            provider_inventory=provider_owner,
            input_files=held_files,
            directory_paths=held_paths,
        )
    assert (
        wrong_hash.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    )

    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.load_package_bound_runtime_policy",
        lambda: SimpleNamespace(
            content_sha256=plan.target.security_artifacts.runtime_policy.sha256
        ),
    )
    monkeypatch.setattr(
        "towerscout_launcher.runtime_transaction_inventory.package_bound_runtime_policy_path",
        lambda: Path(r"C:\Attacker\runtime-policy.v1.json"),
    )
    with pytest.raises(RuntimeTransactionInventoryError) as wrong_path:
        HeldRuntimeTransactionInventory(
            plan=plan,
            provider_inventory=provider_owner,
            input_files=held_files,
            directory_paths=held_paths,
        )
    assert (
        wrong_path.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH
    )
    provider_owner.close()
    for bound_file in held_files:
        bound_file.close()
    for path in held_paths:
        path.close()


def test_runtime_transaction_owner_detects_file_change_after_provider_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_owner, backend, plan, held_files, apis, held_paths, _path_apis = (
        _transaction_components(monkeypatch)
    )
    owner = HeldRuntimeTransactionInventory(
        plan=plan,
        provider_inventory=provider_owner,
        input_files=held_files,
        directory_paths=held_paths,
    )
    original_execute = HeldProviderChildInventory.execute

    def execute_then_mutate(
        self, selected_backend, *, pre_execute_validator=None
    ):  # noqa: ANN001, ANN202
        result = original_execute(
            self,
            selected_backend,
            pre_execute_validator=pre_execute_validator,
        )
        apis[0].content += b"changed"
        return result

    monkeypatch.setattr(HeldProviderChildInventory, "execute", execute_then_mutate)

    with pytest.raises(RuntimeTransactionInventoryError) as changed:
        owner.execute(backend)
    assert changed.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED
    owner.close()


def test_runtime_transaction_owner_rechecks_early_path_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        provider_owner,
        backend,
        plan,
        held_files,
        _apis,
        held_paths,
        path_apis,
    ) = _transaction_components(monkeypatch)
    owner = HeldRuntimeTransactionInventory(
        plan=plan,
        provider_inventory=provider_owner,
        input_files=held_files,
        directory_paths=held_paths,
    )
    path_apis[0].drift_after_queries = 2
    executed = False
    original_execute = HeldProviderChildInventory.execute

    def observe_execute(
        self, selected_backend, *, pre_execute_validator=None
    ):  # noqa: ANN001, ANN202
        nonlocal executed
        executed = True
        return original_execute(
            self,
            selected_backend,
            pre_execute_validator=pre_execute_validator,
        )

    monkeypatch.setattr(HeldProviderChildInventory, "execute", observe_execute)

    with pytest.raises(RuntimeTransactionInventoryError) as changed:
        owner.execute(backend)
    assert changed.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED
    assert not executed
    owner.close()


def test_runtime_transaction_owner_rechecks_inside_fully_acquired_inner_leases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        provider_owner,
        backend,
        plan,
        held_files,
        _apis,
        held_paths,
        path_apis,
    ) = _transaction_components(monkeypatch)
    owner = HeldRuntimeTransactionInventory(
        plan=plan,
        provider_inventory=provider_owner,
        input_files=held_files,
        directory_paths=held_paths,
    )
    original_child_lease = RuntimeLoadPrerequisites.run_while_held
    original_backend_execute = NativeWindowsProviderChildDynamicLoadBackend.execute
    backend_executed = False

    def drift_during_child_lease(self, operation):  # noqa: ANN001, ANN202
        path_apis[0].drift_after_queries = path_apis[0].query_count
        return original_child_lease(self, operation)

    def observe_backend(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        nonlocal backend_executed
        backend_executed = True
        return original_backend_execute(self, *args, **kwargs)

    monkeypatch.setattr(
        RuntimeLoadPrerequisites, "run_while_held", drift_during_child_lease
    )
    monkeypatch.setattr(
        NativeWindowsProviderChildDynamicLoadBackend, "execute", observe_backend
    )

    with pytest.raises(RuntimeTransactionInventoryError) as changed:
        owner.execute(backend)
    assert changed.value.code is RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED
    assert not backend_executed
    owner.close()


def test_held_provider_child_inventory_rejects_endpoint_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _podman_target()
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)
    provider, _provider_api = _held_file(_PROVIDER, 1)
    provider_module, _module_api = _held_file(
        target.compose_provider.artifacts[1].final_path, 8
    )
    base_python, _base_api = _held_file(_BASE_PYTHON, 9)
    base_dll, _base_dll_api = _held_file(_PROVIDER_DLL, 2)
    wrong_child, _wrong_child_api = _held_file(_PODMAN, 3)
    wrong_key, _wrong_key_api = _held_file(
        target.endpoint.identity_key.final_path, 44  # type: ignore[union-attr]
    )
    child_inventory = object.__new__(RuntimeLoadPrerequisites)
    child_inventory._evidence = SimpleNamespace(  # noqa: SLF001
        product_id=RuntimeProductId.PODMAN_CLI
    )
    monkeypatch.setattr(RuntimeLoadPrerequisites, "close", lambda _self: None)

    with pytest.raises(ProviderChildInventoryError) as exc_info:
        HeldProviderChildInventory(
            plan=plan,
            provider_runtime_inventory=_provider_runtime_inventory(
                base_python, base_dll
            ),
            child_runtime_inventory=child_inventory,
            provider_base_executable=base_python,
            child_executable=wrong_child,
            provider_artifacts=(provider, provider_module),
            endpoint_artifacts=(wrong_key,),
        )

    assert exc_info.value.code is ProviderChildInventoryErrorCode.INVENTORY_MISMATCH
    rendered = str(exc_info.value) + repr(exc_info.value)
    assert "podman-machine-key" not in rendered
    assert "private" not in rendered
    for held in (
        provider,
        provider_module,
        base_python,
        base_dll,
        wrong_child,
        wrong_key,
    ):
        held.close()


def test_held_provider_child_inventory_detects_key_replacement_after_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend, identity_key_api, _identity_key = _held_inventory_owner(monkeypatch)
    original_execute = NativeWindowsProviderChildDynamicLoadBackend.execute

    def replace_key_then_execute(
        backend_self,
        command_plan,
        provider_policy,
        child_policy,
    ):  # noqa: ANN001, ANN202
        result = original_execute(
            backend_self, command_plan, provider_policy, child_policy
        )
        identity_key_api.content += b"replacement"
        return result

    monkeypatch.setattr(
        NativeWindowsProviderChildDynamicLoadBackend,
        "execute",
        replace_key_then_execute,
    )

    with pytest.raises(ProviderChildInventoryError) as exc_info:
        owner.execute(backend)

    assert exc_info.value.code is ProviderChildInventoryErrorCode.INVENTORY_CHANGED
    assert "replacement" not in str(exc_info.value)
    owner.close()


def test_held_provider_child_inventory_blocks_cross_thread_key_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, backend, _identity_key_api, identity_key = _held_inventory_owner(monkeypatch)
    original_execute = NativeWindowsProviderChildDynamicLoadBackend.execute
    entered = threading.Event()
    release = threading.Event()
    execution_done = threading.Event()
    close_done = threading.Event()

    def wait_then_execute(
        backend_self,
        command_plan,
        provider_policy,
        child_policy,
    ):  # noqa: ANN001, ANN202
        entered.set()
        assert release.wait(5)
        return original_execute(
            backend_self, command_plan, provider_policy, child_policy
        )

    monkeypatch.setattr(
        NativeWindowsProviderChildDynamicLoadBackend,
        "execute",
        wait_then_execute,
    )

    def execute() -> None:
        owner.execute(backend)
        execution_done.set()

    def close_key() -> None:
        identity_key.close()
        close_done.set()

    worker = threading.Thread(target=execute)
    closer = threading.Thread(target=close_key)
    worker.start()
    assert entered.wait(5)
    closer.start()
    assert not close_done.wait(0.1)

    release.set()
    worker.join(5)
    closer.join(5)

    assert execution_done.is_set()
    assert close_done.is_set()
    assert identity_key.closed
    owner.close()


def test_provider_child_backend_authenticates_both_process_roles_and_images() -> None:
    request, provider_policy, child_policy = _plan_and_policies()
    backend, process_api, debug_api = _backend()

    result = backend._execute_provider_request(  # noqa: SLF001
        request,
        provider_policy,
        child_policy,
        system_directory=_SYSTEM32,
        system_directory_identity=StableFileIdentity(71, (99).to_bytes(16, "big")),
    )

    assert result.command.stdout == b"{}\n"
    assert result.command.exit_code == 0
    assert result.enforcement.provider_image_count == 3
    assert result.enforcement.child_image_count == 3
    assert result.enforcement.child_process_count == 1
    assert result.enforcement.exact_inventory_image_count == 4
    assert result.enforcement.system32_image_count == 2
    assert result.enforcement.active_process_limit == 2
    assert result.enforcement.provider_dynamic_code_prohibited
    assert result.enforcement.root_alive_during_child
    assert result.enforcement.unexpected_processes_denied
    assert result.enforcement.arbitrary_dynamic_destinations_denied
    assert process_api.starts == [(request, True, 2)]
    assert process_api.terminated == 0
    assert process_api.closed == 1
    assert debug_api.closed == [
        "provider",
        "provider-dll",
        "kernel32",
        "podman",
        "podman-dll",
        "ntdll",
    ]
    assert debug_api.prepared == 1


class _PathTrust:
    def __init__(self, path: PureWindowsPath, identity: StableFileIdentity) -> None:
        self.evidence = SimpleNamespace(root_identity=identity)
        self.root_snapshot = SimpleNamespace(final_path=rf"\\?\{path}")
        self.assertions = 0
        self.closed = False

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        del exc_type, exc, traceback
        self.closed = True

    def assert_unchanged(self) -> None:
        self.assertions += 1


def test_public_provider_child_execution_holds_system_and_package_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _podman_target()
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)
    request, provider_policy, child_policy = _plan_and_policies()
    backend, _process_api, _debug_api = _backend()
    system_trust = _PathTrust(
        _SYSTEM32, StableFileIdentity(71, (99).to_bytes(16, "big"))
    )
    package_trust = _PathTrust(
        target.package_root.final_path,
        StableFileIdentity(
            target.package_root.volume_serial, target.package_root.file_id
        ),
    )

    def capture(path: str, *, purpose, api):  # noqa: ANN001, ANN202
        del api
        if purpose.value == "runtime_install":
            assert path == str(_SYSTEM32)
            return system_trust
        assert purpose.value == "package_root"
        assert path == str(target.package_root.final_path)
        return package_trust

    monkeypatch.setattr(dynamic_module, "capture_path_hierarchy", capture)

    result = backend.execute(plan, provider_policy, child_policy)

    assert result.enforcement.request_binding_sha256 == request.binding_sha256
    assert system_trust.assertions == 2
    assert package_trust.assertions == 2
    assert system_trust.closed
    assert package_trust.closed


def test_public_provider_child_execution_rejects_mismatched_child_before_start() -> (
    None
):
    target = _podman_target()
    plan = RuntimeExecutionBinding(target).compose_command(ComposeReadOperation.CONFIG)
    _request, provider_policy, child_policy = _plan_and_policies()
    wrong_child = ProcessImagePolicy(
        ProcessImageRole.RUNTIME_CHILD,
        (
            ProcessImageBinding.from_snapshot(
                _snapshot(str(_ATTACKER), 7), entrypoint=True
            ),
        ),
        child_policy.system_image_names,
    )
    backend, process_api, _debug_api = _backend()

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend.execute(plan, provider_policy, wrong_child)

    assert failure.value.code is DynamicLoadEnforcementErrorCode.PLAN_REJECTED
    assert process_api.starts == []
    assert str(_ATTACKER) not in str(failure.value)


@pytest.mark.parametrize(
    ("events", "expected"),
    (
        (
            _events(child_image="attacker"),
            DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED,
        ),
        (
            _events(child_load="attacker"),
            DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED,
        ),
        (
            (
                *_events()[:5],
                DebugEvent(
                    DebugEventKind.CREATE_PROCESS,
                    103,
                    203,
                    image_handle="podman",
                ),
                DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
            ),
            DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED,
        ),
        (
            (
                *_events()[:5],
                DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
            ),
            DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED,
        ),
    ),
)
def test_provider_child_backend_denies_wrong_child_loads_extra_processes_and_early_root_exit(
    events: tuple[DebugEvent, ...],
    expected: DynamicLoadEnforcementErrorCode,
) -> None:
    request, provider_policy, child_policy = _plan_and_policies()
    backend, process_api, debug_api = _backend(events)

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_provider_request(  # noqa: SLF001
            request,
            provider_policy,
            child_policy,
            system_directory=_SYSTEM32,
            system_directory_identity=StableFileIdentity(71, (99).to_bytes(16, "big")),
        )

    assert failure.value.code is expected
    assert process_api.terminated >= 1
    assert process_api.closed == 1
    assert not process_api.active
    assert "attacker" not in str(failure.value)
    assert debug_api.closed


def test_provider_child_slice_remains_unwired() -> None:
    for relative in (
        "app.py",
        "discovery.py",
        "repair.py",
        "runtime_execution.py",
        "runtime_verification.py",
    ):
        source = (LAUNCHER_ROOT / "towerscout_launcher" / relative).read_text(
            encoding="utf-8"
        )
        assert "runtime_provider_child" not in source
        assert "runtime_provider_inventory" not in source
        assert "runtime_transaction_inventory" not in source


def test_policy_module_has_no_process_or_shell_execution() -> None:
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_provider_child.py"
    ).read_text(encoding="utf-8")

    assert "import subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
