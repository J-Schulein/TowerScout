from __future__ import annotations

import hashlib
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_dynamic_load as dynamic_module  # noqa: E402
from towerscout_launcher.runtime_command_native import _NativeProcess  # noqa: E402
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
from towerscout_launcher.runtime_provider_child import (  # noqa: E402
    ProcessImageBinding,
    ProcessImagePolicy,
    ProcessImageRole,
    ProviderChildProcessRequest,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
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
from towerscout_launcher.windows_security import (  # noqa: E402
    FileSnapshot,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
)

_SYSTEM32 = PureWindowsPath(r"C:\Windows\System32")
_PROVIDER = PureWindowsPath(r"C:\TowerScout\tools\provider\.venv\Scripts\python.exe")
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


def test_policy_module_has_no_process_or_shell_execution() -> None:
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_provider_child.py"
    ).read_text(encoding="utf-8")

    assert "import subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
