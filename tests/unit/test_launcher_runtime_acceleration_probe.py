"""Adversarial coverage for retained native acceleration attestation."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import PureWindowsPath
from typing import Any

import pytest

from launcher.towerscout_launcher.runtime_acceleration_probe import (
    AccelerationProbeError,
    AccelerationProbeErrorCode,
    BoundEngineAccelerationEvidence,
    EngineAccelerationSnapshot,
    _open_engine_acceleration_evidence,
    capture_native_windows_engine_acceleration_evidence,
)
from launcher.towerscout_launcher.runtime_docker_inputs import (
    DockerTargetSourceInputs,
)
from launcher.towerscout_launcher.runtime_package_inputs import (
    PackageEnvironmentInputs,
    _package_binding,
    _ParsedPackage,
)
from launcher.towerscout_launcher.runtime_podman_inputs import (
    PodmanTargetSourceInputs,
)
from launcher.towerscout_launcher.runtime_command_version import (
    CommandProcessRequest,
    CommandProcessResult,
)
from launcher.towerscout_launcher.target_contracts import (
    ComposeInvocationKind,
    ComposeProviderIdentity,
    EndpointBindingKind,
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    GpuMode,
    RuntimeIdentity,
    RuntimeProduct,
    SecurityArtifactInventory,
    WindowsProcessEnvironment,
)

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_MACHINE = "podman-machine-default"
_KEY = r"C:\Users\operator\.local\share\containers\podman\key"
_ENDPOINT = "ssh://operator@127.0.0.1:50222/run/user/1000/podman/podman.sock"


def _file(product: RuntimeProduct) -> FileIdentity:
    leaf = f"{product.value}.exe"
    return FileIdentity(
        logical_name=leaf,
        final_path=PureWindowsPath(rf"C:\Runtime\{leaf}"),
        volume_serial=10,
        file_id=b"i" * 16,
        sha256=_A,
        size_bytes=200,
    )


def _runtime(product: RuntimeProduct) -> RuntimeIdentity:
    return RuntimeIdentity(
        product=product,
        executable=_file(product),
        version="5.8.2",
        publisher_policy_sha256=_B,
    )


def _endpoint(product: RuntimeProduct) -> EndpointIdentity:
    if product is RuntimeProduct.DOCKER:
        return EndpointIdentity(
            product=product,
            kind=EndpointKind.DOCKER_NAMED_PIPE,
            canonical_endpoint="npipe:////./pipe/dockerDesktopLinuxEngine",
            private_metadata_sha256=_C,
        )
    return EndpointIdentity(
        product=product,
        kind=EndpointKind.PODMAN_ROOTLESS_WSL,
        canonical_endpoint=_ENDPOINT,
        private_metadata_sha256=_C,
        identity_key=FileIdentity(
            logical_name="podman_identity_key",
            final_path=PureWindowsPath(_KEY),
            volume_serial=11,
            file_id=b"k" * 16,
            sha256=_D,
            size_bytes=300,
        ),
        rootless=True,
    )


def _source(
    product: RuntimeProduct,
) -> DockerTargetSourceInputs | PodmanTargetSourceInputs:
    if product is RuntimeProduct.DOCKER:
        provider = ComposeProviderIdentity(
            provider_id="docker-compose",
            invocation_kind=ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE,
            endpoint_binding=EndpointBindingKind.DOCKER_HOST_ARGUMENT,
            artifacts=(
                _generic_file(
                    "docker-compose.exe", r"C:\Runtime\docker-compose.exe", 40
                ),
            ),
            integrity_sha256=_D,
        )
        return DockerTargetSourceInputs(
            runtime=_runtime(product),
            endpoint=_endpoint(product),
            compose_provider=provider,
        )
    provider = ComposeProviderIdentity(
        provider_id="podman-compose",
        invocation_kind=ComposeInvocationKind.PODMAN_PYTHON_MODULE,
        endpoint_binding=EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
        artifacts=(
            _generic_file("python.exe", r"C:\Provider\Scripts\python.exe", 41),
            _generic_file(
                "podman_compose_module",
                r"C:\Provider\Lib\site-packages\podman_compose.py",
                42,
            ),
        ),
        integrity_sha256=_D,
    )
    return PodmanTargetSourceInputs(
        runtime=_runtime(product),
        endpoint=_endpoint(product),
        compose_provider=provider,
    )


class _Owner:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.supported = True
        self.closed = False
        self.captures = 0
        self.replacement: Any | None = None

    def capture(self) -> Any:
        self.captures += 1
        if self.replacement is not None and self.captures > 1:
            return self.replacement
        return self.value

    def close(self) -> None:
        self.closed = True


class _SequenceOwner(_Owner):
    def __init__(self, values: list[Any]) -> None:
        super().__init__(values[0])
        self.values = values
        self.last: Any | None = None

    def capture(self) -> Any:
        self.last = self.values.pop(0)
        return self.last


def _generic_file(name: str, path: str, identifier: int) -> FileIdentity:
    return FileIdentity(
        logical_name=name,
        final_path=PureWindowsPath(path),
        volume_serial=30,
        file_id=identifier.to_bytes(16, "big"),
        sha256=_A,
        size_bytes=200,
    )


def _package(
    *,
    engine: str,
    machine: str = _MACHINE,
    mode: GpuMode = GpuMode.AUTO,
) -> PackageEnvironmentInputs:
    package_root = _directory("package_root", r"C:\TowerScout", 20)
    manifest = _generic_file(
        "release-manifest.v1.json", r"C:\TowerScout\release-manifest.v1.json", 21
    )
    runtime_policy = _generic_file(
        "runtime-policy.v1.json",
        r"C:\TowerScout\launcher\towerscout_launcher\runtime-policy.v1.json",
        22,
    )
    dependency_policy = _generic_file(
        "runtime-dependency-policy.v1.json",
        r"C:\TowerScout\launcher\towerscout_launcher\runtime-dependency-policy.v1.json",
        23,
    )
    compose = tuple(
        _generic_file(name, rf"C:\TowerScout\{name}", 24 + index)
        for index, name in enumerate(
            ("compose.yaml", "compose.gpu.yaml", "compose.gpu.podman.yaml")
        )
    )
    environment = _generic_file(".env", r"C:\TowerScout\.env", 27)
    digest = "sha256:" + "e" * 64
    image = "ghcr.io/j-schulein/towerscout@" + digest
    parsed = _ParsedPackage(
        release_identity="TowerScout-test",
        compose_project="towerscout",
        requested_gpu_mode=mode,
        gpu_auto_overlay=True,
        podman_gpu_overlay=True,
        pytorch_flavor="cuda126",
        engine_hint=engine,
        port=5000,
        configured_image_reference=image,
        pinned_image_digest=digest,
        podman_machine=machine,
        planned_environment_sha256=_B,
    )
    files = (manifest, runtime_policy, dependency_policy, *compose, environment)
    return PackageEnvironmentInputs(
        package_root=package_root,
        release_identity=parsed.release_identity,
        security_artifacts=SecurityArtifactInventory(
            release_manifest=manifest,
            runtime_policy=runtime_policy,
            runtime_dependency_policy=dependency_policy,
        ),
        compose_files=compose,
        environment_sha256=environment.sha256,
        planned_environment_sha256=parsed.planned_environment_sha256,
        environment_source=environment,
        environment_file=environment,
        compose_project=parsed.compose_project,
        requested_gpu_mode=mode,
        gpu_auto_overlay=True,
        podman_gpu_overlay=True,
        pytorch_flavor="cuda126",
        engine_hint=engine,
        port=5000,
        configured_image_reference=image,
        pinned_image_digest=digest,
        podman_machine=machine,
        package_binding_sha256=_package_binding(
            package_root,
            files,
            parsed,
            environment.sha256,
            parsed.planned_environment_sha256,
        ),
    )


def _directory(name: str, path: str, identifier: int) -> FileIdentity:
    return FileIdentity(
        logical_name=name,
        final_path=PureWindowsPath(path),
        volume_serial=20,
        file_id=identifier.to_bytes(16, "big"),
        is_directory=True,
    )


def _environment() -> WindowsProcessEnvironment:
    return WindowsProcessEnvironment(
        system_root=_directory("system_root", r"C:\Windows", 1),
        temp_directory=_directory("temp_directory", r"C:\Temp", 2),
        user_profile=_directory("user_profile", r"C:\Users\operator", 3),
        local_app_data=_directory(
            "local_app_data", r"C:\Users\operator\AppData\Local", 4
        ),
        roaming_app_data=_directory(
            "roaming_app_data", r"C:\Users\operator\AppData\Roaming", 5
        ),
    )


def _result(
    stdout: bytes,
    *,
    stderr: bytes = b"",
    exit_code: int = 0,
) -> CommandProcessResult:
    return CommandProcessResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        stdin_closed=True,
        stdout_streamed=True,
        stderr_streamed=True,
        process_tree_contained=True,
        process_tree_empty=True,
    )


class _Backend:
    supported = True

    def __init__(self, results: list[CommandProcessResult]) -> None:
        self.results = results
        self.requests: list[CommandProcessRequest] = []

    def windows_directory(self) -> str:
        return r"C:\Windows"

    def system_directory(self) -> str:
        return r"C:\Windows\System32"

    def execute(self, request: CommandProcessRequest) -> CommandProcessResult:
        self.requests.append(request)
        return self.results.pop(0)


class _UnsupportedBackend(_Backend):
    supported = False


class _WrongWindowsBackend(_Backend):
    def windows_directory(self) -> str:
        return r"D:\Windows"

    def system_directory(self) -> str:
        return r"D:\Windows\System32"


def _machine(*, identity: str = _KEY, port: int = 50222) -> bytes:
    return json.dumps(
        [
            {
                "Name": _MACHINE,
                "VMType": "wsl",
                "State": "running",
                "Rootful": False,
                "SSHConfig": {
                    "RemoteUsername": "operator",
                    "Port": port,
                    "IdentityPath": identity,
                },
            }
        ]
    ).encode()


def _open(
    product: RuntimeProduct,
    backend: _Backend,
    *,
    package: PackageEnvironmentInputs | None = None,
) -> tuple[Any, _Owner, _Owner]:
    backend.results *= 3
    package_owner = _Owner(package or _package(engine=product.value))
    runtime_owner = _Owner(_source(product))
    environment_owner = _Owner(_environment())
    owner = _open_engine_acceleration_evidence(
        package_owner=package_owner,
        runtime_owner=runtime_owner,
        environment_owner=environment_owner,
        backend=backend,
    )
    return owner, package_owner, runtime_owner


def test_docker_probe_is_endpoint_bound_fixed_and_deterministic() -> None:
    output = b'{"runc":{"path":"runc"},"nvidia":{"path":"/usr/bin/nvidia-container-runtime"}}'
    backend = _Backend([_result(output), _result(output)])
    owner, _, _ = _open(RuntimeProduct.DOCKER, backend)

    first = owner.capture()
    request = backend.requests[0]

    assert first.attestation.docker_gpu_ready is True
    assert first.attestation.podman_cdi_ready is False
    assert request.arguments == (
        "--host",
        "npipe:////./pipe/dockerDesktopLinuxEngine",
        "info",
        "--format",
        "{{json .Runtimes}}",
    )
    assert request.environment == (
        ("SystemRoot", r"C:\Windows"),
        ("WINDIR", r"C:\Windows"),
    )
    assert (
        owner.capture().attestation.probe_evidence_sha256
        == first.attestation.probe_evidence_sha256
    )


def test_snapshot_returns_exact_second_stable_captures_and_redacts_repr() -> None:
    package_first = _package(engine="docker")
    package_second = replace(package_first)
    source_first = _source(RuntimeProduct.DOCKER)
    source_second = replace(source_first)
    environment_first = _environment()
    environment_second = replace(environment_first)
    package_owner = _SequenceOwner([package_first, package_second])
    runtime_owner = _SequenceOwner([source_first, source_second])
    environment_owner = _SequenceOwner([environment_first, environment_second])
    owner = BoundEngineAccelerationEvidence(
        package_owner=package_owner,
        runtime_owner=runtime_owner,
        environment_owner=environment_owner,
        backend=_Backend([_result(b'{"runc":{"path":"runc"}}')]),
    )

    snapshot = owner.capture()

    assert type(snapshot) is EngineAccelerationSnapshot
    assert snapshot.package is package_second is package_owner.last
    assert snapshot.target_source is source_second is runtime_owner.last
    assert snapshot.process_environment is environment_second is environment_owner.last
    assert len(snapshot.authority_sha256) == 64
    assert repr(snapshot) == "EngineAccelerationSnapshot(<redacted>)"
    assert _MACHINE not in repr(snapshot)
    assert _KEY not in repr(snapshot)


def test_docker_absent_nvidia_runtime_is_attested_not_ready() -> None:
    owner, _, _ = _open(
        RuntimeProduct.DOCKER,
        _Backend([_result(b'{"runc":{"path":"runc"}}')]),
    )
    assert owner.capture().attestation.docker_gpu_ready is False


def test_gpu_off_uses_retained_environment_without_executing_probe() -> None:
    backend = _UnsupportedBackend([])
    owner, _, _ = _open(
        RuntimeProduct.DOCKER,
        backend,
        package=_package(engine="docker", mode=GpuMode.OFF),
    )
    evidence = owner.capture()
    assert evidence.attestation.docker_gpu_ready is False
    assert backend.requests == []


def test_backend_windows_directory_must_match_retained_environment() -> None:
    backend = _WrongWindowsBackend([_result(b'{"runc":{"path":"runc"}}')])
    with pytest.raises(AccelerationProbeError) as captured:
        _open(RuntimeProduct.DOCKER, backend)
    assert captured.value.code is AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE


@pytest.mark.parametrize(
    "output",
    [
        b'{"nvidia":{"path":"nvidia-container-runtime"},"nvidia":{}}',
        b'{"nvidia":{"path":"evil-runtime"}}',
        b"[]",
    ],
)
def test_docker_malformed_or_ambiguous_evidence_fails_closed(output: bytes) -> None:
    with pytest.raises(AccelerationProbeError) as captured:
        _open(RuntimeProduct.DOCKER, _Backend([_result(output)]))
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_INVALID
    assert output.decode(errors="ignore") not in str(captured.value)


def test_podman_probe_binds_machine_endpoint_key_and_read_only_commands() -> None:
    results = [
        _result(_machine()),
        _result(b"GPU 0: NVIDIA T1000 (UUID: GPU-abcd)\n"),
        _result(b"nvidia.com/gpu=0\nnvidia.com/gpu=all\n"),
    ] * 2
    backend = _Backend(results)
    owner, _, _ = _open(RuntimeProduct.PODMAN, backend)

    evidence = owner.capture()

    assert evidence.attestation.podman_cdi_ready is True
    assert evidence.attestation.docker_gpu_ready is False
    assert [request.arguments for request in backend.requests[:3]] == [
        ("machine", "inspect", _MACHINE, "--format", "json"),
        (
            "machine",
            "ssh",
            _MACHINE,
            "--",
            "/usr/lib/wsl/lib/nvidia-smi",
            "-L",
        ),
        ("machine", "ssh", _MACHINE, "--", "nvidia-ctk", "cdi", "list"),
    ]
    assert not any(
        argument in ("sudo", "generate", "install", "run", "rm")
        for request in backend.requests
        for argument in request.arguments
    )


@pytest.mark.parametrize(
    "machine_output",
    [_machine(identity=r"C:\attacker\key"), _machine(port=50223)],
)
def test_podman_machine_must_match_retained_endpoint(machine_output: bytes) -> None:
    backend = _Backend([_result(machine_output)])
    with pytest.raises(AccelerationProbeError) as captured:
        _open(RuntimeProduct.PODMAN, backend)
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_INVALID


def test_podman_missing_cdi_all_is_attested_not_ready() -> None:
    backend = _Backend(
        [
            _result(_machine()),
            _result(b"GPU 0: NVIDIA T1000 (UUID: GPU-abcd)\n"),
            _result(b"nvidia.com/gpu=0\n"),
        ]
    )
    owner, _, _ = _open(RuntimeProduct.PODMAN, backend)
    assert owner.capture().attestation.podman_cdi_ready is False


def test_benign_stderr_is_hashed_but_does_not_hide_valid_podman_evidence() -> None:
    backend = _Backend(
        [
            _result(_machine(), stderr=b"warning: remote transport"),
            _result(
                b"GPU 0: NVIDIA T1000 (UUID: GPU-abcd)\n",
                stderr=b"warning: locale",
            ),
            _result(b"nvidia.com/gpu=all\n", stderr=b"warning: scan"),
        ]
    )
    owner, _, _ = _open(RuntimeProduct.PODMAN, backend)
    assert owner.capture().attestation.podman_cdi_ready is True


def test_capability_command_failure_is_not_fabricated_as_ready() -> None:
    backend = _Backend(
        [
            _result(_machine()),
            _result(b"", stderr=b"not installed", exit_code=127),
            _result(b"", stderr=b"not installed", exit_code=127),
        ]
    )
    owner, _, _ = _open(RuntimeProduct.PODMAN, backend)
    assert owner.capture().attestation.podman_cdi_ready is False
    assert "not installed" not in repr(owner)


def test_double_capture_rejects_package_or_runtime_change() -> None:
    backend = _Backend([_result(b'{"runc":{"path":"runc"}}')])
    package_owner = _Owner(_package(engine="docker"))
    package_owner.replacement = _package(engine="docker", machine="changed")
    runtime_owner = _Owner(_source(RuntimeProduct.DOCKER))
    with pytest.raises(AccelerationProbeError) as captured:
        _open_engine_acceleration_evidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=_Owner(_environment()),
            backend=backend,
        )
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_CHANGED
    assert package_owner.closed is True
    assert runtime_owner.closed is True


def test_double_capture_rejects_process_environment_change() -> None:
    backend = _Backend([_result(b'{"runc":{"path":"runc"}}')])
    backend.results *= 2
    package_owner = _Owner(_package(engine="docker"))
    runtime_owner = _Owner(_source(RuntimeProduct.DOCKER))
    environment_owner = _Owner(_environment())
    environment_owner.replacement = replace(
        _environment(),
        system_root=_directory("system_root", r"D:\Windows", 9),
    )
    with pytest.raises(AccelerationProbeError) as captured:
        _open_engine_acceleration_evidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=environment_owner,
            backend=backend,
        )
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_CHANGED


class _RetryCloseOwner(_Owner):
    def __init__(self, value: Any, failures: int) -> None:
        super().__init__(value)
        self.failures = failures

    def close(self) -> None:
        if self.failures:
            self.failures -= 1
            raise RuntimeError("private cleanup detail")
        self.closed = True


class _InterruptCloseOwner(_Owner):
    def close(self) -> None:
        self.closed = True
        raise KeyboardInterrupt()


def test_failed_construction_retries_cleanup_until_all_owners_close() -> None:
    package_owner = _RetryCloseOwner(_package(engine="docker"), failures=2)
    runtime_owner = _RetryCloseOwner(_source(RuntimeProduct.DOCKER), failures=2)
    environment_owner = _RetryCloseOwner(_environment(), failures=2)
    with pytest.raises(AccelerationProbeError) as captured:
        _open_engine_acceleration_evidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=environment_owner,
            backend=_Backend([_result(b"not-json")]),
        )
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_INVALID
    assert all(
        owner.closed for owner in (package_owner, runtime_owner, environment_owner)
    )
    assert "private cleanup detail" not in str(captured.value)


def test_cleanup_interruption_is_preserved_after_inputs_are_closed() -> None:
    package_owner = _Owner(_package(engine="docker"))
    runtime_owner = _Owner(_source(RuntimeProduct.DOCKER))
    environment_owner = _InterruptCloseOwner(_environment())
    with pytest.raises(KeyboardInterrupt):
        _open_engine_acceleration_evidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=environment_owner,
            backend=_Backend([_result(b"not-json")]),
        )
    assert all(
        owner.closed for owner in (package_owner, runtime_owner, environment_owner)
    )


def test_engine_hint_mismatch_fails_before_any_command() -> None:
    backend = _Backend([])
    with pytest.raises(AccelerationProbeError) as captured:
        _open(RuntimeProduct.DOCKER, backend, package=_package(engine="podman"))
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_INVALID
    assert backend.requests == []


def test_close_is_complete_and_public_factory_rejects_non_owner_inputs() -> None:
    owner, package_owner, runtime_owner = _open(
        RuntimeProduct.DOCKER,
        _Backend([_result(b'{"runc":{"path":"runc"}}')]),
    )
    owner.close()
    assert owner.closed is True
    assert package_owner.closed is True
    assert runtime_owner.closed is True
    with pytest.raises(AccelerationProbeError) as captured:
        capture_native_windows_engine_acceleration_evidence(
            package_owner=object(),  # type: ignore[arg-type]
            runtime_owner=object(),  # type: ignore[arg-type]
            environment_owner=object(),  # type: ignore[arg-type]
        )
    assert captured.value.code is AccelerationProbeErrorCode.INPUTS_INVALID
