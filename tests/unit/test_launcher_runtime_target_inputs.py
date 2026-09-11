"""Focused adversarial tests for the complete retained target-input owner."""

from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

import launcher.towerscout_launcher.runtime_target_inputs as target_inputs
from launcher.towerscout_launcher.runtime_acceleration_inputs import (
    AttestedEngineAccelerationEvidence,
)
from launcher.towerscout_launcher.runtime_acceleration_probe import (
    AccelerationProbeError,
    AccelerationProbeErrorCode,
    EngineAccelerationSnapshot,
)
from launcher.towerscout_launcher.runtime_docker_inputs import DockerTargetSourceInputs
from launcher.towerscout_launcher.runtime_package_inputs import (
    PackageEnvironmentInputs,
    _package_binding,
    _ParsedPackage,
)
from launcher.towerscout_launcher.runtime_podman_inputs import PodmanTargetSourceInputs
from launcher.towerscout_launcher.runtime_target_inputs import (
    BoundNativeTargetResolutionPlanInputs,
    TargetInputError,
    TargetInputErrorCode,
    _compose_plan_inputs,
    capture_native_windows_target_resolution_plan_inputs,
)
from launcher.towerscout_launcher.target_contracts import (
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

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_IMAGE_DIGEST = "sha256:" + "e" * 64


def _file(name: str, path: str, identifier: int) -> FileIdentity:
    return FileIdentity(
        logical_name=name,
        final_path=PureWindowsPath(path),
        volume_serial=10,
        file_id=identifier.to_bytes(16, "big"),
        sha256=_A,
        size_bytes=200,
    )


def _directory(name: str, path: str, identifier: int) -> FileIdentity:
    return FileIdentity(
        logical_name=name,
        final_path=PureWindowsPath(path),
        volume_serial=10,
        file_id=identifier.to_bytes(16, "big"),
        is_directory=True,
    )


def _environment() -> WindowsProcessEnvironment:
    return WindowsProcessEnvironment(
        system_root=_directory("system_root", r"C:\Windows", 1),
        temp_directory=_directory(
            "temp_directory", r"C:\Users\operator\AppData\Local\Temp", 2
        ),
        user_profile=_directory("user_profile", r"C:\Users\operator", 3),
        local_app_data=_directory(
            "local_app_data", r"C:\Users\operator\AppData\Local", 4
        ),
        roaming_app_data=_directory(
            "roaming_app_data", r"C:\Users\operator\AppData\Roaming", 5
        ),
    )


def _runtime(product: RuntimeProduct) -> RuntimeIdentity:
    leaf = f"{product.value}.exe"
    return RuntimeIdentity(
        product=product,
        executable=_file(leaf, rf"C:\Runtime\{leaf}", 30),
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
        canonical_endpoint=(
            "ssh://operator@127.0.0.1:50222/run/user/1000/podman/podman.sock"
        ),
        private_metadata_sha256=_C,
        identity_key=_file(
            "podman_identity_key",
            r"C:\Users\operator\.local\share\containers\podman\key",
            31,
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
                _file("docker-compose.exe", r"C:\Runtime\docker-compose.exe", 32),
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
            _file("python.exe", r"C:\Provider\Scripts\python.exe", 33),
            _file(
                "podman_compose_module",
                r"C:\Provider\Lib\site-packages\podman_compose.py",
                34,
            ),
        ),
        integrity_sha256=_D,
    )
    return PodmanTargetSourceInputs(
        runtime=_runtime(product),
        endpoint=_endpoint(product),
        compose_provider=provider,
    )


def _package(
    product: RuntimeProduct,
    *,
    engine: str | None = None,
    mode: GpuMode = GpuMode.ON,
    docker_gate: bool = True,
    podman_gate: bool = True,
) -> PackageEnvironmentInputs:
    root = _directory("package_root", r"C:\TowerScout", 10)
    manifest = _file(
        "release-manifest.v1.json", r"C:\TowerScout\release-manifest.v1.json", 11
    )
    runtime_policy = _file(
        "runtime-policy.v1.json",
        r"C:\TowerScout\launcher\towerscout_launcher\runtime-policy.v1.json",
        12,
    )
    dependency_policy = _file(
        "runtime-dependency-policy.v1.json",
        r"C:\TowerScout\launcher\towerscout_launcher\runtime-dependency-policy.v1.json",
        13,
    )
    compose = tuple(
        _file(name, rf"C:\TowerScout\{name}", 14 + index)
        for index, name in enumerate(
            ("compose.yaml", "compose.gpu.yaml", "compose.gpu.podman.yaml")
        )
    )
    environment = _file(".env", r"C:\TowerScout\.env", 17)
    engine_hint = product.value if engine is None else engine
    parsed = _ParsedPackage(
        release_identity="TowerScout-test",
        compose_project="towerscout",
        requested_gpu_mode=mode,
        gpu_auto_overlay=docker_gate,
        podman_gpu_overlay=podman_gate,
        pytorch_flavor="cuda126",
        engine_hint=engine_hint,
        port=5000,
        configured_image_reference="ghcr.io/example/towerscout@" + _IMAGE_DIGEST,
        pinned_image_digest=_IMAGE_DIGEST,
        podman_machine="podman-machine-default",
        planned_environment_sha256=_B,
    )
    bound = (manifest, runtime_policy, dependency_policy, *compose, environment)
    return PackageEnvironmentInputs(
        package_root=root,
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
        gpu_auto_overlay=docker_gate,
        podman_gpu_overlay=podman_gate,
        pytorch_flavor="cuda126",
        engine_hint=engine_hint,
        port=5000,
        configured_image_reference=parsed.configured_image_reference,
        pinned_image_digest=_IMAGE_DIGEST,
        podman_machine=parsed.podman_machine,
        package_binding_sha256=_package_binding(
            root,
            bound,
            parsed,
            environment.sha256,
            parsed.planned_environment_sha256,
        ),
    )


def _snapshot(
    product: RuntimeProduct,
    *,
    engine: str | None = None,
    mode: GpuMode = GpuMode.ON,
    ready: bool = True,
    docker_gate: bool = True,
    podman_gate: bool = True,
) -> EngineAccelerationSnapshot:
    source = _source(product)
    package = _package(
        product,
        engine=engine,
        mode=mode,
        docker_gate=docker_gate,
        podman_gate=podman_gate,
    )
    return EngineAccelerationSnapshot(
        package=package,
        target_source=source,
        process_environment=_environment(),
        attestation=AttestedEngineAccelerationEvidence(
            runtime_product=product,
            runtime_executable_sha256=source.runtime.executable.sha256,
            runtime_publisher_policy_sha256=source.runtime.publisher_policy_sha256,
            endpoint_private_metadata_sha256=source.endpoint.private_metadata_sha256,
            probe_evidence_sha256=_D,
            docker_gpu_ready=ready if product is RuntimeProduct.DOCKER else False,
            podman_cdi_ready=ready if product is RuntimeProduct.PODMAN else False,
        ),
    )


class _Evidence:
    def __init__(self, snapshots: list[EngineAccelerationSnapshot]) -> None:
        self.snapshots = snapshots
        self.supported = True
        self.closed = False
        self.captures = 0
        self.close_calls = 0
        self.close_failures = 0
        self.close_interruption = False
        self.capture_error: BaseException | None = None

    def capture(self) -> EngineAccelerationSnapshot:
        self.captures += 1
        if self.capture_error is not None:
            raise self.capture_error
        return self.snapshots[min(self.captures - 1, len(self.snapshots) - 1)]

    def close(self) -> None:
        self.close_calls += 1
        if self.close_interruption:
            self.close_interruption = False
            raise KeyboardInterrupt("private interruption")
        if self.close_failures:
            self.close_failures -= 1
            raise RuntimeError("private close failure")
        self.closed = True


def _owner(
    monkeypatch: pytest.MonkeyPatch,
    snapshots: list[EngineAccelerationSnapshot],
) -> tuple[BoundNativeTargetResolutionPlanInputs, _Evidence]:
    monkeypatch.setattr(target_inputs, "BoundEngineAccelerationEvidence", _Evidence)
    evidence = _Evidence(snapshots)
    owner = BoundNativeTargetResolutionPlanInputs(
        evidence=evidence,  # type: ignore[arg-type]
        provider=MapProvider.GOOGLE,
    )
    return owner, evidence


@pytest.mark.parametrize(
    ("product", "effective", "files"),
    [
        (
            RuntimeProduct.DOCKER,
            EffectiveProfile.DOCKER_GPU,
            ("compose.yaml", "compose.gpu.yaml"),
        ),
        (
            RuntimeProduct.PODMAN,
            EffectiveProfile.PODMAN_GPU,
            ("compose.yaml", "compose.gpu.podman.yaml"),
        ),
    ],
)
def test_composes_every_plan_field_and_exact_engine_overlay(
    product: RuntimeProduct,
    effective: EffectiveProfile,
    files: tuple[str, ...],
) -> None:
    snapshot = _snapshot(product)
    result = _compose_plan_inputs(snapshot, MapProvider.AZURE)

    assert result.package_root == snapshot.package.package_root
    assert result.process_environment == snapshot.process_environment
    assert result.release_identity == snapshot.package.release_identity
    assert result.security_artifacts == snapshot.package.security_artifacts
    assert result.runtime == snapshot.target_source.runtime
    assert result.endpoint == snapshot.target_source.endpoint
    assert result.compose_provider == snapshot.target_source.compose_provider
    assert tuple(item.logical_name for item in result.ordered_compose_files) == files
    assert result.acceleration.effective is effective
    assert result.provider is MapProvider.AZURE
    assert result.port == 5000
    assert result.configured_image_reference.endswith("@" + _IMAGE_DIGEST)
    assert result.pinned_image_digest == _IMAGE_DIGEST
    assert repr(result) == "TargetResolutionPlanInputs(<redacted>)"


@pytest.mark.parametrize("engine", ["", "DOCKER", "docker,podman"])
def test_rejects_blank_or_ambiguous_engine_without_discovery(engine: str) -> None:
    snapshot = _snapshot(RuntimeProduct.DOCKER, engine="" if not engine else None)
    if engine:
        # Model a corrupted object crossing the internal boundary; the real
        # package constructor rejects these spellings before this layer.
        object.__setattr__(snapshot.package, "engine_hint", engine)

    with pytest.raises(TargetInputError) as raised:
        _compose_plan_inputs(snapshot, MapProvider.GOOGLE)

    assert raised.value.code is TargetInputErrorCode.INPUTS_INVALID
    if engine:
        assert engine not in str(raised.value)


@pytest.mark.parametrize(
    ("product", "docker_gate", "podman_gate"),
    [
        (RuntimeProduct.DOCKER, False, True),
        (RuntimeProduct.PODMAN, True, False),
    ],
)
def test_uses_only_the_selected_engines_overlay_gate(
    product: RuntimeProduct,
    docker_gate: bool,
    podman_gate: bool,
) -> None:
    snapshot = _snapshot(
        product,
        mode=GpuMode.AUTO,
        docker_gate=docker_gate,
        podman_gate=podman_gate,
    )

    result = _compose_plan_inputs(snapshot, MapProvider.GOOGLE)

    assert result.acceleration.effective is EffectiveProfile.CPU
    assert tuple(item.logical_name for item in result.ordered_compose_files) == (
        "compose.yaml",
    )


def test_owner_double_captures_one_stable_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(RuntimeProduct.DOCKER)
    owner, evidence = _owner(monkeypatch, [snapshot])

    result = owner.capture()

    assert evidence.captures == 2
    assert result.runtime.product is RuntimeProduct.DOCKER
    assert owner.supported
    assert not owner.closed
    assert repr(owner) == (
        "BoundNativeTargetResolutionPlanInputs(state='open', <redacted>)"
    )


def test_owner_rejects_changed_aggregate(monkeypatch: pytest.MonkeyPatch) -> None:
    owner, _evidence = _owner(
        monkeypatch,
        [_snapshot(RuntimeProduct.DOCKER), _snapshot(RuntimeProduct.PODMAN)],
    )

    with pytest.raises(TargetInputError) as raised:
        owner.capture()

    assert raised.value.code is TargetInputErrorCode.INPUTS_CHANGED


def test_owner_sanitizes_probe_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    owner, evidence = _owner(monkeypatch, [_snapshot(RuntimeProduct.DOCKER)])
    evidence.capture_error = AccelerationProbeError(
        AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE
    )

    with pytest.raises(TargetInputError) as raised:
        owner.capture()

    assert raised.value.code is TargetInputErrorCode.INPUTS_CHANGED
    assert "private" not in str(raised.value)


def test_close_retries_and_releases_sole_owned_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, evidence = _owner(monkeypatch, [_snapshot(RuntimeProduct.DOCKER)])
    evidence.close_failures = 2

    owner.close()

    assert evidence.close_calls == 3
    assert owner.closed
    assert not owner.supported


def test_close_releases_owner_but_preserves_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, evidence = _owner(monkeypatch, [_snapshot(RuntimeProduct.DOCKER)])
    evidence.close_interruption = True

    with pytest.raises(KeyboardInterrupt, match="private interruption"):
        owner.close()

    assert evidence.close_calls == 2
    assert owner.closed


def test_public_factory_accepts_only_provider_and_builds_internal_owners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(RuntimeProduct.DOCKER)
    package_owner = _Evidence([snapshot])
    runtime_owner = _Evidence([snapshot])
    environment_owner = _Evidence([snapshot])
    evidence = _Evidence([snapshot])
    monkeypatch.setattr(target_inputs, "BoundEngineAccelerationEvidence", _Evidence)
    monkeypatch.setattr(
        target_inputs,
        "_fixed_package_root",
        lambda: PureWindowsPath(r"C:\TowerScout"),
    )
    monkeypatch.setattr(
        target_inputs,
        "capture_native_windows_package_environment_inputs",
        lambda root: package_owner,
    )
    package_owner.capture = lambda: snapshot.package  # type: ignore[method-assign]
    monkeypatch.setattr(
        target_inputs,
        "capture_native_windows_docker_target_source_inputs",
        lambda: runtime_owner,
    )
    monkeypatch.setattr(
        target_inputs,
        "capture_native_windows_process_environment",
        lambda: environment_owner,
    )
    monkeypatch.setattr(
        target_inputs,
        "capture_native_windows_engine_acceleration_evidence",
        lambda **_kwargs: evidence,
    )

    owner = capture_native_windows_target_resolution_plan_inputs(MapProvider.AZURE)

    assert owner.capture().provider is MapProvider.AZURE
    assert evidence.captures == 4
    assert tuple(
        inspect.signature(
            capture_native_windows_target_resolution_plan_inputs
        ).parameters
    ) == ("provider",)


def test_public_factory_rejects_non_enum_provider_before_root_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def root() -> PureWindowsPath:
        nonlocal called
        called = True
        return PureWindowsPath(r"C:\TowerScout")

    monkeypatch.setattr(target_inputs, "_fixed_package_root", root)

    with pytest.raises(TargetInputError) as raised:
        capture_native_windows_target_resolution_plan_inputs("google")  # type: ignore[arg-type]

    assert raised.value.code is TargetInputErrorCode.INPUTS_INVALID
    assert not called


def test_public_factory_rejects_blank_engine_and_closes_package_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_owner = _Evidence([_snapshot(RuntimeProduct.DOCKER)])
    package_owner.capture = lambda: _package(  # type: ignore[method-assign]
        RuntimeProduct.DOCKER,
        engine="",
    )
    runtime_called = False

    def runtime() -> _Evidence:
        nonlocal runtime_called
        runtime_called = True
        return _Evidence([_snapshot(RuntimeProduct.DOCKER)])

    monkeypatch.setattr(
        target_inputs,
        "_fixed_package_root",
        lambda: PureWindowsPath(r"C:\TowerScout"),
    )
    monkeypatch.setattr(
        target_inputs,
        "capture_native_windows_package_environment_inputs",
        lambda _root: package_owner,
    )
    monkeypatch.setattr(
        target_inputs,
        "capture_native_windows_docker_target_source_inputs",
        runtime,
    )

    with pytest.raises(TargetInputError) as raised:
        capture_native_windows_target_resolution_plan_inputs(MapProvider.GOOGLE)

    assert raised.value.code is TargetInputErrorCode.INPUTS_INVALID
    assert package_owner.closed
    assert not runtime_called


def test_fixed_frozen_root_is_exactly_executable_relative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(target_inputs.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        target_inputs.sys,
        "executable",
        r"C:\TowerScout\launcher\TowerScoutLauncher.exe",
    )

    assert target_inputs._fixed_package_root() == PureWindowsPath(r"C:\TowerScout")


def test_public_source_has_no_caller_trust_or_ambient_environment_seam() -> None:
    source = Path(target_inputs.__file__).read_text(encoding="utf-8")

    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "shutil.which" not in source
    assert "from .discovery" not in source
    assert "from .app" not in source
    assert "from .repair" not in source
    assert "caller" not in str(
        inspect.signature(capture_native_windows_target_resolution_plan_inputs)
    )
    assert "backend" not in str(
        inspect.signature(capture_native_windows_target_resolution_plan_inputs)
    )


def test_error_and_snapshot_representations_are_redacted() -> None:
    error = TargetInputError(TargetInputErrorCode.INPUTS_INVALID)
    snapshot = _snapshot(RuntimeProduct.PODMAN)

    assert repr(error) == "TargetInputError(code='inputs_invalid')"
    assert repr(snapshot) == "EngineAccelerationSnapshot(<redacted>)"
    for secret in (
        str(snapshot.package.package_root.final_path),
        snapshot.package.configured_image_reference,
        snapshot.target_source.endpoint.canonical_endpoint,
    ):
        assert secret not in repr(error)
        assert secret not in repr(snapshot)


def test_environment_identity_change_is_detected_between_owner_captures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _snapshot(RuntimeProduct.DOCKER)
    changed_environment = replace(
        first.process_environment,
        temp_directory=_directory("temp_directory", r"D:\Temp", 99),
    )
    second = EngineAccelerationSnapshot(
        package=first.package,
        target_source=first.target_source,
        process_environment=changed_environment,
        attestation=first.attestation,
    )
    owner, _evidence = _owner(monkeypatch, [first, second])

    with pytest.raises(TargetInputError) as raised:
        owner.capture()

    assert raised.value.code is TargetInputErrorCode.INPUTS_CHANGED


def test_constructor_rejects_unretained_evidence() -> None:
    with pytest.raises(ValueError, match="invalid"):
        BoundNativeTargetResolutionPlanInputs(
            evidence=Any,  # type: ignore[arg-type]
            provider=MapProvider.GOOGLE,
        )
