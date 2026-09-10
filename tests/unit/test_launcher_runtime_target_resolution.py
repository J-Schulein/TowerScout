from __future__ import annotations

import hashlib
import json
import sys
import threading
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    EXPECTED_HEALTHCHECK_COMMAND_SHA256,
    BoundResolvedRepairTarget,
    TargetResolutionBackend,
    TargetResolutionError,
    TargetResolutionErrorCode,
    TargetResolutionEvidence,
    TargetResolutionPlan,
    TargetResolutionSnapshot,
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    ABSENT_FILE_SHA256,
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
    ResolvedRepairTarget,
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


def _plan(
    product: RuntimeProduct = RuntimeProduct.DOCKER,
    *,
    requested: GpuMode = GpuMode.OFF,
    effective: EffectiveProfile = EffectiveProfile.CPU,
    port: int = 5000,
) -> TargetResolutionPlan:
    root = PureWindowsPath(r"C:\Users\PRIVATE-PATH\TowerScout")
    package_root = _directory("package_root", str(root), 1)
    process_environment = WindowsProcessEnvironment(
        system_root=_directory("system_root", r"C:\Windows", 50),
        temp_directory=_directory(
            "temp_directory",
            r"C:\Users\PRIVATE-PATH\AppData\Local\Temp",
            51,
        ),
        user_profile=_directory("user_profile", r"C:\Users\PRIVATE-PATH", 52),
        local_app_data=_directory(
            "local_app_data",
            r"C:\Users\PRIVATE-PATH\AppData\Local",
            53,
        ),
        roaming_app_data=_directory(
            "roaming_app_data",
            r"C:\Users\PRIVATE-PATH\AppData\Roaming",
            54,
        ),
    )
    runtime_leaf = "docker.exe" if product is RuntimeProduct.DOCKER else "podman.exe"
    runtime = RuntimeIdentity(
        product=product,
        executable=_file(
            runtime_leaf,
            rf"C:\Program Files\Runtime\{runtime_leaf}",
            2,
        ),
        version="29.5.3" if product is RuntimeProduct.DOCKER else "6.0.2",
        publisher_policy_sha256=_digest("runtime-policy"),
    )
    if product is RuntimeProduct.DOCKER:
        endpoint = EndpointIdentity(
            product=product,
            kind=EndpointKind.DOCKER_NAMED_PIPE,
            canonical_endpoint="npipe:////./pipe/dockerDesktopLinuxEngine",
            private_metadata_sha256=_digest("docker-daemon"),
        )
        compose_provider = ComposeProviderIdentity(
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
        identity_key = _file(
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
            identity_key=identity_key,
            rootless=True,
        )
        python = _file(
            "python.exe",
            r"C:\TowerScoutProvider\.venv\Scripts\python.exe",
            5,
        )
        compose_provider = ComposeProviderIdentity(
            provider_id="podman-compose-pypi-1.5.0",
            invocation_kind=ComposeInvocationKind.PODMAN_PYTHON_MODULE,
            endpoint_binding=EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
            artifacts=(
                python,
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
    overlay = {
        EffectiveProfile.CPU: "",
        EffectiveProfile.DOCKER_GPU: "compose.gpu.yaml",
        EffectiveProfile.PODMAN_GPU: "compose.gpu.podman.yaml",
    }[effective]
    ordered_files = [_file("compose.yaml", str(root / "compose.yaml"), 10)]
    if overlay:
        ordered_files.append(_file(overlay, str(root / overlay), 11))
    environment = _file(".env", str(root / ".env"), 12)
    security = SecurityArtifactInventory(
        release_manifest=_file(
            "release-manifest.v1.json",
            str(root / "release-manifest.v1.json"),
            20,
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
        compose_provider=compose_provider,
        ordered_compose_files=tuple(ordered_files),
        environment_sha256=environment.sha256,
        planned_environment_sha256=_digest("planned environment"),
        environment_source=environment,
        environment_file=environment,
        compose_project="towerscout-private",
        acceleration=AccelerationPlan(requested, effective, overlay),
        provider=MapProvider.GOOGLE,
        port=port,
        configured_image_reference=("ghcr.io/j-schulein/towerscout@sha256:" + "a" * 64),
        pinned_image_digest="sha256:" + "a" * 64,
        certificate=CertificateIdentity(
            provider=MapProvider.GOOGLE,
            windows_root_fingerprint_sha256="b" * 64,
            candidate_content_sha256="c" * 64,
        ),
    )


_BASE_ENVIRONMENT = {
    "FLASK_ENV": "production",
    "TOWERSCOUT_CONTAINER_ENGINE": "docker",
    "TOWERSCOUT_HOST_PORT": "5000",
    "TOWERSCOUT_IMAGE_DIGEST": "sha256:" + "a" * 64,
    "TOWERSCOUT_LAZY_MODEL_INIT": "1",
    "TOWERSCOUT_STARTUP_PRELOAD": "0",
    "TOWERSCOUT_DEVICE": "auto",
    "TOWERSCOUT_GPU_MODE": "off",
    "TOWERSCOUT_GPU_CONCURRENCY": "1",
    "TOWERSCOUT_PILOT_MAX_TILES": "100",
    "TOWERSCOUT_MAX_REQUEST_BODY_BYTES": "52428800",
    "TOWERSCOUT_VERIFY_ASSET_HASHES": "0",
    "TOWERSCOUT_ENABLE_MODEL_UPLOAD": "false",
    "TOWERSCOUT_MODEL_UPLOAD_KEY": "PRIVATE-ENVIRONMENT-VALUE",
    "TOWERSCOUT_TRUSTED_MODEL_SHA256": "",
    "TOWERSCOUT_ALLOW_INSECURE_TLS": "0",
    "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    "YOLO_CONFIG_DIR": "/app/webapp/cache/ultralytics",
}


def _json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _model(plan: TargetResolutionPlan, *, planned: bool) -> dict[str, Any]:
    environment = dict(_BASE_ENVIRONMENT)
    environment["TOWERSCOUT_CONTAINER_ENGINE"] = plan.runtime.product.value
    environment["TOWERSCOUT_HOST_PORT"] = str(plan.port)
    environment["TOWERSCOUT_DEVICE"] = {
        GpuMode.OFF: "cpu",
        GpuMode.AUTO: "auto",
        GpuMode.ON: "cuda",
    }[plan.acceleration.requested]
    environment["TOWERSCOUT_GPU_MODE"] = plan.acceleration.requested.value
    if planned:
        environment["REQUESTS_CA_BUNDLE"] = (
            "/app/webapp/config/certs/towerscout-ca-bundle.pem"
        )
        environment["SSL_CERT_FILE"] = (
            "/app/webapp/config/certs/towerscout-ca-bundle.pem"
        )
    if plan.acceleration.effective is EffectiveProfile.DOCKER_GPU:
        environment.update(
            {
                "NVIDIA_VISIBLE_DEVICES": "all",
                "NVIDIA_DRIVER_CAPABILITIES": "compute,utility",
            }
        )
        profile = {
            "kind": "docker_gpu",
            "devices": ["nvidia:all"],
            "security_options": [],
            "capabilities": ["gpu"],
        }
    elif plan.acceleration.effective is EffectiveProfile.PODMAN_GPU:
        environment.update(
            {
                "NVIDIA_VISIBLE_DEVICES": "all",
                "NVIDIA_DRIVER_CAPABILITIES": "compute,utility",
            }
        )
        profile = {
            "kind": "podman_gpu",
            "devices": ["nvidia.com/gpu=all"],
            "security_options": ["label=disable"],
            "capabilities": [],
        }
    else:
        profile = {
            "kind": "cpu",
            "devices": [],
            "security_options": [],
            "capabilities": [],
        }
    return {
        "schema_version": 1,
        "project": plan.compose_project,
        "service": {
            "name": "towerscout",
            "image": plan.configured_image_reference,
            "provider_config_hash": _digest(
                "planned provider config hash"
                if planned
                else "current provider config hash"
            ),
            "environment": environment,
            "port": {
                "host_ip": "127.0.0.1",
                "published": plan.port,
                "target": 5000,
                "protocol": "tcp",
            },
            "restart": "always",
            "healthcheck": {
                "command_sha256": EXPECTED_HEALTHCHECK_COMMAND_SHA256,
                "interval_seconds": 30,
                "timeout_seconds": 5,
                "start_period_seconds": 30,
                "retries": 3,
            },
            "profile": profile,
        },
        "volumes": [
            {
                "logical_name": logical_name,
                "runtime_name": f"{plan.compose_project}_{logical_name}",
                "destination": destination,
                "type": "volume",
                "read_only": False,
            }
            for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
        ],
    }


def _snapshot(plan: TargetResolutionPlan) -> TargetResolutionSnapshot:
    pre_model = _model(plan, planned=False)
    post_model = _model(plan, planned=True)
    volumes = pre_model["volumes"]
    container_id = "d" * 64
    image_id = "sha256:" + "e" * 64
    container = {
        "schema_version": 1,
        "id": container_id,
        "name": f"{plan.compose_project}-towerscout-1",
        "image_id": image_id,
        "configured_image": plan.configured_image_reference,
        "running": True,
        "labels": {
            "project": plan.compose_project,
            "service": "towerscout",
            "working_directory_sha256": plan.package_root.canonical_path_sha256,
            "compose_files_sha256": plan.compose_files_sha256,
            "config_hash": pre_model["service"]["provider_config_hash"],
        },
        "environment": pre_model["service"]["environment"],
        "ports": [pre_model["service"]["port"]],
        "restart": pre_model["service"]["restart"],
        "healthcheck": pre_model["service"]["healthcheck"],
        "profile": pre_model["service"]["profile"],
        "security": {
            "privileged": False,
            "host_network": False,
            "host_pid": False,
            "host_ipc": False,
            "host_uts": False,
            "host_userns": False,
            "read_only_rootfs": False,
            "command_overridden": False,
            "entrypoint_overridden": False,
            "capabilities_added": [],
            "devices": pre_model["service"]["profile"]["devices"],
            "security_options": pre_model["service"]["profile"]["security_options"],
            "gpu_capabilities": pre_model["service"]["profile"]["capabilities"],
        },
        "networks": [f"{plan.compose_project}_default"],
        "mounts": [
            {
                "type": "volume",
                "name": item["runtime_name"],
                "destination": item["destination"],
                "read_write": True,
            }
            for item in volumes
        ],
    }
    image = {
        "schema_version": 1,
        "id": image_id,
        "repository_digests": [plan.configured_image_reference],
    }
    volume_inspects = tuple(
        (
            logical_name,
            _json(
                {
                    "schema_version": 1,
                    "name": f"{plan.compose_project}_{logical_name}",
                    "driver": "local",
                    "scope": "local",
                    "options": {},
                    "project": plan.compose_project,
                    "logical_name": logical_name,
                    "mountpoint_sha256": _digest(f"mountpoint-{logical_name}"),
                    "engine_metadata_sha256": _digest(f"metadata-{logical_name}"),
                }
            ),
        )
        for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
    )
    return TargetResolutionSnapshot(
        authority_sha256=plan.authority_sha256,
        normalized_pre_model=_json(pre_model),
        normalized_post_model=_json(post_model),
        container_list=_json([container_id]),
        container_inspect=_json(container),
        image_inspect=_json(image),
        volume_inspects=volume_inspects,
    )


class _Backend(TargetResolutionBackend):
    def __init__(
        self,
        *snapshots: TargetResolutionSnapshot,
        supported: bool = True,
        failure: BaseException | None = None,
    ) -> None:
        self._snapshots = list(snapshots)
        self._supported = supported
        self._failure = failure
        self._closed = False
        self.calls = 0
        self.close_calls = 0

    @property
    def supported(self) -> bool:
        return self._supported and not self._closed

    @property
    def closed(self) -> bool:
        return self._closed

    def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot:
        assert type(plan) is TargetResolutionPlan
        if self._closed:
            raise RuntimeError("PRIVATE CLOSED BACKEND DETAIL")
        self.calls += 1
        if self._failure is not None:
            raise self._failure
        if not self._snapshots:
            raise RuntimeError("PRIVATE BACKEND DETAIL")
        return self._snapshots.pop(0)

    def close(self) -> None:
        self.close_calls += 1
        self._closed = True


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_capture_resolves_exact_cpu_target_for_both_runtimes(
    product: RuntimeProduct,
) -> None:
    plan = _plan(product)
    snapshot = _snapshot(plan)
    backend = _Backend(snapshot, snapshot)

    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    assert type(owner) is BoundResolvedRepairTarget
    assert type(owner.target) is ResolvedRepairTarget
    assert type(owner.evidence) is TargetResolutionEvidence
    assert owner.target.runtime.product is product
    assert (
        owner.target.compose.pre_model_sha256 != owner.target.compose.post_model_sha256
    )
    assert len(owner.target.volumes) == 8
    assert backend.calls == 2
    assert owner.evidence.capture_count == 2
    assert owner.evidence.runtime_mutation_performed is False
    assert "PRIVATE" not in repr(owner)
    assert "PRIVATE" not in repr(owner.evidence)
    assert "PRIVATE" not in repr(owner.target)
    assert "PRIVATE" not in repr(snapshot)
    owner.close()
    assert owner.closed is True


@pytest.mark.parametrize(
    ("product", "requested", "effective"),
    [
        (RuntimeProduct.DOCKER, GpuMode.ON, EffectiveProfile.DOCKER_GPU),
        (RuntimeProduct.PODMAN, GpuMode.AUTO, EffectiveProfile.PODMAN_GPU),
    ],
)
def test_capture_resolves_exact_gpu_overlay_profiles(
    product: RuntimeProduct,
    requested: GpuMode,
    effective: EffectiveProfile,
) -> None:
    plan = _plan(product, requested=requested, effective=effective)
    snapshot = _snapshot(plan)

    owner = capture_bound_resolved_repair_target(
        plan, backend=_Backend(snapshot, snapshot)
    )

    assert owner.target.acceleration == plan.acceleration
    assert len(owner.target.compose.ordered_files) == 2
    owner.close()


def test_capture_supports_authenticated_absent_environment_source() -> None:
    present = _plan()
    template = _file(
        ".env.example",
        str(present.package_root.final_path / ".env.example"),
        70,
    )
    plan = replace(
        present,
        environment_sha256=ABSENT_FILE_SHA256,
        environment_source=template,
        environment_file=None,
    )
    snapshot = _snapshot(plan)

    owner = capture_bound_resolved_repair_target(
        plan, backend=_Backend(snapshot, snapshot)
    )

    assert owner.target.compose.environment_file is None
    assert owner.target.compose.environment_source.logical_name == ".env.example"
    owner.close()


def test_capture_preserves_azure_provider_binding() -> None:
    google = _plan()
    plan = replace(
        google,
        provider=MapProvider.AZURE,
        certificate=replace(google.certificate, provider=MapProvider.AZURE),
    )
    snapshot = _snapshot(plan)

    owner = capture_bound_resolved_repair_target(
        plan, backend=_Backend(snapshot, snapshot)
    )

    assert owner.target.provider is MapProvider.AZURE
    assert owner.target.certificate.provider is MapProvider.AZURE
    owner.close()


def _replace_json(
    snapshot: TargetResolutionSnapshot,
    field: str,
    mutate: Any,
) -> TargetResolutionSnapshot:
    raw = {
        "normalized_pre_model": snapshot.normalized_pre_model,
        "normalized_post_model": snapshot.normalized_post_model,
        "container_list": snapshot.container_list,
        "container_inspect": snapshot.container_inspect,
        "image_inspect": snapshot.image_inspect,
    }.get(field)
    if raw is None:
        raise AssertionError("Unsupported test snapshot field.")
    value = json.loads(raw)
    mutate(value)
    encoded = _json(value)
    if field == "normalized_pre_model":
        return replace(snapshot, normalized_pre_model=encoded)
    if field == "normalized_post_model":
        return replace(snapshot, normalized_post_model=encoded)
    if field == "container_list":
        return replace(snapshot, container_list=encoded)
    if field == "container_inspect":
        return replace(snapshot, container_inspect=encoded)
    if field == "image_inspect":
        return replace(snapshot, image_inspect=encoded)
    raise AssertionError("Unsupported test snapshot field.")


@pytest.mark.parametrize(
    ("field", "mutate"),
    [
        ("normalized_pre_model", lambda value: value.update(project="other")),
        (
            "normalized_pre_model",
            lambda value: value.update(extra_service={"name": "attacker"}),
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"].update(build={"context": "."}),
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"].update(restart="no"),
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"]["port"].update(host_ip="0.0.0.0"),
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"]["environment"].update(
                TOWERSCOUT_ALLOW_INSECURE_TLS="1"
            ),
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"]["environment"].update(
                TOWERSCOUT_DEVICE="bananas"
            ),
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"]["environment"].update(
                TOWERSCOUT_MODEL_UPLOAD_KEY="line-one\nline-two"
            ),
        ),
        (
            "normalized_pre_model",
            lambda value: value["volumes"][0].update(type="bind"),
        ),
        (
            "normalized_pre_model",
            lambda value: value["volumes"].reverse(),
        ),
        (
            "normalized_post_model",
            lambda value: value["service"]["environment"].update(
                FLASK_ENV="development"
            ),
        ),
        (
            "normalized_post_model",
            lambda value: value["service"]["environment"].update(
                REQUESTS_CA_BUNDLE="/tmp/attacker.pem"
            ),
        ),
    ],
)
def test_compose_policy_rejects_unapproved_or_non_ca_model_changes(
    field: str,
    mutate: Any,
) -> None:
    plan = _plan()
    snapshot = _replace_json(_snapshot(plan), field, mutate)

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID


def test_numeric_json_fields_require_exact_integer_types() -> None:
    plan = _plan(port=1)
    cases = (
        (
            "normalized_pre_model",
            lambda value: value["service"]["port"].update(published=True),
            TargetResolutionErrorCode.MODEL_INVALID,
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"]["port"].update(target=5000.0),
            TargetResolutionErrorCode.MODEL_INVALID,
        ),
        (
            "normalized_pre_model",
            lambda value: value["service"]["healthcheck"].update(interval_seconds=30.0),
            TargetResolutionErrorCode.MODEL_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["ports"][0].update(published=True),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["ports"][0].update(target=5000.0),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["healthcheck"].update(interval_seconds=30.0),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
    )

    for field, mutate, expected_code in cases:
        snapshot = _replace_json(_snapshot(plan), field, mutate)
        with pytest.raises(TargetResolutionError) as caught:
            capture_bound_resolved_repair_target(
                plan, backend=_Backend(snapshot, snapshot)
            )
        assert caught.value.code is expected_code


def test_profile_device_policy_is_enforced_across_all_observations() -> None:
    plan = _plan()
    snapshot = _snapshot(plan)
    for field in (
        "normalized_pre_model",
        "normalized_post_model",
        "container_inspect",
    ):
        snapshot = _replace_json(
            snapshot,
            field,
            lambda value: (
                value["service"]["environment"].update(TOWERSCOUT_DEVICE="bananas")
                if "service" in value
                else value["environment"].update(TOWERSCOUT_DEVICE="bananas")
            ),
        )

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID


def test_compose_derived_volume_name_cannot_be_substituted_consistently() -> None:
    plan = _plan()
    snapshot = _snapshot(plan)
    replacement_name = "attacker_towerscout_config"
    for field in ("normalized_pre_model", "normalized_post_model"):
        snapshot = _replace_json(
            snapshot,
            field,
            lambda value: value["volumes"][0].update(runtime_name=replacement_name),
        )
    snapshot = _replace_json(
        snapshot,
        "container_inspect",
        lambda value: value["mounts"][0].update(name=replacement_name),
    )
    logical_name, raw = snapshot.volume_inspects[0]
    volume = json.loads(raw)
    volume["name"] = replacement_name
    snapshot = replace(
        snapshot,
        volume_inspects=((logical_name, _json(volume)), *snapshot.volume_inspects[1:]),
    )

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("compose", TargetResolutionErrorCode.MODEL_INVALID),
        ("container", TargetResolutionErrorCode.TARGET_INVALID),
        ("image", TargetResolutionErrorCode.TARGET_INVALID),
        ("volume", TargetResolutionErrorCode.TARGET_INVALID),
    ],
)
def test_schema_version_rejects_json_boolean(
    target: str,
    code: TargetResolutionErrorCode,
) -> None:
    plan = _plan()
    snapshot = _snapshot(plan)
    if target == "compose":
        snapshot = _replace_json(
            snapshot,
            "normalized_pre_model",
            lambda value: value.update(schema_version=True),
        )
        snapshot = _replace_json(
            snapshot,
            "normalized_post_model",
            lambda value: value.update(schema_version=True),
        )
    elif target in {"container", "image"}:
        field = f"{target}_inspect"
        snapshot = _replace_json(
            snapshot,
            field,
            lambda value: value.update(schema_version=True),
        )
    else:
        logical_name, raw = snapshot.volume_inspects[0]
        volume = json.loads(raw)
        volume["schema_version"] = True
        snapshot = replace(
            snapshot,
            volume_inspects=(
                (logical_name, _json(volume)),
                *snapshot.volume_inspects[1:],
            ),
        )

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is code


@pytest.mark.parametrize(
    ("field", "mutate", "code"),
    [
        (
            "container_list",
            lambda value: value.clear(),
            TargetResolutionErrorCode.TARGET_MISSING,
        ),
        (
            "container_list",
            lambda value: value.append("f" * 64),
            TargetResolutionErrorCode.TARGET_AMBIGUOUS,
        ),
        (
            "container_inspect",
            lambda value: value.update(running=False),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["labels"].update(project="other"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["labels"].update(config_hash="0" * 64),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["ports"][0].update(host_ip="::1"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["ports"].append(
                {
                    "host_ip": "127.0.0.1",
                    "published": 6000,
                    "target": 6000,
                    "protocol": "tcp",
                }
            ),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value.update(restart="no"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["healthcheck"].update(command_sha256="0" * 64),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["security"].update(privileged=True),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["security"].update(host_network=True),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["security"]["capabilities_added"].append("SYS_ADMIN"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["security"].update(command_overridden=True),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["networks"].append("host"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["profile"].update(kind="unapproved"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["mounts"][0].update(type="bind"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["mounts"][0].update(read_write=1),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "container_inspect",
            lambda value: value["environment"].update(FLASK_ENV="development"),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "image_inspect",
            lambda value: value.update(id="sha256:" + "0" * 64),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "image_inspect",
            lambda value: value["repository_digests"].clear(),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
        (
            "image_inspect",
            lambda value: value.update(repository_digests=[{}]),
            TargetResolutionErrorCode.TARGET_INVALID,
        ),
    ],
)
def test_actual_container_and_image_mismatches_fail_closed(
    field: str,
    mutate: Any,
    code: TargetResolutionErrorCode,
) -> None:
    plan = _plan()
    snapshot = _replace_json(_snapshot(plan), field, mutate)

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is code


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(name="other_volume"),
        lambda value: value.update(driver="remote"),
        lambda value: value.update(scope="global"),
        lambda value: value.update(project="other"),
        lambda value: value.update(logical_name="other"),
        lambda value: value.update(options={"device": "attacker"}),
        lambda value: value.update(mountpoint_sha256="not-a-hash"),
        lambda value: value.update(engine_metadata_sha256="not-a-hash"),
        lambda value: value.update(unexpected="field"),
    ],
)
def test_each_volume_identity_field_is_validated(mutate: Any) -> None:
    plan = _plan()
    snapshot = _snapshot(plan)
    logical_name, raw = snapshot.volume_inspects[0]
    value = json.loads(raw)
    mutate(value)
    volumes = ((logical_name, _json(value)), *snapshot.volume_inspects[1:])
    changed = replace(snapshot, volume_inspects=volumes)

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(changed, changed))

    assert caught.value.code is TargetResolutionErrorCode.TARGET_INVALID


def test_capture_detects_target_drift_between_two_observations() -> None:
    plan = _plan()
    first = _snapshot(plan)
    second = _replace_json(
        first,
        "container_inspect",
        lambda value: value.update(name="changed-container"),
    )

    backend = _Backend(first, second)
    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=backend)

    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert backend.closed is True
    assert backend.close_calls == 1


def test_revalidation_detects_later_target_drift() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    logical_name, raw = stable.volume_inspects[-1]
    volume = json.loads(raw)
    volume["engine_metadata_sha256"] = _digest("replacement")
    changed = replace(
        stable,
        volume_inspects=(*stable.volume_inspects[:-1], (logical_name, _json(volume))),
    )
    backend = _Backend(stable, stable, changed)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(TargetResolutionError) as caught:
        owner.assert_unchanged()

    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert owner.closed is True
    assert backend.closed is True
    calls = backend.calls
    with pytest.raises(TargetResolutionError):
        owner.assert_unchanged()
    assert backend.calls == calls
    owner.close()


def test_revalidation_drift_cannot_recover_through_aba_restoration() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    changed = _replace_json(
        stable,
        "container_inspect",
        lambda value: value.update(name="temporary-replacement"),
    )
    backend = _Backend(stable, stable, changed, stable)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(TargetResolutionError) as first:
        owner.assert_unchanged()
    with pytest.raises(TargetResolutionError) as second:
        owner.assert_unchanged()

    assert first.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert second.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert owner.closed is True
    assert backend.closed is True
    assert backend.calls == 3


def test_revalidation_returns_same_target_and_evidence_when_stable() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    owner = capture_bound_resolved_repair_target(
        plan, backend=_Backend(stable, stable, stable)
    )

    evidence = owner.assert_unchanged()

    assert evidence == owner.evidence
    owner.close()


def test_run_while_held_revalidates_before_and_after_operation() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    backend = _Backend(stable, stable, stable, stable)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    result = owner.run_while_held(
        lambda target: (target.target_token.display, "operation-result")
    )

    assert result == (owner.target.target_token.display, "operation-result")
    assert backend.calls == 4
    owner.close()
    assert backend.closed is True
    assert backend.close_calls == 1


def test_run_while_held_revalidates_after_operation_failure() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    backend = _Backend(stable, stable, stable, stable)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    def fail(_target: ResolvedRepairTarget) -> None:
        raise RuntimeError("CALLBACK FAILURE")

    with pytest.raises(RuntimeError, match="CALLBACK FAILURE"):
        owner.run_while_held(fail)

    assert backend.calls == 4
    owner.close()


def test_operation_failure_cannot_chain_into_target_change() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    changed = _replace_json(
        stable,
        "container_inspect",
        lambda value: value.update(name="changed-after-failed-operation"),
    )
    backend = _Backend(stable, stable, stable, changed)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    def fail(_target: ResolvedRepairTarget) -> None:
        raise RuntimeError("PRIVATE CALLBACK DETAIL")

    with pytest.raises(TargetResolutionError) as caught:
        owner.run_while_held(fail)

    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert owner.closed is True
    assert backend.closed is True


def test_run_while_held_rejects_target_change_after_operation() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    changed = _replace_json(
        stable,
        "container_inspect",
        lambda value: value.update(name="changed-after-operation"),
    )
    backend = _Backend(stable, stable, stable, changed, stable)
    owner = capture_bound_resolved_repair_target(
        plan,
        backend=backend,
    )

    with pytest.raises(TargetResolutionError) as caught:
        owner.run_while_held(lambda _target: "discarded-result")

    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert owner.closed is True
    assert backend.closed is True
    with pytest.raises(TargetResolutionError):
        owner.assert_unchanged()
    assert backend.calls == 4
    owner.close()


def test_run_while_held_rejects_pre_operation_drift_without_invocation() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    changed = _replace_json(
        stable,
        "container_inspect",
        lambda value: value.update(name="changed-before-operation"),
    )
    backend = _Backend(stable, stable, changed, stable)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    invoked = False

    def operation(_target: ResolvedRepairTarget) -> None:
        nonlocal invoked
        invoked = True

    with pytest.raises(TargetResolutionError) as caught:
        owner.run_while_held(operation)

    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert invoked is False
    assert owner.closed is True
    assert backend.closed is True
    assert backend.calls == 3


def test_authority_mismatch_is_rejected_before_target_construction() -> None:
    plan = _plan()
    snapshot = replace(_snapshot(plan), authority_sha256="0" * 64)

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.AUTHORITY_MISMATCH


@pytest.mark.parametrize(
    "raw",
    [
        b'\xef\xbb\xbf{"schema_version":1}',
        b'{"schema_version":NaN}',
        b'{"schema_version":1,"schema_version":1}',
        b"\xff",
        b"{",
    ],
)
def test_invalid_json_is_sanitized(raw: bytes) -> None:
    plan = _plan()
    snapshot = replace(_snapshot(plan), normalized_pre_model=raw)

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID
    assert raw[:8].decode("utf-8", errors="replace") not in str(caught.value)


@pytest.mark.parametrize(
    "value",
    [
        [0] * 513,
        "x" * 32_768,
        2**63,
        {f"k{index}": [0] * 200 for index in range(100)},
    ],
    ids=["items", "string", "integer", "nodes"],
)
def test_json_structural_limits_are_enforced(value: Any) -> None:
    plan = _plan()
    snapshot = replace(_snapshot(plan), normalized_pre_model=_json(value))

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID


def test_json_depth_limit_is_enforced() -> None:
    plan = _plan()
    value: Any = 0
    for _index in range(18):
        value = [value]
    snapshot = replace(_snapshot(plan), normalized_pre_model=_json(value))

    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=_Backend(snapshot, snapshot))

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID


def test_backend_failure_and_unsupported_state_are_sanitized() -> None:
    plan = _plan()
    for backend in (
        _Backend(supported=False),
        _Backend(failure=RuntimeError("PRIVATE BACKEND DETAIL")),
    ):
        with pytest.raises(TargetResolutionError) as caught:
            capture_bound_resolved_repair_target(plan, backend=backend)
        assert caught.value.code is TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
        assert "PRIVATE" not in str(caught.value)
        assert "PRIVATE" not in repr(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert backend.closed is True
        assert backend.close_calls == 1


@pytest.mark.parametrize("explicit_cause", [False, True])
def test_backend_target_error_chains_are_rebuilt_without_private_context(
    explicit_cause: bool,
) -> None:
    plan = _plan()

    class ChainedBackend(_Backend):
        def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot:
            assert type(plan) is TargetResolutionPlan
            try:
                raise RuntimeError("PRIVATE BACKEND DETAIL")
            except RuntimeError as error:
                if explicit_cause:
                    raise TargetResolutionError(
                        TargetResolutionErrorCode.MODEL_INVALID
                    ) from error
                raise TargetResolutionError(TargetResolutionErrorCode.MODEL_INVALID)

    backend = ChainedBackend(_snapshot(plan))
    with pytest.raises(TargetResolutionError) as caught:
        capture_bound_resolved_repair_target(plan, backend=backend)

    assert caught.value.code is TargetResolutionErrorCode.MODEL_INVALID
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert backend.closed is True


def test_owner_close_failure_is_sanitized_and_terminal() -> None:
    plan = _plan()
    snapshot = _snapshot(plan)

    class FailingCloseBackend(_Backend):
        def close(self) -> None:
            super().close()
            raise RuntimeError("PRIVATE CLOSE DETAIL")

    backend = FailingCloseBackend(snapshot, snapshot)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(TargetResolutionError) as caught:
        owner.close()

    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert owner.closed is True
    assert backend.closed is True
    owner.close()


def test_context_manager_preserves_body_error_when_close_also_fails() -> None:
    plan = _plan()
    snapshot = _snapshot(plan)

    class FailingCloseBackend(_Backend):
        def close(self) -> None:
            super().close()
            raise RuntimeError("PRIVATE CLOSE DETAIL")

    backend = FailingCloseBackend(snapshot, snapshot)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    with pytest.raises(RuntimeError, match="PRIVATE BODY DETAIL") as caught:
        with owner:
            raise RuntimeError("PRIVATE BODY DETAIL")

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert owner.closed is True
    assert backend.closed is True
    assert backend.close_calls == 1


def test_plan_rejects_runtime_endpoint_provider_and_certificate_mismatch() -> None:
    docker = _plan()
    podman = _plan(RuntimeProduct.PODMAN)
    invalid_values = (
        {"endpoint": podman.endpoint},
        {"compose_provider": podman.compose_provider},
        {
            "certificate": replace(
                docker.certificate,
                provider=MapProvider.AZURE,
            )
        },
        {"configured_image_reference": "ghcr.io/example/image:latest"},
    )
    for values in invalid_values:
        with pytest.raises(ValueError, match="invalid"):
            replace(docker, **values)


def test_plan_rejects_aliased_compose_and_environment_file_identities() -> None:
    plan = _plan(
        RuntimeProduct.DOCKER,
        requested=GpuMode.ON,
        effective=EffectiveProfile.DOCKER_GPU,
    )
    base, overlay = plan.ordered_compose_files
    aliased_overlay = replace(
        overlay,
        volume_serial=base.volume_serial,
        file_id=base.file_id,
    )
    aliased_environment = replace(
        plan.environment_source,
        volume_serial=base.volume_serial,
        file_id=base.file_id,
    )

    with pytest.raises(ValueError, match="invalid"):
        replace(plan, ordered_compose_files=(base, aliased_overlay))
    with pytest.raises(ValueError, match="invalid"):
        replace(
            plan,
            environment_source=aliased_environment,
            environment_file=aliased_environment,
            environment_sha256=aliased_environment.sha256,
        )


def test_snapshot_rejects_wrong_volume_order_and_oversized_output() -> None:
    plan = _plan()
    snapshot = _snapshot(plan)
    with pytest.raises(ValueError, match="invalid"):
        replace(snapshot, volume_inspects=tuple(reversed(snapshot.volume_inspects)))
    with pytest.raises(ValueError, match="invalid"):
        replace(snapshot, container_inspect=b"x" * (1024 * 1024 + 1))


@pytest.mark.parametrize("value", [None, (), ("0" * 64,)])
def test_evidence_rejects_malformed_volume_hash_collection(value: Any) -> None:
    plan = _plan()
    snapshot = _snapshot(plan)
    owner = capture_bound_resolved_repair_target(
        plan,
        backend=_Backend(snapshot, snapshot),
    )

    with pytest.raises(ValueError, match="invalid"):
        replace(owner.evidence, volume_inspect_sha256=value)

    owner.close()


def test_owner_rejects_use_after_close_and_serializes_close() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    entered = threading.Event()
    release = threading.Event()

    class BlockingBackend(_Backend):
        def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot:
            result = super().capture(plan)
            if self.calls == 3:
                entered.set()
                assert release.wait(5)
            return result

    backend = BlockingBackend(stable, stable, stable)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    failures: list[BaseException] = []

    def revalidate() -> None:
        try:
            owner.assert_unchanged()
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=revalidate)
    worker.start()
    assert entered.wait(5)
    closer = threading.Thread(target=owner.close)
    closer.start()
    assert closer.is_alive()
    release.set()
    worker.join(5)
    closer.join(5)
    assert not failures
    assert owner.closed is True
    with pytest.raises(TargetResolutionError) as caught:
        owner.assert_unchanged()
    assert caught.value.code is TargetResolutionErrorCode.TARGET_CHANGED


def test_concurrent_close_waits_for_backend_release_to_finish() -> None:
    plan = _plan()
    stable = _snapshot(plan)
    close_entered = threading.Event()
    release_close = threading.Event()
    second_started = threading.Event()

    class BlockingCloseBackend(_Backend):
        def close(self) -> None:
            close_entered.set()
            assert release_close.wait(5)
            super().close()

    backend = BlockingCloseBackend(stable, stable)
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    failures: list[BaseException] = []

    def close_owner(*, announce: threading.Event | None = None) -> None:
        if announce is not None:
            announce.set()
        try:
            owner.close()
        except BaseException as error:
            failures.append(error)

    first = threading.Thread(target=close_owner)
    first.start()
    assert close_entered.wait(5)
    second = threading.Thread(target=close_owner, kwargs={"announce": second_started})
    second.start()
    assert second_started.wait(5)
    assert second.is_alive()

    release_close.set()
    first.join(5)
    second.join(5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not failures
    assert owner.closed is True
    assert backend.closed is True
    assert backend.close_calls == 1


def test_module_remains_absent_from_live_launcher_paths() -> None:
    for relative in (
        "launcher/towerscout_launcher/app.py",
        "launcher/towerscout_launcher/discovery.py",
        "launcher/towerscout_launcher/repair.py",
        "launcher/towerscout_launcher/runtime_execution.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "runtime_target_resolution" not in text
