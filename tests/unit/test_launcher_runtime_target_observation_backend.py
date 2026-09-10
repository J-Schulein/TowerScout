from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_runtime_target_observation import _file, _plan  # noqa: E402
from towerscout_launcher import (  # noqa: E402
    runtime_target_observation_backend as backend_module,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    ObservationOperation,
    TargetObservationExecutionBinding,
    TargetObservationProcessPlan,
)
from towerscout_launcher.runtime_target_observation_backend import (  # noqa: E402
    OwnedTargetObservationBackend,
    TargetObservationAdapterError,
    TargetObservationAdapterErrorCode,
    TargetObservationProcessResult,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    BoundResolvedRepairTarget,
    TargetResolutionError,
    TargetResolutionErrorCode,
    TargetResolutionPlan,
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    CONTAINER_BUNDLE_DESTINATION,
    EXPECTED_VOLUME_DESTINATIONS,
    AccelerationPlan,
    EffectiveProfile,
    GpuMode,
    RuntimeProduct,
)

_HEALTHCHECK_COMMAND = (
    "import json, urllib.request; "
    "data=json.load(urllib.request.urlopen("
    "'http://127.0.0.1:5000/api/health', timeout=3)); "
    "raise SystemExit(0 if data.get('status') == 'ok' else 1)"
)
_CONFIG_HASH = hashlib.sha256(b"private provider configuration").hexdigest()
_CONTAINER_ID = "d" * 64
_NORMALIZED_IMAGE_ID = "sha256:" + "e" * 64


def _raw_image_id(plan: TargetResolutionPlan) -> str:
    return (
        _NORMALIZED_IMAGE_ID
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "e" * 64
    )


def _gpu_plan(product: RuntimeProduct) -> TargetResolutionPlan:
    plan = _plan(product)
    profile = (
        EffectiveProfile.DOCKER_GPU
        if product is RuntimeProduct.DOCKER
        else EffectiveProfile.PODMAN_GPU
    )
    overlay_name = (
        "compose.gpu.yaml"
        if product is RuntimeProduct.DOCKER
        else "compose.gpu.podman.yaml"
    )
    overlay = _file(
        overlay_name,
        str(plan.package_root.final_path / overlay_name),
        90,
    )
    return replace(
        plan,
        ordered_compose_files=(*plan.ordered_compose_files, overlay),
        acceleration=AccelerationPlan(GpuMode.ON, profile, overlay_name),
    )


def _environment(plan: TargetResolutionPlan, *, planned: bool) -> dict[str, str]:
    ca_path = (
        CONTAINER_BUNDLE_DESTINATION
        if planned
        else "/etc/ssl/certs/ca-certificates.crt"
    )
    output = {
        "FLASK_ENV": "production",
        "TOWERSCOUT_CONTAINER_ENGINE": plan.runtime.product.value,
        "TOWERSCOUT_HOST_PORT": str(plan.port),
        "TOWERSCOUT_IMAGE_DIGEST": plan.pinned_image_digest,
        "TOWERSCOUT_LAZY_MODEL_INIT": "1",
        "TOWERSCOUT_STARTUP_PRELOAD": "0",
        "TOWERSCOUT_DEVICE": (
            "cpu" if plan.acceleration.effective is EffectiveProfile.CPU else "cuda"
        ),
        "TOWERSCOUT_GPU_MODE": (
            "off" if plan.acceleration.effective is EffectiveProfile.CPU else "on"
        ),
        "TOWERSCOUT_GPU_CONCURRENCY": "1",
        "TOWERSCOUT_PILOT_MAX_TILES": "100",
        "TOWERSCOUT_MAX_REQUEST_BODY_BYTES": "52428800",
        "TOWERSCOUT_VERIFY_ASSET_HASHES": "0",
        "TOWERSCOUT_ENABLE_MODEL_UPLOAD": "false",
        "TOWERSCOUT_MODEL_UPLOAD_KEY": "PRIVATE-ENVIRONMENT-VALUE",
        "TOWERSCOUT_TRUSTED_MODEL_SHA256": "",
        "TOWERSCOUT_ALLOW_INSECURE_TLS": "0",
        "REQUESTS_CA_BUNDLE": ca_path,
        "SSL_CERT_FILE": ca_path,
        "YOLO_CONFIG_DIR": "/app/webapp/cache/ultralytics",
    }
    if plan.acceleration.effective is not EffectiveProfile.CPU:
        output.update(
            {
                "NVIDIA_VISIBLE_DEVICES": "all",
                "NVIDIA_DRIVER_CAPABILITIES": "compute,utility",
            }
        )
    return output


def _compose(plan: TargetResolutionPlan, *, planned: bool) -> dict[str, Any]:
    compose: dict[str, Any] = {
        "name": plan.compose_project,
        "services": {
            "towerscout": {
                "image": plan.configured_image_reference,
                "ports": [
                    {
                        "host_ip": "127.0.0.1",
                        "published": str(plan.port),
                        "target": 5000,
                        "protocol": "tcp",
                        "mode": "ingress",
                    }
                ],
                "environment": _environment(plan, planned=planned),
                "volumes": [
                    {
                        "type": "volume",
                        "source": logical_name,
                        "target": destination,
                        "read_only": False,
                    }
                    for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
                ],
                "healthcheck": {
                    "test": ["CMD", "python", "-c", _HEALTHCHECK_COMMAND],
                    "interval": "30s",
                    "timeout": "5s",
                    "start_period": "30s",
                    "retries": 3,
                },
                "restart": "always",
                "networks": {"default": None},
            }
        },
        "volumes": {
            logical_name: None
            for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
        },
        "networks": {"default": None},
    }
    service = compose["services"]["towerscout"]
    if plan.runtime.product is RuntimeProduct.PODMAN:
        compose.pop("name")
        compose.pop("networks")
        service.pop("networks")
        service["ports"] = [f"127.0.0.1:{plan.port}:5000"]
        service["volumes"] = [
            f"{logical_name}:{destination}"
            for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
        ]
    if plan.acceleration.effective is EffectiveProfile.DOCKER_GPU:
        service["deploy"] = {
            "resources": {
                "reservations": {
                    "devices": [
                        {
                            "driver": "nvidia",
                            "count": "all",
                            "capabilities": ["gpu"],
                        }
                    ]
                }
            }
        }
    elif plan.acceleration.effective is EffectiveProfile.PODMAN_GPU:
        service["devices"] = ["nvidia.com/gpu=all"]
        service["security_opt"] = ["label=disable"]
    return compose


def _container(plan: TargetResolutionPlan) -> dict[str, Any]:
    project_label = (
        "com.docker.compose.project"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.project"
    )
    service_label = (
        "com.docker.compose.service"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.service"
    )
    hash_label = (
        "com.docker.compose.config-hash"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.config-hash"
    )
    return {
        "Id": _CONTAINER_ID,
        "Name": "/towerscout-private-towerscout-1",
        "Image": _raw_image_id(plan),
        "Config": {
            "Image": plan.configured_image_reference,
            "Env": [
                f"{name}={value}"
                for name, value in _environment(plan, planned=False).items()
            ],
            "Labels": {
                project_label: plan.compose_project,
                service_label: "towerscout",
                hash_label: _CONFIG_HASH,
                "com.docker.compose.project.working_dir": str(
                    plan.package_root.final_path
                ),
                "com.docker.compose.project.config_files": ",".join(
                    item.logical_name for item in plan.ordered_compose_files
                ),
            },
            "Cmd": ["python", "webapp/app.py"],
            "Entrypoint": ["/app/entrypoint.sh"],
            "Healthcheck": {
                "Test": ["CMD", "python", "-c", _HEALTHCHECK_COMMAND],
                "Interval": 30_000_000_000,
                "Timeout": 5_000_000_000,
                "StartPeriod": 30_000_000_000,
                "Retries": 3,
                **(
                    {"StartInterval": 0}
                    if plan.runtime.product is RuntimeProduct.DOCKER
                    else {}
                ),
            },
        },
        "State": {"Running": True},
        "HostConfig": {
            "RestartPolicy": {"Name": "always", "MaximumRetryCount": 0},
            "Privileged": False,
            "ReadonlyRootfs": False,
            "NetworkMode": f"{plan.compose_project}_default",
            **(
                {"CgroupnsMode": "private"}
                if plan.runtime.product is RuntimeProduct.DOCKER
                else {"CgroupMode": "private"}
            ),
            "PidMode": "",
            "IpcMode": (
                "private"
                if plan.runtime.product is RuntimeProduct.DOCKER
                else "shareable"
            ),
            "UTSMode": "",
            "UsernsMode": "",
            "CapAdd": None,
            "Binds": (
                [
                    (
                        f"{plan.compose_project}_{logical_name}:{destination}:rw"
                        if plan.runtime.product is RuntimeProduct.DOCKER
                        else f"{plan.compose_project}_{logical_name}:{destination}:"
                        "nodev,rbind,rw,nosuid,rprivate"
                    )
                    for logical_name, destination in reversed(
                        EXPECTED_VOLUME_DESTINATIONS
                    )
                ]
            ),
            "Devices": (
                ["nvidia.com/gpu=all"]
                if plan.acceleration.effective is EffectiveProfile.PODMAN_GPU
                else []
            ),
            "SecurityOpt": (
                ["label=disable"]
                if plan.acceleration.effective is EffectiveProfile.PODMAN_GPU
                else []
            ),
            "DeviceRequests": (
                [
                    {
                        "Driver": "nvidia",
                        "Count": -1,
                        "DeviceIDs": None,
                        "Capabilities": [["gpu"]],
                        "Options": {},
                    }
                ]
                if plan.acceleration.effective is EffectiveProfile.DOCKER_GPU
                else []
            ),
        },
        "NetworkSettings": {
            "Ports": {
                "5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(plan.port)}]
            },
            "Networks": {f"{plan.compose_project}_default": {}},
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": f"{plan.compose_project}_{logical_name}",
                "Destination": destination,
                "RW": True,
                **(
                    {
                        "Source": (
                            "/private/engine/volumes/"
                            f"{plan.compose_project}_{logical_name}/_data"
                        ),
                        "Driver": "local",
                        "Mode": "",
                        "Options": ["nosuid", "nodev", "rbind"],
                        "Propagation": "rprivate",
                    }
                    if plan.runtime.product is RuntimeProduct.PODMAN
                    else {}
                ),
            }
            for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
        ],
    }


def _image(plan: TargetResolutionPlan) -> dict[str, Any]:
    return {
        "Id": _raw_image_id(plan),
        "RepoDigests": [plan.configured_image_reference],
        "Config": {
            "Cmd": ["python", "webapp/app.py"],
            "Entrypoint": ["/app/entrypoint.sh"],
        },
    }


def _volume(plan: TargetResolutionPlan, logical_name: str) -> dict[str, Any]:
    project_label = (
        "com.docker.compose.project"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.project"
    )
    logical_label = (
        "com.docker.compose.volume"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.volume"
    )
    return {
        "Name": f"{plan.compose_project}_{logical_name}",
        "Driver": "local",
        "Scope": "local",
        "Options": {},
        "Labels": {
            project_label: plan.compose_project,
            logical_label: logical_name,
        },
        "Mountpoint": f"/private/engine/volumes/{logical_name}/_data",
    }


def _encode_compose(plan: TargetResolutionPlan, value: dict[str, Any]) -> bytes:
    if plan.runtime.product is RuntimeProduct.DOCKER:
        return json.dumps(value, separators=(",", ":")).encode("utf-8")
    rendered: str = yaml.safe_dump(value, sort_keys=True)
    return rendered.encode("utf-8")


class _Authority:
    def __init__(self, plan: TargetResolutionPlan) -> None:
        self.authority_sha256 = plan.authority_sha256
        self.closed = False
        self.active = False
        self.calls = 0
        self.close_calls = 0
        self.failure: BaseException | None = None
        self.close_failure: BaseException | None = None

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert self.closed is False
        assert self.active is False
        self.calls += 1
        self.active = True
        try:
            if self.failure is not None:
                raise self.failure
            return operation()
        finally:
            self.active = False

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_failure is not None:
            raise self.close_failure


class _Executor:
    def __init__(self, plan: TargetResolutionPlan, authority: _Authority) -> None:
        self._plan = plan
        self._authority = authority
        self.supported = True
        self.closed = False
        self.close_calls = 0
        self.calls: list[tuple[ObservationOperation, str | None]] = []
        self.overrides: dict[tuple[ObservationOperation, str | None], bytes] = {}
        self.exit_code = 0
        self.force_provider_child: bool | None = None
        self.result_authority: str | None = None
        self.failure: Exception | None = None
        self.close_failure: BaseException | None = None

    def _raw(self, process: TargetObservationProcessPlan) -> bytes:
        key = (process.operation, process.selector)
        if key in self.overrides:
            return self.overrides[key]
        if process.operation is ObservationOperation.COMPOSE_MODEL_CURRENT:
            return _encode_compose(self._plan, _compose(self._plan, planned=False))
        if process.operation is ObservationOperation.COMPOSE_MODEL_PLANNED:
            return _encode_compose(self._plan, _compose(self._plan, planned=True))
        if process.operation is ObservationOperation.CONTAINER_LIST:
            return (_CONTAINER_ID + "\r\n").encode("ascii")
        if process.operation is ObservationOperation.CONTAINER_INSPECT:
            value: Any = [_container(self._plan)]
        elif process.operation is ObservationOperation.IMAGE_INSPECT:
            value = [_image(self._plan)]
        else:
            logical_name = (process.selector or "").removeprefix(
                f"{self._plan.compose_project}_"
            )
            value = [_volume(self._plan, logical_name)]
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    def execute(
        self, process: TargetObservationProcessPlan
    ) -> TargetObservationProcessResult:
        assert self.closed is False
        assert self._authority.active is True
        assert process.target is self._plan
        if self.failure is not None:
            raise self.failure
        self.calls.append((process.operation, process.selector))
        provider_required = (
            self._plan.runtime.product is RuntimeProduct.PODMAN
            and process.operation
            in {
                ObservationOperation.COMPOSE_MODEL_CURRENT,
                ObservationOperation.COMPOSE_MODEL_PLANNED,
            }
        )
        result = TargetObservationProcessResult.from_plan(
            process,
            stdout=self._raw(process),
            stderr=b"PRIVATE STDERR THAT MUST NOT ESCAPE",
            exit_code=self.exit_code,
            provider_child_claimed=(
                provider_required
                if self.force_provider_child is None
                else self.force_provider_child
            ),
            provider_child_claim_sha256=(
                hashlib.sha256(b"held provider-child evidence").hexdigest()
                if (
                    provider_required
                    if self.force_provider_child is None
                    else self.force_provider_child
                )
                else None
            ),
        )
        if self.result_authority is not None:
            result = replace(result, authority_sha256=self.result_authority)
        return result

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_failure is not None:
            raise self.close_failure


def _backend(
    product: RuntimeProduct = RuntimeProduct.DOCKER,
) -> tuple[TargetResolutionPlan, _Authority, _Executor, OwnedTargetObservationBackend]:
    plan = _plan(product)
    return _backend_for_plan(plan)


def _backend_for_plan(
    plan: TargetResolutionPlan,
) -> tuple[TargetResolutionPlan, _Authority, _Executor, OwnedTargetObservationBackend]:
    authority = _Authority(plan)
    executor = _Executor(plan, authority)
    backend = OwnedTargetObservationBackend(
        plan,
        authority=authority,
        executor=executor,
    )
    return plan, authority, executor, backend


def _assert_no_exception_chain(error: BaseException) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_owned_backend_normalizes_provider_output_into_resolved_target(
    product: RuntimeProduct,
) -> None:
    plan, authority, executor, backend = _backend(product)

    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    assert type(owner) is BoundResolvedRepairTarget
    assert owner.target.runtime.product is product
    assert owner.target.container.container_id == _CONTAINER_ID
    assert owner.target.image.daemon_image_id == _NORMALIZED_IMAGE_ID
    assert len(owner.target.volumes) == len(EXPECTED_VOLUME_DESTINATIONS)
    assert authority.calls == 2
    assert len(executor.calls) == 2 * (5 + len(EXPECTED_VOLUME_DESTINATIONS))
    assert executor.calls[:5] == [
        (ObservationOperation.COMPOSE_MODEL_CURRENT, None),
        (ObservationOperation.COMPOSE_MODEL_PLANNED, None),
        (ObservationOperation.CONTAINER_LIST, None),
        (ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID),
        (ObservationOperation.IMAGE_INSPECT, _raw_image_id(plan)),
    ]
    assert executor.calls[5:13] == [
        (
            ObservationOperation.VOLUME_INSPECT,
            f"{plan.compose_project}_{logical_name}",
        )
        for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
    ]
    assert "PRIVATE" not in repr(owner)
    assert "PRIVATE" not in repr(backend)
    owner.close()
    assert authority.close_calls == 1
    assert executor.close_calls == 1


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_gpu_provider_shapes_normalize_into_resolved_target(
    product: RuntimeProduct,
) -> None:
    plan, _authority, _executor, backend = _backend_for_plan(_gpu_plan(product))

    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    assert owner.target.acceleration.effective is plan.acceleration.effective
    assert owner.target.image.daemon_image_id == _NORMALIZED_IMAGE_ID
    owner.close()


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_semantic_model_hashes_bind_current_and_planned_models_independently(
    product: RuntimeProduct,
) -> None:
    plan, _authority, _executor, backend = _backend(product)

    snapshot = backend.capture(plan)
    current = json.loads(snapshot.normalized_pre_model)
    planned = json.loads(snapshot.normalized_post_model)
    container = json.loads(snapshot.container_inspect)
    current_hash = current["service"]["semantic_config_sha256"]
    planned_hash = planned["service"]["semantic_config_sha256"]

    assert current_hash != planned_hash
    assert container["labels"]["semantic_config_sha256"] == current_hash
    assert container["labels"]["native_config_hash"] == _CONFIG_HASH
    assert _CONFIG_HASH not in {current_hash, planned_hash}
    backend.close()


def test_podman_compose_requires_provider_child_containment() -> None:
    plan, authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    executor.force_provider_child = False

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert (
        caught.value.code
        is TargetObservationAdapterErrorCode.PROVIDER_CONTAINMENT_REQUIRED
    )
    assert backend.closed is True
    assert authority.closed is True
    assert executor.closed is True
    assert "PRIVATE" not in str(caught.value)
    assert "PRIVATE" not in repr(caught.value)


def test_docker_engine_rejects_false_provider_child_claim() -> None:
    plan, _authority, executor, backend = _backend()
    executor.force_provider_child = True

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert (
        caught.value.code
        is TargetObservationAdapterErrorCode.PROVIDER_CONTAINMENT_REQUIRED
    )


def test_result_authority_mismatch_poison_closes_every_owner() -> None:
    plan, authority, executor, backend = _backend()
    executor.result_authority = "0" * 64

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.PROCESS_REJECTED
    assert backend.closed is True
    assert authority.close_calls == 1
    assert executor.close_calls == 1


@pytest.mark.parametrize(
    ("operation", "selector", "raw"),
    [
        (ObservationOperation.COMPOSE_MODEL_CURRENT, None, b'{"services":'),
        (ObservationOperation.COMPOSE_MODEL_CURRENT, None, b'{"a":1,"a":2}'),
        (ObservationOperation.CONTAINER_LIST, None, b"short\n"),
        (
            ObservationOperation.CONTAINER_INSPECT,
            _CONTAINER_ID,
            b'[{"Id":"PRIVATE RAW OUTPUT"}]',
        ),
    ],
)
def test_malformed_outputs_fail_closed_without_disclosure(
    operation: ObservationOperation,
    selector: str | None,
    raw: bytes,
) -> None:
    plan, _authority, executor, backend = _backend()
    executor.overrides[(operation, selector)] = raw

    with pytest.raises(
        (TargetObservationAdapterError, TargetResolutionError)
    ) as caught:
        backend.capture(plan)

    assert "PRIVATE" not in str(caught.value)
    assert "PRIVATE" not in repr(caught.value)
    _assert_no_exception_chain(caught.value)
    assert backend.closed is True


def test_duplicate_podman_yaml_member_is_rejected() -> None:
    plan, _authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    executor.overrides[(ObservationOperation.COMPOSE_MODEL_CURRENT, None)] = (
        b"services: {}\nservices: {}\n"
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_podman_yaml_alias_is_rejected() -> None:
    plan, _authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    executor.overrides[(ObservationOperation.COMPOSE_MODEL_CURRENT, None)] = (
        b"services: &services {}\nvolumes: *services\n"
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID
    _assert_no_exception_chain(caught.value)


def test_podman_yaml_scanner_failure_is_sanitized_without_a_private_chain() -> None:
    plan, _authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    executor.overrides[(ObservationOperation.COMPOSE_MODEL_CURRENT, None)] = (
        b"services: [PRIVATE UNTERMINATED\n"
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID
    assert "PRIVATE" not in str(caught.value)
    _assert_no_exception_chain(caught.value)


def test_missing_yaml_dependency_is_sanitized_without_import_context() -> None:
    with patch("builtins.__import__", side_effect=ImportError("PRIVATE IMPORT")):
        with pytest.raises(TargetObservationAdapterError) as caught:
            backend_module._load_yaml(b"services: {}")

    assert caught.value.code is TargetObservationAdapterErrorCode.UNAVAILABLE
    assert "PRIVATE" not in str(caught.value)
    _assert_no_exception_chain(caught.value)


def test_compose_privileged_override_is_rejected() -> None:
    plan, _authority, executor, backend = _backend()
    dangerous = _compose(plan, planned=False)
    dangerous["services"]["towerscout"]["privileged"] = True
    executor.overrides[(ObservationOperation.COMPOSE_MODEL_CURRENT, None)] = (
        _encode_compose(plan, dangerous)
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_podman_compose_unapproved_short_volume_mode_is_rejected() -> None:
    plan, _authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    dangerous = _compose(plan, planned=False)
    dangerous["services"]["towerscout"]["volumes"][0] += ":nocopy"
    executor.overrides[(ObservationOperation.COMPOSE_MODEL_CURRENT, None)] = (
        _encode_compose(plan, dangerous)
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["HostConfig"].update(NetworkMode="host"),
        lambda value: value["HostConfig"].update(IpcMode="host"),
        lambda value: value["HostConfig"].update(Privileged=True),
        lambda value: value["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
        lambda value: value["HostConfig"].update(
            Binds=[r"C:\private-host:/app/webapp/data:rw"]
        ),
        lambda value: value["Config"].update(Cmd=["attacker"]),
        lambda value: value["Config"].update(User="root"),
        lambda value: value["Config"].update(WorkingDir="/private/attacker"),
        lambda value: value["Mounts"][0].update(Name="attacker_volume"),
        lambda value: value["NetworkSettings"]["Networks"].update(host={}),
    ],
)
def test_container_security_or_identity_drift_is_rejected(
    mutation: Callable[[dict[str, Any]], Any],
) -> None:
    plan, _authority, executor, backend = _backend()
    value = _container(plan)
    mutation(value)
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([value], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_nonzero_docker_health_start_interval_is_rejected() -> None:
    plan, _authority, executor, backend = _backend()
    value = _container(plan)
    value["Config"]["Healthcheck"]["StartInterval"] = 1_000_000_000
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([value], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


@pytest.mark.parametrize("product", [RuntimeProduct.DOCKER, RuntimeProduct.PODMAN])
def test_host_cgroup_namespace_is_rejected(product: RuntimeProduct) -> None:
    plan, _authority, executor, backend = _backend(product)
    value = _container(plan)
    mode_name = "CgroupnsMode" if product is RuntimeProduct.DOCKER else "CgroupMode"
    value["HostConfig"][mode_name] = "host"
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([value], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


@pytest.mark.parametrize(
    "mutation",
    [
        lambda binds: binds.__setitem__(0, binds[0].replace("rw,", "ro,")),
        lambda binds: binds.__setitem__(0, binds[0].replace(",rbind", "")),
        lambda binds: binds.__setitem__(0, binds[0] + ",shared"),
        lambda binds: binds.__setitem__(0, binds[0].replace("nodev", "rbind")),
        lambda binds: binds.__setitem__(0, binds[0].replace("towerscout_", "host_")),
    ],
)
def test_podman_named_volume_bind_drift_is_rejected(
    mutation: Callable[[list[str]], Any],
) -> None:
    plan, _authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    value = _container(plan)
    mutation(value["HostConfig"]["Binds"])
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([value], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_podman_named_volume_mount_option_drift_is_rejected() -> None:
    plan, _authority, executor, backend = _backend(RuntimeProduct.PODMAN)
    value = _container(plan)
    value["Mounts"][0]["Propagation"] = "rshared"
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([value], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_image_selector_cannot_change_between_container_and_image_inspect() -> None:
    plan, _authority, executor, backend = _backend()
    value = _image(plan)
    value["Id"] = "sha256:" + "f" * 64
    executor.overrides[(ObservationOperation.IMAGE_INSPECT, _raw_image_id(plan))] = (
        json.dumps([value], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_image_default_environment_is_allowed_but_not_added_to_target_model() -> None:
    plan, _authority, executor, backend = _backend()
    image = _image(plan)
    image["Config"]["Env"] = ["PATH=/trusted/image/path", "LANG=C.UTF-8"]
    container = _container(plan)
    container["Config"]["Env"].extend(image["Config"]["Env"])
    executor.overrides[(ObservationOperation.IMAGE_INSPECT, _raw_image_id(plan))] = (
        json.dumps([image], separators=(",", ":")).encode("utf-8")
    )
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([container], separators=(",", ":")).encode("utf-8")
    )

    owner = capture_bound_resolved_repair_target(plan, backend=backend)

    assert owner.target.container.container_id == _CONTAINER_ID
    owner.close()


def test_changed_image_default_environment_is_rejected() -> None:
    plan, _authority, executor, backend = _backend()
    image = _image(plan)
    image["Config"]["Env"] = ["PATH=/trusted/image/path"]
    container = _container(plan)
    container["Config"]["Env"].append("PATH=/attacker/path")
    executor.overrides[(ObservationOperation.IMAGE_INSPECT, _raw_image_id(plan))] = (
        json.dumps([image], separators=(",", ":")).encode("utf-8")
    )
    executor.overrides[(ObservationOperation.CONTAINER_INSPECT, _CONTAINER_ID)] = (
        json.dumps([container], separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID


def test_volume_project_and_mountpoint_are_validated_but_only_hashed() -> None:
    plan, _authority, executor, backend = _backend()
    logical_name = EXPECTED_VOLUME_DESTINATIONS[0][0]
    value = _volume(plan, logical_name)
    value["Labels"]["com.docker.compose.project"] = "attacker"
    executor.overrides[
        (
            ObservationOperation.VOLUME_INSPECT,
            f"{plan.compose_project}_{logical_name}",
        )
    ] = json.dumps([value], separators=(",", ":")).encode("utf-8")

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.OUTPUT_INVALID
    assert "/private/engine" not in repr(caught.value)


def test_missing_and_ambiguous_container_selection_preserve_resolution_codes() -> None:
    for raw, expected in (
        (b"", TargetResolutionErrorCode.TARGET_MISSING),
        (
            (_CONTAINER_ID + "\n" + "f" * 64 + "\n").encode("ascii"),
            TargetResolutionErrorCode.TARGET_AMBIGUOUS,
        ),
    ):
        plan, _authority, executor, backend = _backend()
        executor.overrides[(ObservationOperation.CONTAINER_LIST, None)] = raw
        with pytest.raises(TargetResolutionError) as caught:
            backend.capture(plan)
        assert caught.value.code is expected


def test_nonzero_exit_is_sanitized_and_poisoned() -> None:
    plan, _authority, executor, backend = _backend()
    executor.exit_code = 17

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.PROCESS_FAILED
    assert "17" not in str(caught.value)
    assert backend.closed is True


@pytest.mark.parametrize("typed", [False, True])
def test_executor_failure_is_sanitized_without_a_private_chain(typed: bool) -> None:
    plan, _authority, executor, backend = _backend()
    private = RuntimeError("PRIVATE EXECUTOR FAILURE")
    if typed:
        failure = TargetObservationAdapterError(
            TargetObservationAdapterErrorCode.PROCESS_FAILED
        )
        failure.__cause__ = private
        executor.failure = failure
    else:
        executor.failure = private

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.PROCESS_FAILED
    assert "PRIVATE" not in str(caught.value)
    assert "PRIVATE" not in repr(caught.value)
    _assert_no_exception_chain(caught.value)
    assert backend.closed is True


def test_authority_failure_is_sanitized_and_poisoned() -> None:
    plan, authority, _executor, backend = _backend()
    authority.failure = RuntimeError("PRIVATE AUTHORITY FAILURE")

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.AUTHORITY_CHANGED
    assert "PRIVATE" not in str(caught.value)
    assert "PRIVATE" not in repr(caught.value)
    _assert_no_exception_chain(caught.value)
    assert backend.closed is True


def test_constructor_rejects_mismatched_authority_without_consuming_details() -> None:
    plan = _plan()
    other = _plan(RuntimeProduct.PODMAN)
    authority = _Authority(other)
    executor = _Executor(plan, authority)

    with pytest.raises(TargetObservationAdapterError) as caught:
        OwnedTargetObservationBackend(plan, authority=authority, executor=executor)

    assert caught.value.code is TargetObservationAdapterErrorCode.UNAVAILABLE
    assert authority.close_calls == 1
    assert executor.close_calls == 1
    _assert_no_exception_chain(caught.value)


def test_constructor_rejects_aliased_resources_and_closes_once() -> None:
    plan = _plan()

    class _AliasedResource:
        authority_sha256 = plan.authority_sha256
        closed = False
        supported = True

        def __init__(self) -> None:
            self.close_calls = 0

        def run_while_held(self, operation: Callable[[], Any]) -> Any:
            return operation()

        def execute(
            self, process: TargetObservationProcessPlan
        ) -> TargetObservationProcessResult:
            raise AssertionError(process)

        def close(self) -> None:
            self.close_calls += 1
            self.closed = True

    resource = _AliasedResource()
    with pytest.raises(TargetObservationAdapterError) as caught:
        OwnedTargetObservationBackend(
            plan,
            authority=resource,
            executor=resource,
        )

    assert caught.value.code is TargetObservationAdapterErrorCode.UNAVAILABLE
    assert resource.close_calls == 1


@pytest.mark.parametrize("interrupting_resource", ["authority", "executor"])
def test_constructor_closes_every_resource_before_preserving_interruption(
    interrupting_resource: str,
) -> None:
    plan = _plan()

    class _InterruptingAuthority:
        closed = False

        def __init__(self) -> None:
            self.close_calls = 0

        @property
        def authority_sha256(self) -> str:
            raise KeyboardInterrupt("FIRST INTERRUPTION")

        def run_while_held(self, operation: Callable[[], Any]) -> Any:
            return operation()

        def close(self) -> None:
            self.close_calls += 1
            self.closed = True

    class _InterruptingExecutor:
        closed = False

        def __init__(self) -> None:
            self.close_calls = 0

        @property
        def supported(self) -> bool:
            raise KeyboardInterrupt("FIRST INTERRUPTION")

        def execute(
            self, process: TargetObservationProcessPlan
        ) -> TargetObservationProcessResult:
            raise AssertionError(process)

        def close(self) -> None:
            self.close_calls += 1
            self.closed = True

    authority: Any
    executor: Any
    if interrupting_resource == "authority":
        authority = _InterruptingAuthority()
        executor = _Executor(plan, authority)
        executor.close_failure = KeyboardInterrupt("SECOND INTERRUPTION")
    else:
        authority = _Authority(plan)
        authority.close_failure = KeyboardInterrupt("SECOND INTERRUPTION")
        executor = _InterruptingExecutor()

    with pytest.raises(KeyboardInterrupt, match="FIRST INTERRUPTION"):
        OwnedTargetObservationBackend(
            plan,
            authority=authority,
            executor=executor,
        )

    assert authority.close_calls == 1
    assert executor.close_calls == 1


def test_capture_requires_the_exact_bound_plan_object() -> None:
    plan, _authority, _executor, backend = _backend()
    equal_copy = deepcopy(plan)

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(equal_copy)

    assert caught.value.code is TargetObservationAdapterErrorCode.AUTHORITY_CHANGED
    assert backend.closed is False
    backend.close()


def test_process_result_enforces_plan_specific_output_limits_and_redaction() -> None:
    process = TargetObservationExecutionBinding(_plan()).container_list()
    with pytest.raises(ValueError):
        TargetObservationProcessResult.from_plan(
            process,
            stdout=b"x" * (process.stdout_limit_bytes + 1),
            stderr=b"",
            exit_code=0,
            provider_child_claimed=False,
        )
    result = TargetObservationProcessResult.from_plan(
        process,
        stdout=b"PRIVATE OUTPUT",
        stderr=b"PRIVATE ERROR",
        exit_code=0,
        provider_child_claimed=False,
    )
    assert "PRIVATE" not in repr(result)
    assert result.stderr_sha256 == hashlib.sha256(b"PRIVATE ERROR").hexdigest()


def test_backend_rejects_forged_operation_specific_output_limit() -> None:
    plan, _authority, executor, backend = _backend()
    original_execute = executor.execute

    def oversized(
        process: TargetObservationProcessPlan,
    ) -> TargetObservationProcessResult:
        result = original_execute(process)
        if process.operation is ObservationOperation.CONTAINER_LIST:
            return replace(result, stdout=b"x" * (process.stdout_limit_bytes + 1))
        return result

    executor.execute = oversized  # type: ignore[method-assign]

    with pytest.raises(TargetObservationAdapterError) as caught:
        backend.capture(plan)

    assert caught.value.code is TargetObservationAdapterErrorCode.PROCESS_REJECTED


def test_close_is_idempotent_and_closes_transferred_resources_once() -> None:
    _plan_value, authority, executor, backend = _backend()

    backend.close()
    backend.close()

    assert backend.closed is True
    assert backend.supported is False
    assert authority.close_calls == 1
    assert executor.close_calls == 1


@pytest.mark.parametrize("interrupting_resource", ["executor", "authority"])
def test_close_attempts_every_resource_before_preserving_interruption(
    interrupting_resource: str,
) -> None:
    _plan_value, authority, executor, backend = _backend()
    selected = executor if interrupting_resource == "executor" else authority
    selected.close_failure = KeyboardInterrupt("PRIVATE INTERRUPTION")

    with pytest.raises(KeyboardInterrupt):
        backend.close()

    assert authority.close_calls == 1
    assert executor.close_calls == 1
    assert backend.closed is True
