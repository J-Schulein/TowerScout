"""Owned, read-only adapter from native observation output to target snapshots.

The adapter is intentionally not wired into the launcher.  It consumes only
the immutable process plans from :mod:`runtime_target_observation`, executes a
complete capture inside one caller-supplied authenticated ownership window,
and converts Docker JSON or Podman Compose YAML plus engine inspect JSON into
the deliberately small schemas accepted by :mod:`runtime_target_resolution`.

No raw child output is logged, persisted, or exposed through public errors.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .runtime_target_observation import (
    ObservationOperation,
    TargetObservationExecutionBinding,
    TargetObservationProcessPlan,
)
from .runtime_target_resolution import (
    EXPECTED_HEALTHCHECK_COMMAND_SHA256,
    TARGET_MODEL_SEMANTIC_HASH_PLACEHOLDER,
    TargetResolutionBackend,
    TargetResolutionError,
    TargetResolutionErrorCode,
    TargetResolutionPlan,
    TargetResolutionSnapshot,
    target_model_semantic_sha256,
)
from .target_contracts import (
    EXPECTED_VOLUME_DESTINATIONS,
    EffectiveProfile,
    RuntimeProduct,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_DOCKER_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_PODMAN_IMAGE_ID = re.compile(r"^[0-9a-f]{64}$")
_OCI_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,447}@sha256:[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_DEPTH = 16
_MAX_ITEMS = 1024
_MAX_NODES = 16_384
_MAX_TEXT = 32_767
_Result = TypeVar("_Result")
_MISSING = object()


class TargetObservationAdapterErrorCode(str, Enum):
    UNAVAILABLE = "unavailable"
    AUTHORITY_CHANGED = "authority_changed"
    PROCESS_REJECTED = "process_rejected"
    PROCESS_FAILED = "process_failed"
    OUTPUT_INVALID = "output_invalid"
    PROVIDER_CONTAINMENT_REQUIRED = "provider_containment_required"


class TargetObservationAdapterError(RuntimeError):
    """Sanitized failure from execution ownership or raw-output handling."""

    _MESSAGES = {
        TargetObservationAdapterErrorCode.UNAVAILABLE: (
            "Secure target observation is unavailable."
        ),
        TargetObservationAdapterErrorCode.AUTHORITY_CHANGED: (
            "The authenticated target-observation authority changed."
        ),
        TargetObservationAdapterErrorCode.PROCESS_REJECTED: (
            "The target-observation process result was rejected."
        ),
        TargetObservationAdapterErrorCode.PROCESS_FAILED: (
            "A read-only target observation did not complete successfully."
        ),
        TargetObservationAdapterErrorCode.OUTPUT_INVALID: (
            "A target-observation response was invalid."
        ),
        TargetObservationAdapterErrorCode.PROVIDER_CONTAINMENT_REQUIRED: (
            "The Podman Compose provider was not executed through its secured "
            "child path."
        ),
    }

    def __init__(self, code: TargetObservationAdapterErrorCode) -> None:
        if type(code) is not TargetObservationAdapterErrorCode:
            raise ValueError("Unknown target-observation adapter error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"TargetObservationAdapterError(code={self.code.value!r})"


def _fail(code: TargetObservationAdapterErrorCode) -> NoReturn:
    raise TargetObservationAdapterError(code)


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _strict_text(value: object, *, maximum: int = _MAX_TEXT) -> str | None:
    if (
        type(value) is not str
        or len(value) > maximum
        or "\x00" in value
        or any(
            ord(character) < 0x20 and character not in {"\t", "\r", "\n"}
            for character in value
        )
        or any(character in {"\x7f", "\x85", "\u2028", "\u2029"} for character in value)
    ):
        return None
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return None
    return value


def _walk(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    counter = nodes if nodes is not None else [0]
    counter[0] += 1
    if counter[0] > _MAX_NODES or depth > _MAX_DEPTH:
        raise ValueError("Document limit exceeded.")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            raise ValueError("Integer limit exceeded.")
        return
    if type(value) is str:
        if _strict_text(value) is None:
            raise ValueError("Text value is invalid.")
        return
    if type(value) is list:
        if len(value) > _MAX_ITEMS:
            raise ValueError("List limit exceeded.")
        for item in value:
            _walk(item, depth=depth + 1, nodes=counter)
        return
    if type(value) is dict:
        if len(value) > _MAX_ITEMS:
            raise ValueError("Object limit exceeded.")
        for key, item in value.items():
            if not key or _strict_text(key, maximum=128) is None:
                raise ValueError("Object key is invalid.")
            _walk(item, depth=depth + 1, nodes=counter)
        return
    raise ValueError("Document value type is invalid.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON member.")
        output[key] = value
    return output


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Non-finite JSON value.")


def _load_json(raw: bytes) -> Any:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_DOCUMENT_BYTES:
        raise ValueError("JSON bytes are invalid.")
    text = raw.decode("utf-8", errors="strict")
    if text.startswith("\ufeff"):
        raise ValueError("JSON BOM is invalid.")
    value = json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=lambda _value: (_ for _ in ()).throw(ValueError("Float rejected.")),
    )
    _walk(value)
    return value


def _load_yaml(raw: bytes) -> Any:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_DOCUMENT_BYTES:
        raise ValueError("YAML bytes are invalid.")
    text = raw.decode("utf-8", errors="strict")
    if text.startswith("\ufeff") or "\x00" in text:
        raise ValueError("YAML text is invalid.")
    yaml: Any = None
    try:
        import yaml as imported_yaml  # type: ignore[import-untyped]
    except ImportError:
        pass
    else:
        yaml = imported_yaml
    if yaml is None:
        _fail(TargetObservationAdapterErrorCode.UNAVAILABLE)

    class _StrictSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise ValueError("YAML aliases are not allowed.")
            return super().compose_node(parent, index)

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        output: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if type(key) is not str or key in output:
                raise ValueError("Duplicate or non-text YAML member.")
            output[key] = loader.construct_object(value_node, deep=deep)
        return output

    _StrictSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    parse_failed = False
    try:
        value = yaml.load(text, Loader=_StrictSafeLoader)
    except Exception:
        parse_failed = True
        value = None
    if parse_failed:
        raise ValueError("YAML document is invalid.")
    _walk(value)
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", errors="strict")


def _object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("Object required.")
    return value


def _list(value: Any) -> list[Any]:
    if type(value) is not list:
        raise ValueError("List required.")
    return value


def _only_keys(value: dict[str, Any], allowed: frozenset[str]) -> None:
    if not frozenset(value).issubset(allowed):
        raise ValueError("Unsupported member.")


def _integer(value: Any) -> int:
    if type(value) is int:
        return value
    if type(value) is str and value and value.isascii() and value.isdigit():
        return int(value, 10)
    raise ValueError("Integer required.")


def _seconds(value: Any, *, nanoseconds: bool = False) -> int:
    if nanoseconds:
        raw = _integer(value)
        if raw < 0 or raw % 1_000_000_000:
            raise ValueError("Exact duration required.")
        return raw // 1_000_000_000
    if type(value) is str and value.endswith("s"):
        body = value[:-1]
        if body.isascii() and body.isdigit():
            return int(body, 10)
    if type(value) is int:
        return value
    raise ValueError("Exact duration required.")


def _environment(value: Any) -> dict[str, str]:
    if type(value) is dict:
        output = value
    elif type(value) is list:
        output = {}
        for item in value:
            if type(item) is not str or "=" not in item:
                raise ValueError("Environment item is invalid.")
            name, item_value = item.split("=", 1)
            if name in output:
                raise ValueError("Duplicate environment item.")
            output[name] = item_value
    else:
        raise ValueError("Environment is invalid.")
    if any(
        not name
        or _strict_text(name, maximum=128) is None
        or type(item) is not str
        or len(item) > 4096
        or any(ord(character) < 0x20 for character in item)
        for name, item in output.items()
    ):
        raise ValueError("Environment is invalid.")
    return dict(output)


def _healthcheck(value: Any, *, inspect: bool) -> dict[str, Any]:
    health = _object(value)
    test = health.get("Test" if inspect else "test")
    inspect_keys = frozenset({"Test", "Interval", "Timeout", "StartPeriod", "Retries"})
    expected_keys = (
        (inspect_keys, inspect_keys | {"StartInterval"})
        if inspect
        else (frozenset({"test", "interval", "timeout", "start_period", "retries"}),)
    )
    if (
        frozenset(health) not in expected_keys
        or type(test) is not list
        or len(test) != 4
        or (inspect and _seconds(health.get("StartInterval", 0), nanoseconds=True) != 0)
    ):
        raise ValueError("Healthcheck is invalid.")
    if test[:3] != ["CMD", "python", "-c"] or type(test[3]) is not str:
        raise ValueError("Healthcheck command is invalid.")
    command_sha256 = hashlib.sha256(
        test[3].encode("utf-8", errors="strict")
    ).hexdigest()
    if command_sha256 != EXPECTED_HEALTHCHECK_COMMAND_SHA256:
        raise ValueError("Healthcheck command is invalid.")
    names = (
        ("Interval", "Timeout", "StartPeriod", "Retries")
        if inspect
        else ("interval", "timeout", "start_period", "retries")
    )
    return {
        "command_sha256": command_sha256,
        "interval_seconds": _seconds(health[names[0]], nanoseconds=inspect),
        "timeout_seconds": _seconds(health[names[1]], nanoseconds=inspect),
        "start_period_seconds": _seconds(health[names[2]], nanoseconds=inspect),
        "retries": _integer(health[names[3]]),
    }


def _compose_port(value: Any) -> dict[str, Any]:
    ports = _list(value)
    if len(ports) != 1:
        raise ValueError("Port binding is invalid.")
    item = ports[0]
    host_ip: Any
    published: Any
    target: Any
    protocol: Any
    if type(item) is str:
        pieces = item.split(":")
        if len(pieces) != 3:
            raise ValueError("Port binding is invalid.")
        host_ip, published, target = pieces
        protocol = "tcp"
    else:
        port = _object(item)
        _only_keys(
            port,
            frozenset({"host_ip", "published", "target", "protocol", "mode"}),
        )
        if port.get("mode", "ingress") not in {"ingress", None}:
            raise ValueError("Port mode is invalid.")
        host_ip = port.get("host_ip")
        published = port.get("published")
        target = port.get("target")
        protocol = port.get("protocol", "tcp")
    return {
        "host_ip": host_ip,
        "published": _integer(published),
        "target": _integer(target),
        "protocol": protocol,
    }


def _expected_profile(plan: TargetResolutionPlan) -> dict[str, Any]:
    return {
        EffectiveProfile.CPU: {
            "kind": "cpu",
            "devices": [],
            "security_options": [],
            "capabilities": [],
        },
        EffectiveProfile.DOCKER_GPU: {
            "kind": "docker_gpu",
            "devices": ["nvidia:all"],
            "security_options": [],
            "capabilities": ["gpu"],
        },
        EffectiveProfile.PODMAN_GPU: {
            "kind": "podman_gpu",
            "devices": ["nvidia.com/gpu=all"],
            "security_options": ["label=disable"],
            "capabilities": [],
        },
    }[plan.acceleration.effective]


def _compose_profile(
    plan: TargetResolutionPlan, service: dict[str, Any]
) -> dict[str, Any]:
    deploy = service.get("deploy")
    devices = service.get("devices")
    security = service.get("security_opt")
    if plan.acceleration.effective is EffectiveProfile.CPU:
        if (
            deploy not in (None, {})
            or devices not in (None, [])
            or security
            not in (
                None,
                [],
            )
        ):
            raise ValueError("CPU profile is invalid.")
    elif plan.acceleration.effective is EffectiveProfile.DOCKER_GPU:
        expected = {
            "resources": {
                "reservations": {
                    "devices": [
                        {"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}
                    ]
                }
            }
        }
        if (
            deploy != expected
            or devices not in (None, [])
            or security
            not in (
                None,
                [],
            )
        ):
            raise ValueError("Docker GPU profile is invalid.")
    else:
        if (
            deploy not in (None, {})
            or devices != ["nvidia.com/gpu=all"]
            or security != ["label=disable"]
        ):
            raise ValueError("Podman GPU profile is invalid.")
    return _expected_profile(plan)


def _compose_volumes(plan: TargetResolutionPlan, value: Any) -> list[dict[str, Any]]:
    volumes = _list(value)
    if len(volumes) != len(EXPECTED_VOLUME_DESTINATIONS):
        raise ValueError("Compose volumes are invalid.")
    output: list[dict[str, Any]] = []
    for raw, (logical_name, destination) in zip(
        volumes, EXPECTED_VOLUME_DESTINATIONS, strict=True
    ):
        source: Any
        target: Any
        if type(raw) is str:
            pieces = raw.split(":")
            if len(pieces) not in {2, 3}:
                raise ValueError("Compose volume is invalid.")
            source, target = pieces[:2]
            if len(pieces) == 3 and pieces[2] != "rw":
                raise ValueError("Compose volume mode is invalid.")
            read_only = False
            volume_type = "volume"
        else:
            item = _object(raw)
            _only_keys(
                item,
                frozenset({"type", "source", "target", "read_only", "volume"}),
            )
            source = item.get("source")
            target = item.get("target")
            read_only = item.get("read_only", False)
            volume_type = item.get("type", "volume")
            if item.get("volume") not in (None, {}):
                raise ValueError("Compose volume options are invalid.")
        if (
            source != logical_name
            or target != destination
            or volume_type != "volume"
            or read_only is not False
        ):
            raise ValueError("Compose volume is invalid.")
        output.append(
            {
                "logical_name": logical_name,
                "runtime_name": f"{plan.compose_project}_{logical_name}",
                "destination": destination,
                "type": "volume",
                "read_only": False,
            }
        )
    return output


def _normalize_compose(
    plan: TargetResolutionPlan,
    raw: bytes,
    *,
    planned: bool,
    semantic_config_sha256: str,
) -> bytes:
    value = (
        _load_json(raw)
        if plan.runtime.product is RuntimeProduct.DOCKER
        else _load_yaml(raw)
    )
    compose = _object(value)
    _only_keys(
        compose, frozenset({"name", "version", "services", "volumes", "networks"})
    )
    if compose.get("name", plan.compose_project) != plan.compose_project:
        raise ValueError("Compose project is invalid.")
    if compose.get("version") not in {None, "3", "3.8", "3.9"}:
        raise ValueError("Compose version is invalid.")
    services = _object(compose.get("services"))
    if frozenset(services) != {"towerscout"}:
        raise ValueError("Compose service set is invalid.")
    service = _object(services["towerscout"])
    _only_keys(
        service,
        frozenset(
            {
                "image",
                "ports",
                "environment",
                "volumes",
                "healthcheck",
                "restart",
                "deploy",
                "devices",
                "security_opt",
                "networks",
            }
        ),
    )
    if (
        service.get("image") != plan.configured_image_reference
        or service.get("restart") != "always"
    ):
        raise ValueError("Compose service policy is invalid.")
    if service.get("networks") not in (None, ["default"], {"default": None}):
        raise ValueError("Compose network is invalid.")
    top_volumes = _object(compose.get("volumes"))
    if frozenset(top_volumes) != {
        name for name, _destination in EXPECTED_VOLUME_DESTINATIONS
    }:
        raise ValueError("Compose volume declarations are invalid.")
    for logical_name, item in top_volumes.items():
        if item not in (None, {}) and item != {
            "name": f"{plan.compose_project}_{logical_name}"
        }:
            raise ValueError("Compose volume declaration is invalid.")
    networks = compose.get("networks")
    accepted_networks: tuple[Any, ...] = (
        None,
        {"default": None},
        {"default": {}},
        {"default": {"name": f"{plan.compose_project}_default"}},
    )
    if networks not in accepted_networks:
        raise ValueError("Compose network declaration is invalid.")
    normalized = {
        "schema_version": 1,
        "project": plan.compose_project,
        "service": {
            "name": "towerscout",
            "image": plan.configured_image_reference,
            "semantic_config_sha256": semantic_config_sha256,
            "environment": _environment(service.get("environment")),
            "port": _compose_port(service.get("ports")),
            "restart": "always",
            "healthcheck": _healthcheck(service.get("healthcheck"), inspect=False),
            "profile": _compose_profile(plan, service),
        },
        "volumes": _compose_volumes(plan, service.get("volumes")),
    }
    return _canonical_json(normalized)


def _one_inspect(raw: bytes) -> dict[str, Any]:
    value = _load_json(raw)
    items = _list(value)
    if len(items) != 1:
        raise ValueError("One inspect record is required.")
    return _object(items[0])


def _normalize_container_list(raw: bytes) -> tuple[bytes, str]:
    if type(raw) is not bytes or len(raw) > 8 * 1024:
        raise ValueError("Container list is invalid.")
    text = raw.decode("ascii", errors="strict")
    if "\x00" in text or "\r" in text.replace("\r\n", ""):
        raise ValueError("Container list is invalid.")
    identifiers = [line for line in text.replace("\r\n", "\n").split("\n") if line]
    if not identifiers:
        raise TargetResolutionError(TargetResolutionErrorCode.TARGET_MISSING)
    if len(identifiers) != 1:
        raise TargetResolutionError(TargetResolutionErrorCode.TARGET_AMBIGUOUS)
    container_id = identifiers[0]
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise ValueError("Container ID is invalid.")
    return _canonical_json([container_id]), container_id


def _labels(container: dict[str, Any]) -> dict[str, str]:
    config = _object(container.get("Config"))
    labels = _object(config.get("Labels"))
    if any(
        type(key) is not str or type(value) is not str for key, value in labels.items()
    ):
        raise ValueError("Container labels are invalid.")
    return labels


def _native_provider_config_hash(
    plan: TargetResolutionPlan,
    container: dict[str, Any],
) -> str:
    labels = _labels(container)
    name = (
        "com.docker.compose.config-hash"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.config-hash"
    )
    value = labels.get(name)
    if not _is_sha256(value):
        raise ValueError("Provider config hash is invalid.")
    assert type(value) is str
    return value


def _bind_provider_model(normalized: bytes) -> tuple[bytes, str]:
    model = _object(_load_json(normalized))
    service = _object(model.get("service"))
    if service.get("semantic_config_sha256") != TARGET_MODEL_SEMANTIC_HASH_PLACEHOLDER:
        raise ValueError("Provider model binding is invalid.")
    digest = target_model_semantic_sha256(normalized)
    service["semantic_config_sha256"] = digest
    return _canonical_json(model), digest


def _raw_image_id(plan: TargetResolutionPlan, container: dict[str, Any]) -> str:
    value = container.get("Image", container.get("ImageID"))
    pattern = (
        _DOCKER_IMAGE_ID
        if plan.runtime.product is RuntimeProduct.DOCKER
        else _PODMAN_IMAGE_ID
    )
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError("Image ID is invalid.")
    return value


def _normalized_image_id(plan: TargetResolutionPlan, value: object) -> str:
    pattern = (
        _DOCKER_IMAGE_ID
        if plan.runtime.product is RuntimeProduct.DOCKER
        else _PODMAN_IMAGE_ID
    )
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError("Image ID is invalid.")
    return value if plan.runtime.product is RuntimeProduct.DOCKER else f"sha256:{value}"


def _normalize_image(
    plan: TargetResolutionPlan,
    raw: bytes,
    expected_image_selector: str,
) -> tuple[bytes, dict[str, Any], str]:
    image = _one_inspect(raw)
    image_id = image.get("Id", image.get("ID"))
    normalized_image_id = _normalized_image_id(plan, image_id)
    repositories = image.get("RepoDigests")
    if (
        image_id != expected_image_selector
        or type(repositories) is not list
        or not 1 <= len(repositories) <= 32
        or any(
            type(item) is not str or _OCI_REFERENCE.fullmatch(item) is None
            for item in repositories
        )
        or len(set(repositories)) != len(repositories)
        or plan.configured_image_reference not in repositories
        or type(image.get("Config")) is not dict
    ):
        raise ValueError("Image inspect is invalid.")
    normalized = {
        "schema_version": 1,
        "id": normalized_image_id,
        "repository_digests": sorted(repositories),
    }
    return _canonical_json(normalized), image, normalized_image_id


def _configuration_files_match(plan: TargetResolutionPlan, value: str) -> bool:
    values = tuple(item.strip() for item in value.split(","))
    logical = tuple(item.logical_name for item in plan.ordered_compose_files)
    absolute = tuple(str(item.final_path) for item in plan.ordered_compose_files)
    return values in {logical, absolute}


def _inspect_port(value: Any) -> list[dict[str, Any]]:
    ports = _object(value)
    if frozenset(ports) != {"5000/tcp"}:
        raise ValueError("Container ports are invalid.")
    bindings = _list(ports["5000/tcp"])
    if len(bindings) != 1:
        raise ValueError("Container ports are invalid.")
    item = _object(bindings[0])
    if frozenset(item) != {"HostIp", "HostPort"}:
        raise ValueError("Container ports are invalid.")
    return [
        {
            "host_ip": item["HostIp"],
            "published": _integer(item["HostPort"]),
            "target": 5000,
            "protocol": "tcp",
        }
    ]


def _host_profile(plan: TargetResolutionPlan, host: dict[str, Any]) -> dict[str, Any]:
    devices = host.get("Devices")
    security = host.get("SecurityOpt")
    requests = host.get("DeviceRequests")
    if plan.acceleration.effective is EffectiveProfile.CPU:
        if (
            devices not in (None, [])
            or security not in (None, [])
            or requests
            not in (
                None,
                [],
            )
        ):
            raise ValueError("CPU host profile is invalid.")
    elif plan.acceleration.effective is EffectiveProfile.DOCKER_GPU:
        expected = [
            {
                "Driver": "nvidia",
                "Count": -1,
                "DeviceIDs": None,
                "Capabilities": [["gpu"]],
                "Options": {},
            }
        ]
        if (
            requests != expected
            or devices not in (None, [])
            or security
            not in (
                None,
                [],
            )
        ):
            raise ValueError("Docker GPU host profile is invalid.")
    else:
        accepted_devices = ["nvidia.com/gpu=all"]
        if (
            devices != accepted_devices
            or security != ["label=disable"]
            or requests
            not in (
                None,
                [],
            )
        ):
            raise ValueError("Podman GPU host profile is invalid.")
    return _expected_profile(plan)


def _validate_named_volume_binds(
    plan: TargetResolutionPlan,
    value: Any,
) -> None:
    expected = {
        f"{plan.compose_project}_{logical_name}:{destination}:rw"
        for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
    }
    if (
        type(value) is not list
        or len(value) != len(expected)
        or any(type(item) is not str for item in value)
    ):
        raise ValueError("Container volume binds are invalid.")
    if plan.runtime.product is RuntimeProduct.DOCKER:
        if set(value) != expected:
            raise ValueError("Container volume binds are invalid.")
        return

    expected_pairs = {
        (f"{plan.compose_project}_{logical_name}", destination)
        for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS
    }
    expected_options = frozenset({"rw", "rprivate", "nosuid", "nodev", "rbind"})
    observed_pairs: set[tuple[str, str]] = set()
    for raw in value:
        pieces = raw.split(":")
        if len(pieces) != 3:
            raise ValueError("Container volume bind is invalid.")
        source, destination, raw_options = pieces
        options = raw_options.split(",")
        if (
            len(options) != len(expected_options)
            or frozenset(options) != expected_options
        ):
            raise ValueError("Container volume bind options are invalid.")
        observed_pairs.add((source, destination))
    if observed_pairs != expected_pairs:
        raise ValueError("Container volume binds are invalid.")


def _security(plan: TargetResolutionPlan, host: dict[str, Any]) -> dict[str, Any]:
    profile = _host_profile(plan, host)
    _validate_named_volume_binds(plan, host.get("Binds"))
    network_mode = host.get("NetworkMode")
    cgroup_mode = host.get(
        "CgroupnsMode"
        if plan.runtime.product is RuntimeProduct.DOCKER
        else "CgroupMode"
    )
    accepted_ipc_modes = (
        {None, "", "private"}
        if plan.runtime.product is RuntimeProduct.DOCKER
        else {None, "", "private", "shareable"}
    )
    if (
        host.get("Privileged") is not False
        or host.get("ReadonlyRootfs") is not False
        or network_mode not in {"bridge", f"{plan.compose_project}_default"}
        or host.get("PidMode") not in {None, "", "private"}
        or host.get("IpcMode") not in accepted_ipc_modes
        or host.get("UTSMode") not in {None, "", "private"}
        or host.get("UsernsMode") not in {None, "", "private"}
        or cgroup_mode not in {None, "", "private"}
        or host.get("CapAdd") not in (None, [])
        or host.get("CapDrop") not in (None, [])
        or host.get("Links") not in (None, [])
    ):
        raise ValueError("Container security policy is invalid.")
    return {
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
        "devices": profile["devices"],
        "security_options": profile["security_options"],
        "gpu_capabilities": profile["capabilities"],
    }


def _normalize_container(
    plan: TargetResolutionPlan,
    container: dict[str, Any],
    image: dict[str, Any],
    *,
    container_id: str,
    native_provider_config_hash: str,
    semantic_config_sha256: str,
    normalized_image_id: str,
    expected_environment: dict[str, str],
) -> bytes:
    observed_id = container.get("Id", container.get("ID"))
    name = container.get("Name")
    if type(name) is str and name.startswith("/"):
        name = name[1:]
    config = _object(container.get("Config"))
    image_config = _object(image.get("Config"))
    state = _object(container.get("State"))
    host = _object(container.get("HostConfig"))
    network = _object(container.get("NetworkSettings"))
    labels = _labels(container)
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
    working = labels.get("com.docker.compose.project.working_dir")
    files = labels.get("com.docker.compose.project.config_files")
    if (
        observed_id != container_id
        or type(name) is not str
        or not name
        or _strict_text(name, maximum=256) is None
        or _raw_image_id(plan, container) != image.get("Id", image.get("ID"))
        or config.get("Image") != plan.configured_image_reference
        or state.get("Running") is not True
        or labels.get(project_label) != plan.compose_project
        or labels.get(service_label) != "towerscout"
        or working != str(plan.package_root.final_path)
        or type(files) is not str
        or not _configuration_files_match(plan, files)
        or labels.get(
            "com.docker.compose.config-hash"
            if plan.runtime.product is RuntimeProduct.DOCKER
            else "io.podman.compose.config-hash"
        )
        != native_provider_config_hash
        or config.get("Cmd") != image_config.get("Cmd")
        or config.get("Entrypoint") != image_config.get("Entrypoint")
        or config.get("User") != image_config.get("User")
        or config.get("WorkingDir") != image_config.get("WorkingDir")
    ):
        raise ValueError("Container identity is invalid.")
    observed_environment = _environment(config.get("Env"))
    image_environment = _environment(image_config.get("Env", []))
    if any(
        observed_environment.get(name) != value
        for name, value in expected_environment.items()
    ):
        raise ValueError("Container environment is invalid.")
    observed_defaults = {
        name: value
        for name, value in observed_environment.items()
        if name not in expected_environment
    }
    image_defaults = {
        name: value
        for name, value in image_environment.items()
        if name not in expected_environment
    }
    if observed_defaults != image_defaults:
        raise ValueError("Container environment is invalid.")
    restart = _object(host.get("RestartPolicy"))
    if restart.get("Name") != "always":
        raise ValueError("Container restart policy is invalid.")
    networks = _object(network.get("Networks"))
    expected_network = f"{plan.compose_project}_default"
    if frozenset(networks) != {expected_network}:
        raise ValueError("Container network is invalid.")
    raw_mounts = _list(container.get("Mounts"))
    by_destination: dict[str, dict[str, Any]] = {}
    for raw_mount in raw_mounts:
        mount = _object(raw_mount)
        destination = mount.get("Destination")
        if type(destination) is not str or destination in by_destination:
            raise ValueError("Container mounts are invalid.")
        by_destination[destination] = mount
    mounts: list[dict[str, Any]] = []
    for logical_name, destination in EXPECTED_VOLUME_DESTINATIONS:
        selected_mount = by_destination.get(destination)
        if selected_mount is None:
            raise ValueError("Container mount is invalid.")
        podman_mount_invalid = False
        if plan.runtime.product is RuntimeProduct.PODMAN:
            mount_options = selected_mount.get("Options")
            podman_mount_invalid = (
                selected_mount.get("Driver") != "local"
                or selected_mount.get("Mode") != ""
                or type(mount_options) is not list
                or len(mount_options) != 3
                or any(type(item) is not str for item in mount_options)
                or frozenset(mount_options) != {"nosuid", "nodev", "rbind"}
                or selected_mount.get("Propagation") != "rprivate"
                or _strict_text(selected_mount.get("Source"), maximum=4096) is None
            )
        if (
            selected_mount.get("Type") != "volume"
            or selected_mount.get("Name") != f"{plan.compose_project}_{logical_name}"
            or selected_mount.get("RW") is not True
            or podman_mount_invalid
        ):
            raise ValueError("Container mount is invalid.")
        mounts.append(
            {
                "type": "volume",
                "name": selected_mount["Name"],
                "destination": destination,
                "read_write": True,
            }
        )
    if len(by_destination) != len(mounts):
        raise ValueError("Unexpected container mount.")
    normalized = {
        "schema_version": 1,
        "id": container_id,
        "name": name,
        "image_id": normalized_image_id,
        "configured_image": plan.configured_image_reference,
        "running": True,
        "labels": {
            "project": plan.compose_project,
            "service": "towerscout",
            "working_directory_sha256": plan.package_root.canonical_path_sha256,
            "compose_files_sha256": plan.compose_files_sha256,
            "native_config_hash": native_provider_config_hash,
            "semantic_config_sha256": semantic_config_sha256,
        },
        "environment": expected_environment,
        "ports": _inspect_port(network.get("Ports")),
        "restart": "always",
        "healthcheck": _healthcheck(config.get("Healthcheck"), inspect=True),
        "profile": _host_profile(plan, host),
        "security": _security(plan, host),
        "networks": [expected_network],
        "mounts": mounts,
    }
    return _canonical_json(normalized)


def _normalize_volume(
    plan: TargetResolutionPlan,
    raw: bytes,
    logical_name: str,
) -> bytes:
    volume = _one_inspect(raw)
    runtime_name = f"{plan.compose_project}_{logical_name}"
    labels = volume.get("Labels")
    labels = {} if labels is None else _object(labels)
    project_values = {
        labels.get("com.docker.compose.project"),
        labels.get("io.podman.compose.project"),
    } - {None}
    logical_values = {
        labels.get("com.docker.compose.volume"),
        labels.get("io.podman.compose.volume"),
    } - {None}
    options = volume.get("Options")
    if options is None:
        options = {}
    mountpoint = volume.get("Mountpoint")
    if (
        volume.get("Name") != runtime_name
        or volume.get("Driver") != "local"
        or volume.get("Scope", "local") != "local"
        or options != {}
        or project_values != {plan.compose_project}
        or logical_values not in (set(), {logical_name})
        or not mountpoint
        or _strict_text(mountpoint, maximum=4096) is None
    ):
        raise ValueError("Volume inspect is invalid.")
    return _canonical_json(
        {
            "schema_version": 1,
            "name": runtime_name,
            "driver": "local",
            "scope": "local",
            "options": {},
            "project": plan.compose_project,
            "logical_name": logical_name,
            "mountpoint_sha256": hashlib.sha256(
                mountpoint.encode("utf-8", errors="strict")
            ).hexdigest(),
            "engine_metadata_sha256": hashlib.sha256(
                _canonical_json(volume)
            ).hexdigest(),
        }
    )


@dataclass(frozen=True, slots=True, repr=False)
class TargetObservationProcessResult:
    """Bounded, redacted claims returned by one injected native executor."""

    operation: ObservationOperation
    authority_sha256: str = field(repr=False)
    stdout: bytes = field(repr=False)
    stderr_sha256: str = field(repr=False)
    exit_code: int
    provider_child_claimed: bool
    provider_child_claim_sha256: str | None = field(repr=False)
    stdin_closed: bool = True
    stdout_streamed: bool = True
    stderr_streamed: bool = True
    process_tree_contained: bool = True
    process_tree_empty: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.operation) is not ObservationOperation
            or not _is_sha256(self.authority_sha256)
            or type(self.stdout) is not bytes
            or len(self.stdout) > _MAX_DOCUMENT_BYTES
            or not _is_sha256(self.stderr_sha256)
            or type(self.exit_code) is not int
            or isinstance(self.exit_code, bool)
            or not -(2**31) <= self.exit_code < 2**32
            or type(self.provider_child_claimed) is not bool
            or (
                self.provider_child_claimed
                and not _is_sha256(self.provider_child_claim_sha256)
            )
            or (
                not self.provider_child_claimed
                and self.provider_child_claim_sha256 is not None
            )
            or any(
                value is not True
                for value in (
                    self.stdin_closed,
                    self.stdout_streamed,
                    self.stderr_streamed,
                    self.process_tree_contained,
                    self.process_tree_empty,
                )
            )
        ):
            raise ValueError("Target-observation process result is invalid.")

    @classmethod
    def from_plan(
        cls,
        plan: TargetObservationProcessPlan,
        *,
        stdout: bytes,
        stderr: bytes,
        exit_code: int,
        provider_child_claimed: bool,
        provider_child_claim_sha256: str | None = None,
    ) -> "TargetObservationProcessResult":
        if (
            type(plan) is not TargetObservationProcessPlan
            or type(stdout) is not bytes
            or len(stdout) > plan.stdout_limit_bytes
            or type(stderr) is not bytes
            or len(stderr) > plan.stderr_limit_bytes
        ):
            raise ValueError("Target-observation process result is invalid.")
        return cls(
            operation=plan.operation,
            authority_sha256=plan.authority_sha256,
            stdout=stdout,
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            exit_code=exit_code,
            provider_child_claimed=provider_child_claimed,
            provider_child_claim_sha256=provider_child_claim_sha256,
        )

    def __repr__(self) -> str:
        return (
            "TargetObservationProcessResult("
            f"operation={self.operation.value!r}, exit_code={self.exit_code}, "
            f"stdout_bytes={len(self.stdout)}, containment='claimed', <redacted>)"
        )


class TargetObservationExecutor(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def execute(
        self, plan: TargetObservationProcessPlan
    ) -> TargetObservationProcessResult: ...

    def close(self) -> None: ...


class TargetObservationAuthority(Protocol):
    @property
    def authority_sha256(self) -> str: ...

    @property
    def closed(self) -> bool: ...

    def run_while_held(self, operation: Callable[[], _Result]) -> _Result: ...

    def close(self) -> None: ...


def _close_distinct_resources(*resources: Any) -> tuple[bool, BaseException | None]:
    failed = False
    interruption: BaseException | None = None
    seen: set[int] = set()
    for resource in resources:
        if resource is None or id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            close = getattr(resource, "close", None)
            if callable(close):
                close()
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
    return failed, interruption


class OwnedTargetObservationBackend(TargetResolutionBackend):
    """Serialize complete observations under one transferred authority owner."""

    __slots__ = (
        "_active",
        "_authority",
        "_binding",
        "_closed",
        "_executor",
        "_lock",
        "_plan",
    )

    def __init__(
        self,
        plan: TargetResolutionPlan,
        *,
        authority: TargetObservationAuthority,
        executor: TargetObservationExecutor,
    ) -> None:
        valid = False
        binding: TargetObservationExecutionBinding | None = None
        construction_interruption: BaseException | None = None
        try:
            valid = (
                type(plan) is TargetResolutionPlan
                and id(authority) != id(executor)
                and authority.authority_sha256 == plan.authority_sha256
                and authority.closed is False
                and executor.supported is True
                and executor.closed is False
                and callable(authority.run_while_held)
                and callable(authority.close)
                and callable(executor.execute)
                and callable(executor.close)
            )
            if valid:
                binding = TargetObservationExecutionBinding(plan)
        except BaseException as error:
            valid = False
            binding = None
            if not isinstance(error, Exception):
                construction_interruption = error
        if not valid or binding is None:
            _failed, cleanup_interruption = _close_distinct_resources(
                executor, authority
            )
            if construction_interruption is not None:
                raise construction_interruption
            if cleanup_interruption is not None:
                raise cleanup_interruption
            raise TargetObservationAdapterError(
                TargetObservationAdapterErrorCode.UNAVAILABLE
            ) from None
        self._lock = threading.RLock()
        self._active = False
        self._closed = False
        self._plan = plan
        self._binding = binding
        self._authority: TargetObservationAuthority | None = authority
        self._executor: TargetObservationExecutor | None = executor

    @property
    def supported(self) -> bool:
        with self._lock:
            if self._closed or self._authority is None or self._executor is None:
                return False
            try:
                return (
                    self._authority.closed is False
                    and self._authority.authority_sha256 == self._plan.authority_sha256
                    and self._executor.closed is False
                    and self._executor.supported is True
                )
            except Exception:
                return False

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def _execute(self, plan: TargetObservationProcessPlan) -> bytes:
        executor = self._executor
        if executor is None:
            _fail(TargetObservationAdapterErrorCode.UNAVAILABLE)
        failure_code: TargetObservationAdapterErrorCode | None = None
        try:
            result = executor.execute(plan)
        except TargetObservationAdapterError as error:
            failure_code = error.code
        except Exception:
            failure_code = TargetObservationAdapterErrorCode.PROCESS_FAILED
        if failure_code is not None:
            raise TargetObservationAdapterError(failure_code)
        if (
            type(result) is not TargetObservationProcessResult
            or result.operation is not plan.operation
            or result.authority_sha256 != plan.authority_sha256
            or len(result.stdout) > plan.stdout_limit_bytes
        ):
            _fail(TargetObservationAdapterErrorCode.PROCESS_REJECTED)
        provider_required = (
            plan.target.runtime.product is RuntimeProduct.PODMAN
            and plan.operation
            in {
                ObservationOperation.COMPOSE_MODEL_CURRENT,
                ObservationOperation.COMPOSE_MODEL_PLANNED,
            }
        )
        if (
            result.provider_child_claimed is not provider_required
            or (
                provider_required and not _is_sha256(result.provider_child_claim_sha256)
            )
            or (
                not provider_required and result.provider_child_claim_sha256 is not None
            )
        ):
            _fail(TargetObservationAdapterErrorCode.PROVIDER_CONTAINMENT_REQUIRED)
        if result.exit_code != 0:
            _fail(TargetObservationAdapterErrorCode.PROCESS_FAILED)
        return result.stdout

    def _capture_while_held(self) -> TargetResolutionSnapshot:
        adapter_failure: TargetObservationAdapterErrorCode | None = None
        resolution_failure: TargetResolutionErrorCode | None = None
        try:
            current = self._execute(self._binding.compose_model(planned=False))
            planned = self._execute(self._binding.compose_model(planned=True))
            container_list, container_id = _normalize_container_list(
                self._execute(self._binding.container_list())
            )
            raw_container = self._execute(self._binding.container_inspect(container_id))
            container = _one_inspect(raw_container)
            if container.get("Id", container.get("ID")) != container_id:
                raise ValueError("Container selector changed.")
            native_provider_config_hash = _native_provider_config_hash(
                self._plan,
                container,
            )
            image_selector = _raw_image_id(self._plan, container)
            normalized_image, raw_image, normalized_image_id = _normalize_image(
                self._plan,
                self._execute(self._binding.image_inspect(image_selector)),
                image_selector,
            )
            normalized_pre_model, pre_semantic_config_sha256 = _bind_provider_model(
                _normalize_compose(
                    self._plan,
                    current,
                    planned=False,
                    semantic_config_sha256=(TARGET_MODEL_SEMANTIC_HASH_PLACEHOLDER),
                )
            )
            normalized_post_model, _post_semantic_config_sha256 = _bind_provider_model(
                _normalize_compose(
                    self._plan,
                    planned,
                    planned=True,
                    semantic_config_sha256=(TARGET_MODEL_SEMANTIC_HASH_PLACEHOLDER),
                )
            )
            expected_environment = _object(
                _object(_load_json(normalized_pre_model)["service"])["environment"]
            )
            if any(type(value) is not str for value in expected_environment.values()):
                raise ValueError("Normalized environment is invalid.")
            normalized_container = _normalize_container(
                self._plan,
                container,
                raw_image,
                container_id=container_id,
                native_provider_config_hash=native_provider_config_hash,
                semantic_config_sha256=pre_semantic_config_sha256,
                normalized_image_id=normalized_image_id,
                expected_environment=dict(expected_environment),
            )
            volume_inspects = tuple(
                (
                    logical_name,
                    _normalize_volume(
                        self._plan,
                        self._execute(self._binding.volume_inspect(logical_name)),
                        logical_name,
                    ),
                )
                for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
            )
            return TargetResolutionSnapshot(
                authority_sha256=self._plan.authority_sha256,
                normalized_pre_model=normalized_pre_model,
                normalized_post_model=normalized_post_model,
                container_list=container_list,
                container_inspect=normalized_container,
                image_inspect=normalized_image,
                volume_inspects=volume_inspects,
            )
        except TargetObservationAdapterError as error:
            adapter_failure = error.code
        except TargetResolutionError as error:
            resolution_failure = error.code
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            adapter_failure = TargetObservationAdapterErrorCode.OUTPUT_INVALID
        if adapter_failure is not None:
            raise TargetObservationAdapterError(adapter_failure)
        assert resolution_failure is not None
        raise TargetResolutionError(resolution_failure)

    def _poison(self) -> None:
        authority = self._authority
        executor = self._executor
        self._authority = None
        self._executor = None
        self._closed = True
        seen: set[int] = set()
        for resource in (executor, authority):
            if resource is not None and id(resource) not in seen:
                seen.add(id(resource))
                try:
                    resource.close()
                except BaseException:
                    pass

    def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot:
        with self._lock:
            if (
                self._active
                or self._closed
                or plan is not self._plan
                or self.supported is not True
                or self._authority is None
            ):
                _fail(TargetObservationAdapterErrorCode.AUTHORITY_CHANGED)
            self._active = True
            snapshot: TargetResolutionSnapshot | None = None
            adapter_failure: TargetObservationAdapterErrorCode | None = None
            resolution_failure: TargetResolutionErrorCode | None = None
            try:
                snapshot = self._authority.run_while_held(self._capture_while_held)
                if type(snapshot) is not TargetResolutionSnapshot:
                    adapter_failure = (
                        TargetObservationAdapterErrorCode.AUTHORITY_CHANGED
                    )
            except BaseException as error:
                self._poison()
                if not isinstance(error, Exception):
                    raise
                if isinstance(error, TargetObservationAdapterError):
                    adapter_failure = error.code
                elif isinstance(error, TargetResolutionError):
                    resolution_failure = error.code
                else:
                    adapter_failure = (
                        TargetObservationAdapterErrorCode.AUTHORITY_CHANGED
                    )
            finally:
                self._active = False
            if (adapter_failure is not None or resolution_failure is not None) and (
                not self._closed
            ):
                self._poison()
            if adapter_failure is not None:
                raise TargetObservationAdapterError(adapter_failure)
            if resolution_failure is not None:
                raise TargetResolutionError(resolution_failure)
            assert snapshot is not None
            return snapshot

    def close(self) -> None:
        with self._lock:
            if self._active:
                _fail(TargetObservationAdapterErrorCode.AUTHORITY_CHANGED)
            if self._closed:
                return
            authority = self._authority
            executor = self._executor
            self._authority = None
            self._executor = None
            self._closed = True
            failed, interruption = _close_distinct_resources(executor, authority)
            if interruption is not None:
                raise interruption
            if failed:
                _fail(TargetObservationAdapterErrorCode.AUTHORITY_CHANGED)

    def __repr__(self) -> str:
        return (
            "OwnedTargetObservationBackend("
            f"runtime={self._plan.runtime.product.value!r}, "
            f"state={'closed' if self.closed else 'open'!r}, <redacted>)"
        )


__all__ = [
    "OwnedTargetObservationBackend",
    "TargetObservationAdapterError",
    "TargetObservationAdapterErrorCode",
    "TargetObservationAuthority",
    "TargetObservationExecutor",
    "TargetObservationProcessResult",
]
