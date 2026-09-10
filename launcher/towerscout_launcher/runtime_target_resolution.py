"""Strict, inert resolution of one exact Gate-A container target.

The native command layer will eventually translate authenticated Compose and
engine output into the small normalized JSON schemas accepted here.  This
module validates those schemas, binds both the current and planned Compose
models, and constructs :class:`ResolvedRepairTarget` without mutating a
runtime, package, certificate store, or environment file.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import struct
import threading
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, Sequence, TypeVar

from .target_contracts import (
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

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_RELEASE_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_ITEMS = 512
_MAX_JSON_NODES = 16_384
_MAX_JSON_STRING_CHARACTERS = 32_767
_MAX_ENVIRONMENT_VALUE_CHARACTERS = 4096
_AUTHORITY_DOMAIN = b"TowerScout.TargetResolutionAuthority.v1"
_COMPOSE_FILES_DOMAIN = b"TowerScout.TargetResolutionComposeFiles.v1"
_OBSERVATION_DOMAIN = b"TowerScout.TargetResolutionObservation.v1"
_EVIDENCE_DOMAIN = b"TowerScout.TargetResolutionEvidence.v1"
_CA_DESTINATION = "/app/webapp/config/certs/towerscout-ca-bundle.pem"
_Result = TypeVar("_Result")

_HEALTHCHECK_COMMAND = (
    "import json, urllib.request; "
    "data=json.load(urllib.request.urlopen("
    "'http://127.0.0.1:5000/api/health', timeout=3)); "
    "raise SystemExit(0 if data.get('status') == 'ok' else 1)"
)
EXPECTED_HEALTHCHECK_COMMAND_SHA256 = hashlib.sha256(
    _HEALTHCHECK_COMMAND.encode("utf-8")
).hexdigest()
_HEALTHCHECK_INTEGER_FIELDS = (
    "interval_seconds",
    "timeout_seconds",
    "start_period_seconds",
    "retries",
)

_BASE_ENVIRONMENT_NAMES = frozenset(
    {
        "FLASK_ENV",
        "TOWERSCOUT_CONTAINER_ENGINE",
        "TOWERSCOUT_HOST_PORT",
        "TOWERSCOUT_IMAGE_DIGEST",
        "TOWERSCOUT_LAZY_MODEL_INIT",
        "TOWERSCOUT_STARTUP_PRELOAD",
        "TOWERSCOUT_DEVICE",
        "TOWERSCOUT_GPU_MODE",
        "TOWERSCOUT_GPU_CONCURRENCY",
        "TOWERSCOUT_PILOT_MAX_TILES",
        "TOWERSCOUT_MAX_REQUEST_BODY_BYTES",
        "TOWERSCOUT_VERIFY_ASSET_HASHES",
        "TOWERSCOUT_ENABLE_MODEL_UPLOAD",
        "TOWERSCOUT_MODEL_UPLOAD_KEY",
        "TOWERSCOUT_TRUSTED_MODEL_SHA256",
        "TOWERSCOUT_ALLOW_INSECURE_TLS",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "YOLO_CONFIG_DIR",
    }
)
_GPU_ENVIRONMENT_NAMES = frozenset(
    {"NVIDIA_VISIBLE_DEVICES", "NVIDIA_DRIVER_CAPABILITIES"}
)


class TargetResolutionErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    AUTHORITY_MISMATCH = "authority_mismatch"
    MODEL_INVALID = "model_invalid"
    TARGET_MISSING = "target_missing"
    TARGET_AMBIGUOUS = "target_ambiguous"
    TARGET_INVALID = "target_invalid"
    TARGET_CHANGED = "target_changed"


class TargetResolutionError(RuntimeError):
    """Sanitized failure from exact target resolution or revalidation."""

    _MESSAGES = {
        TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure runtime target verification is unavailable."
        ),
        TargetResolutionErrorCode.AUTHORITY_MISMATCH: (
            "The target observation did not use the approved runtime authority."
        ),
        TargetResolutionErrorCode.MODEL_INVALID: (
            "The normalized Compose plan is not approved for TowerScout repair."
        ),
        TargetResolutionErrorCode.TARGET_MISSING: (
            "No matching TowerScout container was found."
        ),
        TargetResolutionErrorCode.TARGET_AMBIGUOUS: (
            "More than one matching TowerScout container was found."
        ),
        TargetResolutionErrorCode.TARGET_INVALID: (
            "The matching container target is inconsistent or unsupported."
        ),
        TargetResolutionErrorCode.TARGET_CHANGED: (
            "The approved container target changed during verification."
        ),
    }

    def __init__(self, code: TargetResolutionErrorCode) -> None:
        if type(code) is not TargetResolutionErrorCode:
            raise ValueError("Unknown target resolution error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"TargetResolutionError(code={self.code.value!r})"


def _fail(code: TargetResolutionErrorCode) -> NoReturn:
    raise TargetResolutionError(code)


def _add(digest: Any, value: bytes) -> None:
    if type(value) is not bytes:
        raise ValueError("Target evidence field is invalid.")
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _digest(domain: bytes, values: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (domain, *values):
        _add(digest, value)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _strict_text(value: object, *, maximum: int) -> str | None:
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
    except UnicodeEncodeError:
        return None
    return value


def _strict_environment_value(value: object) -> str | None:
    text = _strict_text(value, maximum=_MAX_ENVIRONMENT_VALUE_CHARACTERS)
    if text is None or any(ord(character) < 0x20 for character in text):
        return None
    return text


def _authority_scalar(value: Any, prefix: str) -> tuple[bytes, ...] | None:
    label = prefix.encode("ascii")
    if value is None:
        return (label, b"none")
    if isinstance(value, Enum):
        return (label, str(value.value).encode("utf-8"))
    if type(value) is PureWindowsPath:
        return (label, str(value).encode("utf-16-le"))
    if type(value) is bytes:
        return (label, value)
    if type(value) is bool:
        return (label, b"true" if value else b"false")
    if type(value) is int:
        return (label, str(value).encode("ascii"))
    if type(value) is str:
        return (label, value.encode("utf-8", errors="strict"))
    return None


def _authority_tuple(value: tuple[Any, ...], prefix: str) -> tuple[bytes, ...]:
    output: list[bytes] = [prefix.encode("ascii"), str(len(value)).encode("ascii")]
    for index, item in enumerate(value):
        output.extend(_authority_fields(item, f"{prefix}.{index}"))
    return tuple(output)


def _authority_dataclass(value: Any, prefix: str) -> tuple[bytes, ...]:
    output = [prefix.encode("ascii"), type(value).__name__.encode("ascii")]
    for item in fields(value):
        if item.metadata.get("authority", True):
            output.extend(
                _authority_fields(getattr(value, item.name), f"{prefix}.{item.name}")
            )
    return tuple(output)


def _authority_fields(value: Any, prefix: str = "plan") -> tuple[bytes, ...]:
    scalar = _authority_scalar(value, prefix)
    if scalar is not None:
        return scalar
    if type(value) is tuple:
        return _authority_tuple(value, prefix)
    if is_dataclass(value):
        return _authority_dataclass(value, prefix)
    raise TypeError("Target authority contains an unsupported field.")


def _file_binding_fields(identity: FileIdentity) -> tuple[bytes, ...]:
    return (
        identity.logical_name.encode("utf-8", errors="strict"),
        identity.canonical_path_sha256.encode("ascii"),
        identity.volume_serial.to_bytes(8, "big"),
        identity.file_id,
        identity.sha256.encode("ascii"),
        identity.size_bytes.to_bytes(8, "big"),
    )


def _compose_files_sha256(files_value: tuple[FileIdentity, ...]) -> str:
    return _digest(
        _COMPOSE_FILES_DOMAIN,
        tuple(
            value
            for identity in files_value
            for value in _file_binding_fields(identity)
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class TargetResolutionPlan:
    """Authenticated static inputs needed to interpret normalized observations."""

    package_root: FileIdentity
    process_environment: WindowsProcessEnvironment
    release_identity: str
    security_artifacts: SecurityArtifactInventory
    runtime: RuntimeIdentity
    endpoint: EndpointIdentity
    compose_provider: ComposeProviderIdentity
    ordered_compose_files: tuple[FileIdentity, ...]
    environment_sha256: str = field(repr=False)
    planned_environment_sha256: str = field(repr=False)
    environment_source: FileIdentity = field(repr=False)
    environment_file: FileIdentity | None = field(repr=False)
    compose_project: str
    acceleration: AccelerationPlan
    provider: MapProvider
    port: int
    configured_image_reference: str = field(repr=False)
    pinned_image_digest: str = field(repr=False)
    certificate: CertificateIdentity = field(repr=False)
    compose_files_sha256: str = field(
        init=False, repr=False, metadata={"authority": False}
    )
    authority_sha256: str = field(init=False, repr=False, metadata={"authority": False})

    def __post_init__(self) -> None:
        expected_provider = {
            RuntimeProduct.DOCKER: (
                ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE,
                EndpointBindingKind.DOCKER_HOST_ARGUMENT,
            ),
            RuntimeProduct.PODMAN: (
                ComposeInvocationKind.PODMAN_PYTHON_MODULE,
                EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
            ),
        }
        expected_files = {
            EffectiveProfile.CPU: ("compose.yaml",),
            EffectiveProfile.DOCKER_GPU: ("compose.yaml", "compose.gpu.yaml"),
            EffectiveProfile.PODMAN_GPU: (
                "compose.yaml",
                "compose.gpu.podman.yaml",
            ),
        }
        configured_name, separator, configured_digest = (
            self.configured_image_reference.rpartition("@")
            if type(self.configured_image_reference) is str
            else ("", "", "")
        )
        valid = (
            type(self.package_root) is FileIdentity
            and self.package_root.is_directory
            and type(self.process_environment) is WindowsProcessEnvironment
            and type(self.security_artifacts) is SecurityArtifactInventory
            and type(self.runtime) is RuntimeIdentity
            and type(self.endpoint) is EndpointIdentity
            and type(self.compose_provider) is ComposeProviderIdentity
            and type(self.ordered_compose_files) is tuple
            and all(type(item) is FileIdentity for item in self.ordered_compose_files)
            and type(self.environment_source) is FileIdentity
            and (
                self.environment_file is None
                or type(self.environment_file) is FileIdentity
            )
            and type(self.acceleration) is AccelerationPlan
            and type(self.provider) is MapProvider
            and type(self.certificate) is CertificateIdentity
            and type(self.port) is int
            and 1 <= self.port <= 65535
            and type(self.release_identity) is str
            and _RELEASE_IDENTITY.fullmatch(self.release_identity) is not None
            and type(self.compose_project) is str
            and _COMPOSE_PROJECT.fullmatch(self.compose_project) is not None
            and _is_sha256(self.environment_sha256)
            and _is_sha256(self.planned_environment_sha256)
            and type(self.pinned_image_digest) is str
            and _OCI_DIGEST.fullmatch(self.pinned_image_digest) is not None
            and bool(configured_name)
            and bool(separator)
            and configured_digest == self.pinned_image_digest
            and _strict_text(self.configured_image_reference, maximum=512)
            == self.configured_image_reference
            and self.runtime.product is self.endpoint.product
            and (
                self.compose_provider.invocation_kind,
                self.compose_provider.endpoint_binding,
            )
            == expected_provider.get(self.runtime.product)
            and self.certificate.provider is self.provider
            and tuple(item.logical_name for item in self.ordered_compose_files)
            == expected_files.get(self.acceleration.effective)
        )
        allowed_profiles = {
            RuntimeProduct.DOCKER: {
                EffectiveProfile.CPU,
                EffectiveProfile.DOCKER_GPU,
            },
            RuntimeProduct.PODMAN: {
                EffectiveProfile.CPU,
                EffectiveProfile.PODMAN_GPU,
            },
        }
        valid = valid and self.acceleration.effective in allowed_profiles.get(
            self.runtime.product, set()
        )
        runtime_leaf = f"{self.runtime.product.value}.exe"
        valid = (
            valid
            and self.runtime.executable.logical_name.casefold() == runtime_leaf
            and self.runtime.executable.final_path.name.casefold() == runtime_leaf
        )
        if self.environment_file is None:
            valid = (
                valid
                and self.environment_sha256 == ABSENT_FILE_SHA256
                and self.environment_source.logical_name == ".env.example"
            )
        else:
            valid = (
                valid
                and self.environment_file.logical_name == ".env"
                and self.environment_source == self.environment_file
                and self.environment_file.sha256 == self.environment_sha256
            )
        valid = valid and all(
            not item.is_directory
            and item.final_path == self.package_root.final_path / item.logical_name
            for item in self.ordered_compose_files
        )
        valid = (
            valid
            and not self.environment_source.is_directory
            and self.environment_source.final_path
            == self.package_root.final_path / self.environment_source.logical_name
        )
        if valid:
            content_files = (*self.ordered_compose_files, self.environment_source)
            valid = len({item.final_path for item in content_files}) == len(
                content_files
            ) and len(
                {(item.volume_serial, item.file_id) for item in content_files}
            ) == len(
                content_files
            )
        if not valid:
            raise ValueError("Target resolution plan is invalid.")
        try:
            compose_files_sha256 = _compose_files_sha256(self.ordered_compose_files)
            authority_sha256 = _digest(
                _AUTHORITY_DOMAIN,
                _authority_fields(self),
            )
        except (OverflowError, TypeError, UnicodeError, ValueError):
            raise ValueError("Target resolution plan is invalid.") from None
        object.__setattr__(self, "compose_files_sha256", compose_files_sha256)
        object.__setattr__(self, "authority_sha256", authority_sha256)

    def __repr__(self) -> str:
        return (
            "TargetResolutionPlan("
            f"runtime={self.runtime.product.value!r}, "
            f"provider={self.provider.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TargetResolutionSnapshot:
    """Bounded normalized outputs from one future authenticated read adapter."""

    authority_sha256: str = field(repr=False)
    normalized_pre_model: bytes = field(repr=False)
    normalized_post_model: bytes = field(repr=False)
    container_list: bytes = field(repr=False)
    container_inspect: bytes = field(repr=False)
    image_inspect: bytes = field(repr=False)
    volume_inspects: tuple[tuple[str, bytes], ...] = field(repr=False)

    def __post_init__(self) -> None:
        raw_values = (
            self.normalized_pre_model,
            self.normalized_post_model,
            self.container_list,
            self.container_inspect,
            self.image_inspect,
        )
        expected_names = tuple(name for name, _ in EXPECTED_VOLUME_DESTINATIONS)
        valid = (
            _is_sha256(self.authority_sha256)
            and all(
                type(value) is bytes and 1 <= len(value) <= _MAX_JSON_BYTES
                for value in raw_values
            )
            and type(self.volume_inspects) is tuple
            and len(self.volume_inspects) == len(EXPECTED_VOLUME_DESTINATIONS)
            and all(
                type(item) is tuple
                and len(item) == 2
                and type(item[0]) is str
                and type(item[1]) is bytes
                and 1 <= len(item[1]) <= _MAX_JSON_BYTES
                for item in self.volume_inspects
            )
            and tuple(item[0] for item in self.volume_inspects) == expected_names
        )
        if not valid:
            raise ValueError("Target resolution snapshot is invalid.")

    def __repr__(self) -> str:
        return "TargetResolutionSnapshot(state='bounded', <redacted>)"


class TargetResolutionBackend(Protocol):
    """Transferred exact-runtime adapter seam; captures must be read-only."""

    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture(self, plan: TargetResolutionPlan) -> TargetResolutionSnapshot: ...

    def close(self) -> None: ...


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Non-finite JSON value.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON member.")
        output[key] = value
    return output


def _validate_json_list(value: list[Any], *, depth: int) -> int:
    if len(value) > _MAX_JSON_ITEMS:
        raise ValueError("JSON list exceeded.")
    return 1 + sum(_validate_json_tree(item, depth=depth + 1) for item in value)


def _validate_json_object(value: dict[str, Any], *, depth: int) -> int:
    if len(value) > _MAX_JSON_ITEMS:
        raise ValueError("JSON object exceeded.")
    total = 1
    for key, item in value.items():
        if _strict_text(key, maximum=128) is None:
            raise ValueError("JSON member is invalid.")
        total += _validate_json_tree(item, depth=depth + 1)
    return total


def _validate_json_tree(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeded.")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("JSON integer exceeded.")
        return 1
    if type(value) is str:
        if _strict_text(value, maximum=_MAX_JSON_STRING_CHARACTERS) is None:
            raise ValueError("JSON string is invalid.")
        return 1
    if type(value) is list:
        return _validate_json_list(value, depth=depth)
    if type(value) is dict:
        return _validate_json_object(value, depth=depth)
    raise ValueError("JSON value type is invalid.")


def _load_json(raw: bytes, code: TargetResolutionErrorCode) -> Any:
    value: Any = None
    invalid = False
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_JSON_BYTES:
            raise ValueError("JSON bytes are invalid.")
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise ValueError("JSON BOM is invalid.")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if _validate_json_tree(value) > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded.")
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        invalid = True
    if invalid:
        _fail(code)
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", errors="strict")


def _object(value: Any, code: TargetResolutionErrorCode) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(code)
    return value


def _exact_keys(
    value: dict[str, Any], expected: frozenset[str], code: TargetResolutionErrorCode
) -> None:
    if frozenset(value) != expected:
        _fail(code)


def _schema_version_one(value: object) -> bool:
    return type(value) is int and value == 1


def _safe_private_name(value: object) -> str | None:
    if type(value) is not str or _PRIVATE_NAME.fullmatch(value) is None:
        return None
    return value


def _container_path(value: object) -> str | None:
    text = _strict_text(value, maximum=512)
    if text is None or not text.startswith("/") or "\\" in text:
        return None
    normalized = posixpath.normpath(text)
    if normalized != text or any(
        part in {"", ".", ".."} for part in text.split("/")[1:]
    ):
        return None
    return text


@dataclass(frozen=True, slots=True, repr=False)
class _ComposeObservation:
    pre_model_sha256: str
    post_model_sha256: str
    pre_provider_config_hash: str = field(repr=False)
    post_provider_config_hash: str = field(repr=False)
    pre_environment: dict[str, str] = field(repr=False)
    runtime_volumes: tuple[tuple[str, str, str], ...] = field(repr=False)


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


def _expected_container_security(plan: TargetResolutionPlan) -> dict[str, Any]:
    profile = _expected_profile(plan)
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


def _validated_environment(
    plan: TargetResolutionPlan,
    value: Any,
    *,
    planned: bool,
) -> dict[str, str]:
    environment = _object(value, TargetResolutionErrorCode.MODEL_INVALID)
    expected_names = _BASE_ENVIRONMENT_NAMES | (
        _GPU_ENVIRONMENT_NAMES
        if plan.acceleration.effective is not EffectiveProfile.CPU
        else frozenset()
    )
    if frozenset(environment) != expected_names or any(
        type(item) is not str or _strict_environment_value(item) is None
        for item in environment.values()
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    expected_values = {
        "FLASK_ENV": "production",
        "TOWERSCOUT_CONTAINER_ENGINE": plan.runtime.product.value,
        "TOWERSCOUT_HOST_PORT": str(plan.port),
        "TOWERSCOUT_IMAGE_DIGEST": plan.pinned_image_digest,
        "TOWERSCOUT_LAZY_MODEL_INIT": "1",
        "TOWERSCOUT_STARTUP_PRELOAD": "0",
        "TOWERSCOUT_DEVICE": {
            GpuMode.OFF: "cpu",
            GpuMode.AUTO: "auto",
            GpuMode.ON: "cuda",
        }[plan.acceleration.requested],
        "TOWERSCOUT_GPU_MODE": plan.acceleration.requested.value,
        "TOWERSCOUT_ALLOW_INSECURE_TLS": "0",
    }
    if any(
        environment.get(name) != expected for name, expected in expected_values.items()
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    if plan.acceleration.effective is not EffectiveProfile.CPU and (
        environment.get("NVIDIA_VISIBLE_DEVICES") != "all"
        or environment.get("NVIDIA_DRIVER_CAPABILITIES") != "compute,utility"
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    if planned:
        if (
            environment.get("REQUESTS_CA_BUNDLE") != _CA_DESTINATION
            or environment.get("SSL_CERT_FILE") != _CA_DESTINATION
        ):
            _fail(TargetResolutionErrorCode.MODEL_INVALID)
    else:
        if any(
            _container_path(environment.get(name)) is None
            for name in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")
        ):
            _fail(TargetResolutionErrorCode.MODEL_INVALID)
    return dict(environment)


def _validate_model(
    plan: TargetResolutionPlan,
    raw: bytes,
    *,
    planned: bool,
) -> tuple[dict[str, Any], dict[str, str], tuple[tuple[str, str, str], ...]]:
    model = _object(
        _load_json(raw, TargetResolutionErrorCode.MODEL_INVALID),
        TargetResolutionErrorCode.MODEL_INVALID,
    )
    _exact_keys(
        model,
        frozenset({"schema_version", "project", "service", "volumes"}),
        TargetResolutionErrorCode.MODEL_INVALID,
    )
    if (
        not _schema_version_one(model["schema_version"])
        or model["project"] != plan.compose_project
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    service = _object(model["service"], TargetResolutionErrorCode.MODEL_INVALID)
    _exact_keys(
        service,
        frozenset(
            {
                "name",
                "image",
                "provider_config_hash",
                "environment",
                "port",
                "restart",
                "healthcheck",
                "profile",
            }
        ),
        TargetResolutionErrorCode.MODEL_INVALID,
    )
    if (
        service["name"] != "towerscout"
        or service["image"] != plan.configured_image_reference
        or not _is_sha256(service["provider_config_hash"])
        or service["restart"] != "always"
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    environment = _validated_environment(plan, service["environment"], planned=planned)
    port = _object(service["port"], TargetResolutionErrorCode.MODEL_INVALID)
    _exact_keys(
        port,
        frozenset({"host_ip", "published", "target", "protocol"}),
        TargetResolutionErrorCode.MODEL_INVALID,
    )
    if (
        type(port["published"]) is not int
        or type(port["target"]) is not int
        or port
        != {
            "host_ip": "127.0.0.1",
            "published": plan.port,
            "target": 5000,
            "protocol": "tcp",
        }
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    healthcheck = _object(
        service["healthcheck"], TargetResolutionErrorCode.MODEL_INVALID
    )
    if any(
        type(healthcheck.get(name)) is not int for name in _HEALTHCHECK_INTEGER_FIELDS
    ) or healthcheck != {
        "command_sha256": EXPECTED_HEALTHCHECK_COMMAND_SHA256,
        "interval_seconds": 30,
        "timeout_seconds": 5,
        "start_period_seconds": 30,
        "retries": 3,
    }:
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    profile = _object(service["profile"], TargetResolutionErrorCode.MODEL_INVALID)
    if profile != _expected_profile(plan):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    volumes_value = model["volumes"]
    if type(volumes_value) is not list or len(volumes_value) != len(
        EXPECTED_VOLUME_DESTINATIONS
    ):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    runtime_volumes: list[tuple[str, str, str]] = []
    for item, (logical_name, destination) in zip(
        volumes_value, EXPECTED_VOLUME_DESTINATIONS, strict=True
    ):
        volume = _object(item, TargetResolutionErrorCode.MODEL_INVALID)
        _exact_keys(
            volume,
            frozenset(
                {"logical_name", "runtime_name", "destination", "type", "read_only"}
            ),
            TargetResolutionErrorCode.MODEL_INVALID,
        )
        runtime_name = _safe_private_name(volume["runtime_name"])
        expected_runtime_name = f"{plan.compose_project}_{logical_name}"
        if (
            volume["logical_name"] != logical_name
            or runtime_name != expected_runtime_name
            or volume["destination"] != destination
            or volume["type"] != "volume"
            or volume["read_only"] is not False
        ):
            _fail(TargetResolutionErrorCode.MODEL_INVALID)
        runtime_volumes.append((logical_name, runtime_name, destination))
    if len({item[1] for item in runtime_volumes}) != len(runtime_volumes):
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    return model, environment, tuple(runtime_volumes)


def _compose_observation(
    plan: TargetResolutionPlan,
    snapshot: TargetResolutionSnapshot,
) -> _ComposeObservation:
    pre_model, pre_environment, pre_volumes = _validate_model(
        plan, snapshot.normalized_pre_model, planned=False
    )
    post_model, _post_environment, post_volumes = _validate_model(
        plan, snapshot.normalized_post_model, planned=True
    )
    pre_comparison = json.loads(_canonical_json(pre_model))
    post_comparison = json.loads(_canonical_json(post_model))
    for model in (pre_comparison, post_comparison):
        environment = model["service"]["environment"]
        environment["REQUESTS_CA_BUNDLE"] = "<planned-ca>"
        environment["SSL_CERT_FILE"] = "<planned-ca>"
        model["service"]["provider_config_hash"] = "<provider-config>"
    if pre_comparison != post_comparison or pre_volumes != post_volumes:
        _fail(TargetResolutionErrorCode.MODEL_INVALID)
    return _ComposeObservation(
        pre_model_sha256=hashlib.sha256(_canonical_json(pre_model)).hexdigest(),
        post_model_sha256=hashlib.sha256(_canonical_json(post_model)).hexdigest(),
        pre_provider_config_hash=pre_model["service"]["provider_config_hash"],
        post_provider_config_hash=post_model["service"]["provider_config_hash"],
        pre_environment=pre_environment,
        runtime_volumes=pre_volumes,
    )


def _container_id(snapshot: TargetResolutionSnapshot) -> str:
    value = _load_json(
        snapshot.container_list, TargetResolutionErrorCode.TARGET_INVALID
    )
    if type(value) is not list:
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    if not value:
        _fail(TargetResolutionErrorCode.TARGET_MISSING)
    if len(value) != 1:
        _fail(TargetResolutionErrorCode.TARGET_AMBIGUOUS)
    container_id = value[0]
    if type(container_id) is not str or _CONTAINER_ID.fullmatch(container_id) is None:
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    return container_id


def _container_observation(
    plan: TargetResolutionPlan,
    snapshot: TargetResolutionSnapshot,
    compose: _ComposeObservation,
) -> tuple[ContainerIdentity, str]:
    container_id = _container_id(snapshot)
    value = _object(
        _load_json(
            snapshot.container_inspect, TargetResolutionErrorCode.TARGET_INVALID
        ),
        TargetResolutionErrorCode.TARGET_INVALID,
    )
    _exact_keys(
        value,
        frozenset(
            {
                "schema_version",
                "id",
                "name",
                "image_id",
                "configured_image",
                "running",
                "labels",
                "environment",
                "ports",
                "restart",
                "healthcheck",
                "profile",
                "security",
                "networks",
                "mounts",
            }
        ),
        TargetResolutionErrorCode.TARGET_INVALID,
    )
    image_id = value["image_id"]
    name = _safe_private_name(value["name"])
    labels = _object(value["labels"], TargetResolutionErrorCode.TARGET_INVALID)
    healthcheck = _object(
        value["healthcheck"], TargetResolutionErrorCode.TARGET_INVALID
    )
    _exact_keys(
        labels,
        frozenset(
            {
                "project",
                "service",
                "working_directory_sha256",
                "compose_files_sha256",
                "config_hash",
            }
        ),
        TargetResolutionErrorCode.TARGET_INVALID,
    )
    if (
        not _schema_version_one(value["schema_version"])
        or value["id"] != container_id
        or name is None
        or type(image_id) is not str
        or _OCI_DIGEST.fullmatch(image_id) is None
        or value["configured_image"] != plan.configured_image_reference
        or value["running"] is not True
        or labels
        != {
            "project": plan.compose_project,
            "service": "towerscout",
            "working_directory_sha256": plan.package_root.canonical_path_sha256,
            "compose_files_sha256": plan.compose_files_sha256,
            "config_hash": compose.pre_provider_config_hash,
        }
        or value["environment"] != compose.pre_environment
        or value["restart"] != "always"
        or any(
            type(healthcheck.get(name)) is not int
            for name in _HEALTHCHECK_INTEGER_FIELDS
        )
        or healthcheck
        != {
            "command_sha256": EXPECTED_HEALTHCHECK_COMMAND_SHA256,
            "interval_seconds": 30,
            "timeout_seconds": 5,
            "start_period_seconds": 30,
            "retries": 3,
        }
        or value["profile"] != _expected_profile(plan)
        or value["security"] != _expected_container_security(plan)
        or value["networks"] != [f"{plan.compose_project}_default"]
    ):
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    ports = value["ports"]
    if (
        type(ports) is not list
        or len(ports) != 1
        or type(ports[0]) is not dict
        or type(ports[0].get("published")) is not int
        or type(ports[0].get("target")) is not int
        or ports[0]
        != {
            "host_ip": "127.0.0.1",
            "published": plan.port,
            "target": 5000,
            "protocol": "tcp",
        }
    ):
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    security = _object(value["security"], TargetResolutionErrorCode.TARGET_INVALID)
    false_security_fields = (
        "privileged",
        "host_network",
        "host_pid",
        "host_ipc",
        "host_uts",
        "host_userns",
        "read_only_rootfs",
        "command_overridden",
        "entrypoint_overridden",
    )
    if any(security.get(name) is not False for name in false_security_fields):
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    mounts = value["mounts"]
    if type(mounts) is not list or len(mounts) != len(compose.runtime_volumes):
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    for mount_value, (_logical, runtime_name, destination) in zip(
        mounts, compose.runtime_volumes, strict=True
    ):
        mount = _object(mount_value, TargetResolutionErrorCode.TARGET_INVALID)
        if mount.get("read_write") is not True or mount != {
            "type": "volume",
            "name": runtime_name,
            "destination": destination,
            "read_write": True,
        }:
            _fail(TargetResolutionErrorCode.TARGET_INVALID)
    inspect_sha256 = hashlib.sha256(_canonical_json(value)).hexdigest()
    return (
        ContainerIdentity(
            container_id=container_id,
            container_name=name,
            daemon_image_id=image_id,
            private_inspect_sha256=inspect_sha256,
        ),
        inspect_sha256,
    )


def _image_observation(
    plan: TargetResolutionPlan,
    snapshot: TargetResolutionSnapshot,
    container: ContainerIdentity,
) -> tuple[ImageIdentity, str]:
    value = _object(
        _load_json(snapshot.image_inspect, TargetResolutionErrorCode.TARGET_INVALID),
        TargetResolutionErrorCode.TARGET_INVALID,
    )
    _exact_keys(
        value,
        frozenset({"schema_version", "id", "repository_digests"}),
        TargetResolutionErrorCode.TARGET_INVALID,
    )
    repository_digests = value["repository_digests"]
    repositories_are_text = type(repository_digests) is list and all(
        type(item) is str for item in repository_digests
    )
    valid_repositories = (
        repositories_are_text
        and 1 <= len(repository_digests) <= 32
        and len(set(repository_digests)) == len(repository_digests)
        and all(
            "@" in item and _OCI_DIGEST.fullmatch(item.rpartition("@")[2]) is not None
            for item in repository_digests
        )
    )
    if (
        not _schema_version_one(value["schema_version"])
        or value["id"] != container.daemon_image_id
        or not valid_repositories
        or plan.configured_image_reference not in repository_digests
    ):
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    inspect_sha256 = hashlib.sha256(_canonical_json(value)).hexdigest()
    return (
        ImageIdentity(
            configured_reference=plan.configured_image_reference,
            pinned_digest=plan.pinned_image_digest,
            repository_digest=plan.configured_image_reference,
            daemon_image_id=container.daemon_image_id,
            private_inspect_sha256=inspect_sha256,
        ),
        inspect_sha256,
    )


def _volume_observations(
    plan: TargetResolutionPlan,
    snapshot: TargetResolutionSnapshot,
    compose: _ComposeObservation,
) -> tuple[tuple[VolumeIdentity, ...], tuple[str, ...]]:
    volumes: list[VolumeIdentity] = []
    hashes: list[str] = []
    for (observed_name, raw), (logical_name, runtime_name, destination) in zip(
        snapshot.volume_inspects, compose.runtime_volumes, strict=True
    ):
        value = _object(
            _load_json(raw, TargetResolutionErrorCode.TARGET_INVALID),
            TargetResolutionErrorCode.TARGET_INVALID,
        )
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "name",
                    "driver",
                    "scope",
                    "options",
                    "project",
                    "logical_name",
                    "mountpoint_sha256",
                    "engine_metadata_sha256",
                }
            ),
            TargetResolutionErrorCode.TARGET_INVALID,
        )
        if (
            observed_name != logical_name
            or not _schema_version_one(value["schema_version"])
            or value["name"] != runtime_name
            or value["driver"] != "local"
            or value["scope"] != "local"
            or value["options"] != {}
            or value["project"] != plan.compose_project
            or value["logical_name"] != logical_name
            or not _is_sha256(value["mountpoint_sha256"])
            or not _is_sha256(value["engine_metadata_sha256"])
        ):
            _fail(TargetResolutionErrorCode.TARGET_INVALID)
        inspect_sha256 = hashlib.sha256(_canonical_json(value)).hexdigest()
        volumes.append(
            VolumeIdentity(
                logical_name=logical_name,
                runtime_name=runtime_name,
                destination=destination,
                private_inspect_sha256=inspect_sha256,
            )
        )
        hashes.append(inspect_sha256)
    return tuple(volumes), tuple(hashes)


@dataclass(frozen=True, slots=True, repr=False)
class _ParsedObservation:
    target: ResolvedRepairTarget = field(repr=False)
    binding_sha256: str = field(repr=False)
    container_inspect_sha256: str = field(repr=False)
    image_inspect_sha256: str = field(repr=False)
    volume_inspect_sha256: tuple[str, ...] = field(repr=False)


def _parse_observation(
    plan: TargetResolutionPlan,
    snapshot: TargetResolutionSnapshot,
) -> _ParsedObservation:
    if type(snapshot) is not TargetResolutionSnapshot:
        _fail(TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE)
    if snapshot.authority_sha256 != plan.authority_sha256:
        _fail(TargetResolutionErrorCode.AUTHORITY_MISMATCH)
    compose = _compose_observation(plan, snapshot)
    container, container_sha256 = _container_observation(plan, snapshot, compose)
    image, image_sha256 = _image_observation(plan, snapshot, container)
    volumes, volume_hashes = _volume_observations(plan, snapshot, compose)
    try:
        compose_plan = ComposePlan(
            ordered_files=plan.ordered_compose_files,
            environment_sha256=plan.environment_sha256,
            planned_environment_sha256=plan.planned_environment_sha256,
            pre_model_sha256=compose.pre_model_sha256,
            post_model_sha256=compose.post_model_sha256,
            environment_source=plan.environment_source,
            environment_file=plan.environment_file,
        )
        target = ResolvedRepairTarget(
            package_root=plan.package_root,
            process_environment=plan.process_environment,
            release_identity=plan.release_identity,
            security_artifacts=plan.security_artifacts,
            runtime=plan.runtime,
            endpoint=plan.endpoint,
            compose_provider=plan.compose_provider,
            compose=compose_plan,
            compose_project=plan.compose_project,
            service="towerscout",
            acceleration=plan.acceleration,
            provider=plan.provider,
            port=plan.port,
            image=image,
            container=container,
            volumes=volumes,
            certificate=plan.certificate,
        )
    except (TypeError, ValueError, UnicodeError):
        _fail(TargetResolutionErrorCode.TARGET_INVALID)
    binding_sha256 = _digest(
        _OBSERVATION_DOMAIN,
        (
            plan.authority_sha256.encode("ascii"),
            target.target_token.digest_sha256.encode("ascii"),
            container_sha256.encode("ascii"),
            image_sha256.encode("ascii"),
            *(value.encode("ascii") for value in volume_hashes),
        ),
    )
    return _ParsedObservation(
        target=target,
        binding_sha256=binding_sha256,
        container_inspect_sha256=container_sha256,
        image_inspect_sha256=image_sha256,
        volume_inspect_sha256=volume_hashes,
    )


@dataclass(frozen=True, slots=True, repr=False)
class TargetResolutionEvidence:
    target_token: str
    authority_sha256: str = field(repr=False)
    observation_binding_sha256: str = field(repr=False)
    pre_model_sha256: str = field(repr=False)
    post_model_sha256: str = field(repr=False)
    container_inspect_sha256: str = field(repr=False)
    image_inspect_sha256: str = field(repr=False)
    volume_inspect_sha256: tuple[str, ...] = field(repr=False)
    capture_count: int
    runtime_mutation_performed: bool
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.volume_inspect_sha256) is not tuple or len(
            self.volume_inspect_sha256
        ) != len(EXPECTED_VOLUME_DESTINATIONS):
            raise ValueError("Target resolution evidence is invalid.")
        hashes = (
            self.authority_sha256,
            self.observation_binding_sha256,
            self.pre_model_sha256,
            self.post_model_sha256,
            self.container_inspect_sha256,
            self.image_inspect_sha256,
            *self.volume_inspect_sha256,
        )
        if (
            type(self.target_token) is not str
            or not self.target_token.startswith("TSRT1-")
            or len(self.target_token) != 38
            or any(
                character not in "0123456789abcdef"
                for character in self.target_token[6:]
            )
            or any(not _is_sha256(value) for value in hashes)
            or self.capture_count != 2
            or self.runtime_mutation_performed is not False
        ):
            raise ValueError("Target resolution evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _digest(
                _EVIDENCE_DOMAIN,
                (
                    self.target_token.encode("ascii"),
                    *(value.encode("ascii") for value in hashes),
                    self.capture_count.to_bytes(2, "big"),
                    b"read-only",
                ),
            ),
        )

    def __repr__(self) -> str:
        return (
            "TargetResolutionEvidence("
            f"target_token={self.target_token!r}, captures={self.capture_count}, "
            "mutation=False, <redacted>)"
        )


def _capture_once(
    plan: TargetResolutionPlan,
    backend: TargetResolutionBackend,
) -> _ParsedObservation:
    snapshot: TargetResolutionSnapshot | None = None
    failure_code: TargetResolutionErrorCode | None = None
    try:
        snapshot = backend.capture(plan)
    except TargetResolutionError as error:
        failure_code = error.code
    except Exception:
        failure_code = TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
    if failure_code is not None:
        _fail(failure_code)
    if snapshot is None:
        _fail(TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE)
    return _parse_observation(plan, snapshot)


def _close_backend(backend: TargetResolutionBackend) -> bool:
    failed = False
    try:
        backend.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        closed = backend.closed is True
    except Exception:
        closed = False
    return failed or not closed


def _suppress_backend_close(backend: TargetResolutionBackend) -> None:
    try:
        _close_backend(backend)
    except BaseException:
        pass


class BoundResolvedRepairTarget:
    """Retain one immutable target and revalidate its normalized observations."""

    __slots__ = (
        "_active_owner",
        "_backend",
        "_binding_sha256",
        "_closed",
        "_evidence",
        "_lifetime_lock",
        "_plan",
        "_target",
    )

    def __init__(
        self,
        *,
        plan: TargetResolutionPlan,
        backend: TargetResolutionBackend,
        target: ResolvedRepairTarget,
        evidence: TargetResolutionEvidence,
    ) -> None:
        if (
            type(plan) is not TargetResolutionPlan
            or type(target) is not ResolvedRepairTarget
            or type(evidence) is not TargetResolutionEvidence
            or target.target_token.display != evidence.target_token
        ):
            raise ValueError("Bound resolved target is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._closed = False
        self._plan = plan
        self._backend: TargetResolutionBackend | None = backend
        self._target = target
        self._evidence = evidence
        self._binding_sha256 = evidence.observation_binding_sha256

    @property
    def target(self) -> ResolvedRepairTarget:
        return self._target

    @property
    def evidence(self) -> TargetResolutionEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return self._closed

    def _begin_use(self) -> None:
        self._lifetime_lock.acquire()
        if self._active_owner is not None or self._closed or self._backend is None:
            self._lifetime_lock.release()
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        self._active_owner = threading.get_ident()

    def _end_use(self) -> None:
        self._active_owner = None
        self._lifetime_lock.release()

    def _poison(self) -> None:
        backend = self._backend
        self._backend = None
        self._closed = True
        if backend is not None:
            _suppress_backend_close(backend)

    def _revalidate(self) -> None:
        observation: _ParsedObservation | None = None
        changed = False
        backend = self._backend
        if backend is None:
            self._poison()
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        try:
            observation = _capture_once(self._plan, backend)
        except BaseException as error:
            if not isinstance(error, Exception):
                self._poison()
                raise
            changed = True
        if changed or observation is None:
            self._poison()
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        if (
            observation.binding_sha256 != self._binding_sha256
            or observation.target.target_token != self._target.target_token
        ):
            self._poison()
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)

    def assert_unchanged(self) -> TargetResolutionEvidence:
        self._begin_use()
        try:
            self._revalidate()
            return self._evidence
        finally:
            self._end_use()

    def run_while_held(
        self,
        operation: Callable[[ResolvedRepairTarget], _Result],
    ) -> _Result:
        if not callable(operation):
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        self._begin_use()
        try:
            self._revalidate()
            operation_error: BaseException | None = None
            try:
                result = operation(self._target)
            except BaseException as error:
                operation_error = error
            if operation_error is not None:
                self._revalidate()
                raise operation_error
            self._revalidate()
            return result
        finally:
            self._end_use()

    def close(self) -> None:
        backend: TargetResolutionBackend | None = None
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(TargetResolutionErrorCode.TARGET_CHANGED)
            if self._closed:
                return
            backend = self._backend
            self._backend = None
            self._closed = True
            if backend is not None and _close_backend(backend):
                _fail(TargetResolutionErrorCode.TARGET_CHANGED)

    def __enter__(self) -> BoundResolvedRepairTarget:
        if self.closed:
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is None:
            self.close()
            return
        try:
            self.close()
        except TargetResolutionError:
            # Preserve the active operation error without attaching it to a
            # sanitized cleanup failure as implicit exception context.
            return

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "BoundResolvedRepairTarget("
            f"target_token={self._target.target_token.display!r}, "
            f"state={state!r}, <redacted>)"
        )


def capture_bound_resolved_repair_target(
    plan: TargetResolutionPlan,
    *,
    backend: TargetResolutionBackend,
) -> BoundResolvedRepairTarget:
    """Resolve twice and transfer the read-only backend into the target owner."""

    if type(plan) is not TargetResolutionPlan:
        _fail(TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE)
    try:
        supported = (
            backend.supported is True
            and backend.closed is False
            and callable(backend.capture)
            and callable(backend.close)
        )
    except Exception:
        supported = False
    if not supported:
        _suppress_backend_close(backend)
        _fail(TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE)
    transferred = False
    try:
        first = _capture_once(plan, backend)
        second = _capture_once(plan, backend)
        if (
            first.binding_sha256 != second.binding_sha256
            or first.target.target_token != second.target.target_token
        ):
            _fail(TargetResolutionErrorCode.TARGET_CHANGED)
        evidence = TargetResolutionEvidence(
            target_token=second.target.target_token.display,
            authority_sha256=plan.authority_sha256,
            observation_binding_sha256=second.binding_sha256,
            pre_model_sha256=second.target.compose.pre_model_sha256,
            post_model_sha256=second.target.compose.post_model_sha256,
            container_inspect_sha256=second.container_inspect_sha256,
            image_inspect_sha256=second.image_inspect_sha256,
            volume_inspect_sha256=second.volume_inspect_sha256,
            capture_count=2,
            runtime_mutation_performed=False,
        )
        owner = BoundResolvedRepairTarget(
            plan=plan,
            backend=backend,
            target=second.target,
            evidence=evidence,
        )
        transferred = True
        return owner
    finally:
        if not transferred:
            _suppress_backend_close(backend)


__all__ = [
    "EXPECTED_HEALTHCHECK_COMMAND_SHA256",
    "BoundResolvedRepairTarget",
    "TargetResolutionBackend",
    "TargetResolutionError",
    "TargetResolutionErrorCode",
    "TargetResolutionEvidence",
    "TargetResolutionPlan",
    "TargetResolutionSnapshot",
    "capture_bound_resolved_repair_target",
]
