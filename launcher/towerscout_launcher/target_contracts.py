"""Immutable Gate-A target contracts for the fail-closed repair path."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_FRAGMENT = re.compile(r"^[0-9a-f]{16}$")
_PUBLIC_TARGET_TOKEN = re.compile(r"^TSRT1-[0-9a-f]{32}$")
_PUBLIC_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+_-]{0,31}$")
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_PUBLIC_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PODMAN_SOCKET = re.compile(r"^/run/user/[1-9][0-9]*/podman/podman\.sock$")
_PODMAN_USER = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_TARGET_TOKEN_DOMAIN = b"TowerScout.ResolvedRepairTarget"
_PUBLIC_TOKEN_DOMAIN = b"TowerScout.PublicIdentity"
_PRIVATE_PATH_TOKEN_DOMAIN = b"TowerScout.CanonicalWindowsPath"
_TOKEN_SCHEMA_VERSION = 1
ABSENT_FILE_SHA256 = hashlib.sha256(b"TowerScout.AbsentFile.v1").hexdigest()

CONTAINER_CERT_DESTINATION = "/app/webapp/config/certs/local-ca.pem"
CONTAINER_BUNDLE_DESTINATION = "/app/webapp/config/certs/towerscout-ca-bundle.pem"
EXPECTED_VOLUME_DESTINATIONS: tuple[tuple[str, str], ...] = (
    ("towerscout_config", "/app/webapp/config"),
    ("towerscout_model_params", "/app/webapp/model_params"),
    ("towerscout_data", "/app/webapp/data"),
    ("towerscout_logs", "/app/webapp/logs"),
    ("towerscout_flask_session", "/app/webapp/flask_session"),
    ("towerscout_session_temp", "/app/webapp/temp/session"),
    ("towerscout_uploads", "/app/webapp/uploads"),
    ("towerscout_cache", "/app/webapp/cache"),
)


def _require_sha256(value: str, label: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest.")


def _require_text(value: str, label: str, maximum: int = 512) -> None:
    if not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{label} is invalid.")


def _hash_fields(domain: bytes, values: Sequence[str]) -> str:
    digest = hashlib.sha256()
    for value in (domain.decode("ascii"), str(_TOKEN_SCHEMA_VERSION), *values):
        encoded = value.encode("utf-8", errors="strict")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _canonical_fields(value: Any, prefix: str = "target") -> tuple[str, ...]:
    """Serialize approved immutable fields without delimiter ambiguity."""
    if value is None:
        return (prefix, "<absent>")
    if isinstance(value, Enum):
        return (prefix, str(value.value))
    if isinstance(value, bytes):
        return (prefix, value.hex())
    if isinstance(value, bool):
        return (prefix, "true" if value else "false")
    if isinstance(value, (str, int)):
        return (prefix, str(value))
    if type(value) is tuple:
        output: list[str] = [f"{prefix}.count", str(len(value))]
        for index, item in enumerate(value):
            output.extend(_canonical_fields(item, f"{prefix}.{index}"))
        return tuple(output)
    if is_dataclass(value):
        output = [f"{prefix}.type", type(value).__name__]
        for item in fields(value):
            if item.metadata.get("token", True):
                output.extend(
                    _canonical_fields(
                        getattr(value, item.name), f"{prefix}.{item.name}"
                    )
                )
        return tuple(output)
    raise TypeError(f"Unsupported target-token field type: {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class TargetToken:
    digest_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_sha256(self.digest_sha256, "target digest")

    @property
    def display(self) -> str:
        return f"TSRT1-{self.digest_sha256[:32]}"

    def __repr__(self) -> str:
        return f"TargetToken(display={self.display!r})"


def encode_target_token(values: Sequence[str]) -> TargetToken:
    return TargetToken(_hash_fields(_TARGET_TOKEN_DOMAIN, tuple(values)))


def _public_token(*values: str) -> str:
    return _hash_fields(_PUBLIC_TOKEN_DOMAIN, values)[:16]


class RuntimeProduct(str, Enum):
    DOCKER = "docker"
    PODMAN = "podman"


class EndpointKind(str, Enum):
    DOCKER_NAMED_PIPE = "docker_named_pipe"
    PODMAN_ROOTLESS_WSL = "podman_rootless_wsl"


class ComposeInvocationKind(str, Enum):
    DOCKER_COMPOSE_EXECUTABLE = "docker_compose_executable"
    PODMAN_PYTHON_MODULE = "podman_python_module"


class EndpointBindingKind(str, Enum):
    DOCKER_HOST_ARGUMENT = "docker_host_argument"
    PODMAN_CONTAINER_HOST_ENVIRONMENT = "podman_container_host_environment"


class GpuMode(str, Enum):
    OFF = "off"
    AUTO = "auto"
    ON = "on"


class EffectiveProfile(str, Enum):
    CPU = "cpu"
    DOCKER_GPU = "docker_gpu"
    PODMAN_GPU = "podman_gpu"


class MapProvider(str, Enum):
    GOOGLE = "google"
    AZURE = "azure"


class _Redacted:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FileIdentity(_Redacted):
    logical_name: str
    final_path: Path = field(repr=False, metadata={"token": False})
    volume_serial: int = field(repr=False)
    file_id: bytes = field(repr=False)
    is_directory: bool = False
    sha256: str = field(default="", repr=False)
    size_bytes: int = field(default=0, repr=False)
    canonical_path_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _require_text(self.logical_name, "file logical name", 128)
        final_path = str(self.final_path)
        if (
            not self.final_path.is_absolute()
            or "\x00" in final_path
            or len(final_path) > 32_768
        ):
            raise ValueError("File identity paths must be absolute.")
        if self.volume_serial < 0 or not 1 <= len(self.file_id) <= 64:
            raise ValueError("File identity is invalid.")
        if self.is_directory:
            if self.sha256 or self.size_bytes:
                raise ValueError("Directory identities cannot carry file content.")
        else:
            _require_sha256(self.sha256, "file digest")
            if self.size_bytes < 0:
                raise ValueError("File size is invalid.")
        object.__setattr__(
            self,
            "canonical_path_sha256",
            _hash_fields(_PRIVATE_PATH_TOKEN_DOMAIN, (final_path,)),
        )


@dataclass(frozen=True, slots=True, repr=False)
class WindowsProcessEnvironment(_Redacted):
    """Authenticated directory identities needed by Windows child processes."""

    system_root: FileIdentity
    temp_directory: FileIdentity
    user_profile: FileIdentity
    local_app_data: FileIdentity
    roaming_app_data: FileIdentity

    def __post_init__(self) -> None:
        expected = (
            ("system_root", self.system_root),
            ("temp_directory", self.temp_directory),
            ("user_profile", self.user_profile),
            ("local_app_data", self.local_app_data),
            ("roaming_app_data", self.roaming_app_data),
        )
        if any(
            type(identity) is not FileIdentity
            or identity.logical_name != logical_name
            or not identity.is_directory
            for logical_name, identity in expected
        ):
            raise ValueError("Windows process environment identity is invalid.")


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeIdentity(_Redacted):
    product: RuntimeProduct
    executable: FileIdentity
    version: str
    publisher_policy_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.executable.is_directory:
            raise ValueError("Runtime executable identity must refer to a file.")
        if not _PUBLIC_VERSION.fullmatch(self.version):
            raise ValueError("Runtime version is invalid.")
        _require_sha256(self.publisher_policy_sha256, "publisher policy")


@dataclass(frozen=True, slots=True, repr=False)
class EndpointIdentity(_Redacted):
    product: RuntimeProduct
    kind: EndpointKind
    canonical_endpoint: str = field(repr=False)
    private_metadata_sha256: str = field(repr=False)
    identity_key: FileIdentity | None = field(default=None, repr=False)
    discovery_artifacts: tuple[FileIdentity, ...] = field(default=(), repr=False)
    rootless: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.discovery_artifacts) is not tuple
            or any(
                type(artifact) is not FileIdentity
                for artifact in self.discovery_artifacts
            )
            or (
                self.identity_key is not None
                and type(self.identity_key) is not FileIdentity
            )
        ):
            raise ValueError("Endpoint artifacts are invalid.")
        _require_text(self.canonical_endpoint, "endpoint", 2048)
        _require_sha256(self.private_metadata_sha256, "endpoint metadata")
        expected = {
            RuntimeProduct.DOCKER: EndpointKind.DOCKER_NAMED_PIPE,
            RuntimeProduct.PODMAN: EndpointKind.PODMAN_ROOTLESS_WSL,
        }[self.product]
        if self.kind is not expected:
            raise ValueError("Endpoint kind does not match the runtime.")
        artifacts = (
            *self.discovery_artifacts,
            *((self.identity_key,) if self.identity_key is not None else ()),
        )
        if any(artifact.is_directory for artifact in artifacts):
            raise ValueError("Endpoint artifacts must be content-bearing files.")
        artifact_identities = {
            (artifact.volume_serial, artifact.file_id) for artifact in artifacts
        }
        if len(artifact_identities) != len(artifacts):
            raise ValueError("Endpoint artifacts cannot be duplicated.")
        if self.product is RuntimeProduct.DOCKER:
            if self.rootless or self.identity_key is not None:
                raise ValueError("Docker endpoint identity is inconsistent.")
            prefix = "npipe:////./pipe/"
            pipe_name = self.canonical_endpoint.removeprefix(prefix)
            if not self.canonical_endpoint.startswith(
                prefix
            ) or not _PUBLIC_LABEL.fullmatch(pipe_name):
                raise ValueError("Docker endpoint must be a local named pipe.")
        else:
            if not self.rootless:
                raise ValueError("Podman endpoints must be proven rootless.")
            if (
                self.identity_key is None
                or self.identity_key.logical_name != "podman_identity_key"
            ):
                raise ValueError("Podman endpoint identity material is missing.")
            try:
                parsed = urlsplit(self.canonical_endpoint)
                port = parsed.port
            except (ValueError, UnicodeError):
                raise ValueError("Podman endpoint URI is invalid.") from None
            try:
                host = ipaddress.ip_address(parsed.hostname or "")
            except ValueError:
                host = None
            if (
                parsed.scheme != "ssh"
                or not parsed.username
                or not _PODMAN_USER.fullmatch(parsed.username)
                or parsed.username.casefold() == "root"
                or parsed.password is not None
                or host is None
                or not host.is_loopback
                or port is None
                or not 1 <= port <= 65535
                or not _PODMAN_SOCKET.fullmatch(parsed.path)
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Podman endpoint must be a local rootless SSH socket.")


@dataclass(frozen=True, slots=True, repr=False)
class ComposeProviderIdentity(_Redacted):
    provider_id: str
    invocation_kind: ComposeInvocationKind
    endpoint_binding: EndpointBindingKind
    artifacts: tuple[FileIdentity, ...]
    integrity_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.artifacts) is not tuple or any(
            type(artifact) is not FileIdentity for artifact in self.artifacts
        ):
            raise ValueError("Compose provider artifacts are invalid.")
        _require_text(self.provider_id, "Compose provider id", 128)
        if not self.artifacts:
            raise ValueError("Compose provider artifacts are missing.")
        if any(artifact.is_directory for artifact in self.artifacts):
            raise ValueError("Compose provider artifacts must be files.")
        artifact_identities = {
            (artifact.volume_serial, artifact.file_id) for artifact in self.artifacts
        }
        artifact_paths = {artifact.final_path for artifact in self.artifacts}
        if len(artifact_identities) != len(self.artifacts) or len(
            artifact_paths
        ) != len(self.artifacts):
            raise ValueError("Compose provider artifacts must be distinct.")
        if self.invocation_kind is ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE:
            if (
                len(self.artifacts) != 1
                or self.artifacts[0].logical_name.casefold() != "docker-compose.exe"
            ):
                raise ValueError("Docker Compose provider identity is invalid.")
        else:
            if (
                len(self.artifacts) < 2
                or self.artifacts[0].logical_name.casefold() != "python.exe"
                or self.artifacts[1].logical_name != "podman_compose_module"
                or self.artifacts[0].final_path.parent.name.casefold() != "scripts"
                or self.artifacts[1].final_path
                != self.artifacts[0].final_path.parent.parent
                / "Lib"
                / "site-packages"
                / "podman_compose.py"
            ):
                raise ValueError("Podman Compose provider identity is invalid.")
        _require_sha256(self.integrity_sha256, "Compose provider integrity")


@dataclass(frozen=True, slots=True, repr=False)
class ComposePlan(_Redacted):
    ordered_files: tuple[FileIdentity, ...]
    environment_sha256: str = field(repr=False)
    planned_environment_sha256: str = field(repr=False)
    pre_model_sha256: str = field(repr=False)
    post_model_sha256: str = field(repr=False)
    environment_source: FileIdentity = field(repr=False)
    environment_file: FileIdentity | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.ordered_files) is not tuple
            or any(type(item) is not FileIdentity for item in self.ordered_files)
            or type(self.environment_source) is not FileIdentity
            or (
                self.environment_file is not None
                and type(self.environment_file) is not FileIdentity
            )
        ):
            raise ValueError("Compose input identities are invalid.")
        if (
            not self.ordered_files
            or self.ordered_files[0].logical_name != "compose.yaml"
        ):
            raise ValueError("The Compose plan must begin with compose.yaml.")
        if any(item.is_directory for item in self.ordered_files):
            raise ValueError("Compose inputs must be content-bearing files.")
        logical_names = tuple(item.logical_name for item in self.ordered_files)
        if len(set(logical_names)) != len(logical_names):
            raise ValueError("Compose inputs cannot be duplicated.")
        if self.environment_source.is_directory:
            raise ValueError("Compose environment source must be a file.")
        if self.environment_file is None:
            if (
                self.environment_sha256 != ABSENT_FILE_SHA256
                or self.environment_source.logical_name != ".env.example"
            ):
                raise ValueError("Absent environment file identity is inconsistent.")
        elif (
            self.environment_file.is_directory
            or self.environment_file.logical_name != ".env"
            or self.environment_file.sha256 != self.environment_sha256
            or self.environment_source != self.environment_file
        ):
            raise ValueError("Environment file identity is inconsistent.")
        for label, value in (
            ("environment", self.environment_sha256),
            ("planned environment", self.planned_environment_sha256),
            ("pre-change model", self.pre_model_sha256),
            ("post-change model", self.post_model_sha256),
        ):
            _require_sha256(value, label)


@dataclass(frozen=True, slots=True)
class AccelerationPlan:
    requested: GpuMode
    effective: EffectiveProfile
    overlay_logical_name: str = ""

    def __post_init__(self) -> None:
        if self.requested is GpuMode.OFF and self.effective is not EffectiveProfile.CPU:
            raise ValueError("GPU mode off must resolve to CPU.")
        if self.requested is GpuMode.ON and self.effective is EffectiveProfile.CPU:
            raise ValueError("GPU mode on cannot resolve to CPU.")
        if (self.effective is EffectiveProfile.CPU) == bool(self.overlay_logical_name):
            raise ValueError("GPU overlay and effective profile disagree.")


@dataclass(frozen=True, slots=True, repr=False)
class ImageIdentity(_Redacted):
    configured_reference: str = field(repr=False)
    pinned_digest: str = field(repr=False)
    repository_digest: str = field(repr=False)
    daemon_image_id: str = field(repr=False)
    private_inspect_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_text(self.configured_reference, "image reference")
        if not _OCI_DIGEST.fullmatch(self.pinned_digest):
            raise ValueError("Pinned image digest is invalid.")
        configured_name, separator, configured_digest = (
            self.configured_reference.rpartition("@")
        )
        if (
            not separator
            or not configured_name
            or configured_digest != self.pinned_digest
        ):
            raise ValueError("Configured image reference is not pinned to its digest.")
        repository_name, separator, repository_digest = (
            self.repository_digest.rpartition("@")
        )
        if (
            not separator
            or not repository_name
            or repository_digest != self.pinned_digest
        ):
            raise ValueError("Repository digest does not match the pinned image.")
        if not _OCI_DIGEST.fullmatch(self.daemon_image_id):
            raise ValueError("Daemon image ID is invalid.")
        _require_sha256(self.private_inspect_sha256, "image inspection")


@dataclass(frozen=True, slots=True, repr=False)
class ContainerIdentity(_Redacted):
    container_id: str = field(repr=False)
    container_name: str = field(repr=False)
    daemon_image_id: str = field(repr=False)
    private_inspect_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_text(self.container_id, "container id", 256)
        _require_text(self.container_name, "container name", 256)
        if not _OCI_DIGEST.fullmatch(self.daemon_image_id):
            raise ValueError("Daemon image ID is invalid.")
        _require_sha256(self.private_inspect_sha256, "container inspection")


@dataclass(frozen=True, slots=True, repr=False)
class VolumeIdentity(_Redacted):
    logical_name: str
    runtime_name: str = field(repr=False)
    destination: str
    private_inspect_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_text(self.logical_name, "volume logical name", 128)
        _require_text(self.runtime_name, "runtime volume name", 256)
        _require_text(self.destination, "volume destination", 256)
        _require_sha256(self.private_inspect_sha256, "volume inspection")


@dataclass(frozen=True, slots=True, repr=False)
class CertificateIdentity(_Redacted):
    provider: MapProvider
    windows_root_fingerprint_sha256: str = field(repr=False)
    candidate_content_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_sha256(self.windows_root_fingerprint_sha256, "Windows root")
        _require_sha256(self.candidate_content_sha256, "CA candidate")


@dataclass(frozen=True, slots=True)
class PublicRepairSummary:
    target_token: str
    runtime_product: RuntimeProduct
    runtime_version: str
    endpoint_kind: EndpointKind
    compose_project: str
    service: str
    container_token: str
    image_token: str
    requested_gpu_mode: GpuMode
    effective_profile: EffectiveProfile
    provider: MapProvider
    port: int
    config_volume_label: str
    config_volume_token: str
    compose_model_token: str

    def __post_init__(self) -> None:
        if not _PUBLIC_TARGET_TOKEN.fullmatch(self.target_token):
            raise ValueError("Public target token is invalid.")
        if not _PUBLIC_VERSION.fullmatch(self.runtime_version):
            raise ValueError("Runtime version is not public-safe.")
        expected_endpoint = {
            RuntimeProduct.DOCKER: EndpointKind.DOCKER_NAMED_PIPE,
            RuntimeProduct.PODMAN: EndpointKind.PODMAN_ROOTLESS_WSL,
        }[self.runtime_product]
        if self.endpoint_kind is not expected_endpoint:
            raise ValueError("Public endpoint kind does not match the runtime.")
        allowed_profiles = {
            RuntimeProduct.DOCKER: {
                EffectiveProfile.CPU,
                EffectiveProfile.DOCKER_GPU,
            },
            RuntimeProduct.PODMAN: {
                EffectiveProfile.CPU,
                EffectiveProfile.PODMAN_GPU,
            },
        }[self.runtime_product]
        if self.effective_profile not in allowed_profiles:
            raise ValueError("Public acceleration profile does not match the runtime.")
        invalid_requested_profile = (
            self.requested_gpu_mode is GpuMode.OFF
            and self.effective_profile is not EffectiveProfile.CPU
        ) or (
            self.requested_gpu_mode is GpuMode.ON
            and self.effective_profile is EffectiveProfile.CPU
        )
        if invalid_requested_profile:
            raise ValueError("Public requested and effective GPU profiles disagree.")
        if not _COMPOSE_PROJECT.fullmatch(self.compose_project):
            raise ValueError("Compose project is not public-safe.")
        if self.service != "towerscout" or not 1 <= self.port <= 65535:
            raise ValueError("Public service or port is invalid.")
        if not _PUBLIC_LABEL.fullmatch(self.config_volume_label):
            raise ValueError("Config-volume label is not public-safe.")
        for label, value in (
            ("container", self.container_token),
            ("image", self.image_token),
            ("config volume", self.config_volume_token),
            ("Compose model", self.compose_model_token),
        ):
            if not _PUBLIC_FRAGMENT.fullmatch(value):
                raise ValueError(f"Public {label} token is invalid.")

    @property
    def endpoint_label(self) -> str:
        return {
            EndpointKind.DOCKER_NAMED_PIPE: "local Windows named pipe",
            EndpointKind.PODMAN_ROOTLESS_WSL: "local rootless Podman WSL endpoint",
        }[self.endpoint_kind]

    def render(self) -> str:
        runtime = (
            "Docker" if self.runtime_product is RuntimeProduct.DOCKER else "Podman"
        )
        provider = (
            "Google Maps" if self.provider is MapProvider.GOOGLE else "Azure Maps"
        )
        return (
            f"Transaction target: {self.target_token}\n"
            f"Runtime: {runtime} {self.runtime_version}\n"
            f"Endpoint: {self.endpoint_label}\n"
            f"Compose target: {self.compose_project}/{self.service}\n"
            f"Container token: {self.container_token}\n"
            f"Image token: {self.image_token}\n"
            f"GPU profile: requested {self.requested_gpu_mode.value}, "
            f"effective {self.effective_profile.value}\n"
            f"Provider: {provider}\n"
            f"Port: {self.port}\n"
            f"Config volume: {self.config_volume_label} [{self.config_volume_token}]\n"
            f"Compose model token: {self.compose_model_token}\n"
            f"Certificate destinations: {CONTAINER_CERT_DESTINATION}, "
            f"{CONTAINER_BUNDLE_DESTINATION}"
        )

    def __str__(self) -> str:
        return self.render()


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedRepairTarget:
    package_root: FileIdentity
    process_environment: WindowsProcessEnvironment
    release_identity: str
    runtime: RuntimeIdentity
    endpoint: EndpointIdentity
    compose_provider: ComposeProviderIdentity
    compose: ComposePlan
    compose_project: str
    service: str
    acceleration: AccelerationPlan
    provider: MapProvider
    port: int
    image: ImageIdentity
    container: ContainerIdentity
    volumes: tuple[VolumeIdentity, ...]
    certificate: CertificateIdentity
    target_token: TargetToken = field(init=False, metadata={"token": False})

    def __post_init__(self) -> None:
        if type(self.volumes) is not tuple or any(
            type(volume) is not VolumeIdentity for volume in self.volumes
        ):
            raise ValueError("Runtime volume identities are invalid.")
        _require_text(self.release_identity, "release identity", 256)
        if not self.package_root.is_directory:
            raise ValueError("Package root must be a directory identity.")
        expected_compose_paths = tuple(
            self.package_root.final_path / item.logical_name
            for item in self.compose.ordered_files
        )
        if tuple(item.final_path for item in self.compose.ordered_files) != (
            expected_compose_paths
        ):
            raise ValueError("Compose inputs are outside the bound package root.")
        if self.compose.environment_file is not None and (
            self.compose.environment_file.final_path
            != self.package_root.final_path / ".env"
        ):
            raise ValueError("Environment file is outside the bound package root.")
        if self.compose.environment_source.final_path != (
            self.package_root.final_path / self.compose.environment_source.logical_name
        ):
            raise ValueError("Compose environment source is outside the package root.")
        if self.runtime.product is not self.endpoint.product:
            raise ValueError("Runtime and endpoint products differ.")
        expected_compose = {
            RuntimeProduct.DOCKER: (
                ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE,
                EndpointBindingKind.DOCKER_HOST_ARGUMENT,
            ),
            RuntimeProduct.PODMAN: (
                ComposeInvocationKind.PODMAN_PYTHON_MODULE,
                EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
            ),
        }[self.runtime.product]
        if (
            self.compose_provider.invocation_kind,
            self.compose_provider.endpoint_binding,
        ) != expected_compose:
            raise ValueError("Compose execution does not match the bound runtime.")
        allowed_profiles = {
            RuntimeProduct.DOCKER: {
                EffectiveProfile.CPU,
                EffectiveProfile.DOCKER_GPU,
            },
            RuntimeProduct.PODMAN: {
                EffectiveProfile.CPU,
                EffectiveProfile.PODMAN_GPU,
            },
        }[self.runtime.product]
        if self.acceleration.effective not in allowed_profiles:
            raise ValueError(
                "Effective acceleration profile does not match the runtime."
            )
        expected_files = {
            EffectiveProfile.CPU: ("compose.yaml",),
            EffectiveProfile.DOCKER_GPU: ("compose.yaml", "compose.gpu.yaml"),
            EffectiveProfile.PODMAN_GPU: (
                "compose.yaml",
                "compose.gpu.podman.yaml",
            ),
        }[self.acceleration.effective]
        ordered_names = tuple(item.logical_name for item in self.compose.ordered_files)
        if ordered_names != expected_files:
            raise ValueError(
                "Compose inputs do not match the effective acceleration profile."
            )
        expected_overlay = expected_files[1] if len(expected_files) == 2 else ""
        if self.acceleration.overlay_logical_name != expected_overlay:
            raise ValueError(
                "The selected acceleration overlay is not the bound input."
            )
        if self.provider is not self.certificate.provider:
            raise ValueError("Provider and certificate plans differ.")
        if not _COMPOSE_PROJECT.fullmatch(self.compose_project):
            raise ValueError("Compose project identity is invalid.")
        if self.service != "towerscout" or not 1 <= self.port <= 65535:
            raise ValueError("Target service or port is invalid.")
        if self.container.daemon_image_id != self.image.daemon_image_id:
            raise ValueError("Container and inspected image identities differ.")
        observed = tuple(
            (volume.logical_name, volume.destination) for volume in self.volumes
        )
        if observed != EXPECTED_VOLUME_DESTINATIONS:
            raise ValueError("The target must bind all eight ordered volumes.")
        if len({volume.runtime_name for volume in self.volumes}) != len(self.volumes):
            raise ValueError("Runtime volume names must be distinct.")
        token = encode_target_token(_canonical_fields(self))
        object.__setattr__(self, "target_token", token)

    def to_public_summary(self) -> PublicRepairSummary:
        config_volume = self.volumes[0]
        return PublicRepairSummary(
            target_token=self.target_token.display,
            runtime_product=self.runtime.product,
            runtime_version=self.runtime.version,
            endpoint_kind=self.endpoint.kind,
            compose_project=self.compose_project,
            service=self.service,
            container_token=_public_token(
                "container", self.container.container_id, self.container.container_name
            ),
            image_token=_public_token(
                "image", self.container.daemon_image_id, self.image.repository_digest
            ),
            requested_gpu_mode=self.acceleration.requested,
            effective_profile=self.acceleration.effective,
            provider=self.provider,
            port=self.port,
            config_volume_label=config_volume.runtime_name,
            config_volume_token=_public_token(
                "volume",
                config_volume.runtime_name,
                config_volume.private_inspect_sha256,
            ),
            compose_model_token=self.compose.post_model_sha256[:16],
        )

    def __repr__(self) -> str:
        return (
            "ResolvedRepairTarget("
            f"token={self.target_token.display!r}, "
            f"runtime={self.runtime.product.value!r}, "
            f"provider={self.provider.value!r})"
        )
