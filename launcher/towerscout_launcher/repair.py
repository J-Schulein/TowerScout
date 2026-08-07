from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess  # nosec B404 - fixed container-runtime commands only
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .discovery import load_package_identity, read_towerscout_status
from .models import LauncherSnapshot, PublicState


_PROVIDER_HOSTS: Mapping[str, str] = {
    "google": "maps.googleapis.com",
    "azure": "atlas.microsoft.com",
}
_ENGINES = {"docker", "podman"}
_GPU_MODES = {"off", "auto", "on"}
_CONFIRMATION = "repair_tls_and_restart"
_MAX_CHAIN_DEPTH = 8
_MAX_RUNTIME_OUTPUT = 1_048_576
_COMMAND_TIMEOUT_SECONDS = 30.0
_RESTART_TIMEOUT_SECONDS = 180.0
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_PODMAN_COMPOSE_VERSIONS: Mapping[str, re.Pattern[str]] = {
    "podman-compose": re.compile(r"(?i)podman-compose\s+version\s+1\.5\.0"),
    "podman-compose.exe": re.compile(r"(?i)podman-compose\s+version\s+1\.5\.0"),
    "docker-compose": re.compile(r"(?i)docker compose version v?5\.1\.4"),
    "docker-compose.exe": re.compile(r"(?i)docker compose version v?5\.1\.4"),
}
_CERT_DIR = "/app/webapp/config/certs"
_SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
_CONTAINER_CERT = f"{_CERT_DIR}/local-ca.pem"
_CONTAINER_BUNDLE = f"{_CERT_DIR}/towerscout-ca-bundle.pem"
_TLS_VERIFY_SCRIPT = (
    "import socket,ssl,sys;"
    "c=ssl.create_default_context(cafile=sys.argv[2]);"
    "s=socket.create_connection((sys.argv[1],443),timeout=10);"
    "t=c.wrap_socket(s,server_hostname=sys.argv[1]);"
    "t.close();s.close();print('tls_verified')"
)


class RepairState(str, Enum):
    PREPARED = "prepared"
    CONFIRMED = "confirmed"
    APPLYING = "applying"
    RESTARTING = "restarting"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    RECOVERY_REQUIRED = "recovery_required"


class RepairError(RuntimeError):
    def __init__(self, category: str, public_message: str) -> None:
        super().__init__(public_message)
        self.category = category
        self.public_message = public_message


@dataclass(frozen=True)
class RepairTarget:
    package_root: Path = field(repr=False)
    target_fingerprint: str
    provider: str
    engine: str
    gpu_mode: str
    port: int
    compose_project: str
    image: str
    image_digest: str


@dataclass(frozen=True)
class CertificateCandidate:
    pem: str = field(repr=False)
    fingerprint_sha256: str = field(repr=False)
    public_message: str


@dataclass
class RepairTransaction:
    target: RepairTarget
    state: RepairState
    public_message: str
    candidate: CertificateCandidate | None = field(default=None, repr=False)


@dataclass
class _RepairBackup:
    staging_root: Path = field(repr=False)
    container_id: str = field(repr=False)
    env_existed: bool
    env_bytes: bytes = field(repr=False)
    previous_cert: Path | None = field(default=None, repr=False)
    previous_bundle: Path | None = field(default=None, repr=False)


def _target_fingerprint(snapshot: LauncherSnapshot, provider: str, engine: str) -> str:
    package = snapshot.package
    material = "\n".join(
        (
            str(package.root.resolve()),
            package.release_version,
            package.compose_project,
            package.image,
            package.image_digest,
            engine,
            package.gpu_mode,
            str(package.port),
            provider,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_repair_target(
    snapshot: LauncherSnapshot, *, provider: str, engine: str
) -> RepairTarget:
    if provider not in _PROVIDER_HOSTS or engine not in _ENGINES:
        raise RepairError(
            "invalid_selection",
            "Choose one fixed TowerScout provider and one detected runtime.",
        )
    runtime = next((item for item in snapshot.runtimes if item.engine == engine), None)
    if runtime is None or not runtime.reachable:
        raise RepairError(
            "runtime_unavailable",
            "The selected container runtime is not reachable. No changes were made.",
        )
    package = snapshot.package
    if package.engine_hint and package.engine_hint != engine:
        raise RepairError(
            "runtime_profile_mismatch",
            "The selected runtime does not match this package profile.",
        )
    if (
        snapshot.towerscout.runtime_engine
        and snapshot.towerscout.runtime_engine != engine
    ):
        raise RepairError(
            "running_runtime_mismatch",
            "The running TowerScout instance uses a different container runtime.",
        )
    if package.gpu_mode not in _GPU_MODES:
        raise RepairError("invalid_profile", "The package GPU profile is invalid.")
    if not _COMPOSE_PROJECT.fullmatch(package.compose_project):
        raise RepairError(
            "invalid_compose_project",
            "The package compose project identity is invalid.",
        )
    if package.is_release_package and not package.image_digest:
        raise RepairError(
            "image_identity_unavailable",
            "The package image identity could not be verified.",
        )
    return RepairTarget(
        package_root=package.root.resolve(),
        target_fingerprint=_target_fingerprint(snapshot, provider, engine),
        provider=provider,
        engine=engine,
        gpu_mode=package.gpu_mode,
        port=package.port,
        compose_project=package.compose_project,
        image=package.image,
        image_digest=package.image_digest,
    )


def _certificate_name(value: object) -> tuple[tuple[tuple[str, str], ...], ...]:
    if not isinstance(value, (tuple, list)):
        return ()
    normalized: list[tuple[tuple[str, str], ...]] = []
    for relative_name in value:
        if not isinstance(relative_name, (tuple, list)):
            return ()
        attributes: list[tuple[str, str]] = []
        for attribute in relative_name:
            if not isinstance(attribute, (tuple, list)) or len(attribute) != 2:
                return ()
            attributes.append((str(attribute[0]), str(attribute[1])))
        normalized.append(tuple(attributes))
    return tuple(normalized)


def _load_trusted_ca_records(
    context: ssl.SSLContext,
) -> tuple[tuple[dict[str, object], bytes], ...]:
    decoded = context.get_ca_certs(binary_form=False)
    encoded = context.get_ca_certs(binary_form=True)
    if len(decoded) != len(encoded) or not decoded:
        raise RepairError(
            "windows_trust_unavailable",
            "The Windows trusted certificate set could not be inspected safely.",
        )
    records: list[tuple[dict[str, object], bytes]] = []
    seen: set[str] = set()
    for details, der in zip(decoded, encoded):
        if isinstance(details, dict) and isinstance(der, bytes):
            fingerprint = hashlib.sha256(der).hexdigest()
            if fingerprint not in seen:
                records.append((details, der))
                seen.add(fingerprint)
    if os.name == "nt" and hasattr(ssl, "enum_certificates"):
        windows_der = []
        for store_name in ("ROOT", "CA"):
            windows_der.extend(
                der
                for der, encoding, _trust in ssl.enum_certificates(store_name)
                if encoding == "x509_asn" and isinstance(der, bytes)
            )
        if windows_der:
            decode_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            decode_context.load_verify_locations(
                cadata="\n".join(ssl.DER_cert_to_PEM_cert(der) for der in windows_der)
            )
            decoded_windows = decode_context.get_ca_certs(binary_form=False)
            encoded_windows = decode_context.get_ca_certs(binary_form=True)
            for details, der in zip(decoded_windows, encoded_windows):
                fingerprint = hashlib.sha256(der).hexdigest()
                if isinstance(details, dict) and fingerprint not in seen:
                    records.append((details, der))
                    seen.add(fingerprint)
    return tuple(records)


def _find_unique_trusted_root(
    leaf: Mapping[str, object],
    records: Sequence[tuple[dict[str, object], bytes]],
) -> bytes:
    issuer = _certificate_name(leaf.get("issuer"))
    if not issuer:
        raise RepairError(
            "provider_chain_invalid",
            "The provider certificate chain could not be classified safely.",
        )
    visited: set[tuple[tuple[tuple[str, str], ...], ...]] = set()
    for _ in range(_MAX_CHAIN_DEPTH):
        if issuer in visited:
            break
        visited.add(issuer)
        matches = [
            (details, der)
            for details, der in records
            if _certificate_name(details.get("subject")) == issuer
        ]
        if len(matches) != 1:
            category = "trusted_ca_not_found" if not matches else "trusted_ca_ambiguous"
            raise RepairError(
                category,
                "TowerScout could not select one unambiguous trusted CA certificate.",
            )
        details, der = matches[0]
        subject = _certificate_name(details.get("subject"))
        parent = _certificate_name(details.get("issuer"))
        if subject and subject == parent:
            return der
        if not parent:
            break
        issuer = parent
    raise RepairError(
        "trusted_root_not_found",
        "TowerScout could not resolve the provider chain to one trusted root.",
    )


def _verified_root_from_socket(tls_socket: ssl.SSLSocket) -> bytes | None:
    ssl_object = getattr(tls_socket, "_sslobj", None)
    chain_reader = getattr(ssl_object, "get_verified_chain", None)
    if not callable(chain_reader):
        return None
    try:
        chain = tuple(chain_reader())
    except (OSError, ssl.SSLError, ValueError):
        return None
    if not chain or len(chain) > _MAX_CHAIN_DEPTH:
        return None
    root = chain[-1]
    info_reader = getattr(root, "get_info", None)
    bytes_reader = getattr(root, "public_bytes", None)
    if not callable(info_reader) or not callable(bytes_reader):
        return None
    try:
        details = info_reader()
        pem = bytes_reader()
    except (OSError, ssl.SSLError, ValueError):
        return None
    if not isinstance(details, dict) or not isinstance(pem, str):
        return None
    subject = _certificate_name(details.get("subject"))
    issuer = _certificate_name(details.get("issuer"))
    if not subject or subject != issuer:
        return None
    try:
        return ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        return None


def select_windows_ca_candidate(
    provider: str,
    *,
    context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    connection_factory: Callable[..., socket.socket] = socket.create_connection,
) -> CertificateCandidate:
    if provider not in _PROVIDER_HOSTS:
        raise RepairError("invalid_provider", "The selected provider is unsupported.")
    if os.name != "nt":
        raise RepairError(
            "windows_required",
            "Provider TLS repair requires the approved Windows launcher.",
        )
    host = _PROVIDER_HOSTS[provider]
    context = context_factory()
    verified_root: bytes | None = None
    try:
        with connection_factory((host, 443), timeout=10.0) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                leaf = tls_socket.getpeercert()
                verified_root = _verified_root_from_socket(tls_socket)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise RepairError(
            "provider_tls_probe_failed",
            "TowerScout could not inspect the provider TLS chain safely.",
        ) from exc
    if not isinstance(leaf, dict):
        raise RepairError(
            "provider_chain_invalid",
            "The provider certificate chain could not be classified safely.",
        )
    root_der = verified_root or _find_unique_trusted_root(
        leaf, _load_trusted_ca_records(context)
    )
    return CertificateCandidate(
        pem=ssl.DER_cert_to_PEM_cert(root_der),
        fingerprint_sha256=hashlib.sha256(root_der).hexdigest(),
        public_message=(
            "One trusted Windows CA candidate was selected privately for the fixed "
            "provider target."
        ),
    )


def _default_runtime_runner(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    return subprocess.run(  # nosec B603 - command is built only from fixed tokens
        list(command),
        cwd=cwd,
        env=dict(environment),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=creation_flags,
    )


def _updated_env(original: bytes) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepairError(
            "environment_invalid",
            "The package environment file is not valid UTF-8. No changes were made.",
        ) from exc
    values = {
        "REQUESTS_CA_BUNDLE": _CONTAINER_BUNDLE,
        "SSL_CERT_FILE": _CONTAINER_BUNDLE,
    }
    newline = "\r\n" if "\r\n" in text else "\n"
    output: list[str] = []
    replaced: set[str] = set()
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        ending = line[len(content) :]
        stripped = content.lstrip()
        name = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if name in values and not stripped.startswith("#"):
            output.append(f"{name}={values[name]}{ending}")
            replaced.add(name)
        else:
            output.append(line)
    updated = "".join(output)
    for name, value in values.items():
        if name not in replaced:
            if updated and not updated.endswith(("\n", "\r")):
                updated += newline
            updated += f"{name}={value}{newline}"
    return updated.encode("utf-8")


def _is_docker_desktop_provider(value: str) -> bool:
    normalized = re.sub(r"\\{2,}", r"\\", value.replace("/", "\\")).lower()
    return (
        "\\docker\\docker\\resources\\bin\\docker-compose" in normalized
        or "docker desktop" in normalized
    )


class NativeRepairAdapter:
    """Native boundary for the visible launcher repair transaction."""

    def __init__(
        self,
        *,
        selector: Callable[[str], CertificateCandidate] = select_windows_ca_candidate,
        resolver: Callable[[str], str | None] = shutil.which,
        runner: Callable[
            ..., subprocess.CompletedProcess[str]
        ] = _default_runtime_runner,
        status_reader: Callable[..., object] = read_towerscout_status,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._selector = selector
        self._resolver = resolver
        self._runner = runner
        self._status_reader = status_reader
        self._sleeper = sleeper
        self._environment = dict(os.environ)
        self._podman_provider = ""
        self._backup: _RepairBackup | None = None

    def select_candidate(self, target: RepairTarget) -> CertificateCandidate:
        return self._selector(target.provider)

    def _engine_executable(self, target: RepairTarget) -> str:
        executable = self._resolver(target.engine)
        if not executable:
            raise RepairError(
                "runtime_unavailable",
                "The selected container runtime is no longer available.",
            )
        resolved = Path(executable).resolve()
        if not resolved.is_absolute() or resolved.name.lower() not in {
            target.engine,
            f"{target.engine}.exe",
        }:
            raise RepairError(
                "runtime_invalid",
                "The selected container runtime could not be verified safely.",
            )
        return str(resolved)

    def _run(
        self,
        target: RepairTarget,
        arguments: Sequence[str],
        *,
        timeout: float = _COMMAND_TIMEOUT_SECONDS,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = (self._engine_executable(target), *arguments)
        try:
            result = self._runner(
                command,
                cwd=target.package_root,
                timeout=timeout,
                environment=self._environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RepairError(
                "runtime_timeout",
                "The fixed container-runtime operation timed out.",
            ) from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise RepairError(
                "runtime_operation_failed",
                "The fixed container-runtime operation could not be completed.",
            ) from exc
        if len(result.stdout) + len(result.stderr) > _MAX_RUNTIME_OUTPUT:
            raise RepairError(
                "runtime_output_invalid",
                "The container runtime returned an invalid response.",
            )
        if result.returncode and not allow_failure:
            raise RepairError(
                "runtime_operation_failed",
                "The fixed container-runtime operation failed.",
            )
        return result

    def _read_podman_provider_override(self, target: RepairTarget) -> str:
        env_path = target.package_root / ".env"
        if not env_path.is_file() or env_path.stat().st_size > 262_144:
            return ""
        try:
            lines = env_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise RepairError(
                "podman_provider_invalid",
                "The Podman Compose provider setting could not be read safely.",
            ) from exc
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() != "PODMAN_COMPOSE_PROVIDER":
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value if len(value) <= 1024 else ""
        return ""

    def _prepare_podman_provider(self, target: RepairTarget) -> None:
        if target.engine != "podman":
            return
        configured = self._read_podman_provider_override(target)
        if not configured:
            raise RepairError(
                "podman_provider_required",
                "Set one approved Podman Compose provider before repairing "
                "with Podman.",
            )
        resolved_value = configured
        configured_path = Path(configured)
        if not configured_path.is_file():
            resolved_value = self._resolver(configured) or ""
        resolved = Path(resolved_value).resolve() if resolved_value else Path()
        leaf = resolved.name.lower()
        version_pattern = _PODMAN_COMPOSE_VERSIONS.get(leaf)
        if (
            not resolved_value
            or not resolved.is_absolute()
            or version_pattern is None
            or _is_docker_desktop_provider(str(resolved))
        ):
            raise RepairError(
                "podman_provider_rejected",
                "The configured Podman Compose provider is not approved.",
            )
        try:
            result = self._runner(
                (str(resolved), "version"),
                cwd=target.package_root,
                timeout=10.0,
                environment=self._environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RepairError(
                "podman_provider_unavailable",
                "The approved Podman Compose provider is unavailable.",
            ) from exc
        output = result.stdout + result.stderr
        if (
            result.returncode
            or len(output) > _MAX_RUNTIME_OUTPUT
            or not version_pattern.search(output)
        ):
            raise RepairError(
                "podman_provider_rejected",
                "The configured Podman Compose provider did not pass validation.",
            )
        self._podman_provider = str(resolved)
        self._environment["PODMAN_COMPOSE_PROVIDER"] = self._podman_provider
        compose_result = self._run(
            target, ("compose", "version"), timeout=10.0, allow_failure=True
        )
        compose_output = compose_result.stdout + compose_result.stderr
        if (
            compose_result.returncode
            or _is_docker_desktop_provider(compose_output)
            or not version_pattern.search(compose_output)
        ):
            self._environment.pop("PODMAN_COMPOSE_PROVIDER", None)
            self._podman_provider = ""
            raise RepairError(
                "podman_compose_unavailable",
                "Podman Compose did not accept the approved provider.",
            )

    def _validate_package_identity(self, target: RepairTarget) -> None:
        try:
            package = load_package_identity(target.package_root)
        except (OSError, RuntimeError) as exc:
            raise RepairError(
                "package_identity_changed",
                "The TowerScout package identity could not be revalidated.",
            ) from exc
        observed = (
            package.root.resolve(),
            package.compose_project,
            package.image,
            package.image_digest,
            package.engine_hint,
            package.gpu_mode,
            package.port,
        )
        expected = (
            target.package_root,
            target.compose_project,
            target.image,
            target.image_digest,
            target.engine,
            target.gpu_mode,
            target.port,
        )
        if observed != expected:
            raise RepairError(
                "package_identity_changed",
                "The TowerScout package target changed after confirmation.",
            )

    def _find_container(self, target: RepairTarget) -> str:
        label_sets = (
            ("com.docker.compose.project", "com.docker.compose.service"),
            ("io.podman.compose.project", "io.podman.compose.service"),
        )
        found: set[str] = set()
        for project_label, service_label in label_sets:
            result = self._run(
                target,
                (
                    "ps",
                    "-a",
                    "--filter",
                    f"label={project_label}={target.compose_project}",
                    "--filter",
                    f"label={service_label}=towerscout",
                    "--format",
                    "{{.ID}}",
                ),
            )
            found.update(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        if len(found) != 1:
            raise RepairError(
                "container_target_ambiguous" if found else "container_target_missing",
                "TowerScout could not identify exactly one matching container.",
            )
        container_id = next(iter(found))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", container_id):
            raise RepairError(
                "container_target_invalid",
                "The matching container identity is invalid.",
            )
        self._validate_container(target, container_id)
        return container_id

    def _validate_container(self, target: RepairTarget, container_id: str) -> None:
        result = self._run(
            target,
            (
                "inspect",
                "--type",
                "container",
                "--format",
                "{{json .}}",
                container_id,
            ),
        )
        try:
            details = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RepairError(
                "container_identity_invalid",
                "The matching container identity could not be verified.",
            ) from exc
        if not isinstance(details, dict):
            raise RepairError(
                "container_identity_invalid",
                "The matching container identity could not be verified.",
            )
        config = (
            details.get("Config") if isinstance(details.get("Config"), dict) else {}
        )
        labels = (
            config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
        )
        projects = {
            str(labels.get("com.docker.compose.project", "")),
            str(labels.get("io.podman.compose.project", "")),
        }
        services = {
            str(labels.get("com.docker.compose.service", "")),
            str(labels.get("io.podman.compose.service", "")),
        }
        environment = {}
        environment_items = (
            config.get("Env", ()) if isinstance(config.get("Env"), list) else ()
        )
        for item in environment_items:
            if isinstance(item, str) and "=" in item:
                name, value = item.split("=", 1)
                environment[name] = value
        network = details.get("NetworkSettings")
        ports = network.get("Ports", {}) if isinstance(network, dict) else {}
        bindings = ports.get("5000/tcp", ()) if isinstance(ports, dict) else ()
        host_bindings = {
            (
                str(binding.get("HostIp", "")),
                str(binding.get("HostPort", "")),
            )
            for binding in bindings or ()
            if isinstance(binding, dict)
        }
        if (
            target.compose_project not in projects
            or "towerscout" not in services
            or str(config.get("Image", "")) != target.image
            or environment.get("TOWERSCOUT_CONTAINER_ENGINE") != target.engine
            or environment.get("TOWERSCOUT_GPU_MODE") != target.gpu_mode
            or environment.get("TOWERSCOUT_IMAGE_DIGEST", "") != target.image_digest
            or ("127.0.0.1", str(target.port)) not in host_bindings
        ):
            raise RepairError(
                "container_identity_mismatch",
                "The matching container does not match the confirmed package profile.",
            )

    def _copy_out_if_present(
        self, target: RepairTarget, container_id: str, remote: str, local: Path
    ) -> Path | None:
        exists = self._run(
            target,
            ("exec", container_id, "test", "-f", remote),
            allow_failure=True,
        )
        if exists.returncode:
            return None
        self._run(target, ("cp", f"{container_id}:{remote}", str(local)))
        return local

    def _write_env(self, target: RepairTarget, content: bytes) -> None:
        env_path = target.package_root / ".env"
        temporary = target.package_root / f".env.task087-{uuid.uuid4().hex}.tmp"
        try:
            temporary.write_bytes(content)
            os.replace(temporary, env_path)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise RepairError(
                "environment_update_failed",
                "The package environment could not be updated atomically.",
            ) from exc

    def _verify_provider(self, target: RepairTarget, container_id: str) -> None:
        host = _PROVIDER_HOSTS[target.provider]
        result = self._run(
            target,
            (
                "exec",
                "-e",
                f"REQUESTS_CA_BUNDLE={_CONTAINER_BUNDLE}",
                "-e",
                f"SSL_CERT_FILE={_CONTAINER_BUNDLE}",
                container_id,
                "python",
                "-c",
                _TLS_VERIFY_SCRIPT,
                host,
                _CONTAINER_BUNDLE,
            ),
        )
        if result.stdout.strip() != "tls_verified":
            raise RepairError(
                "provider_verification_failed",
                "Provider TLS verification returned an invalid result.",
            )

    def _restore(self, target: RepairTarget, backup: _RepairBackup) -> None:
        container_id = backup.container_id
        try:
            container_id = self._find_container(target)
        except RepairError:
            pass
        for previous, remote in (
            (backup.previous_cert, _CONTAINER_CERT),
            (backup.previous_bundle, _CONTAINER_BUNDLE),
        ):
            if previous is None:
                self._run(
                    target,
                    ("exec", container_id, "rm", "-f", remote),
                    allow_failure=True,
                )
            else:
                self._run(
                    target,
                    ("cp", str(previous), f"{container_id}:{remote}"),
                    allow_failure=True,
                )
        env_path = target.package_root / ".env"
        if backup.env_existed:
            self._write_env(target, backup.env_bytes)
        else:
            env_path.unlink(missing_ok=True)

    @staticmethod
    def _discard_backup(backup: _RepairBackup) -> None:
        shutil.rmtree(backup.staging_root, ignore_errors=True)

    def apply_candidate(
        self, target: RepairTarget, candidate: CertificateCandidate
    ) -> None:
        if self._backup is not None:
            raise RepairError(
                "repair_in_progress", "Another repair transaction is active."
            )
        self._validate_package_identity(target)
        self._prepare_podman_provider(target)
        container_id = self._find_container(target)
        runtime_root = target.package_root / ".towerscout-runtime"
        if runtime_root.is_symlink():
            raise RepairError(
                "staging_path_invalid",
                "The private repair staging path could not be verified safely.",
            )
        staging_root = runtime_root / f"repair-{uuid.uuid4().hex}"
        try:
            staging_root.mkdir(parents=True, exist_ok=False)
            env_path = target.package_root / ".env"
            backup = _RepairBackup(
                staging_root=staging_root,
                container_id=container_id,
                env_existed=env_path.is_file(),
                env_bytes=env_path.read_bytes() if env_path.is_file() else b"",
            )
            self._backup = backup
            backup.previous_cert = self._copy_out_if_present(
                target,
                container_id,
                _CONTAINER_CERT,
                staging_root / "previous-cert.pem",
            )
            backup.previous_bundle = self._copy_out_if_present(
                target,
                container_id,
                _CONTAINER_BUNDLE,
                staging_root / "previous-bundle.pem",
            )
            system_bundle = staging_root / "system-bundle.pem"
            candidate_path = staging_root / "candidate.pem"
            combined_path = staging_root / "combined.pem"
            self._run(
                target,
                ("cp", f"{container_id}:{_SYSTEM_BUNDLE}", str(system_bundle)),
            )
            candidate_path.write_text(candidate.pem, encoding="ascii", newline="\n")
            combined_path.write_bytes(
                system_bundle.read_bytes().rstrip(b"\r\n")
                + b"\n"
                + candidate_path.read_bytes().lstrip(b"\r\n")
            )
            self._run(target, ("exec", container_id, "mkdir", "-p", _CERT_DIR))
            self._run(
                target,
                ("cp", str(candidate_path), f"{container_id}:{_CONTAINER_CERT}"),
            )
            self._run(
                target,
                ("cp", str(combined_path), f"{container_id}:{_CONTAINER_BUNDLE}"),
            )
            self._run(
                target,
                (
                    "exec",
                    container_id,
                    "chmod",
                    "0644",
                    _CONTAINER_CERT,
                    _CONTAINER_BUNDLE,
                ),
            )
            self._verify_provider(target, container_id)
            self._write_env(target, _updated_env(backup.env_bytes))
        except (OSError, UnicodeError, RepairError) as exc:
            if self._backup is not None:
                try:
                    self._restore(target, self._backup)
                finally:
                    self._discard_backup(self._backup)
                    self._backup = None
            if isinstance(exc, RepairError):
                raise
            raise RepairError(
                "repair_apply_failed",
                "The TLS repair could not be staged and was rolled back.",
            ) from exc

    def restart(self, target: RepairTarget) -> None:
        backup = self._backup
        if backup is None:
            raise RepairError("repair_not_staged", "The TLS repair is not staged.")
        compose = (
            "compose",
            "-p",
            target.compose_project,
            "-f",
            str(target.package_root / "compose.yaml"),
        )
        try:
            self._run(target, (*compose, "down", "--remove-orphans"), timeout=60.0)
            self._run(target, (*compose, "up", "-d"), timeout=120.0)
            container_id = self._find_container(target)
            self._verify_provider(target, container_id)
            deadline = time.monotonic() + _RESTART_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                status = self._status_reader(load_package_identity(target.package_root))
                state = getattr(status, "state", None)
                readiness = getattr(status, "readiness", "")
                runtime_matches = (
                    getattr(status, "runtime_engine", "") == target.engine
                    and (
                        not target.image_digest
                        or getattr(status, "image_digest", "") == target.image_digest
                    )
                )
                if (
                    state is PublicState.SUCCESS
                    and runtime_matches
                    and readiness in {"setup_required", "degraded", "ready"}
                ):
                    self._discard_backup(backup)
                    self._backup = None
                    return
                if readiness == "fatal":
                    break
                self._sleeper(2.0)
            raise RepairError(
                "restart_readiness_failed",
                "TowerScout did not return to an acceptable readiness state.",
            )
        except RepairError:
            try:
                self._run(
                    target,
                    (*compose, "up", "-d"),
                    timeout=120.0,
                    allow_failure=True,
                )
                self._restore(target, backup)
                self._run(
                    target,
                    (*compose, "up", "-d", "--force-recreate"),
                    timeout=120.0,
                    allow_failure=True,
                )
            finally:
                self._discard_backup(backup)
                self._backup = None
            raise


class RepairCoordinator:
    def __init__(
        self,
        adapter: NativeRepairAdapter,
        *,
        mutation_enabled: bool = False,
    ) -> None:
        self.adapter = adapter
        self.mutation_enabled = mutation_enabled

    def prepare(
        self, snapshot: LauncherSnapshot, *, provider: str, engine: str
    ) -> RepairTransaction:
        target = build_repair_target(snapshot, provider=provider, engine=engine)
        candidate = self.adapter.select_candidate(target)
        return RepairTransaction(
            target=target,
            state=RepairState.PREPARED,
            public_message=(
                "One unambiguous CA candidate was selected privately. Review the "
                "fixed target and confirm before any change."
            ),
            candidate=candidate,
        )

    def confirm(self, transaction: RepairTransaction, confirmation: str) -> None:
        if transaction.state is not RepairState.PREPARED:
            raise RepairError(
                "invalid_state", "The repair is not ready for confirmation."
            )
        if confirmation != _CONFIRMATION:
            transaction.state = RepairState.REJECTED
            transaction.public_message = (
                "Repair confirmation was rejected. No changes were made."
            )
            raise RepairError("confirmation_rejected", transaction.public_message)
        transaction.state = RepairState.CONFIRMED
        transaction.public_message = "Repair confirmed for the fixed TowerScout target."

    def execute(
        self,
        transaction: RepairTransaction,
        *,
        on_transition: Callable[[RepairTransaction], None] | None = None,
    ) -> None:
        if not self.mutation_enabled:
            raise RepairError(
                "mutation_disabled",
                "Controlled TLS repair remains disabled in this prototype build.",
            )
        if transaction.state is not RepairState.CONFIRMED:
            raise RepairError("invalid_state", "The repair has not been confirmed.")
        if transaction.candidate is None:
            raise RepairError(
                "candidate_missing", "The repair certificate is unavailable."
            )
        try:
            transaction.state = RepairState.APPLYING
            transaction.public_message = "Applying the verified TowerScout TLS repair."
            if on_transition is not None:
                on_transition(transaction)
            self.adapter.apply_candidate(transaction.target, transaction.candidate)
            transaction.state = RepairState.RESTARTING
            transaction.public_message = (
                "Restarting the same TowerScout runtime profile."
            )
            if on_transition is not None:
                on_transition(transaction)
            self.adapter.restart(transaction.target)
        except RepairError:
            transaction.state = RepairState.RECOVERY_REQUIRED
            transaction.public_message = (
                "The repair did not complete. Use the Task-086 manual recovery path; "
                "named volumes were not intentionally removed."
            )
            if on_transition is not None:
                on_transition(transaction)
            raise
        transaction.state = RepairState.SUCCEEDED
        transaction.public_message = "TLS repair completed and TowerScout restarted."
        if on_transition is not None:
            on_transition(transaction)
