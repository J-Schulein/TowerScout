"""Retained, read-only native engine acceleration capability attestation.

The public factory consumes authenticated package and runtime-source owners,
never caller-supplied paths, commands, endpoints, environments, or evidence.
It executes only the fixed queries in this module through the contained
Windows process backend.  The owner remains source-only and is intentionally
not connected to confirmation or repair.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import re
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, NoReturn, Protocol
from urllib.parse import urlsplit

from .runtime_acceleration_inputs import AttestedEngineAccelerationEvidence
from .runtime_command_version import (
    COMMAND_STDERR_LIMIT_BYTES,
    COMMAND_STDOUT_LIMIT_BYTES,
    COMMAND_TIMEOUT_MS,
    CommandExecutionError,
    CommandProcessRequest,
    CommandProcessResult,
)
from .runtime_docker_inputs import (
    BoundDockerTargetSourceInputs,
    DockerTargetSourceInputs,
)
from .runtime_package_inputs import (
    BoundPackageEnvironmentInputs,
    PackageEnvironmentInputs,
)
from .runtime_process_environment import BoundWindowsProcessEnvironment
from .runtime_podman_inputs import (
    BoundPodmanTargetSourceInputs,
    PodmanTargetSourceInputs,
)
from .target_contracts import (
    EndpointIdentity,
    GpuMode,
    RuntimeIdentity,
    RuntimeProduct,
    WindowsProcessEnvironment,
)

_EVIDENCE_DOMAIN = b"TowerScout.EngineAccelerationProbe.v1"
_DOCKER_FORMAT = "{{json .Runtimes}}"
_CDI_DEVICE = "nvidia.com/gpu=all"
_MACHINE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_GPU_LINE = re.compile(r"^GPU [0-9]+: [\x20-\x7e]{1,1024}$")
_CDI_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}=[A-Za-z0-9._-]{1,64}$")
_MAX_JSON_DEPTH = 16
_MAX_JSON_ITEMS = 128
_MAX_JSON_NODES = 1024


class AccelerationProbeErrorCode(str, Enum):
    """Stable, non-sensitive native probe failure categories."""

    INPUTS_INVALID = "inputs_invalid"
    INPUTS_CHANGED = "inputs_changed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class AccelerationProbeError(RuntimeError):
    """Sanitized failure from retained engine capability attestation."""

    _MESSAGES = {
        AccelerationProbeErrorCode.INPUTS_INVALID: (
            "The authenticated acceleration probe inputs are invalid."
        ),
        AccelerationProbeErrorCode.INPUTS_CHANGED: (
            "The authenticated acceleration probe inputs changed during verification."
        ),
        AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure acceleration capability verification is unavailable."
        ),
    }

    def __init__(self, code: AccelerationProbeErrorCode) -> None:
        if type(code) is not AccelerationProbeErrorCode:
            raise ValueError("Unknown acceleration probe error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"AccelerationProbeError(code={self.code.value!r})"


def _fail(code: AccelerationProbeErrorCode) -> NoReturn:
    raise AccelerationProbeError(code)


class _PackageOwner(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture(self) -> PackageEnvironmentInputs: ...

    def close(self) -> None: ...


class _CloseableOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


class _RuntimeOwner(Protocol):
    @property
    def supported(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    def capture(self) -> DockerTargetSourceInputs | PodmanTargetSourceInputs: ...

    def close(self) -> None: ...


class _EnvironmentOwner(Protocol):
    @property
    def closed(self) -> bool: ...

    def capture(self) -> WindowsProcessEnvironment: ...

    def close(self) -> None: ...


class _CommandBackend(Protocol):
    @property
    def supported(self) -> bool: ...

    def windows_directory(self) -> str: ...

    def system_directory(self) -> str: ...

    def execute(self, request: CommandProcessRequest) -> CommandProcessResult: ...


@dataclass(frozen=True, slots=True)
class _ProbeResult:
    ready: bool
    evidence_sha256: str


def _identity_binding(identity: Any) -> tuple[bytes, ...]:
    try:
        return (
            identity.logical_name.encode("utf-8", errors="strict"),
            str(identity.final_path).encode("utf-16-le", errors="strict"),
            identity.volume_serial.to_bytes(8, "big"),
            identity.file_id,
            b"directory" if identity.is_directory else b"file",
            identity.sha256.encode("ascii"),
            identity.size_bytes.to_bytes(8, "big"),
        )
    except (AttributeError, OverflowError, TypeError, UnicodeError, ValueError):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)


@dataclass(frozen=True, slots=True, repr=False)
class EngineAccelerationSnapshot:
    """One coherent immutable view of every retained acceleration authority."""

    package: PackageEnvironmentInputs
    target_source: DockerTargetSourceInputs | PodmanTargetSourceInputs
    process_environment: WindowsProcessEnvironment
    attestation: AttestedEngineAccelerationEvidence
    authority_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        source_types = {
            RuntimeProduct.DOCKER: DockerTargetSourceInputs,
            RuntimeProduct.PODMAN: PodmanTargetSourceInputs,
        }
        if (
            type(self.package) is not PackageEnvironmentInputs
            or type(self.target_source)
            not in {DockerTargetSourceInputs, PodmanTargetSourceInputs}
            or type(self.target_source)
            is not source_types.get(self.target_source.runtime.product)
            or type(self.process_environment) is not WindowsProcessEnvironment
            or type(self.attestation) is not AttestedEngineAccelerationEvidence
        ):
            _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
        try:
            self.package.__post_init__()
            self.target_source.__post_init__()
            self.process_environment.__post_init__()
            self.attestation.__post_init__()
        except (AttributeError, RuntimeError, TypeError, ValueError, UnicodeError):
            _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
        runtime = self.target_source.runtime
        endpoint = self.target_source.endpoint
        provider = self.target_source.compose_provider
        evidence = self.attestation
        environment_identities = (
            self.process_environment.system_root,
            self.process_environment.temp_directory,
            self.process_environment.user_profile,
            self.process_environment.local_app_data,
            self.process_environment.roaming_app_data,
        )
        if (
            self.package.engine_hint not in {"", runtime.product.value}
            or evidence.runtime_product is not runtime.product
            or evidence.runtime_executable_sha256 != runtime.executable.sha256
            or evidence.runtime_publisher_policy_sha256
            != runtime.publisher_policy_sha256
            or evidence.endpoint_private_metadata_sha256
            != endpoint.private_metadata_sha256
            or (
                self.package.requested_gpu_mode is GpuMode.OFF
                and (evidence.docker_gpu_ready or evidence.podman_cdi_ready)
            )
            or any(not identity.is_directory for identity in environment_identities)
        ):
            _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
        expected = _digest(
            (
                b"aggregate-authority",
                self.package.package_binding_sha256.encode("ascii"),
                runtime.product.value.encode("ascii"),
                *_identity_binding(runtime.executable),
                runtime.publisher_policy_sha256.encode("ascii"),
                endpoint.canonical_endpoint.encode("utf-8", errors="strict"),
                endpoint.private_metadata_sha256.encode("ascii"),
                *(
                    field
                    for identity in (
                        *endpoint.discovery_artifacts,
                        *((endpoint.identity_key,) if endpoint.identity_key else ()),
                    )
                    for field in _identity_binding(identity)
                ),
                provider.provider_id.encode("utf-8", errors="strict"),
                provider.invocation_kind.value.encode("ascii"),
                provider.endpoint_binding.value.encode("ascii"),
                provider.integrity_sha256.encode("ascii"),
                *(
                    field
                    for identity in provider.artifacts
                    for field in _identity_binding(identity)
                ),
                *(
                    field
                    for identity in environment_identities
                    for field in _identity_binding(identity)
                ),
                evidence.probe_evidence_sha256.encode("ascii"),
            )
        )
        object.__setattr__(self, "authority_sha256", expected)

    def __repr__(self) -> str:
        return "EngineAccelerationSnapshot(<redacted>)"


def _digest(fields: tuple[bytes, ...]) -> str:
    digest = hashlib.sha256()
    for value in (_EVIDENCE_DOMAIN, *fields):
        if type(value) is not bytes or len(value) > COMMAND_STDOUT_LIMIT_BYTES:
            _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _windows_path(value: object) -> PureWindowsPath:
    if type(value) is not str or not value or "\x00" in value:
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    try:
        path = PureWindowsPath(value)
    except (TypeError, ValueError):
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    if (
        not path.is_absolute()
        or path.root != "\\"
        or path.drive.startswith("\\")
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    return path


def _process_context(
    backend: _CommandBackend,
    process_environment: WindowsProcessEnvironment,
) -> tuple[tuple[tuple[str, str], ...], PureWindowsPath]:
    try:
        if backend.supported is not True:
            _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
        windows = _windows_path(str(process_environment.system_root.final_path))
        backend_windows = _windows_path(backend.windows_directory())
        system = _windows_path(backend.system_directory())
    except AccelerationProbeError:
        raise
    except Exception:
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    if (
        backend_windows != windows
        or system.parent != windows
        or system.name.casefold() != "system32"
        or windows.name.casefold() != "windows"
    ):
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    return (("SystemRoot", str(windows)), ("WINDIR", str(windows))), system


def _execute(
    backend: _CommandBackend,
    *,
    runtime: RuntimeIdentity,
    process_environment: WindowsProcessEnvironment,
    arguments: tuple[str, ...],
) -> CommandProcessResult:
    environment, working = _process_context(backend, process_environment)
    try:
        result = backend.execute(
            CommandProcessRequest(
                executable_path=runtime.executable.final_path,
                arguments=arguments,
                environment=environment,
                working_directory=working,
                timeout_ms=COMMAND_TIMEOUT_MS,
                stdout_limit_bytes=COMMAND_STDOUT_LIMIT_BYTES,
                stderr_limit_bytes=COMMAND_STDERR_LIMIT_BYTES,
            )
        )
    except (CommandExecutionError, OSError, RuntimeError, TypeError, ValueError):
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    if (
        type(result) is not CommandProcessResult
        or result.stdin_closed is not True
        or result.stdout_streamed is not True
        or result.stderr_streamed is not True
        or result.process_tree_contained is not True
        or result.process_tree_empty is not True
    ):
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.")
        result[key] = value
    return result


def _json_nodes(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeded.")
    if value is None or type(value) in {bool, int}:
        return 1
    if type(value) is str:
        if len(value) > 4096:
            raise ValueError("JSON string exceeded.")
        return 1
    if type(value) is list:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON list exceeded.")
        return 1 + sum(_json_nodes(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON object exceeded.")
        return 1 + sum(_json_nodes(item, depth=depth + 1) for item in value.values())
    raise ValueError("JSON value type is invalid.")


def _load_json(output: bytes) -> Any:
    if (
        type(output) is not bytes
        or not output
        or len(output) > COMMAND_STDOUT_LIMIT_BYTES
    ):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    try:
        text = output.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            raise ValueError("JSON encoding is invalid.")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("Non-finite JSON value.")
            ),
        )
        if _json_nodes(value) > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded.")
        return value
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)


def _result_fields(label: bytes, result: CommandProcessResult) -> tuple[bytes, ...]:
    return (
        label,
        result.exit_code.to_bytes(8, "big", signed=True),
        hashlib.sha256(result.stdout).digest(),
        hashlib.sha256(result.stderr).digest(),
    )


def _docker_probe(
    backend: _CommandBackend,
    package: PackageEnvironmentInputs,
    runtime: RuntimeIdentity,
    endpoint: EndpointIdentity,
    process_environment: WindowsProcessEnvironment,
) -> _ProbeResult:
    """Attest endpoint registration, not a transient container execution.

    Gate A keeps this boundary read-only.  A successful result therefore
    proves that the selected daemon advertises the fixed NVIDIA runtime; it
    does not claim that a new GPU container has been created successfully.
    """

    arguments = (
        "--host",
        endpoint.canonical_endpoint,
        "info",
        "--format",
        _DOCKER_FORMAT,
    )
    result = _execute(
        backend,
        runtime=runtime,
        process_environment=process_environment,
        arguments=arguments,
    )
    ready = False
    normalized = b"unavailable"
    if result.exit_code == 0:
        value = _load_json(result.stdout)
        if type(value) is not dict:
            _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
        nvidia = value.get("nvidia")
        if nvidia is not None:
            if type(nvidia) is not dict or type(nvidia.get("path")) is not str:
                _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
            path = nvidia["path"].replace("\\", "/")
            if path.rsplit("/", 1)[-1] != "nvidia-container-runtime":
                _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
            ready = True
            normalized = b"nvidia-container-runtime"
        else:
            normalized = b"nvidia-runtime-absent"
    return _ProbeResult(
        ready,
        _digest(
            (
                b"docker",
                runtime.executable.sha256.encode("ascii"),
                runtime.publisher_policy_sha256.encode("ascii"),
                endpoint.private_metadata_sha256.encode("ascii"),
                package.package_binding_sha256.encode("ascii"),
                "\0".join(arguments).encode("utf-8"),
                normalized,
                *_result_fields(b"docker-info", result),
            )
        ),
    )


def _path_key(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value.removeprefix("\\\\?\\")))


def _validate_podman_machine(
    output: bytes,
    *,
    machine_name: str,
    endpoint: EndpointIdentity,
) -> bytes:
    value = _load_json(output)
    if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    machine = value[0]
    ssh = machine.get("SSHConfig")
    key = endpoint.identity_key
    try:
        parsed = urlsplit(endpoint.canonical_endpoint)
        host = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    if (
        type(ssh) is not dict
        or key is None
        or machine.get("Name") != machine_name
        or machine.get("VMType") != "wsl"
        or machine.get("State") != "running"
        or machine.get("Rootful") is not False
        or ssh.get("RemoteUsername") != parsed.username
        or ssh.get("Port") != port
        or type(ssh.get("IdentityPath")) is not str
        or _path_key(ssh["IdentityPath"]) != _path_key(str(key.final_path))
        or parsed.scheme != "ssh"
        or parsed.password is not None
        or not host.is_loopback
        or port is None
        or not 1 <= port <= 65535
    ):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    return json.dumps(
        {
            "machine": machine_name,
            "port": port,
            "user": parsed.username,
            "key_sha256": key.sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _normalized_lines(output: bytes, pattern: re.Pattern[str]) -> tuple[str, ...]:
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    if text.startswith("\ufeff") or "\x00" in text or "\r" in text.replace("\r\n", ""):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    lines = tuple(
        line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()
    )
    if (
        not lines
        or len(lines) > 128
        or any(pattern.fullmatch(line) is None for line in lines)
    ):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    return lines


def _podman_probe(
    backend: _CommandBackend,
    package: PackageEnvironmentInputs,
    runtime: RuntimeIdentity,
    endpoint: EndpointIdentity,
    process_environment: WindowsProcessEnvironment,
) -> _ProbeResult:
    machine = package.podman_machine
    if _MACHINE_NAME.fullmatch(machine) is None:
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    inspect_arguments = ("machine", "inspect", machine, "--format", "json")
    inspect = _execute(
        backend,
        runtime=runtime,
        process_environment=process_environment,
        arguments=inspect_arguments,
    )
    if inspect.exit_code != 0:
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    normalized_machine = _validate_podman_machine(
        inspect.stdout, machine_name=machine, endpoint=endpoint
    )
    gpu_arguments = (
        "machine",
        "ssh",
        machine,
        "--",
        "/usr/lib/wsl/lib/nvidia-smi",
        "-L",
    )
    gpu = _execute(
        backend,
        runtime=runtime,
        process_environment=process_environment,
        arguments=gpu_arguments,
    )
    cdi_arguments = (
        "machine",
        "ssh",
        machine,
        "--",
        "nvidia-ctk",
        "cdi",
        "list",
    )
    cdi = _execute(
        backend,
        runtime=runtime,
        process_environment=process_environment,
        arguments=cdi_arguments,
    )
    gpu_ready = False
    cdi_ready = False
    gpu_normalized = b"gpu-unavailable"
    cdi_normalized = b"cdi-unavailable"
    if gpu.exit_code == 0:
        gpu_lines = _normalized_lines(gpu.stdout, _GPU_LINE)
        gpu_ready = True
        gpu_normalized = "\n".join(gpu_lines).encode("utf-8")
    if cdi.exit_code == 0:
        cdi_lines = _normalized_lines(cdi.stdout, _CDI_LINE)
        cdi_ready = _CDI_DEVICE in cdi_lines
        cdi_normalized = "\n".join(sorted(cdi_lines)).encode("ascii")
    ready = gpu_ready and cdi_ready
    return _ProbeResult(
        ready,
        _digest(
            (
                b"podman",
                runtime.executable.sha256.encode("ascii"),
                runtime.publisher_policy_sha256.encode("ascii"),
                endpoint.private_metadata_sha256.encode("ascii"),
                package.package_binding_sha256.encode("ascii"),
                normalized_machine,
                "\0".join(inspect_arguments).encode("utf-8"),
                "\0".join(gpu_arguments).encode("utf-8"),
                "\0".join(cdi_arguments).encode("utf-8"),
                gpu_normalized,
                cdi_normalized,
                *_result_fields(b"machine-inspect", inspect),
                *_result_fields(b"machine-gpu", gpu),
                *_result_fields(b"machine-cdi", cdi),
            )
        ),
    )


def _skipped_probe(
    package: PackageEnvironmentInputs,
    runtime: RuntimeIdentity,
    endpoint: EndpointIdentity,
    process_environment: WindowsProcessEnvironment,
) -> _ProbeResult:
    """Bind a requested CPU-only decision without invoking the engine."""

    return _ProbeResult(
        False,
        _digest(
            (
                b"probe-skipped-gpu-off",
                runtime.product.value.encode("ascii"),
                runtime.executable.sha256.encode("ascii"),
                runtime.publisher_policy_sha256.encode("ascii"),
                endpoint.private_metadata_sha256.encode("ascii"),
                package.package_binding_sha256.encode("ascii"),
                str(process_environment.system_root.final_path).encode("utf-16-le"),
            )
        ),
    )


class BoundEngineAccelerationEvidence:
    """Retain package/runtime authorities and re-attest on every capture."""

    __slots__ = (
        "_active_owner",
        "_backend",
        "_environment",
        "_lifetime_lock",
        "_package",
        "_runtime",
    )

    def __init__(
        self,
        *,
        package_owner: _PackageOwner,
        runtime_owner: _RuntimeOwner,
        environment_owner: _EnvironmentOwner,
        backend: _CommandBackend,
    ) -> None:
        try:
            supported = (
                package_owner.supported is True
                and runtime_owner.supported is True
                and not environment_owner.closed
            )
            closed = (
                package_owner.closed or runtime_owner.closed or environment_owner.closed
            )
        except Exception:
            supported = False
            closed = True
        if not supported or closed:
            raise ValueError("Bound acceleration evidence inputs are invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._package: _PackageOwner | None = package_owner
        self._runtime: _RuntimeOwner | None = runtime_owner
        self._environment: _EnvironmentOwner | None = environment_owner
        self._backend = backend

    @property
    def supported(self) -> bool:
        with self._lifetime_lock:
            package = self._package
            runtime = self._runtime
            environment = self._environment
            try:
                return bool(
                    package is not None
                    and package.supported
                    and runtime is not None
                    and runtime.supported
                    and environment is not None
                    and not environment.closed
                )
            except Exception:
                return False

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            package = self._package
            runtime = self._runtime
            environment = self._environment
            return bool(
                (package is None or package.closed)
                and (runtime is None or runtime.closed)
                and (environment is None or environment.closed)
            )

    def capture(self) -> EngineAccelerationSnapshot:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)
        package_owner = self._package
        runtime_owner = self._runtime
        environment_owner = self._environment
        if (
            package_owner is None
            or package_owner.closed
            or runtime_owner is None
            or runtime_owner.closed
            or environment_owner is None
            or environment_owner.closed
        ):
            self._lifetime_lock.release()
            _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            first_package = package_owner.capture()
            first_runtime = runtime_owner.capture()
            first_environment = environment_owner.capture()
            runtime = first_runtime.runtime
            endpoint = first_runtime.endpoint
            expected_hint = runtime.product.value
            if first_package.engine_hint not in {"", expected_hint}:
                _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
            if first_package.requested_gpu_mode is GpuMode.OFF:
                result = _skipped_probe(
                    first_package,
                    runtime,
                    endpoint,
                    first_environment,
                )
            elif runtime.product is RuntimeProduct.DOCKER:
                result = _docker_probe(
                    self._backend,
                    first_package,
                    runtime,
                    endpoint,
                    first_environment,
                )
            elif runtime.product is RuntimeProduct.PODMAN:
                result = _podman_probe(
                    self._backend,
                    first_package,
                    runtime,
                    endpoint,
                    first_environment,
                )
            else:
                _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
            second_runtime = runtime_owner.capture()
            second_package = package_owner.capture()
            second_environment = environment_owner.capture()
            if (
                first_runtime != second_runtime
                or first_package != second_package
                or first_environment != second_environment
            ):
                _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)
            attestation = AttestedEngineAccelerationEvidence(
                runtime_product=runtime.product,
                runtime_executable_sha256=runtime.executable.sha256,
                runtime_publisher_policy_sha256=runtime.publisher_policy_sha256,
                endpoint_private_metadata_sha256=endpoint.private_metadata_sha256,
                probe_evidence_sha256=result.evidence_sha256,
                docker_gpu_ready=(
                    result.ready if runtime.product is RuntimeProduct.DOCKER else False
                ),
                podman_cdi_ready=(
                    result.ready if runtime.product is RuntimeProduct.PODMAN else False
                ),
            )
            return EngineAccelerationSnapshot(
                package=second_package,
                target_source=second_runtime,
                process_environment=second_environment,
                attestation=attestation,
            )
        except AccelerationProbeError:
            raise
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)
            interruption: BaseException | None = None
            for _attempt in range(3):
                for attribute in ("_environment", "_runtime", "_package"):
                    owner = getattr(self, attribute)
                    if owner is None:
                        continue
                    if owner.closed:
                        setattr(self, attribute, None)
                        continue
                    try:
                        owner.close()
                    except BaseException as error:
                        if not isinstance(error, Exception) and interruption is None:
                            interruption = error
                    if owner.closed:
                        setattr(self, attribute, None)
                if self.closed:
                    break
            if interruption is not None:
                raise interruption
            if not self.closed:
                _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundEngineAccelerationEvidence":
        if self.closed:
            _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundEngineAccelerationEvidence(state={state!r}, <redacted>)"


def _open_engine_acceleration_evidence(
    *,
    package_owner: _PackageOwner,
    runtime_owner: _RuntimeOwner,
    environment_owner: _EnvironmentOwner,
    backend: _CommandBackend,
) -> BoundEngineAccelerationEvidence:
    owner: BoundEngineAccelerationEvidence | None = None
    primary: BaseException | None = None
    try:
        owner = BoundEngineAccelerationEvidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=environment_owner,
            backend=backend,
        )
        owner.capture()
        return owner
    except BaseException as error:
        primary = error

    closeables: tuple[_CloseableOwner, ...]
    if owner is not None:
        closeables = (owner,)
    else:
        closeables = (environment_owner, runtime_owner, package_owner)
    interruption: BaseException | None = None
    for _attempt in range(3):
        for closeable in closeables:
            try:
                closed = closeable.closed
            except Exception:
                closed = False
            if closed:
                continue
            try:
                closeable.close()
            except BaseException as error:
                if not isinstance(error, Exception) and interruption is None:
                    interruption = error
        if all(closeable.closed for closeable in closeables):
            break
    incomplete = any(not closeable.closed for closeable in closeables)
    if interruption is not None and isinstance(primary, Exception):
        raise interruption from None
    if incomplete:
        _fail(AccelerationProbeErrorCode.INPUTS_CHANGED)
    if primary is not None and not isinstance(primary, Exception):
        raise primary from None
    if isinstance(primary, AccelerationProbeError):
        raise primary from None
    _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)


def capture_native_windows_engine_acceleration_evidence(
    *,
    package_owner: BoundPackageEnvironmentInputs,
    runtime_owner: BoundDockerTargetSourceInputs | BoundPodmanTargetSourceInputs,
    environment_owner: BoundWindowsProcessEnvironment,
) -> BoundEngineAccelerationEvidence:
    """Capture a fixed native probe from retained authenticated owner capabilities."""

    if (
        type(package_owner) is not BoundPackageEnvironmentInputs
        or type(runtime_owner)
        not in {
            BoundDockerTargetSourceInputs,
            BoundPodmanTargetSourceInputs,
        }
        or type(environment_owner) is not BoundWindowsProcessEnvironment
    ):
        _fail(AccelerationProbeErrorCode.INPUTS_INVALID)
    try:
        from .runtime_command_native import NativeWindowsCommandVersionBackend

        backend: _CommandBackend = NativeWindowsCommandVersionBackend()
        return _open_engine_acceleration_evidence(
            package_owner=package_owner,
            runtime_owner=runtime_owner,
            environment_owner=environment_owner,
            backend=backend,
        )
    except AccelerationProbeError:
        raise
    except Exception:
        _fail(AccelerationProbeErrorCode.VERIFICATION_UNAVAILABLE)


__all__ = [
    "AccelerationProbeError",
    "AccelerationProbeErrorCode",
    "BoundEngineAccelerationEvidence",
    "EngineAccelerationSnapshot",
    "capture_native_windows_engine_acceleration_evidence",
]
