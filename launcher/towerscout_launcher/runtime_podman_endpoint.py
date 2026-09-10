"""Source-only capture of one explicit local rootless Podman endpoint.

The resolver executes only three fixed read-only Podman queries through an
injected contained-process backend.  It treats connection names and default
flags as metadata, binds the configured machine to its explicit loopback SSH
URI and identity key, and verifies the endpoint itself is rootless before
returning a handle-owning evidence object.  Nothing in this module changes a
Podman default, machine mode, container, image, or volume.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import re
import struct
import sys
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Any, NoReturn, Protocol, Sequence
from urllib.parse import urlsplit

from .runtime_command_version import (
    COMMAND_STDERR_LIMIT_BYTES,
    COMMAND_STDOUT_LIMIT_BYTES,
    COMMAND_TIMEOUT_MS,
    BoundCommandRuntimeEvidence,
    CommandExecutionError,
    CommandProcessResult,
    RuntimeCommandVerificationError,
)
from .runtime_policy import RuntimeProductId
from .runtime_package_config import (
    BoundPodmanMachineConfiguration,
    PackageConfigurationError,
    PodmanMachineConfigurationEvidence,
)
from .target_contracts import (
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    RuntimeProduct,
)
from .windows_security import (
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)

_MACHINE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_USER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_USER_SOCKET = re.compile(r"^/run/user/([1-9][0-9]*)/podman/podman\.sock$")
_NORMAL_DRIVE = re.compile(r"^[A-Za-z]:$")
_EXTENDED_DRIVE = re.compile(r"^\\\\\?\\[A-Za-z]:$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INVALID_PATH_CHARACTERS = frozenset('<>"|?*')
_RESERVED_LEAVES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 8_192
_MAX_JSON_ITEMS = 256
_MAX_JSON_STRING_CHARACTERS = 32_767
_MAX_KEY_BYTES = 1024 * 1024
_BINDING_DOMAIN = b"TowerScout.PodmanEndpointBinding.v1"
_EVIDENCE_DOMAIN = b"TowerScout.PodmanEndpointEvidence.v1"
_KEY_PARENT_DOMAIN = b"TowerScout.PodmanIdentityKeyParent.v1"


class PodmanEndpointCommandKind(str, Enum):
    MACHINE_INSPECT = "machine_inspect"
    CONNECTION_LIST = "connection_list"
    ENDPOINT_INFO = "endpoint_info"


class PodmanEndpointErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    RUNTIME_INVALID = "runtime_invalid"
    ENDPOINT_INVALID = "endpoint_invalid"
    ENDPOINT_CHANGED = "endpoint_changed"


class PodmanEndpointError(RuntimeError):
    """Sanitized failure from rootless-Podman endpoint capture."""

    _MESSAGES = {
        PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure Podman endpoint verification is unavailable."
        ),
        PodmanEndpointErrorCode.RUNTIME_INVALID: (
            "The authenticated Podman runtime is unavailable or changed."
        ),
        PodmanEndpointErrorCode.ENDPOINT_INVALID: (
            "No single approved local rootless Podman endpoint was found."
        ),
        PodmanEndpointErrorCode.ENDPOINT_CHANGED: (
            "The approved Podman endpoint changed during verification."
        ),
    }

    def __init__(self, code: PodmanEndpointErrorCode) -> None:
        if type(code) is not PodmanEndpointErrorCode:
            raise ValueError("Unknown Podman endpoint error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"PodmanEndpointError(code={self.code.value!r})"


def _fail(code: PodmanEndpointErrorCode) -> NoReturn:
    raise PodmanEndpointError(code)


@dataclass(frozen=True, slots=True, repr=False)
class PodmanEndpointCommandRequest:
    """One fixed read-only command against an authenticated Podman client."""

    kind: PodmanEndpointCommandKind
    executable_path: PureWindowsPath = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    environment: tuple[tuple[str, str], ...] = field(repr=False)
    working_directory: PureWindowsPath = field(repr=False)
    timeout_ms: int = COMMAND_TIMEOUT_MS
    stdout_limit_bytes: int = COMMAND_STDOUT_LIMIT_BYTES
    stderr_limit_bytes: int = COMMAND_STDERR_LIMIT_BYTES
    stdin_closed: bool = True
    shell: bool = False

    def __post_init__(self) -> None:
        valid_shape = False
        if (
            type(self.kind) is PodmanEndpointCommandKind
            and type(self.executable_path) is PureWindowsPath
            and type(self.arguments) is tuple
            and type(self.environment) is tuple
            and len(self.environment) == 2
            and all(
                type(item) is tuple
                and len(item) == 2
                and all(type(value) is str for value in item)
                for item in self.environment
            )
            and type(self.working_directory) is PureWindowsPath
        ):
            try:
                executable = _windows_path(str(self.executable_path), file=True)
                working = _windows_path(str(self.working_directory), file=False)
                system_root = _windows_path(self.environment[0][1], file=False)
                valid_shape = (
                    executable == self.executable_path
                    and working == self.working_directory
                    and self.environment
                    == (
                        ("SystemRoot", str(system_root)),
                        ("WINDIR", str(system_root)),
                    )
                    and working.parent == system_root
                    and working.name.casefold() == "system32"
                    and system_root.name.casefold() == "windows"
                    and _valid_arguments(self.kind, self.arguments)
                )
            except (IndexError, PodmanEndpointError, TypeError, ValueError):
                valid_shape = False
        if (
            not valid_shape
            or self.timeout_ms != COMMAND_TIMEOUT_MS
            or self.stdout_limit_bytes != COMMAND_STDOUT_LIMIT_BYTES
            or self.stderr_limit_bytes != COMMAND_STDERR_LIMIT_BYTES
            or self.stdin_closed is not True
            or self.shell is not False
        ):
            raise ValueError("Podman endpoint command request is invalid.")

    def __repr__(self) -> str:
        return (
            "PodmanEndpointCommandRequest("
            f"kind={self.kind.value!r}, arguments={len(self.arguments)}, "
            "environment='minimal', path='<redacted>')"
        )


class PodmanEndpointCommandBackend(Protocol):
    """Injected contained-process seam; it must ignore ambient environment."""

    @property
    def supported(self) -> bool: ...

    def windows_directory(self) -> str: ...

    def system_directory(self) -> str: ...

    def execute(
        self, request: PodmanEndpointCommandRequest
    ) -> CommandProcessResult: ...


@dataclass(frozen=True, slots=True, repr=False)
class PodmanEndpointEvidence:
    """Opaque proof for one endpoint and retained identity-key snapshot."""

    endpoint: EndpointIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    machine_output_sha256: str = field(repr=False)
    connection_output_sha256: str = field(repr=False)
    endpoint_output_sha256: str = field(repr=False)
    binding_sha256: str = field(repr=False)
    configured_machine_sha256: str = field(repr=False)
    configuration_binding_sha256: str = field(repr=False)
    identity_key_parent_sha256: str = field(repr=False)
    connection_metadata_sha256: str = field(repr=False)
    configuration_source: FileIdentity = field(repr=False)
    machine_running: bool = True
    machine_rootful: bool = False
    endpoint_rootless: bool = True
    local_loopback: bool = True
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        digests = (
            self.runtime_evidence_sha256,
            self.machine_output_sha256,
            self.connection_output_sha256,
            self.endpoint_output_sha256,
            self.binding_sha256,
            self.configured_machine_sha256,
            self.configuration_binding_sha256,
            self.identity_key_parent_sha256,
            self.connection_metadata_sha256,
        )
        if (
            type(self.endpoint) is not EndpointIdentity
            or self.endpoint.product is not RuntimeProduct.PODMAN
            or self.endpoint.kind is not EndpointKind.PODMAN_ROOTLESS_WSL
            or any(
                type(value) is not str or not _SHA256.fullmatch(value)
                for value in digests
            )
            or self.machine_running is not True
            or self.machine_rootful is not False
            or self.endpoint_rootless is not True
            or self.local_loopback is not True
            or self.endpoint.private_metadata_sha256 != self.binding_sha256
            or type(self.configuration_source) is not FileIdentity
            or self.configuration_source.logical_name != ".env"
            or self.configuration_source.is_directory
        ):
            raise ValueError("Podman endpoint evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _digest(
                _EVIDENCE_DOMAIN,
                (
                    *(value.encode("ascii") for value in digests),
                    self.configuration_source.volume_serial.to_bytes(8, "big"),
                    self.configuration_source.file_id,
                    self.configuration_source.sha256.encode("ascii"),
                    b"machine-running",
                    b"machine-rootless",
                    b"endpoint-rootless",
                    b"local-loopback",
                ),
            ),
        )

    def __repr__(self) -> str:
        return "PodmanEndpointEvidence(state='verified', <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _EndpointUri:
    canonical: str = field(repr=False)
    username: str = field(repr=False)
    host: str = field(repr=False)
    port: int
    socket_path: str = field(repr=False)
    uid: int


@dataclass(frozen=True, slots=True, repr=False)
class _Machine:
    name: str = field(repr=False)
    vm_type: str = field(repr=False)
    username: str = field(repr=False)
    port: int
    identity_path: PureWindowsPath = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _Observation:
    machine: _Machine = field(repr=False)
    endpoint: _EndpointUri = field(repr=False)
    connection_name: str = field(repr=False)
    server_version: str
    machine_output_sha256: str = field(repr=False)
    connection_output_sha256: str = field(repr=False)
    endpoint_output_sha256: str = field(repr=False)


def _digest(domain: bytes, fields: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (domain, *fields):
        if type(value) is not bytes or len(value) > 512 * 1024:
            raise ValueError("Podman endpoint evidence field is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _text_digest(domain: bytes, value: str) -> str:
    return _digest(domain, (value.encode("utf-8", errors="strict"),))


def _windows_path(value: object, *, file: bool) -> PureWindowsPath:
    invalid_scan_start = 4 if type(value) is str and value.startswith("\\\\?\\") else 2
    if (
        type(value) is not str
        or not value
        or len(value) > 32_767
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
        or any(
            character in _INVALID_PATH_CHARACTERS
            for character in value[invalid_scan_start:]
        )
        or value.startswith("\\\\")
        and not value.startswith("\\\\?\\")
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    normalized = value.replace("/", "\\")
    try:
        path = PureWindowsPath(normalized)
    except (TypeError, ValueError):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    if (
        not path.is_absolute()
        or not (
            _NORMAL_DRIVE.fullmatch(path.drive) or _EXTENDED_DRIVE.fullmatch(path.drive)
        )
        or path.root != "\\"
        or str(path) != normalized
        or any(
            not part
            or part in {".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or part.casefold().partition(".")[0] in _RESERVED_LEAVES
            for part in path.parts[1:]
        )
        or (file and (normalized.endswith("\\") or not path.name))
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return path


def _path_key(path: PureWindowsPath) -> str:
    value = str(path)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _parse_uri(value: object) -> _EndpointUri:
    if type(value) is not str or not value or len(value) > 2048 or "\x00" in value:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host_value = parsed.hostname or ""
        host = ipaddress.ip_address(host_value)
    except (ValueError, UnicodeError):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    username = parsed.username or ""
    socket_match = _USER_SOCKET.fullmatch(parsed.path)
    uid = int(socket_match.group(1)) if socket_match is not None else 0
    if (
        parsed.scheme != "ssh"
        or not _USER_NAME.fullmatch(username)
        or username.casefold() == "root"
        or parsed.password is not None
        or not host.is_loopback
        or port is None
        or not 1 <= port <= 65535
        or socket_match is None
        or not 1 <= uid <= 0xFFFFFFFE
        or parsed.query
        or parsed.fragment
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    display_host = f"[{host.compressed}]" if host.version == 6 else host.compressed
    canonical = f"ssh://{username}@{display_host}:{port}{parsed.path}"
    if value != canonical:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return _EndpointUri(
        canonical=canonical,
        username=username,
        host=host.compressed,
        port=port,
        socket_path=parsed.path,
        uid=uid,
    )


def _valid_arguments(
    kind: PodmanEndpointCommandKind, arguments: tuple[str, ...]
) -> bool:
    if any(
        type(value) is not str
        or not value
        or len(value) > 32_767
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
        for value in arguments
    ):
        return False
    if kind is PodmanEndpointCommandKind.MACHINE_INSPECT:
        return (
            len(arguments) == 5
            and arguments[:2] == ("machine", "inspect")
            and bool(_MACHINE_NAME.fullmatch(arguments[2]))
            and arguments[3:] == ("--format", "json")
        )
    if kind is PodmanEndpointCommandKind.CONNECTION_LIST:
        return arguments == ("system", "connection", "list", "--format", "json")
    if kind is PodmanEndpointCommandKind.ENDPOINT_INFO:
        if (
            len(arguments) != 7
            or arguments[0] != "--url"
            or arguments[2] != "--identity"
            or arguments[4:] != ("info", "--format", "json")
        ):
            return False
        try:
            _parse_uri(arguments[1])
            _windows_path(arguments[3], file=True)
        except PodmanEndpointError:
            return False
        return True
    return False


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Non-finite JSON value.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON member.")
        output[key] = value
    return output


def _validate_json_tree(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeded.")
    if value is None or type(value) in {bool, int}:
        return 1
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING_CHARACTERS:
            raise ValueError("JSON string exceeded.")
        return 1
    if type(value) is list:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON list exceeded.")
        return 1 + sum(_validate_json_tree(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON object exceeded.")
        total = 1
        for key, item in value.items():
            if type(key) is not str or len(key) > 128:
                raise ValueError("JSON member is invalid.")
            total += _validate_json_tree(item, depth=depth + 1)
        return total
    raise ValueError("JSON value type is invalid.")


def _load_json(output: bytes) -> Any:
    if (
        type(output) is not bytes
        or not output
        or len(output) > COMMAND_STDOUT_LIMIT_BYTES
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    try:
        text = output.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise ValueError("JSON BOM is not accepted.")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if _validate_json_tree(value) > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded.")
        return value
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)


def _object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return value


def _machine_from_output(output: bytes, configured_machine: str) -> _Machine:
    value = _load_json(output)
    if type(value) is not list or len(value) != 1:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    machine = _object(value[0])
    ssh = _object(machine.get("SSHConfig"))
    name = machine.get("Name")
    vm_type = machine.get("VMType")
    username = ssh.get("RemoteUsername")
    port = ssh.get("Port")
    if (
        type(name) is not str
        or name != configured_machine
        or type(vm_type) is not str
        or vm_type != "wsl"
        or machine.get("State") != "running"
        or machine.get("Rootful") is not False
        or type(username) is not str
        or not _USER_NAME.fullmatch(username)
        or username.casefold() == "root"
        or type(port) is not int
        or isinstance(port, bool)
        or not 1 <= port <= 65535
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return _Machine(
        name=name,
        vm_type=vm_type,
        username=username,
        port=port,
        identity_path=_windows_path(ssh.get("IdentityPath"), file=True),
    )


def _connection_from_output(
    output: bytes, machine: _Machine
) -> tuple[_EndpointUri, str]:
    value = _load_json(output)
    if type(value) is not list or not 1 <= len(value) <= _MAX_JSON_ITEMS:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    candidates: list[tuple[_EndpointUri, str]] = []
    for raw in value:
        connection = _object(raw)
        if connection.get("IsMachine") is not True:
            continue
        try:
            endpoint = _parse_uri(connection.get("URI"))
            identity_path = _windows_path(connection.get("Identity"), file=True)
        except PodmanEndpointError:
            continue
        name = connection.get("Name")
        if (
            type(name) is not str
            or not name
            or len(name) > 128
            or "\x00" in name
            or any(ord(character) < 0x20 for character in name)
        ):
            _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
        if (
            endpoint.username == machine.username
            and endpoint.port == machine.port
            and _path_key(identity_path) == _path_key(machine.identity_path)
        ):
            candidates.append((endpoint, name))
    if len(candidates) != 1:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return candidates[0]


def _endpoint_info_version(
    output: bytes,
    endpoint: _EndpointUri,
    expected_version: str,
) -> str:
    value = _object(_load_json(output))
    host = _object(value.get("host"))
    security = _object(host.get("security"))
    remote_socket = _object(host.get("remoteSocket"))
    store = _object(value.get("store"))
    version = _object(value.get("version"))
    server_version = version.get("Version")
    if (
        security.get("rootless") is not True
        or remote_socket.get("path") != endpoint.socket_path
        or store.get("graphRoot")
        != f"/home/{endpoint.username}/.local/share/containers/storage"
        or store.get("runRoot") != f"/run/user/{endpoint.uid}/containers"
        or type(server_version) is not str
        or server_version != expected_version
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return server_version


def _environment(
    backend: PodmanEndpointCommandBackend,
) -> tuple[tuple[tuple[str, str], ...], PureWindowsPath]:
    try:
        if backend.supported is not True:
            _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)
        windows = _windows_path(backend.windows_directory(), file=False)
        system = _windows_path(backend.system_directory(), file=False)
    except PodmanEndpointError:
        raise
    except Exception:
        _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    if system.parent != windows or system.name.casefold() != "system32":
        _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    return (("SystemRoot", str(windows)), ("WINDIR", str(windows))), system


def _execute(
    backend: PodmanEndpointCommandBackend,
    request: PodmanEndpointCommandRequest,
) -> tuple[bytes, str]:
    try:
        result = backend.execute(request)
    except CommandExecutionError:
        _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    except PodmanEndpointError:
        raise
    except Exception:
        _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    if (
        type(result) is not CommandProcessResult
        or result.exit_code != 0
        or result.stderr
        or result.stdin_closed is not True
        or result.stdout_streamed is not True
        or result.stderr_streamed is not True
        or result.process_tree_contained is not True
        or result.process_tree_empty is not True
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    return result.stdout, hashlib.sha256(result.stdout).hexdigest()


def _observe_under_runtime(
    runtime: BoundCommandRuntimeEvidence,
    configured_machine: str,
    backend: PodmanEndpointCommandBackend,
    key: HandleBoundFile | None = None,
) -> _Observation:
    environment, working_directory = _environment(backend)

    def run(executable_path: PureWindowsPath) -> _Observation:
        machine_output, machine_hash = _execute(
            backend,
            PodmanEndpointCommandRequest(
                kind=PodmanEndpointCommandKind.MACHINE_INSPECT,
                executable_path=executable_path,
                arguments=(
                    "machine",
                    "inspect",
                    configured_machine,
                    "--format",
                    "json",
                ),
                environment=environment,
                working_directory=working_directory,
            ),
        )
        machine = _machine_from_output(machine_output, configured_machine)
        connection_output, connection_hash = _execute(
            backend,
            PodmanEndpointCommandRequest(
                kind=PodmanEndpointCommandKind.CONNECTION_LIST,
                executable_path=executable_path,
                arguments=("system", "connection", "list", "--format", "json"),
                environment=environment,
                working_directory=working_directory,
            ),
        )
        endpoint, connection_name = _connection_from_output(connection_output, machine)
        if key is not None and _path_key(
            PureWindowsPath(key.snapshot.final_path)
        ) != _path_key(machine.identity_path):
            _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
        endpoint_output, endpoint_hash = _execute(
            backend,
            PodmanEndpointCommandRequest(
                kind=PodmanEndpointCommandKind.ENDPOINT_INFO,
                executable_path=executable_path,
                arguments=(
                    "--url",
                    endpoint.canonical,
                    "--identity",
                    str(machine.identity_path),
                    "info",
                    "--format",
                    "json",
                ),
                environment=environment,
                working_directory=working_directory,
            ),
        )
        server_version = _endpoint_info_version(
            endpoint_output,
            endpoint,
            runtime.evidence.exact_version,
        )
        return _Observation(
            machine=machine,
            endpoint=endpoint,
            connection_name=connection_name,
            server_version=server_version,
            machine_output_sha256=machine_hash,
            connection_output_sha256=connection_hash,
            endpoint_output_sha256=endpoint_hash,
        )

    try:
        if key is None:
            return runtime._run_while_held(run)  # noqa: SLF001
        return runtime._run_while_held(  # noqa: SLF001
            lambda executable: key.run_while_held(lambda: run(executable))
        )
    except PodmanEndpointError:
        raise
    except RuntimeCommandVerificationError:
        _fail(PodmanEndpointErrorCode.RUNTIME_INVALID)
    except WindowsSecurityError:
        _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)


def _observation_fields(observation: _Observation) -> tuple[bytes, ...]:
    return (
        observation.machine.name.encode("utf-8", errors="strict"),
        observation.machine.vm_type.encode("ascii", errors="strict"),
        observation.machine.username.encode("utf-8", errors="strict"),
        observation.machine.port.to_bytes(2, "big"),
        _path_key(observation.machine.identity_path).encode(
            "utf-16-le", errors="strict"
        ),
        observation.endpoint.canonical.encode("utf-8", errors="strict"),
        observation.endpoint.username.encode("utf-8", errors="strict"),
        observation.endpoint.host.encode("ascii"),
        observation.endpoint.port.to_bytes(2, "big"),
        observation.endpoint.socket_path.encode("ascii"),
        observation.endpoint.uid.to_bytes(8, "big"),
        observation.server_version.encode("ascii"),
    )


def _snapshot_fields(snapshot: FileSnapshot) -> tuple[bytes, ...]:
    return (
        snapshot.identity.volume_serial.to_bytes(8, "big"),
        snapshot.identity.file_id,
        snapshot.sha256.encode("ascii"),
        snapshot.size.to_bytes(8, "big"),
        _path_key(PureWindowsPath(snapshot.final_path)).encode(
            "utf-16-le", errors="strict"
        ),
    )


def _key_parent_sha256(parent: PathHierarchyTrust) -> str:
    evidence = parent.evidence
    snapshot = parent.root_snapshot
    if evidence.purpose is not PathTrustPurpose.PODMAN_IDENTITY_KEY:
        raise ValueError("Podman identity-key parent evidence is invalid.")
    return _digest(
        _KEY_PARENT_DOMAIN,
        (
            evidence.root_identity.volume_serial.to_bytes(8, "big"),
            evidence.root_identity.file_id,
            evidence.lexical_depth.to_bytes(4, "big"),
            evidence.resolved_depth.to_bytes(4, "big"),
            _path_key(PureWindowsPath(snapshot.final_path)).encode(
                "utf-16-le", errors="strict"
            ),
        ),
    )


def _binding_sha256(
    runtime: BoundCommandRuntimeEvidence,
    observation: _Observation,
    snapshot: FileSnapshot,
    configuration: PodmanMachineConfigurationEvidence,
    key_parent: PathHierarchyTrust,
) -> str:
    return _digest(
        _BINDING_DOMAIN,
        (
            runtime.evidence.evidence_sha256.encode("ascii"),
            configuration.binding_sha256.encode("ascii"),
            _key_parent_sha256(key_parent).encode("ascii"),
            *_observation_fields(observation),
            *_snapshot_fields(snapshot),
        ),
    )


def _identity_from_snapshot(snapshot: FileSnapshot) -> FileIdentity:
    return FileIdentity(
        logical_name="podman_identity_key",
        final_path=PureWindowsPath(snapshot.final_path),
        volume_serial=snapshot.identity.volume_serial,
        file_id=snapshot.identity.file_id,
        sha256=snapshot.sha256,
        size_bytes=snapshot.size,
    )


def _snapshot_matches_identity(snapshot: FileSnapshot, identity: FileIdentity) -> bool:
    try:
        return (
            type(snapshot) is FileSnapshot
            and type(identity) is FileIdentity
            and not identity.is_directory
            and snapshot.identity.volume_serial == identity.volume_serial
            and snapshot.identity.file_id == identity.file_id
            and snapshot.sha256 == identity.sha256
            and snapshot.size == identity.size_bytes
            and _path_key(PureWindowsPath(snapshot.final_path))
            == _path_key(identity.final_path)
        )
    except (TypeError, ValueError, UnicodeError):
        return False


class BoundPodmanEndpointEvidence:
    """Own the package selector and identity key; revalidate both on demand."""

    __slots__ = (
        "_active_owner",
        "_binding_sha256",
        "_configuration",
        "_configured_machine",
        "_evidence",
        "_key",
        "_key_parent",
        "_lifetime_lock",
    )

    def __init__(
        self,
        *,
        configured_machine: str,
        configuration: BoundPodmanMachineConfiguration,
        key_parent: PathHierarchyTrust,
        key: HandleBoundFile,
        evidence: PodmanEndpointEvidence,
    ) -> None:
        if (
            type(configuration) is not BoundPodmanMachineConfiguration
            or configuration.closed
        ):
            raise ValueError("Bound Podman endpoint evidence is invalid.")
        configuration_evidence = configuration.evidence
        if (
            type(configured_machine) is not str
            or not _MACHINE_NAME.fullmatch(configured_machine)
            or type(key_parent) is not PathHierarchyTrust
            or key_parent.closed
            or key_parent.evidence.purpose is not PathTrustPurpose.PODMAN_IDENTITY_KEY
            or type(key) is not HandleBoundFile
            or key.closed
            or type(evidence) is not PodmanEndpointEvidence
            or evidence.endpoint.identity_key is None
            or evidence.endpoint.discovery_artifacts
            or not _snapshot_matches_identity(
                key.snapshot,
                evidence.endpoint.identity_key,
            )
            or evidence.configuration_source
            != configuration_evidence.environment_source
            or evidence.configured_machine_sha256
            != configuration_evidence.configured_machine_sha256
            or evidence.configuration_binding_sha256
            != configuration_evidence.binding_sha256
            or evidence.identity_key_parent_sha256 != _key_parent_sha256(key_parent)
        ):
            raise ValueError("Bound Podman endpoint evidence is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._configured_machine = configured_machine
        self._configuration: BoundPodmanMachineConfiguration | None = configuration
        self._key_parent: PathHierarchyTrust | None = key_parent
        self._key: HandleBoundFile | None = key
        self._evidence = evidence
        self._binding_sha256 = evidence.binding_sha256

    @property
    def evidence(self) -> PodmanEndpointEvidence:
        return self._evidence

    @property
    def endpoint(self) -> EndpointIdentity:
        return self._evidence.endpoint

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return (
                self._configuration is None
                or self._configuration.closed
                or self._key is None
                or self._key.closed
                or self._key_parent is None
                or self._key_parent.closed
            )

    def assert_unchanged(
        self,
        runtime: BoundCommandRuntimeEvidence,
        backend: PodmanEndpointCommandBackend,
    ) -> PodmanEndpointEvidence:
        if type(runtime) is not BoundCommandRuntimeEvidence:
            _fail(PodmanEndpointErrorCode.RUNTIME_INVALID)
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
        key = self._key
        key_parent = self._key_parent
        configuration = self._configuration
        if (
            configuration is None
            or configuration.closed
            or key is None
            or key.closed
            or key_parent is None
            or key_parent.closed
        ):
            self._lifetime_lock.release()
            _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
        self._active_owner = threading.get_ident()

        def revalidate(
            configured_machine: str,
            configuration_evidence: PodmanMachineConfigurationEvidence,
        ) -> PodmanEndpointEvidence:
            if (
                configured_machine != self._configured_machine
                or configuration_evidence.environment_source
                != self._evidence.configuration_source
                or configuration_evidence.configured_machine_sha256
                != self._evidence.configured_machine_sha256
                or configuration_evidence.binding_sha256
                != self._evidence.configuration_binding_sha256
            ):
                _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
            observation = key_parent.run_while_held(
                lambda: _observe_under_runtime(
                    runtime,
                    configured_machine,
                    backend,
                    key,
                )
            )
            if (
                _binding_sha256(
                    runtime,
                    observation,
                    key.snapshot,
                    configuration_evidence,
                    key_parent,
                )
                != self._binding_sha256
            ):
                _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
            return self._evidence

        try:
            return configuration._run_while_held(revalidate)  # noqa: SLF001
        except PodmanEndpointError as error:
            if error.code is PodmanEndpointErrorCode.ENDPOINT_INVALID:
                _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
            raise
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
            configuration = self._configuration
            key = self._key
            key_parent = self._key_parent
            self._configuration = None
            self._key = None
            self._key_parent = None
            if configuration is None and key is None and key_parent is None:
                return
            failed = False
            if configuration is not None:
                try:
                    configuration.close()
                except PackageConfigurationError:
                    failed = True
            if key is not None:
                try:
                    key.close()
                except WindowsSecurityError:
                    failed = True
            if key_parent is not None:
                try:
                    key_parent.close()
                except WindowsSecurityError:
                    failed = True
            if failed:
                _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)

    def __enter__(self) -> BoundPodmanEndpointEvidence:
        if self.closed:
            _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundPodmanEndpointEvidence(state={state!r}, <redacted>)"


def capture_bound_podman_endpoint(
    runtime: BoundCommandRuntimeEvidence,
    configuration: BoundPodmanMachineConfiguration,
    *,
    backend: PodmanEndpointCommandBackend | None = None,
    file_api: WindowsFileApi | None = None,
    path_api: WindowsPathTrustApi | None = None,
) -> BoundPodmanEndpointEvidence:
    """Resolve one package-selected endpoint and transfer configuration ownership."""

    if (
        type(runtime) is not BoundCommandRuntimeEvidence
        or runtime.closed
        or runtime.evidence.product_id is not RuntimeProductId.PODMAN_CLI
    ):
        _fail(PodmanEndpointErrorCode.RUNTIME_INVALID)
    if (
        type(configuration) is not BoundPodmanMachineConfiguration
        or configuration.closed
    ):
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    selected_backend = backend
    if selected_backend is None:
        try:
            from .runtime_command_native import (
                NativeWindowsPodmanEndpointCommandBackend,
            )

            selected_backend = NativeWindowsPodmanEndpointCommandBackend()
        except Exception:
            _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)

    key: HandleBoundFile | None = None
    key_parent: PathHierarchyTrust | None = None
    owner: BoundPodmanEndpointEvidence | None = None

    def resolve(
        configured_machine: str,
        configuration_evidence: PodmanMachineConfigurationEvidence,
    ) -> BoundPodmanEndpointEvidence:
        nonlocal key, key_parent, owner
        first = _observe_under_runtime(runtime, configured_machine, selected_backend)
        key_parent = capture_path_hierarchy(
            str(first.machine.identity_path.parent),
            purpose=PathTrustPurpose.PODMAN_IDENTITY_KEY,
            api=path_api,
        )
        key = capture_handle_bound_file(
            Path(str(first.machine.identity_path)),
            api=file_api,
            policy=FileCapturePolicy(
                max_bytes=_MAX_KEY_BYTES,
                require_single_link=True,
                allow_hydrated_cloud_placeholder=False,
            ),
        )
        resolved_key = PureWindowsPath(key.snapshot.final_path)
        resolved_parent = PureWindowsPath(key_parent.root_snapshot.final_path)
        if (
            not 1 <= key.snapshot.size <= _MAX_KEY_BYTES
            or _path_key(resolved_key) != _path_key(first.machine.identity_path)
            or _path_key(resolved_key.parent) != _path_key(resolved_parent)
        ):
            _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
        second = key_parent.run_while_held(
            lambda: _observe_under_runtime(
                runtime,
                configured_machine,
                selected_backend,
                key,
            )
        )
        if _observation_fields(first) != _observation_fields(second):
            _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
        binding = _binding_sha256(
            runtime,
            second,
            key.snapshot,
            configuration_evidence,
            key_parent,
        )
        key_identity = _identity_from_snapshot(key.snapshot)
        endpoint = EndpointIdentity(
            product=RuntimeProduct.PODMAN,
            kind=EndpointKind.PODMAN_ROOTLESS_WSL,
            canonical_endpoint=second.endpoint.canonical,
            private_metadata_sha256=binding,
            identity_key=key_identity,
            discovery_artifacts=(),
            rootless=True,
        )
        evidence = PodmanEndpointEvidence(
            endpoint=endpoint,
            runtime_evidence_sha256=runtime.evidence.evidence_sha256,
            machine_output_sha256=second.machine_output_sha256,
            connection_output_sha256=second.connection_output_sha256,
            endpoint_output_sha256=second.endpoint_output_sha256,
            binding_sha256=binding,
            configured_machine_sha256=(
                configuration_evidence.configured_machine_sha256
            ),
            configuration_binding_sha256=configuration_evidence.binding_sha256,
            identity_key_parent_sha256=_key_parent_sha256(key_parent),
            connection_metadata_sha256=_text_digest(
                b"TowerScout.PodmanConnectionMetadata.v1", second.connection_name
            ),
            configuration_source=configuration_evidence.environment_source,
        )
        owner = BoundPodmanEndpointEvidence(
            configured_machine=configured_machine,
            configuration=configuration,
            key_parent=key_parent,
            key=key,
            evidence=evidence,
        )
        key = None
        key_parent = None
        return owner

    try:
        return configuration._run_while_held(resolve)  # noqa: SLF001
    except PodmanEndpointError:
        raise
    except PackageConfigurationError:
        _fail(PodmanEndpointErrorCode.ENDPOINT_CHANGED)
    except WindowsSecurityError:
        _fail(PodmanEndpointErrorCode.ENDPOINT_INVALID)
    except RuntimeCommandVerificationError:
        _fail(PodmanEndpointErrorCode.RUNTIME_INVALID)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(PodmanEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    finally:
        failed = sys.exc_info()[0] is not None
        if failed and owner is not None:
            try:
                owner.close()
            except BaseException:
                pass
        elif owner is None:
            if key is not None:
                try:
                    key.close()
                except BaseException:
                    pass
            if key_parent is not None:
                try:
                    key_parent.close()
                except BaseException:
                    pass


__all__ = [
    "BoundPodmanEndpointEvidence",
    "PodmanEndpointCommandBackend",
    "PodmanEndpointCommandKind",
    "PodmanEndpointCommandRequest",
    "PodmanEndpointError",
    "PodmanEndpointErrorCode",
    "PodmanEndpointEvidence",
    "capture_bound_podman_endpoint",
]
