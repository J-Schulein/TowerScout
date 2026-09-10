"""Source-only capture of one explicit local Docker named-pipe endpoint.

The resolver discovers the current Docker context from an explicit current-user
Docker configuration directory, treats its name as metadata, and then queries
the discovered local Windows named pipe explicitly.  Ambient Docker variables
cannot select the daemon, and every later revalidation repeats the explicit
``--host`` query through the authenticated Docker CLI.  Nothing in this module
changes a Docker context, container, image, volume, or daemon.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import posixpath
import re
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, NoReturn, Protocol, Sequence

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
from .target_contracts import EndpointIdentity, EndpointKind, RuntimeProduct

_PIPE_PREFIX = "npipe:////./pipe/"
_PIPE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CONTEXT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DAEMON_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SERVER_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?$")
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
_MAX_PRIVATE_TEXT_CHARACTERS = 512
_MAX_DIGEST_FIELD_BYTES = 262_144
_INFO_FORMAT = "{{json .}}"
_BINDING_DOMAIN = b"TowerScout.DockerEndpointBinding.v1"
_EVIDENCE_DOMAIN = b"TowerScout.DockerEndpointEvidence.v1"
_CONTEXT_METADATA_DOMAIN = b"TowerScout.DockerContextMetadata.v1"
_CONFIGURATION_DIRECTORY_DOMAIN = b"TowerScout.DockerConfigDirectory.v1"


class DockerEndpointCommandKind(str, Enum):
    CONTEXT_INSPECT = "context_inspect"
    ENDPOINT_INFO = "endpoint_info"


class DockerEndpointErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    RUNTIME_INVALID = "runtime_invalid"
    ENDPOINT_INVALID = "endpoint_invalid"
    ENDPOINT_CHANGED = "endpoint_changed"


class DockerEndpointError(RuntimeError):
    """Sanitized failure from Docker named-pipe endpoint capture."""

    _MESSAGES = {
        DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure Docker endpoint verification is unavailable."
        ),
        DockerEndpointErrorCode.RUNTIME_INVALID: (
            "The authenticated Docker runtime is unavailable or changed."
        ),
        DockerEndpointErrorCode.ENDPOINT_INVALID: (
            "No single approved local Docker named-pipe endpoint was found."
        ),
        DockerEndpointErrorCode.ENDPOINT_CHANGED: (
            "The approved Docker endpoint changed during verification."
        ),
    }

    def __init__(self, code: DockerEndpointErrorCode) -> None:
        if type(code) is not DockerEndpointErrorCode:
            raise ValueError("Unknown Docker endpoint error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"DockerEndpointError(code={self.code.value!r})"


def _fail(code: DockerEndpointErrorCode) -> NoReturn:
    raise DockerEndpointError(code)


def _digest(domain: bytes, fields: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (domain, *fields):
        if type(value) is not bytes or len(value) > _MAX_DIGEST_FIELD_BYTES:
            raise ValueError("Docker endpoint evidence field is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _text_digest(domain: bytes, value: str) -> str:
    if type(value) is not str:
        raise ValueError("Docker endpoint evidence text is invalid.")
    return _digest(domain, (value.encode("utf-8", errors="strict"),))


def _private_text(value: object, *, maximum: int = _MAX_PRIVATE_TEXT_CHARACTERS) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or "\x00" in value
        or any(
            ord(character) < 0x20 or character in {"\x7f", "\x85", "\u2028", "\u2029"}
            for character in value
        )
    ):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return value


def _windows_path(value: object, *, file: bool) -> PureWindowsPath:
    if type(value) is not str or not value or len(value) > 32_767:
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    invalid_scan_start = 4 if value.startswith("\\\\?\\") else 0
    if (
        "\x00" in value
        or any(ord(character) < 0x20 for character in value)
        or any(
            character in _INVALID_PATH_CHARACTERS
            for character in value[invalid_scan_start:]
        )
        or value.startswith("\\\\")
        and not value.startswith("\\\\?\\")
    ):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    normalized = value.replace("/", "\\")
    try:
        path = PureWindowsPath(normalized)
    except (TypeError, ValueError):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
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
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return path


def _path_key(path: PureWindowsPath) -> str:
    value = str(path)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _parse_pipe(value: object) -> str:
    if type(value) is not str or not value.startswith(_PIPE_PREFIX):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    pipe_name = value.removeprefix(_PIPE_PREFIX)
    if not _PIPE_NAME.fullmatch(pipe_name) or value != f"{_PIPE_PREFIX}{pipe_name}":
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return value


def _valid_arguments(
    kind: DockerEndpointCommandKind,
    arguments: tuple[str, ...],
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
    if kind is DockerEndpointCommandKind.CONTEXT_INSPECT:
        if (
            len(arguments) != 4
            or arguments[0] != "--config"
            or arguments[2:] != ("context", "inspect")
        ):
            return False
        try:
            configuration = _windows_path(arguments[1], file=False)
        except DockerEndpointError:
            return False
        return configuration.name.casefold() == ".docker"
    if kind is DockerEndpointCommandKind.ENDPOINT_INFO:
        if (
            len(arguments) != 7
            or arguments[0] != "--config"
            or arguments[2] != "--host"
            or arguments[4:] != ("info", "--format", _INFO_FORMAT)
        ):
            return False
        try:
            configuration = _windows_path(arguments[1], file=False)
            _parse_pipe(arguments[3])
        except DockerEndpointError:
            return False
        return configuration.name.casefold() == ".docker"
    return False


@dataclass(frozen=True, slots=True, repr=False)
class DockerEndpointCommandRequest:
    """One fixed read-only query through an authenticated Docker client."""

    kind: DockerEndpointCommandKind
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
            type(self.kind) is DockerEndpointCommandKind
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
            except (IndexError, DockerEndpointError, TypeError, ValueError):
                valid_shape = False
        if (
            not valid_shape
            or self.timeout_ms != COMMAND_TIMEOUT_MS
            or self.stdout_limit_bytes != COMMAND_STDOUT_LIMIT_BYTES
            or self.stderr_limit_bytes != COMMAND_STDERR_LIMIT_BYTES
            or self.stdin_closed is not True
            or self.shell is not False
        ):
            raise ValueError("Docker endpoint command request is invalid.")

    def __repr__(self) -> str:
        return (
            "DockerEndpointCommandRequest("
            f"kind={self.kind.value!r}, arguments={len(self.arguments)}, "
            "environment='minimal', path='<redacted>')"
        )


class DockerEndpointCommandBackend(Protocol):
    """Injected contained-process seam; it must ignore ambient Docker variables."""

    @property
    def supported(self) -> bool: ...

    def windows_directory(self) -> str: ...

    def system_directory(self) -> str: ...

    def user_profile_directory(self) -> str: ...

    def execute(
        self,
        request: DockerEndpointCommandRequest,
    ) -> CommandProcessResult: ...


@dataclass(frozen=True, slots=True, repr=False)
class DockerEndpointEvidence:
    """Opaque proof for one explicit local Docker daemon endpoint."""

    endpoint: EndpointIdentity
    runtime_evidence_sha256: str = field(repr=False)
    context_output_sha256: str = field(repr=False)
    endpoint_output_sha256: str = field(repr=False)
    context_metadata_sha256: str = field(repr=False)
    configuration_directory_sha256: str = field(repr=False)
    binding_sha256: str = field(repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        values = (
            self.runtime_evidence_sha256,
            self.context_output_sha256,
            self.endpoint_output_sha256,
            self.context_metadata_sha256,
            self.configuration_directory_sha256,
            self.binding_sha256,
        )
        if (
            type(self.endpoint) is not EndpointIdentity
            or self.endpoint.product is not RuntimeProduct.DOCKER
            or self.endpoint.kind is not EndpointKind.DOCKER_NAMED_PIPE
            or self.endpoint.rootless
            or self.endpoint.identity_key is not None
            or self.endpoint.discovery_artifacts
            or any(
                type(value) is not str or not _SHA256.fullmatch(value)
                for value in values
            )
            or self.endpoint.private_metadata_sha256 != self.binding_sha256
        ):
            raise ValueError("Docker endpoint evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _digest(
                _EVIDENCE_DOMAIN,
                (
                    self.endpoint.canonical_endpoint.encode("ascii"),
                    *(value.encode("ascii") for value in values),
                ),
            ),
        )

    def __repr__(self) -> str:
        return "DockerEndpointEvidence(state='verified', <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _DaemonFacts:
    daemon_id: str = field(repr=False)
    server_version: str = field(repr=False)
    operating_system: str = field(repr=False)
    os_type: str = field(repr=False)
    architecture: str = field(repr=False)
    name: str = field(repr=False)
    docker_root: str = field(repr=False)
    driver: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _Observation:
    endpoint: str = field(repr=False)
    context_name: str = field(repr=False)
    configuration_directory: PureWindowsPath = field(repr=False)
    daemon: _DaemonFacts = field(repr=False)
    context_output_sha256: str = field(repr=False)
    endpoint_output_sha256: str = field(repr=False)


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
        if type(key) is not str or len(key) > 128:
            raise ValueError("JSON member is invalid.")
        total += _validate_json_tree(item, depth=depth + 1)
    return total


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
        return _validate_json_list(value, depth=depth)
    if type(value) is dict:
        return _validate_json_object(value, depth=depth)
    raise ValueError("JSON value type is invalid.")


def _load_json(output: bytes) -> Any:
    if (
        type(output) is not bytes
        or not output
        or len(output) > COMMAND_STDOUT_LIMIT_BYTES
    ):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
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
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)


def _object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return value


def _context_from_output(output: bytes) -> tuple[str, str]:
    value = _load_json(output)
    if type(value) is not list or len(value) != 1:
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    context = _object(value[0])
    name = context.get("Name")
    if type(name) is not str or not _CONTEXT_NAME.fullmatch(name):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    endpoints = _object(context.get("Endpoints"))
    docker = _object(endpoints.get("docker"))
    if docker.get("SkipTLSVerify") is not False:
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    tls_material = context.get("TLSMaterial")
    if type(tls_material) is not dict or tls_material:
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return _parse_pipe(docker.get("Host")), name


def _daemon_from_output(output: bytes) -> _DaemonFacts:
    value = _object(_load_json(output))
    daemon_id = value.get("ID")
    server_version = value.get("ServerVersion")
    os_type = value.get("OSType")
    architecture = value.get("Architecture")
    if (
        type(daemon_id) is not str
        or not _DAEMON_ID.fullmatch(daemon_id)
        or type(server_version) is not str
        or not _SERVER_VERSION.fullmatch(server_version)
        or os_type != "linux"
        or architecture not in {"amd64", "x86_64"}
    ):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    docker_root = _private_text(value.get("DockerRootDir"), maximum=4096)
    if (
        not docker_root.startswith("/")
        or "\\" in docker_root
        or posixpath.normpath(docker_root) != docker_root
        or any(part in {"", ".", ".."} for part in docker_root.split("/")[1:])
    ):
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return _DaemonFacts(
        daemon_id=daemon_id,
        server_version=server_version,
        operating_system=_private_text(value.get("OperatingSystem")),
        os_type=os_type,
        architecture=architecture,
        name=_private_text(value.get("Name")),
        docker_root=docker_root,
        driver=_private_text(value.get("Driver")),
    )


def _environment(
    backend: DockerEndpointCommandBackend,
) -> tuple[tuple[tuple[str, str], ...], PureWindowsPath, PureWindowsPath]:
    try:
        if backend.supported is not True:
            _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)
        windows_value = backend.windows_directory()
        system_value = backend.system_directory()
        profile_value = backend.user_profile_directory()
    except DockerEndpointError:
        raise
    except Exception:
        _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    try:
        windows = _windows_path(windows_value, file=False)
        system = _windows_path(system_value, file=False)
        profile = _windows_path(profile_value, file=False)
    except DockerEndpointError:
        _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    configuration = profile / ".docker"
    if (
        system.parent != windows
        or system.name.casefold() != "system32"
        or profile.name.casefold() in _RESERVED_LEAVES
        or configuration.parent != profile
    ):
        _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    return (
        (("SystemRoot", str(windows)), ("WINDIR", str(windows))),
        system,
        configuration,
    )


def _execute(
    backend: DockerEndpointCommandBackend,
    request: DockerEndpointCommandRequest,
) -> tuple[bytes, str]:
    try:
        result = backend.execute(request)
    except CommandExecutionError:
        _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)
    except DockerEndpointError:
        raise
    except Exception:
        _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)
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
        _fail(DockerEndpointErrorCode.ENDPOINT_INVALID)
    return result.stdout, hashlib.sha256(result.stdout).hexdigest()


def _observe_under_runtime(
    runtime: BoundCommandRuntimeEvidence,
    backend: DockerEndpointCommandBackend,
) -> _Observation:
    environment, working_directory, configuration = _environment(backend)

    def run(executable_path: PureWindowsPath) -> _Observation:
        context_output, context_hash = _execute(
            backend,
            DockerEndpointCommandRequest(
                kind=DockerEndpointCommandKind.CONTEXT_INSPECT,
                executable_path=executable_path,
                arguments=("--config", str(configuration), "context", "inspect"),
                environment=environment,
                working_directory=working_directory,
            ),
        )
        endpoint, context_name = _context_from_output(context_output)
        endpoint_output, endpoint_hash = _execute(
            backend,
            DockerEndpointCommandRequest(
                kind=DockerEndpointCommandKind.ENDPOINT_INFO,
                executable_path=executable_path,
                arguments=(
                    "--config",
                    str(configuration),
                    "--host",
                    endpoint,
                    "info",
                    "--format",
                    _INFO_FORMAT,
                ),
                environment=environment,
                working_directory=working_directory,
            ),
        )
        return _Observation(
            endpoint=endpoint,
            context_name=context_name,
            configuration_directory=configuration,
            daemon=_daemon_from_output(endpoint_output),
            context_output_sha256=context_hash,
            endpoint_output_sha256=endpoint_hash,
        )

    try:
        return runtime._run_while_held(run)  # noqa: SLF001
    except DockerEndpointError:
        raise
    except RuntimeCommandVerificationError:
        _fail(DockerEndpointErrorCode.RUNTIME_INVALID)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)


def _observation_fields(observation: _Observation) -> tuple[bytes, ...]:
    daemon = observation.daemon
    return (
        _path_key(observation.configuration_directory).encode(
            "utf-16-le", errors="strict"
        ),
        observation.endpoint.encode("ascii"),
        daemon.daemon_id.encode("ascii"),
        daemon.server_version.encode("ascii"),
        daemon.operating_system.encode("utf-8", errors="strict"),
        daemon.os_type.encode("ascii"),
        daemon.architecture.encode("ascii"),
        daemon.name.encode("utf-8", errors="strict"),
        daemon.docker_root.encode("utf-8", errors="strict"),
        daemon.driver.encode("utf-8", errors="strict"),
    )


def _binding_sha256(
    runtime: BoundCommandRuntimeEvidence,
    observation: _Observation,
) -> str:
    return _digest(
        _BINDING_DOMAIN,
        (
            runtime.evidence.evidence_sha256.encode("ascii"),
            *_observation_fields(observation),
        ),
    )


class BoundDockerEndpointEvidence:
    """Retain one Docker endpoint binding and revalidate it on demand."""

    __slots__ = (
        "_active_owner",
        "_binding_sha256",
        "_closed",
        "_evidence",
        "_lifetime_lock",
    )

    def __init__(self, evidence: DockerEndpointEvidence) -> None:
        if type(evidence) is not DockerEndpointEvidence:
            raise ValueError("Bound Docker endpoint evidence is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._closed = False
        self._evidence = evidence
        self._binding_sha256 = evidence.binding_sha256

    @property
    def evidence(self) -> DockerEndpointEvidence:
        return self._evidence

    @property
    def endpoint(self) -> EndpointIdentity:
        return self._evidence.endpoint

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return self._closed

    def assert_unchanged(
        self,
        runtime: BoundCommandRuntimeEvidence,
        backend: DockerEndpointCommandBackend,
    ) -> DockerEndpointEvidence:
        if (
            type(runtime) is not BoundCommandRuntimeEvidence
            or runtime.closed
            or runtime.evidence.product_id is not RuntimeProductId.DOCKER_CLI
        ):
            _fail(DockerEndpointErrorCode.RUNTIME_INVALID)
        self._lifetime_lock.acquire()
        if self._active_owner is not None or self._closed:
            self._lifetime_lock.release()
            _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            observation = _observe_under_runtime(runtime, backend)
            if (
                observation.endpoint != self._evidence.endpoint.canonical_endpoint
                or _binding_sha256(runtime, observation) != self._binding_sha256
            ):
                _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
            return self._evidence
        except DockerEndpointError as error:
            if error.code is DockerEndpointErrorCode.ENDPOINT_INVALID:
                _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
            raise
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
            self._closed = True

    def __enter__(self) -> BoundDockerEndpointEvidence:
        if self.closed:
            _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundDockerEndpointEvidence(state={state!r}, <redacted>)"


def capture_bound_docker_endpoint(
    runtime: BoundCommandRuntimeEvidence,
    *,
    backend: DockerEndpointCommandBackend | None = None,
) -> BoundDockerEndpointEvidence:
    """Resolve and retain one explicit local Docker named-pipe binding."""

    if (
        type(runtime) is not BoundCommandRuntimeEvidence
        or runtime.closed
        or runtime.evidence.product_id is not RuntimeProductId.DOCKER_CLI
    ):
        _fail(DockerEndpointErrorCode.RUNTIME_INVALID)
    selected_backend = backend
    if selected_backend is None:
        try:
            from .runtime_command_native import (
                NativeWindowsDockerEndpointCommandBackend,
            )

            selected_backend = NativeWindowsDockerEndpointCommandBackend()
        except Exception:
            _fail(DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE)

    first = _observe_under_runtime(runtime, selected_backend)
    second = _observe_under_runtime(runtime, selected_backend)
    if _observation_fields(first) != _observation_fields(second):
        _fail(DockerEndpointErrorCode.ENDPOINT_CHANGED)
    binding = _binding_sha256(runtime, second)
    endpoint = EndpointIdentity(
        product=RuntimeProduct.DOCKER,
        kind=EndpointKind.DOCKER_NAMED_PIPE,
        canonical_endpoint=second.endpoint,
        private_metadata_sha256=binding,
        identity_key=None,
        discovery_artifacts=(),
        rootless=False,
    )
    evidence = DockerEndpointEvidence(
        endpoint=endpoint,
        runtime_evidence_sha256=runtime.evidence.evidence_sha256,
        context_output_sha256=second.context_output_sha256,
        endpoint_output_sha256=second.endpoint_output_sha256,
        context_metadata_sha256=_text_digest(
            _CONTEXT_METADATA_DOMAIN,
            second.context_name,
        ),
        configuration_directory_sha256=_text_digest(
            _CONFIGURATION_DIRECTORY_DOMAIN,
            _path_key(second.configuration_directory),
        ),
        binding_sha256=binding,
    )
    return BoundDockerEndpointEvidence(evidence)


__all__ = [
    "BoundDockerEndpointEvidence",
    "DockerEndpointCommandBackend",
    "DockerEndpointCommandKind",
    "DockerEndpointCommandRequest",
    "DockerEndpointError",
    "DockerEndpointErrorCode",
    "DockerEndpointEvidence",
    "capture_bound_docker_endpoint",
]
