"""Fail-closed process plans for read-only Gate-A target observation.

This module does not execute a child process.  It binds every future Compose
or engine observation to an immutable :class:`TargetResolutionPlan`, an
absolute authenticated executable, an explicit endpoint, a minimal child
environment, and the complete set of file/path identities that an execution
owner must retain.  Dynamic daemon selectors are deliberately limited to one
full container ID, one digest-form image ID, or one of TowerScout's eight
derived named-volume names.

The native executor and provider-specific output normalizers remain separate
review boundaries.  In particular, constructing these plans performs no
Docker, Podman, Compose, filesystem, or launcher mutation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import NoReturn, Sequence

from .runtime_target_resolution import TargetResolutionPlan
from .target_contracts import (
    CONTAINER_BUNDLE_DESTINATION,
    EXPECTED_VOLUME_DESTINATIONS,
    ComposeInvocationKind,
    EndpointBindingKind,
    FileIdentity,
    RuntimeProduct,
)

OBSERVATION_CA_DESTINATION = CONTAINER_BUNDLE_DESTINATION
OBSERVATION_TIMEOUT_MS = 15_000
OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES = 1024 * 1024
OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES = 1024 * 1024
OBSERVATION_LIST_STDOUT_LIMIT_BYTES = 8 * 1024
OBSERVATION_STDERR_LIMIT_BYTES = 16 * 1024

_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_CHARACTERS = 32_767
_MAX_COMMAND_LINE_CHARACTERS = 32_767
_MAX_ENVIRONMENT_ITEMS = 32
_MAX_ENVIRONMENT_BLOCK_CHARACTERS = 32_767


class ObservationOperation(str, Enum):
    COMPOSE_MODEL_CURRENT = "compose_model_current"
    COMPOSE_MODEL_PLANNED = "compose_model_planned"
    CONTAINER_LIST = "container_list"
    CONTAINER_INSPECT = "container_inspect"
    IMAGE_INSPECT = "image_inspect"
    VOLUME_INSPECT = "volume_inspect"


class TargetObservationBindingErrorCode(str, Enum):
    TARGET_MISMATCH = "target_mismatch"
    OPERATION_REJECTED = "operation_rejected"
    SELECTOR_REJECTED = "selector_rejected"
    PLAN_REJECTED = "plan_rejected"


_PUBLIC_ERROR_MESSAGES = {
    TargetObservationBindingErrorCode.TARGET_MISMATCH: (
        "The target-observation authority is inconsistent."
    ),
    TargetObservationBindingErrorCode.OPERATION_REJECTED: (
        "The requested target-observation operation is not allowed."
    ),
    TargetObservationBindingErrorCode.SELECTOR_REJECTED: (
        "The requested target-observation selector is not allowed."
    ),
    TargetObservationBindingErrorCode.PLAN_REJECTED: (
        "The target-observation process plan is invalid."
    ),
}


class TargetObservationBindingError(ValueError):
    """A fixed-category error that never includes private plan material."""

    def __init__(self, code: TargetObservationBindingErrorCode) -> None:
        if type(code) is not TargetObservationBindingErrorCode:
            raise ValueError("Unknown target-observation binding error code.")
        self.code = code
        super().__init__(_PUBLIC_ERROR_MESSAGES[code])

    def __repr__(self) -> str:
        return f"TargetObservationBindingError(code={self.code.value!r})"


def _reject(code: TargetObservationBindingErrorCode) -> NoReturn:
    raise TargetObservationBindingError(code)


def _same_file_identity(left: FileIdentity, right: FileIdentity) -> bool:
    return (
        left.logical_name == right.logical_name
        and left.final_path == right.final_path
        and left.volume_serial == right.volume_serial
        and left.file_id == right.file_id
        and left.is_directory == right.is_directory
        and left.sha256 == right.sha256
        and left.size_bytes == right.size_bytes
    )


def _deduplicated_identities(
    identities: Sequence[FileIdentity],
) -> tuple[FileIdentity, ...]:
    output: list[FileIdentity] = []
    for identity in identities:
        if not any(_same_file_identity(identity, current) for current in output):
            output.append(identity)
    return tuple(output)


def _windows_environment(
    target: TargetResolutionPlan,
) -> tuple[tuple[str, str], ...]:
    environment = target.process_environment
    return (
        ("SYSTEMROOT", str(environment.system_root.final_path)),
        ("WINDIR", str(environment.system_root.final_path)),
        ("TEMP", str(environment.temp_directory.final_path)),
        ("TMP", str(environment.temp_directory.final_path)),
        ("USERPROFILE", str(environment.user_profile.final_path)),
        ("LOCALAPPDATA", str(environment.local_app_data.final_path)),
        ("APPDATA", str(environment.roaming_app_data.final_path)),
    )


def _all_authenticated_identities(
    target: TargetResolutionPlan,
) -> tuple[FileIdentity, ...]:
    endpoint_key = (
        () if target.endpoint.identity_key is None else (target.endpoint.identity_key,)
    )
    return _deduplicated_identities(
        (
            target.runtime.executable,
            *target.compose_provider.artifacts,
            *target.ordered_compose_files,
            target.environment_source,
            *target.security_artifacts.ordered_files,
            target.package_root,
            target.process_environment.system_root,
            target.process_environment.temp_directory,
            target.process_environment.user_profile,
            target.process_environment.local_app_data,
            target.process_environment.roaming_app_data,
            *endpoint_key,
            *target.endpoint.discovery_artifacts,
        )
    )


def _valid_argument(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_ARGUMENT_CHARACTERS
        and "\x00" not in value
        and not any(ord(character) < 0x20 for character in value)
    )


def _utf16_code_units(value: str) -> int | None:
    try:
        return len(value.encode("utf-16-le", errors="strict")) // 2
    except UnicodeError:
        return None


def _command_line_upper_bound(
    executable: FileIdentity,
    arguments: tuple[str, ...],
) -> int:
    """Bound Windows quoting without constructing or exposing the command."""

    values = (str(executable.final_path), *arguments)
    code_units = tuple(_utf16_code_units(value) for value in values)
    if any(value is None for value in code_units):
        return _MAX_COMMAND_LINE_CHARACTERS + 1
    # Windows quoting can at most double each input code unit, add two quote
    # characters per argv item, one separator between items, and the final NUL.
    return sum(2 * value + 2 for value in code_units if value is not None) + len(values)


def _environment_block_characters(
    environment_items: tuple[tuple[str, str], ...],
) -> int:
    total = 1
    for name, value in environment_items:
        name_characters = _utf16_code_units(name)
        value_characters = _utf16_code_units(value)
        if name_characters is None or value_characters is None:
            return _MAX_ENVIRONMENT_BLOCK_CHARACTERS + 1
        total += name_characters + value_characters + 2
    # Each entry is NAME=VALUE\0 and the complete block has one final NUL.
    return total


def _require_executable(identity: FileIdentity, leaf: str) -> None:
    if (
        type(identity) is not FileIdentity
        or identity.is_directory
        or not identity.final_path.is_absolute()
        or identity.logical_name.casefold() != leaf
        or identity.final_path.name.casefold() != leaf
    ):
        _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)


def _endpoint_prefix(target: TargetResolutionPlan) -> tuple[str, ...]:
    if target.runtime.product is RuntimeProduct.DOCKER:
        return ("--host", target.endpoint.canonical_endpoint)
    key = target.endpoint.identity_key
    if key is None:
        _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
    return (
        "--url",
        target.endpoint.canonical_endpoint,
        "--identity",
        str(key.final_path),
    )


@dataclass(frozen=True, slots=True, repr=False)
class _ExpectedProcess:
    executable: FileIdentity
    arguments: tuple[str, ...]
    environment_items: tuple[tuple[str, str], ...]
    authenticated_files: tuple[FileIdentity, ...]
    timeout_ms: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int


def _compose_expected(
    target: TargetResolutionPlan,
    *,
    planned: bool,
) -> _ExpectedProcess:
    environment = _windows_environment(target)
    if target.runtime.product is RuntimeProduct.DOCKER:
        provider = target.compose_provider
        if (
            provider.invocation_kind
            is not ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE
            or provider.endpoint_binding is not EndpointBindingKind.DOCKER_HOST_ARGUMENT
            or not provider.artifacts
        ):
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        executable = provider.artifacts[0]
        _require_executable(executable, "docker-compose.exe")
        arguments = (
            "--host",
            target.endpoint.canonical_endpoint,
            "--project-name",
            target.compose_project,
            "--project-directory",
            str(target.package_root.final_path),
            *tuple(
                value
                for identity in target.ordered_compose_files
                for value in ("--file", str(identity.final_path))
            ),
            "--env-file",
            str(target.environment_source.final_path),
            "config",
            "--format",
            "json",
        )
    else:
        provider = target.compose_provider
        key = target.endpoint.identity_key
        if (
            provider.invocation_kind is not ComposeInvocationKind.PODMAN_PYTHON_MODULE
            or provider.endpoint_binding
            is not EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT
            or len(provider.artifacts) < 2
            or key is None
        ):
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        executable = provider.artifacts[0]
        _require_executable(executable, "python.exe")
        _require_executable(target.runtime.executable, "podman.exe")
        arguments = (
            "-I",
            "-m",
            "podman_compose",
            "--podman-path",
            str(target.runtime.executable.final_path),
            "-p",
            target.compose_project,
            *tuple(
                value
                for identity in target.ordered_compose_files
                for value in ("-f", str(identity.final_path))
            ),
            "--env-file",
            str(target.environment_source.final_path),
            "config",
        )
        environment = (
            *environment,
            ("COMPOSE_PROJECT_DIR", str(target.package_root.final_path)),
            ("CONTAINER_HOST", target.endpoint.canonical_endpoint),
            ("CONTAINER_SSHKEY", str(key.final_path)),
        )
    if planned:
        environment = (
            *environment,
            ("REQUESTS_CA_BUNDLE", OBSERVATION_CA_DESTINATION),
            ("SSL_CERT_FILE", OBSERVATION_CA_DESTINATION),
        )
    return _ExpectedProcess(
        executable=executable,
        arguments=arguments,
        environment_items=environment,
        authenticated_files=_all_authenticated_identities(target),
        timeout_ms=OBSERVATION_TIMEOUT_MS,
        stdout_limit_bytes=OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=OBSERVATION_STDERR_LIMIT_BYTES,
    )


def _valid_selector(
    operation: ObservationOperation,
    target: TargetResolutionPlan,
    selector: str | None,
) -> bool:
    if operation in {
        ObservationOperation.COMPOSE_MODEL_CURRENT,
        ObservationOperation.COMPOSE_MODEL_PLANNED,
        ObservationOperation.CONTAINER_LIST,
    }:
        return selector is None
    if operation is ObservationOperation.CONTAINER_INSPECT:
        return type(selector) is str and _CONTAINER_ID.fullmatch(selector) is not None
    if operation is ObservationOperation.IMAGE_INSPECT:
        return type(selector) is str and _IMAGE_ID.fullmatch(selector) is not None
    if operation is ObservationOperation.VOLUME_INSPECT:
        expected = {
            f"{target.compose_project}_{logical_name}"
            for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
        }
        return type(selector) is str and selector in expected
    return False


def _engine_expected(
    target: TargetResolutionPlan,
    operation: ObservationOperation,
    selector: str | None,
) -> _ExpectedProcess:
    _require_executable(
        target.runtime.executable,
        (
            "docker.exe"
            if target.runtime.product is RuntimeProduct.DOCKER
            else "podman.exe"
        ),
    )
    prefix = _endpoint_prefix(target)
    project_label = (
        "com.docker.compose.project"
        if target.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.project"
    )
    service_label = (
        "com.docker.compose.service"
        if target.runtime.product is RuntimeProduct.DOCKER
        else "io.podman.compose.service"
    )
    suffix: tuple[str, ...]
    if operation is ObservationOperation.CONTAINER_LIST:
        suffix = (
            "container",
            "ls",
            "--all",
            "--filter",
            f"label={project_label}={target.compose_project}",
            "--filter",
            f"label={service_label}=towerscout",
            "--no-trunc",
            "--quiet",
        )
        stdout_limit = OBSERVATION_LIST_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.CONTAINER_INSPECT:
        suffix = ("container", "inspect", selector or "")
        stdout_limit = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.IMAGE_INSPECT:
        suffix = ("image", "inspect", selector or "")
        stdout_limit = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    elif operation is ObservationOperation.VOLUME_INSPECT:
        suffix = ("volume", "inspect", selector or "")
        stdout_limit = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    else:
        _reject(TargetObservationBindingErrorCode.OPERATION_REJECTED)
    return _ExpectedProcess(
        executable=target.runtime.executable,
        arguments=(*prefix, *suffix),
        environment_items=_windows_environment(target),
        authenticated_files=_all_authenticated_identities(target),
        timeout_ms=OBSERVATION_TIMEOUT_MS,
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=OBSERVATION_STDERR_LIMIT_BYTES,
    )


def _expected_process(
    target: TargetResolutionPlan,
    operation: ObservationOperation,
    selector: str | None,
) -> _ExpectedProcess:
    if not _valid_selector(operation, target, selector):
        _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
    if operation is ObservationOperation.COMPOSE_MODEL_CURRENT:
        return _compose_expected(target, planned=False)
    if operation is ObservationOperation.COMPOSE_MODEL_PLANNED:
        return _compose_expected(target, planned=True)
    return _engine_expected(target, operation, selector)


@dataclass(frozen=True, slots=True, repr=False)
class TargetObservationProcessPlan:
    """One exact, inert, shell-free target-observation process plan."""

    operation: ObservationOperation
    target: TargetResolutionPlan = field(repr=False)
    executable: FileIdentity = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    environment_items: tuple[tuple[str, str], ...] = field(repr=False)
    authenticated_files: tuple[FileIdentity, ...] = field(repr=False)
    selector: str | None = field(default=None, repr=False)
    timeout_ms: int = OBSERVATION_TIMEOUT_MS
    stdout_limit_bytes: int = OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES
    stderr_limit_bytes: int = OBSERVATION_STDERR_LIMIT_BYTES
    stdin_closed: bool = True
    shell: bool = False

    def __post_init__(self) -> None:
        structurally_valid = (
            type(self.operation) is ObservationOperation
            and type(self.target) is TargetResolutionPlan
            and type(self.executable) is FileIdentity
            and type(self.arguments) is tuple
            and 1 <= len(self.arguments) <= _MAX_ARGUMENTS
            and all(_valid_argument(value) for value in self.arguments)
            and _command_line_upper_bound(self.executable, self.arguments)
            <= _MAX_COMMAND_LINE_CHARACTERS
            and type(self.environment_items) is tuple
            and 1 <= len(self.environment_items) <= _MAX_ENVIRONMENT_ITEMS
            and all(
                type(item) is tuple
                and len(item) == 2
                and type(item[0]) is str
                and type(item[1]) is str
                and bool(item[0])
                and bool(item[1])
                and "\x00" not in item[0]
                and "\x00" not in item[1]
                for item in self.environment_items
            )
            and _environment_block_characters(self.environment_items)
            <= _MAX_ENVIRONMENT_BLOCK_CHARACTERS
            and type(self.authenticated_files) is tuple
            and all(type(item) is FileIdentity for item in self.authenticated_files)
            and (self.selector is None or type(self.selector) is str)
            and type(self.timeout_ms) is int
            and type(self.stdout_limit_bytes) is int
            and type(self.stderr_limit_bytes) is int
            and self.stdin_closed is True
            and self.shell is False
        )
        if not structurally_valid:
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        try:
            expected = _expected_process(self.target, self.operation, self.selector)
        except TargetObservationBindingError as error:
            if error.code is TargetObservationBindingErrorCode.SELECTOR_REJECTED:
                raise
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)
        keys = tuple(name for name, _value in self.environment_items)
        if (
            not _same_file_identity(self.executable, expected.executable)
            or self.arguments != expected.arguments
            or self.environment_items != expected.environment_items
            or len(set(keys)) != len(keys)
            or self.authenticated_files != expected.authenticated_files
            or len({id(item) for item in self.authenticated_files})
            != len(self.authenticated_files)
            or self.timeout_ms != expected.timeout_ms
            or self.stdout_limit_bytes != expected.stdout_limit_bytes
            or self.stderr_limit_bytes != expected.stderr_limit_bytes
        ):
            _reject(TargetObservationBindingErrorCode.PLAN_REJECTED)

    @property
    def authority_sha256(self) -> str:
        return self.target.authority_sha256

    @property
    def command(self) -> tuple[str, ...]:
        return (str(self.executable.final_path), *self.arguments)

    @property
    def environment(self) -> dict[str, str]:
        return dict(self.environment_items)

    @property
    def working_directory(self) -> PureWindowsPath:
        return self.target.package_root.final_path

    def __repr__(self) -> str:
        return (
            "TargetObservationProcessPlan("
            f"operation={self.operation.value!r}, runtime="
            f"{self.target.runtime.product.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TargetObservationExecutionBinding:
    """Construct only the reviewed observation commands for one target plan."""

    target: TargetResolutionPlan = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.target) is not TargetResolutionPlan:
            _reject(TargetObservationBindingErrorCode.TARGET_MISMATCH)
        try:
            _compose_expected(self.target, planned=False)
            _engine_expected(
                self.target,
                ObservationOperation.CONTAINER_LIST,
                None,
            )
        except TargetObservationBindingError:
            _reject(TargetObservationBindingErrorCode.TARGET_MISMATCH)

    def _build(
        self,
        operation: ObservationOperation,
        selector: str | None = None,
    ) -> TargetObservationProcessPlan:
        if not _valid_selector(operation, self.target, selector):
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        expected = _expected_process(self.target, operation, selector)
        return TargetObservationProcessPlan(
            operation=operation,
            target=self.target,
            executable=expected.executable,
            arguments=expected.arguments,
            environment_items=expected.environment_items,
            authenticated_files=expected.authenticated_files,
            selector=selector,
            timeout_ms=expected.timeout_ms,
            stdout_limit_bytes=expected.stdout_limit_bytes,
            stderr_limit_bytes=expected.stderr_limit_bytes,
        )

    def compose_model(self, *, planned: bool) -> TargetObservationProcessPlan:
        if type(planned) is not bool:
            _reject(TargetObservationBindingErrorCode.OPERATION_REJECTED)
        return self._build(
            (
                ObservationOperation.COMPOSE_MODEL_PLANNED
                if planned
                else ObservationOperation.COMPOSE_MODEL_CURRENT
            )
        )

    def container_list(self) -> TargetObservationProcessPlan:
        return self._build(ObservationOperation.CONTAINER_LIST)

    def container_inspect(self, container_id: str) -> TargetObservationProcessPlan:
        return self._build(ObservationOperation.CONTAINER_INSPECT, container_id)

    def image_inspect(self, image_id: str) -> TargetObservationProcessPlan:
        return self._build(ObservationOperation.IMAGE_INSPECT, image_id)

    def volume_inspect(self, logical_name: str) -> TargetObservationProcessPlan:
        expected_logical = {item for item, _destination in EXPECTED_VOLUME_DESTINATIONS}
        if type(logical_name) is not str or logical_name not in expected_logical:
            _reject(TargetObservationBindingErrorCode.SELECTOR_REJECTED)
        return self._build(
            ObservationOperation.VOLUME_INSPECT,
            f"{self.target.compose_project}_{logical_name}",
        )

    def volume_inspects(self) -> tuple[TargetObservationProcessPlan, ...]:
        return tuple(
            self.volume_inspect(logical_name)
            for logical_name, _destination in EXPECTED_VOLUME_DESTINATIONS
        )

    def __repr__(self) -> str:
        return (
            "TargetObservationExecutionBinding("
            f"runtime={self.target.runtime.product.value!r}, <redacted>)"
        )


__all__ = [
    "OBSERVATION_CA_DESTINATION",
    "OBSERVATION_COMPOSE_STDOUT_LIMIT_BYTES",
    "OBSERVATION_ENGINE_STDOUT_LIMIT_BYTES",
    "OBSERVATION_LIST_STDOUT_LIMIT_BYTES",
    "OBSERVATION_STDERR_LIMIT_BYTES",
    "OBSERVATION_TIMEOUT_MS",
    "ObservationOperation",
    "TargetObservationBindingError",
    "TargetObservationBindingErrorCode",
    "TargetObservationExecutionBinding",
    "TargetObservationProcessPlan",
]
