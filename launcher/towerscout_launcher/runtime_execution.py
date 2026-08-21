"""Fail-closed command construction for an already resolved Gate-A target.

This module deliberately does not execute processes.  It converts immutable,
authenticated target identities into immutable command plans that a later
bounded executor can consume without consulting PATH, the current directory,
runtime connection names, Compose plugins, or ambient redirect variables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Mapping, Sequence

from .target_contracts import (
    ComposeInvocationKind,
    EndpointBindingKind,
    FileIdentity,
    ResolvedRepairTarget,
    RuntimeProduct,
)

_PODMAN_COMPOSE_ENVIRONMENT = frozenset(
    {"COMPOSE_PROJECT_DIR", "CONTAINER_HOST", "CONTAINER_SSHKEY"}
)


class CommandKind(str, Enum):
    DOCKER_ENGINE = "docker_engine"
    DOCKER_COMPOSE = "docker_compose"
    PODMAN_ENGINE = "podman_engine"
    PODMAN_COMPOSE = "podman_compose"


class EngineReadOperation(str, Enum):
    """Reviewed read-only engine discovery operations for this isolated slice."""

    VERSION_JSON = "version_json"
    INFO_JSON = "info_json"


class ComposeReadOperation(str, Enum):
    """Reviewed read-only Compose discovery operations for this isolated slice."""

    CONFIG = "config"


_ENGINE_READ_ARGUMENTS = {
    (RuntimeProduct.DOCKER, EngineReadOperation.VERSION_JSON): (
        "version",
        "--format",
        "json",
    ),
    (RuntimeProduct.PODMAN, EngineReadOperation.VERSION_JSON): (
        "version",
        "--format",
        "json",
    ),
    (RuntimeProduct.PODMAN, EngineReadOperation.INFO_JSON): (
        "info",
        "--format",
        "json",
    ),
}
_COMPOSE_READ_ARGUMENTS = {
    (RuntimeProduct.DOCKER, ComposeReadOperation.CONFIG): (
        "config",
        "--format",
        "json",
    ),
    (RuntimeProduct.PODMAN, ComposeReadOperation.CONFIG): ("config",),
}


class BindingErrorCode(str, Enum):
    TARGET_MISMATCH = "target_mismatch"
    EXECUTABLE_REJECTED = "executable_rejected"
    PROVIDER_REJECTED = "provider_rejected"
    ENDPOINT_MATERIAL_REJECTED = "endpoint_material_rejected"
    OPERATION_REJECTED = "operation_rejected"
    PLAN_REJECTED = "plan_rejected"


_PUBLIC_ERROR_MESSAGES = {
    BindingErrorCode.TARGET_MISMATCH: "The resolved runtime target is inconsistent.",
    BindingErrorCode.EXECUTABLE_REJECTED: "An authenticated executable identity is required.",
    BindingErrorCode.PROVIDER_REJECTED: "The authenticated Compose provider is not supported.",
    BindingErrorCode.ENDPOINT_MATERIAL_REJECTED: "The captured local endpoint material is incomplete.",
    BindingErrorCode.OPERATION_REJECTED: "The requested fixed runtime operation is not allowed.",
    BindingErrorCode.PLAN_REJECTED: "The runtime command plan is invalid.",
}


class RuntimeExecutionBindingError(ValueError):
    """A public-safe failure that never includes private binding material."""

    def __init__(self, code: BindingErrorCode) -> None:
        self.code = code
        super().__init__(_PUBLIC_ERROR_MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeExecutionBindingError(code={self.code.value!r})"


def _reject(code: BindingErrorCode) -> None:
    raise RuntimeExecutionBindingError(code)


def _same_file_identity(left: FileIdentity, right: FileIdentity) -> bool:
    """Compare every fixed identity field, including the captured final path."""
    return (
        left.logical_name == right.logical_name
        and left.final_path == right.final_path
        and left.volume_serial == right.volume_serial
        and left.file_id == right.file_id
        and left.is_directory == right.is_directory
        and left.sha256 == right.sha256
        and left.size_bytes == right.size_bytes
    )


def _require_executable(identity: FileIdentity, expected_name: str) -> None:
    if (
        identity.is_directory
        or identity.logical_name.casefold() != expected_name
        or identity.final_path.name.casefold() != expected_name
        or not identity.final_path.is_absolute()
    ):
        _reject(BindingErrorCode.EXECUTABLE_REJECTED)


def _require_endpoint_key(identity: FileIdentity) -> None:
    if (
        identity.is_directory
        or identity.logical_name != "podman_identity_key"
        or not identity.final_path.is_absolute()
    ):
        _reject(BindingErrorCode.ENDPOINT_MATERIAL_REJECTED)


def _engine_read_arguments(
    product: RuntimeProduct, operation: EngineReadOperation
) -> tuple[str, ...]:
    if not isinstance(operation, EngineReadOperation):
        _reject(BindingErrorCode.OPERATION_REJECTED)
    arguments = _ENGINE_READ_ARGUMENTS.get((product, operation))
    if arguments is None:
        _reject(BindingErrorCode.OPERATION_REJECTED)
    return arguments


def _compose_read_arguments(
    product: RuntimeProduct, operation: ComposeReadOperation
) -> tuple[str, ...]:
    if not isinstance(operation, ComposeReadOperation):
        _reject(BindingErrorCode.OPERATION_REJECTED)
    arguments = _COMPOSE_READ_ARGUMENTS.get((product, operation))
    if arguments is None:
        _reject(BindingErrorCode.OPERATION_REJECTED)
    return arguments


def _allowed_suffixes(kind: CommandKind) -> frozenset[tuple[str, ...]]:
    product = {
        CommandKind.DOCKER_ENGINE: RuntimeProduct.DOCKER,
        CommandKind.DOCKER_COMPOSE: RuntimeProduct.DOCKER,
        CommandKind.PODMAN_ENGINE: RuntimeProduct.PODMAN,
        CommandKind.PODMAN_COMPOSE: RuntimeProduct.PODMAN,
    }[kind]
    source = (
        _COMPOSE_READ_ARGUMENTS
        if kind in {CommandKind.DOCKER_COMPOSE, CommandKind.PODMAN_COMPOSE}
        else _ENGINE_READ_ARGUMENTS
    )
    return frozenset(
        arguments
        for (candidate_product, _operation), arguments in source.items()
        if candidate_product is product
    )


def _deduplicated_identities(
    identities: Sequence[FileIdentity],
) -> tuple[FileIdentity, ...]:
    output: list[FileIdentity] = []
    for identity in identities:
        if not any(_same_file_identity(identity, present) for present in output):
            output.append(identity)
    return tuple(output)


def _compose_environment_arguments(
    target: ResolvedRepairTarget,
) -> tuple[str, ...]:
    return ("--env-file", str(target.compose.environment_source.final_path))


def _compose_authenticated_files(
    target: ResolvedRepairTarget,
) -> tuple[FileIdentity, ...]:
    environment_files = (
        (target.compose.environment_source,)
        if target.compose.environment_file is None
        else (target.compose.environment_source, target.compose.environment_file)
    )
    return (target.package_root, *target.compose.ordered_files, *environment_files)


def _endpoint_authenticated_files(
    target: ResolvedRepairTarget,
) -> tuple[FileIdentity, ...]:
    identity_key = (
        () if target.endpoint.identity_key is None else (target.endpoint.identity_key,)
    )
    return (*identity_key, *target.endpoint.discovery_artifacts)


def _windows_environment_items(
    target: ResolvedRepairTarget,
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


def _windows_environment_identities(
    target: ResolvedRepairTarget,
) -> tuple[FileIdentity, ...]:
    environment = target.process_environment
    return (
        environment.system_root,
        environment.temp_directory,
        environment.user_profile,
        environment.local_app_data,
        environment.roaming_app_data,
    )


@dataclass(frozen=True, slots=True, repr=False)
class ProcessCommandPlan:
    """An immutable process invocation with private values hidden from repr."""

    kind: CommandKind
    target: ResolvedRepairTarget = field(repr=False)
    executable: FileIdentity = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    environment_items: tuple[tuple[str, str], ...] = field(repr=False)
    authenticated_files: tuple[FileIdentity, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not CommandKind
            or type(self.target) is not ResolvedRepairTarget
            or type(self.executable) is not FileIdentity
            or type(self.arguments) is not tuple
            or any(type(argument) is not str for argument in self.arguments)
            or type(self.environment_items) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or not all(type(value) is str for value in item)
                for item in self.environment_items
            )
            or type(self.authenticated_files) is not tuple
            or any(
                type(identity) is not FileIdentity
                for identity in self.authenticated_files
            )
        ):
            _reject(BindingErrorCode.PLAN_REJECTED)
        expected_product = {
            CommandKind.DOCKER_ENGINE: RuntimeProduct.DOCKER,
            CommandKind.DOCKER_COMPOSE: RuntimeProduct.DOCKER,
            CommandKind.PODMAN_ENGINE: RuntimeProduct.PODMAN,
            CommandKind.PODMAN_COMPOSE: RuntimeProduct.PODMAN,
        }[self.kind]
        if self.target.runtime.product is not expected_product:
            _reject(BindingErrorCode.PLAN_REJECTED)

        expected_environment = _windows_environment_items(self.target)
        expected_executable = self.target.runtime.executable
        expected_authenticated: tuple[FileIdentity, ...] = (expected_executable,)
        if self.kind is CommandKind.DOCKER_ENGINE:
            _require_executable(expected_executable, "docker.exe")
            prefix = ("--host", self.target.endpoint.canonical_endpoint)
            expected_authenticated = _deduplicated_identities(
                (
                    expected_executable,
                    self.target.package_root,
                    *_windows_environment_identities(self.target),
                    *_endpoint_authenticated_files(self.target),
                )
            )
        elif self.kind is CommandKind.DOCKER_COMPOSE:
            expected_executable = self.target.compose_provider.artifacts[0]
            _require_executable(expected_executable, "docker-compose.exe")
            expected_authenticated = self.target.compose_provider.artifacts
            prefix = (
                "--host",
                self.target.endpoint.canonical_endpoint,
                "--project-name",
                self.target.compose_project,
                "--project-directory",
                str(self.target.package_root.final_path),
                *tuple(
                    value
                    for identity in self.target.compose.ordered_files
                    for value in ("--file", str(identity.final_path))
                ),
                *_compose_environment_arguments(self.target),
            )
            expected_authenticated = _deduplicated_identities(
                (
                    *self.target.compose_provider.artifacts,
                    *_compose_authenticated_files(self.target),
                    *_windows_environment_identities(self.target),
                    *_endpoint_authenticated_files(self.target),
                )
            )
        elif self.kind is CommandKind.PODMAN_ENGINE:
            identity_key = self.target.endpoint.identity_key
            if identity_key is None:
                _reject(BindingErrorCode.PLAN_REJECTED)
            _require_executable(expected_executable, "podman.exe")
            _require_endpoint_key(identity_key)
            prefix = (
                "--url",
                self.target.endpoint.canonical_endpoint,
                "--identity",
                str(identity_key.final_path),
            )
            expected_authenticated = _deduplicated_identities(
                (
                    expected_executable,
                    identity_key,
                    self.target.package_root,
                    *_windows_environment_identities(self.target),
                    *_endpoint_authenticated_files(self.target),
                )
            )
        else:
            identity_key = self.target.endpoint.identity_key
            if identity_key is None:
                _reject(BindingErrorCode.PLAN_REJECTED)
            expected_executable = self.target.compose_provider.artifacts[0]
            _require_executable(expected_executable, "python.exe")
            _require_executable(self.target.runtime.executable, "podman.exe")
            _require_endpoint_key(identity_key)
            prefix = (
                "-I",
                "-m",
                "podman_compose",
                "--podman-path",
                str(self.target.runtime.executable.final_path),
                "-p",
                self.target.compose_project,
                *tuple(
                    value
                    for identity in self.target.compose.ordered_files
                    for value in ("-f", str(identity.final_path))
                ),
                *_compose_environment_arguments(self.target),
            )
            expected_environment = (
                *expected_environment,
                ("COMPOSE_PROJECT_DIR", str(self.target.package_root.final_path)),
                ("CONTAINER_HOST", self.target.endpoint.canonical_endpoint),
                ("CONTAINER_SSHKEY", str(identity_key.final_path)),
            )
            expected_authenticated = _deduplicated_identities(
                (
                    expected_executable,
                    self.target.runtime.executable,
                    identity_key,
                    *self.target.compose_provider.artifacts,
                    *_compose_authenticated_files(self.target),
                    *_windows_environment_identities(self.target),
                    *_endpoint_authenticated_files(self.target),
                )
            )

        keys = tuple(key for key, _value in self.environment_items)
        if (
            self.executable.is_directory
            or not self.executable.final_path.is_absolute()
            or not _same_file_identity(self.executable, expected_executable)
            or len(self.arguments) <= len(prefix)
            or self.arguments[: len(prefix)] != prefix
            or len(self.authenticated_files) != len(expected_authenticated)
            or any(
                not _same_file_identity(observed, expected)
                for observed, expected in zip(
                    self.authenticated_files, expected_authenticated, strict=True
                )
            )
            or len(set(keys)) != len(keys)
            or frozenset(keys)
            != (
                (
                    _PODMAN_COMPOSE_ENVIRONMENT
                    | {key for key, _ in _windows_environment_items(self.target)}
                )
                if self.kind is CommandKind.PODMAN_COMPOSE
                else frozenset(
                    key for key, _ in _windows_environment_items(self.target)
                )
            )
            or self.environment_items != expected_environment
            or any(
                not value or "\x00" in value for _key, value in self.environment_items
            )
        ):
            _reject(BindingErrorCode.PLAN_REJECTED)
        if self.arguments[len(prefix) :] not in _allowed_suffixes(self.kind):
            _reject(BindingErrorCode.PLAN_REJECTED)

    @property
    def target_token(self) -> str:
        return self.target.target_token.display

    @property
    def command(self) -> tuple[str, ...]:
        """Return the exact argv tuple for a future shell-free executor."""
        return (str(self.executable.final_path), *self.arguments)

    @property
    def environment(self) -> dict[str, str]:
        """Return a fresh minimal environment; no ambient values are retained."""
        return dict(self.environment_items)

    @property
    def working_directory(self) -> PureWindowsPath:
        """Return the authenticated package root, never an ambient directory."""
        return self.target.package_root.final_path

    @property
    def shell(self) -> bool:
        return False

    def __repr__(self) -> str:
        keys = tuple(key for key, _value in self.environment_items)
        return (
            "ProcessCommandPlan("
            f"kind={self.kind.value!r}, target_token={self.target_token!r}, "
            f"environment_keys={keys!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeExecutionBinding:
    """Bind engine and Compose commands to one immutable resolved target."""

    target: ResolvedRepairTarget = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.target, ResolvedRepairTarget):
            _reject(BindingErrorCode.TARGET_MISMATCH)
        _require_executable(
            self.target.runtime.executable,
            f"{self.target.runtime.product.value}.exe",
        )
        if self.target.runtime.product is RuntimeProduct.DOCKER:
            self._docker_compose_executable()
            return

        identity_key = self.target.endpoint.identity_key
        if identity_key is None:
            _reject(BindingErrorCode.ENDPOINT_MATERIAL_REJECTED)
        _require_endpoint_key(identity_key)
        self._require_podman_provider()

    def _docker_compose_executable(self) -> FileIdentity:
        provider = self.target.compose_provider
        if (
            provider.invocation_kind
            is not ComposeInvocationKind.DOCKER_COMPOSE_EXECUTABLE
            or provider.endpoint_binding is not EndpointBindingKind.DOCKER_HOST_ARGUMENT
            or not provider.artifacts
        ):
            _reject(BindingErrorCode.PROVIDER_REJECTED)
        executable = provider.artifacts[0]
        _require_executable(executable, "docker-compose.exe")
        return executable

    def _require_podman_provider(self) -> None:
        provider = self.target.compose_provider
        if (
            provider.invocation_kind is not ComposeInvocationKind.PODMAN_PYTHON_MODULE
            or provider.endpoint_binding
            is not EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT
            or len(provider.artifacts) < 2
        ):
            _reject(BindingErrorCode.PROVIDER_REJECTED)

    def _base_plan(
        self,
        kind: CommandKind,
        executable: FileIdentity,
        arguments: tuple[str, ...],
        environment: tuple[tuple[str, str], ...],
        authenticated_files: Sequence[FileIdentity],
    ) -> ProcessCommandPlan:
        return ProcessCommandPlan(
            kind=kind,
            target=self.target,
            executable=executable,
            arguments=arguments,
            environment_items=environment,
            authenticated_files=_deduplicated_identities(authenticated_files),
        )

    def engine_command(self, operation: EngineReadOperation) -> ProcessCommandPlan:
        runtime = self.target.runtime
        operation_args = _engine_read_arguments(runtime.product, operation)
        endpoint = self.target.endpoint
        expected_name = f"{runtime.product.value}.exe"
        _require_executable(runtime.executable, expected_name)

        if runtime.product is RuntimeProduct.DOCKER:
            arguments = ("--host", endpoint.canonical_endpoint, *operation_args)
            kind = CommandKind.DOCKER_ENGINE
            authenticated = (
                runtime.executable,
                self.target.package_root,
                *_windows_environment_identities(self.target),
                *_endpoint_authenticated_files(self.target),
            )
        else:
            identity_key = endpoint.identity_key
            if identity_key is None:
                _reject(BindingErrorCode.ENDPOINT_MATERIAL_REJECTED)
            arguments = (
                "--url",
                endpoint.canonical_endpoint,
                "--identity",
                str(identity_key.final_path),
                *operation_args,
            )
            kind = CommandKind.PODMAN_ENGINE
            authenticated = (
                runtime.executable,
                identity_key,
                self.target.package_root,
                *_windows_environment_identities(self.target),
                *_endpoint_authenticated_files(self.target),
            )

        return self._base_plan(
            kind,
            runtime.executable,
            arguments,
            _windows_environment_items(self.target),
            authenticated,
        )

    def compose_command(self, operation: ComposeReadOperation) -> ProcessCommandPlan:
        target = self.target
        operation_args = _compose_read_arguments(target.runtime.product, operation)
        compose_files = tuple(
            str(identity.final_path) for identity in target.compose.ordered_files
        )

        if target.runtime.product is RuntimeProduct.DOCKER:
            executable = self._docker_compose_executable()
            arguments: tuple[str, ...] = (
                "--host",
                target.endpoint.canonical_endpoint,
                "--project-name",
                target.compose_project,
                "--project-directory",
                str(target.package_root.final_path),
                *tuple(value for path in compose_files for value in ("--file", path)),
                *_compose_environment_arguments(target),
                *operation_args,
            )
            return self._base_plan(
                CommandKind.DOCKER_COMPOSE,
                executable,
                arguments,
                _windows_environment_items(target),
                (
                    *target.compose_provider.artifacts,
                    *_compose_authenticated_files(target),
                    *_windows_environment_identities(target),
                    *_endpoint_authenticated_files(target),
                ),
            )

        self._require_podman_provider()
        identity_key = target.endpoint.identity_key
        if identity_key is None:
            _reject(BindingErrorCode.ENDPOINT_MATERIAL_REJECTED)
        arguments = (
            "-I",
            "-m",
            "podman_compose",
            "--podman-path",
            str(target.runtime.executable.final_path),
            "-p",
            target.compose_project,
            *tuple(value for path in compose_files for value in ("-f", path)),
            *_compose_environment_arguments(target),
            *operation_args,
        )
        environment = (
            *_windows_environment_items(target),
            ("COMPOSE_PROJECT_DIR", str(target.package_root.final_path)),
            ("CONTAINER_HOST", target.endpoint.canonical_endpoint),
            ("CONTAINER_SSHKEY", str(identity_key.final_path)),
        )
        return self._base_plan(
            CommandKind.PODMAN_COMPOSE,
            target.compose_provider.artifacts[0],
            arguments,
            environment,
            (
                target.compose_provider.artifacts[0],
                target.runtime.executable,
                identity_key,
                *target.compose_provider.artifacts,
                *_compose_authenticated_files(target),
                *_windows_environment_identities(target),
                *_endpoint_authenticated_files(target),
            ),
        )

    def __repr__(self) -> str:
        return (
            "RuntimeExecutionBinding("
            f"target_token={self.target.target_token.display!r}, "
            f"runtime={self.target.runtime.product.value!r})"
        )


def sanitized_environment(
    plan: ProcessCommandPlan, ambient: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return only planned entries; ``ambient`` is accepted solely to discard it."""
    if type(plan) is not ProcessCommandPlan:
        _reject(BindingErrorCode.PLAN_REJECTED)
    del ambient
    return plan.environment
