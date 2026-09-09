"""Immutable exact-image policy for an authenticated provider-child boundary.

The policy in this module is inert.  It records the only process images and
direct System32 image names that a later Windows debug-event executor may
admit.  It does not discover files, execute a process, consult ambient state,
or authorize launcher mutation.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Protocol

from .runtime_command_version import (
    COMMAND_STDERR_LIMIT_BYTES,
    COMMAND_STDOUT_LIMIT_BYTES,
    COMMAND_TIMEOUT_MS,
)
from .runtime_execution import CommandKind, ProcessCommandPlan
from .target_contracts import FileIdentity
from .windows_security import FileSnapshot, StableFileIdentity

_PATH_DOMAIN = b"TowerScout.ProviderChildImagePath.v1"
_BINDING_DOMAIN = b"TowerScout.ProviderChildImageBinding.v1"
_POLICY_DOMAIN = b"TowerScout.ProviderChildImagePolicy.v1"
_MAX_EXACT_IMAGES = 512
_MAX_SYSTEM_IMAGES = 256
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_CHARACTERS = 32_767
_MAX_ENVIRONMENT_ITEMS = 32
_MAX_ENVIRONMENT_BLOCK_CHARACTERS = 32_767
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_LOCAL_DRIVE = re.compile(r"^[A-Za-z]:$")
_REQUEST_DOMAIN = b"TowerScout.ProviderChildProcessRequest.v1"
_PROVIDER_ENVIRONMENT_NAMES = frozenset(
    {
        "APPDATA",
        "COMPOSE_PROJECT_DIR",
        "CONTAINER_HOST",
        "CONTAINER_SSHKEY",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


class _Digest(Protocol):
    def update(self, value: bytes) -> None: ...


def _add(digest: _Digest, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _canonical_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("Provider-child image path is invalid.")
    path = value.replace("/", "\\")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if not PureWindowsPath(normalized).is_absolute():
        raise ValueError("Provider-child image path is invalid.")
    return ntpath.normcase(normalized)


def _path_sha256(value: str) -> str:
    digest = hashlib.sha256()
    _add(digest, _PATH_DOMAIN)
    _add(digest, _canonical_path(value).encode("utf-16-le", errors="strict"))
    return digest.hexdigest()


def _local_absolute_path(value: PureWindowsPath) -> bool:
    if type(value) is not PureWindowsPath:
        return False
    text = str(value)
    try:
        canonical = PureWindowsPath(_canonical_path(text))
    except (TypeError, ValueError, UnicodeError):
        return False
    return (
        value.is_absolute()
        and _LOCAL_DRIVE.fullmatch(canonical.drive) is not None
        and not str(canonical).startswith("\\\\")
        and len(text) <= _MAX_ARGUMENT_CHARACTERS
    )


class ProcessImageRole(str, Enum):
    PROVIDER = "provider"
    RUNTIME_CHILD = "runtime_child"


@dataclass(frozen=True, slots=True, repr=False)
class ProcessImageBinding:
    """One exact executable image admitted from a Windows debug event."""

    identity: StableFileIdentity = field(repr=False)
    sha256: str = field(repr=False)
    final_path_sha256: str = field(repr=False)
    entrypoint: bool
    content_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not StableFileIdentity
            or not _is_sha256(self.sha256)
            or not _is_sha256(self.final_path_sha256)
            or type(self.entrypoint) is not bool
        ):
            raise ValueError("Provider-child image binding is invalid.")
        digest = hashlib.sha256()
        for value in (
            _BINDING_DOMAIN,
            self.identity.volume_serial.to_bytes(8, "big"),
            self.identity.file_id,
            self.sha256.encode("ascii"),
            self.final_path_sha256.encode("ascii"),
            bytes((self.entrypoint,)),
        ):
            _add(digest, value)
        object.__setattr__(self, "content_sha256", digest.hexdigest())

    @classmethod
    def from_snapshot(
        cls,
        snapshot: FileSnapshot,
        *,
        entrypoint: bool,
    ) -> "ProcessImageBinding":
        if type(snapshot) is not FileSnapshot or type(entrypoint) is not bool:
            raise ValueError("Provider-child image snapshot is invalid.")
        return cls(
            identity=snapshot.identity,
            sha256=snapshot.sha256,
            final_path_sha256=_path_sha256(snapshot.final_path),
            entrypoint=entrypoint,
        )

    def matches(self, snapshot: FileSnapshot) -> bool:
        if type(snapshot) is not FileSnapshot:
            return False
        try:
            path_sha256 = _path_sha256(snapshot.final_path)
        except (TypeError, ValueError, UnicodeError):
            return False
        return (
            snapshot.identity == self.identity
            and snapshot.sha256 == self.sha256
            and path_sha256 == self.final_path_sha256
        )

    def matches_file_identity(self, identity: FileIdentity) -> bool:
        if type(identity) is not FileIdentity or identity.is_directory:
            return False
        try:
            path_sha256 = _path_sha256(str(identity.final_path))
        except (TypeError, ValueError, UnicodeError):
            return False
        return (
            self.identity
            == StableFileIdentity(identity.volume_serial, identity.file_id)
            and self.sha256 == identity.sha256
            and self.final_path_sha256 == path_sha256
        )

    def __repr__(self) -> str:
        return f"ProcessImageBinding(entrypoint={self.entrypoint}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ProcessImagePolicy:
    """Exact private images plus reviewed direct-System32 image leaf names."""

    role: ProcessImageRole
    exact_files: tuple[ProcessImageBinding, ...] = field(repr=False)
    system_image_names: tuple[str, ...] = field(repr=False)
    content_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.role) is not ProcessImageRole
            or type(self.exact_files) is not tuple
            or not 1 <= len(self.exact_files) <= _MAX_EXACT_IMAGES
            or any(type(item) is not ProcessImageBinding for item in self.exact_files)
            or sum(item.entrypoint for item in self.exact_files) != 1
            or len(set(self.exact_files)) != len(self.exact_files)
            or len({item.identity for item in self.exact_files})
            != len(self.exact_files)
            or len({item.final_path_sha256 for item in self.exact_files})
            != len(self.exact_files)
            or type(self.system_image_names) is not tuple
            or not 1 <= len(self.system_image_names) <= _MAX_SYSTEM_IMAGES
            or self.system_image_names
            != tuple(sorted(set(self.system_image_names), key=str.casefold))
            or any(
                type(name) is not str
                or not name
                or name != name.casefold()
                or ntpath.basename(name) != name
                or not name.endswith(".dll")
                for name in self.system_image_names
            )
        ):
            raise ValueError("Provider-child image policy is invalid.")
        digest = hashlib.sha256()
        for value in (
            _POLICY_DOMAIN,
            self.role.value.encode("ascii"),
            *(item.content_sha256.encode("ascii") for item in self.exact_files),
            *(
                name.encode("ascii", errors="strict")
                for name in self.system_image_names
            ),
        ):
            _add(digest, value)
        object.__setattr__(self, "content_sha256", digest.hexdigest())

    @property
    def entrypoint(self) -> ProcessImageBinding:
        return next(item for item in self.exact_files if item.entrypoint)

    def __repr__(self) -> str:
        return (
            "ProcessImagePolicy("
            f"role={self.role.value!r}, exact_image_count={len(self.exact_files)}, "
            f"system_image_count={len(self.system_image_names)}, <redacted>)"
        )


def _request_digest(plan: ProcessCommandPlan) -> str:
    digest = hashlib.sha256()
    values: list[bytes] = [
        _REQUEST_DOMAIN,
        plan.target.target_token.digest_sha256.encode("ascii"),
        plan.kind.value.encode("ascii"),
        str(plan.executable.final_path).encode("utf-16-le", errors="strict"),
    ]
    values.extend(
        argument.encode("utf-8", errors="strict") for argument in plan.arguments
    )
    for name, value in plan.environment_items:
        values.extend(
            (
                name.encode("ascii", errors="strict"),
                value.encode("utf-8", errors="strict"),
            )
        )
    values.append(str(plan.working_directory).encode("utf-16-le", errors="strict"))
    for identity in plan.authenticated_files:
        values.extend(
            (
                identity.volume_serial.to_bytes(8, "big"),
                identity.file_id,
                identity.sha256.encode("ascii") if identity.sha256 else b"<directory>",
                identity.canonical_path_sha256.encode("ascii"),
            )
        )
    for encoded_value in values:
        _add(digest, encoded_value)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ProviderChildProcessRequest:
    """Exact, shell-free request derived from one validated Podman plan."""

    executable_path: PureWindowsPath = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    environment: tuple[tuple[str, str], ...] = field(repr=False)
    working_directory: PureWindowsPath = field(repr=False)
    timeout_ms: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    target_token: str
    binding_sha256: str = field(repr=False)
    stdin_closed: bool = True
    shell: bool = False

    def __post_init__(self) -> None:
        keys = (
            tuple(item[0] for item in self.environment)
            if type(self.environment) is tuple
            and all(type(item) is tuple and len(item) == 2 for item in self.environment)
            else ()
        )
        environment_characters = (
            sum(len(name) + len(value) + 2 for name, value in self.environment) + 1
            if keys
            else 0
        )
        if (
            not _local_absolute_path(self.executable_path)
            or not _local_absolute_path(self.working_directory)
            or type(self.arguments) is not tuple
            or not 1 <= len(self.arguments) <= _MAX_ARGUMENTS
            or any(
                type(value) is not str
                or not value
                or "\x00" in value
                or len(value) > _MAX_ARGUMENT_CHARACTERS
                for value in self.arguments
            )
            or sum(len(value) + 1 for value in self.arguments)
            > _MAX_ARGUMENT_CHARACTERS
            or type(self.environment) is not tuple
            or not 1 <= len(self.environment) <= _MAX_ENVIRONMENT_ITEMS
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or _ENVIRONMENT_NAME.fullmatch(item[0]) is None
                or type(item[1]) is not str
                or not item[1]
                or "\x00" in item[1]
                for item in self.environment
            )
            or len({key.casefold() for key in keys}) != len(keys)
            or frozenset(keys) != _PROVIDER_ENVIRONMENT_NAMES
            or environment_characters > _MAX_ENVIRONMENT_BLOCK_CHARACTERS
            or self.timeout_ms != COMMAND_TIMEOUT_MS
            or self.stdout_limit_bytes != COMMAND_STDOUT_LIMIT_BYTES
            or self.stderr_limit_bytes != COMMAND_STDERR_LIMIT_BYTES
            or type(self.target_token) is not str
            or not self.target_token.startswith("TSRT1-")
            or len(self.target_token) != 38
            or any(
                character not in "0123456789abcdef"
                for character in self.target_token[6:]
            )
            or not _is_sha256(self.binding_sha256)
            or self.stdin_closed is not True
            or self.shell is not False
        ):
            raise ValueError("Provider-child process request is invalid.")

    @classmethod
    def from_plan(cls, plan: ProcessCommandPlan) -> "ProviderChildProcessRequest":
        if type(plan) is not ProcessCommandPlan:
            raise ValueError("Provider-child process plan is invalid.")
        try:
            validated = ProcessCommandPlan(
                kind=plan.kind,
                target=plan.target,
                executable=plan.executable,
                arguments=plan.arguments,
                environment_items=plan.environment_items,
                authenticated_files=plan.authenticated_files,
            )
        except (TypeError, ValueError):
            raise ValueError("Provider-child process plan is invalid.") from None
        if validated != plan or validated.kind is not CommandKind.PODMAN_COMPOSE:
            raise ValueError("Provider-child process plan is invalid.")
        return cls(
            executable_path=validated.executable.final_path,
            arguments=validated.arguments,
            environment=tuple(
                sorted(validated.environment_items, key=lambda item: item[0].casefold())
            ),
            working_directory=validated.working_directory,
            timeout_ms=COMMAND_TIMEOUT_MS,
            stdout_limit_bytes=COMMAND_STDOUT_LIMIT_BYTES,
            stderr_limit_bytes=COMMAND_STDERR_LIMIT_BYTES,
            target_token=validated.target_token,
            binding_sha256=_request_digest(validated),
        )

    def __repr__(self) -> str:
        return (
            "ProviderChildProcessRequest("
            f"target_token={self.target_token!r}, arguments={len(self.arguments)}, "
            f"environment_keys={tuple(name for name, _ in self.environment)!r}, "
            "path='<redacted>')"
        )


__all__ = [
    "ProcessImageBinding",
    "ProcessImagePolicy",
    "ProcessImageRole",
    "ProviderChildProcessRequest",
]
