"""Retained package and environment inputs for Gate-A target resolution.

This source-only boundary derives target configuration solely from held,
package-local files.  It never consults the process environment, launcher UI,
or current working directory, and it does not execute a child or mutate the
package.  The public native factory intentionally exposes no injectable trust
seam; tests use the private factory below.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Callable, NoReturn, Protocol, Sequence, TypeVar

from .runtime_load_trust import DirectoryEntry, NativeRuntimeLoadInventoryApi
from .target_contracts import (
    ABSENT_FILE_SHA256,
    CONTAINER_BUNDLE_DESTINATION,
    FileIdentity,
    GpuMode,
    SecurityArtifactInventory,
)
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import (
    KNOWN_CLOUD_REPARSE_TAGS,
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    RandomAccessFileReader,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_MAX_ENV_BYTES = 262_144
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_POLICY_BYTES = 2 * 1_048_576
_MAX_COMPOSE_BYTES = 2 * 1_048_576
_MAX_DIRECTORY_ENTRIES = 16_384
_MAX_ENV_LINES = 4_096
_MAX_ENV_LINE_CHARACTERS = 16_384
_MAX_JSON_DEPTH = 16
_MAX_JSON_CONTAINER_ITEMS = 1_024
_MAX_JSON_NODES = 16_384
_MAX_JSON_STRING_CHARACTERS = 32_767
_READ_CHUNK_BYTES = 65_536
_RELEASE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_TARGET_RELEASE_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$")
_SOURCE_REF = re.compile(r"^[0-9a-f]{40}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_MACHINE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BINDING_DOMAIN = b"TowerScout.PackageEnvironmentInputs.v1"
_CLOUD_HYDRATION_MARKERS = 0x00001000 | 0x00040000 | 0x00400000
_POLICY_DIRECTORIES = (
    PureWindowsPath(r"launcher\towerscout_launcher"),
    PureWindowsPath(r"launcher\_internal\towerscout_launcher"),
)
_COMPOSE_FILES = (
    "compose.yaml",
    "compose.gpu.yaml",
    "compose.gpu.podman.yaml",
)
_POLICY_FILES = (
    "runtime-policy.v1.json",
    "runtime-dependency-policy.v1.json",
)
_REQUIRED_ENV = frozenset(
    {
        "TOWERSCOUT_IMAGE",
        "TOWERSCOUT_IMAGE_DIGEST",
        "TOWERSCOUT_PYTORCH_FLAVOR",
        "TOWERSCOUT_GPU_MODE",
        "TOWERSCOUT_GPU_AUTO_OVERLAY",
        "TOWERSCOUT_PODMAN_GPU_OVERLAY",
        "TOWERSCOUT_PODMAN_MACHINE",
    }
)
_Result = TypeVar("_Result")


class PackageInputErrorCode(str, Enum):
    PACKAGE_INVALID = "package_invalid"
    INPUTS_CHANGED = "inputs_changed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class PackageInputError(RuntimeError):
    """Sanitized package-input verification failure."""

    _MESSAGES = {
        PackageInputErrorCode.PACKAGE_INVALID: (
            "The TowerScout package configuration is invalid."
        ),
        PackageInputErrorCode.INPUTS_CHANGED: (
            "The authenticated package inputs changed during verification."
        ),
        PackageInputErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure package input verification is unavailable."
        ),
    }

    def __init__(self, code: PackageInputErrorCode) -> None:
        if type(code) is not PackageInputErrorCode:
            raise ValueError("Unknown package input error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"PackageInputError(code={self.code.value!r})"


def _fail(code: PackageInputErrorCode) -> NoReturn:
    raise PackageInputError(code)


class _DirectoryInventoryApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]: ...


@dataclass(frozen=True, slots=True, repr=False)
class PackageEnvironmentInputs:
    """Immutable package fields needed by the eventual complete plan owner."""

    package_root: FileIdentity = field(repr=False)
    release_identity: str
    security_artifacts: SecurityArtifactInventory = field(repr=False)
    compose_files: tuple[FileIdentity, ...] = field(repr=False)
    environment_sha256: str = field(repr=False)
    planned_environment_sha256: str = field(repr=False)
    environment_source: FileIdentity = field(repr=False)
    environment_file: FileIdentity | None = field(repr=False)
    compose_project: str
    requested_gpu_mode: GpuMode
    gpu_auto_overlay: bool
    podman_gpu_overlay: bool
    pytorch_flavor: str
    engine_hint: str
    port: int
    configured_image_reference: str = field(repr=False)
    pinned_image_digest: str = field(repr=False)
    podman_machine: str = field(repr=False)
    package_binding_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.package_root) is not FileIdentity
            or not self.package_root.is_directory
            or type(self.security_artifacts) is not SecurityArtifactInventory
            or type(self.compose_files) is not tuple
            or tuple(item.logical_name for item in self.compose_files) != _COMPOSE_FILES
            or any(
                type(item) is not FileIdentity or item.is_directory
                for item in self.compose_files
            )
            or type(self.environment_source) is not FileIdentity
            or self.environment_source.is_directory
            or (
                self.environment_file is not None
                and type(self.environment_file) is not FileIdentity
            )
            or type(self.release_identity) is not str
            or not _TARGET_RELEASE_IDENTITY.fullmatch(self.release_identity)
            or type(self.compose_project) is not str
            or not _COMPOSE_PROJECT.fullmatch(self.compose_project)
            or type(self.requested_gpu_mode) is not GpuMode
            or type(self.gpu_auto_overlay) is not bool
            or type(self.podman_gpu_overlay) is not bool
            or self.pytorch_flavor not in {"cpu", "cuda126"}
            or self.engine_hint not in {"", "docker", "podman"}
            or type(self.port) is not int
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65_535
            or type(self.configured_image_reference) is not str
            or not 1 <= len(self.configured_image_reference) <= 512
            or type(self.pinned_image_digest) is not str
            or not _OCI_DIGEST.fullmatch(self.pinned_image_digest)
            or not self.configured_image_reference.endswith(
                "@" + self.pinned_image_digest
            )
            or type(self.podman_machine) is not str
            or not _MACHINE_NAME.fullmatch(self.podman_machine)
            or type(self.package_binding_sha256) is not str
            or not _SHA256.fullmatch(self.package_binding_sha256)
            or type(self.planned_environment_sha256) is not str
            or not _SHA256.fullmatch(self.planned_environment_sha256)
        ):
            raise ValueError("Package environment inputs are invalid.")
        if self.environment_file is None:
            if (
                self.environment_sha256 != ABSENT_FILE_SHA256
                or self.environment_source.logical_name != ".env.example"
            ):
                raise ValueError("Absent environment identity is invalid.")
        elif (
            self.environment_file.logical_name != ".env"
            or self.environment_file.is_directory
            or self.environment_file.sha256 != self.environment_sha256
            or self.environment_file != self.environment_source
        ):
            raise ValueError("Existing environment identity is invalid.")
        parsed = _ParsedPackage(
            release_identity=self.release_identity,
            compose_project=self.compose_project,
            requested_gpu_mode=self.requested_gpu_mode,
            gpu_auto_overlay=self.gpu_auto_overlay,
            podman_gpu_overlay=self.podman_gpu_overlay,
            pytorch_flavor=self.pytorch_flavor,
            engine_hint=self.engine_hint,
            port=self.port,
            configured_image_reference=self.configured_image_reference,
            pinned_image_digest=self.pinned_image_digest,
            podman_machine=self.podman_machine,
            planned_environment_sha256=self.planned_environment_sha256,
        )
        bound_files = (
            *self.security_artifacts.ordered_files,
            *self.compose_files,
            self.environment_source,
        )
        if (
            _package_binding(
                self.package_root,
                bound_files,
                parsed,
                self.environment_sha256,
                self.planned_environment_sha256,
            )
            != self.package_binding_sha256
        ):
            raise ValueError("Package environment binding is invalid.")

    def __repr__(self) -> str:
        return "PackageEnvironmentInputs(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _HeldPackageFile:
    logical_name: str
    owner: HandleBoundFile = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _ParsedPackage:
    release_identity: str
    compose_project: str
    requested_gpu_mode: GpuMode
    gpu_auto_overlay: bool
    podman_gpu_overlay: bool
    pytorch_flavor: str
    engine_hint: str
    port: int
    configured_image_reference: str = field(repr=False)
    pinned_image_digest: str = field(repr=False)
    podman_machine: str = field(repr=False)
    planned_environment_sha256: str = field(repr=False)


def _canonical_path(path: PureWindowsPath | str) -> str:
    value = str(path).replace("/", "\\")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    normalized = ntpath.normpath(value)
    if not PureWindowsPath(normalized).is_absolute() or "\x00" in normalized:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return ntpath.normcase(normalized)


def _identity(logical_name: str, owner: HandleBoundFile) -> FileIdentity:
    snapshot = owner.snapshot
    return FileIdentity(
        logical_name=logical_name,
        final_path=PureWindowsPath(snapshot.final_path),
        volume_serial=snapshot.identity.volume_serial,
        file_id=snapshot.identity.file_id,
        sha256=snapshot.sha256,
        size_bytes=snapshot.size,
    )


def _directory_identity(owner: PathHierarchyTrust) -> FileIdentity:
    snapshot = owner.root_snapshot
    return FileIdentity(
        logical_name="package_root",
        final_path=PureWindowsPath(snapshot.final_path),
        volume_serial=snapshot.identity.volume_serial,
        file_id=snapshot.identity.file_id,
        is_directory=True,
    )


def _package_binding(
    package_root: FileIdentity,
    files: Sequence[FileIdentity],
    parsed: _ParsedPackage,
    environment_sha256: str,
    planned_environment_sha256: str,
) -> str:
    values = [
        package_root.volume_serial.to_bytes(8, "big"),
        package_root.file_id,
        parsed.release_identity.encode("utf-8", errors="strict"),
        environment_sha256.encode("ascii"),
        planned_environment_sha256.encode("ascii"),
        parsed.compose_project.encode("ascii"),
        parsed.requested_gpu_mode.value.encode("ascii"),
        b"1" if parsed.gpu_auto_overlay else b"0",
        b"1" if parsed.podman_gpu_overlay else b"0",
        parsed.pytorch_flavor.encode("ascii"),
        parsed.engine_hint.encode("ascii"),
        str(parsed.port).encode("ascii"),
        parsed.configured_image_reference.encode("ascii"),
        parsed.pinned_image_digest.encode("ascii"),
        parsed.podman_machine.encode("ascii"),
    ]
    for identity in files:
        values.extend(
            (
                identity.logical_name.encode("utf-8", errors="strict"),
                identity.volume_serial.to_bytes(8, "big"),
                identity.file_id,
                identity.sha256.encode("ascii"),
                identity.size_bytes.to_bytes(8, "big"),
            )
        )
    digest = hashlib.sha256()
    for value in (_BINDING_DOMAIN, *values):
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _read_file(owner: HandleBoundFile, maximum: int) -> bytes:
    def read(reader: RandomAccessFileReader, _snapshot: FileSnapshot) -> bytes:
        if not 1 <= reader.size <= maximum:
            _fail(PackageInputErrorCode.PACKAGE_INVALID)
        offset = 0
        chunks: list[bytes] = []
        while offset < reader.size:
            amount = min(_READ_CHUNK_BYTES, reader.size - offset)
            chunk = reader.read_at(offset, amount)
            if type(chunk) is not bytes or len(chunk) != amount:
                _fail(PackageInputErrorCode.PACKAGE_INVALID)
            chunks.append(chunk)
            offset += amount
        return b"".join(chunks)

    return owner.inspect_same_handle_random_access(read)


def _decode_utf8(
    contents: bytes,
    maximum: int,
    *,
    preserve_newlines: bool = False,
) -> str:
    if type(contents) is not bytes or not 1 <= len(contents) <= maximum:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    try:
        text = contents.decode("utf-8-sig", errors="strict")
    except UnicodeError:
        raise PackageInputError(PackageInputErrorCode.PACKAGE_INVALID) from None
    if (
        "\x00" in text
        or any(character in text for character in ("\x85", "\u2028", "\u2029"))
        or any(
            ord(character) < 0x20 and character not in {"\t", "\r", "\n"}
            for character in text
        )
    ):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return text if preserve_newlines else normalized


def _parse_env(contents: bytes) -> dict[str, str]:
    text = _decode_utf8(contents, _MAX_ENV_BYTES)
    lines = text.split("\n")
    if len(lines) > _MAX_ENV_LINES or any(
        len(line) > _MAX_ENV_LINE_CHARACTERS for line in lines
    ):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    result: dict[str, str] = {}
    seen: set[str] = set()
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, raw_value = raw_line.partition("=")
        key = name.strip()
        folded = key.casefold()
        if separator != "=" or not _ENV_NAME.fullmatch(key) or folded in seen:
            _fail(PackageInputErrorCode.PACKAGE_INVALID)
        seen.add(folded)
        if key in _REQUIRED_ENV or key in {
            "COMPOSE_PROJECT_NAME",
            "TOWERSCOUT_CONTAINER_ENGINE",
            "TOWERSCOUT_PORT",
        }:
            result[key] = raw_value.strip()
    if not _REQUIRED_ENV.issubset(result):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return result


def _planned_environment_sha256(contents: bytes) -> str:
    text = _decode_utf8(contents, _MAX_ENV_BYTES, preserve_newlines=True)
    has_bom = contents.startswith(b"\xef\xbb\xbf")
    targets = {
        "REQUESTS_CA_BUNDLE": CONTAINER_BUNDLE_DESTINATION,
        "SSL_CERT_FILE": CONTAINER_BUNDLE_DESTINATION,
    }
    output: list[str] = []
    replaced: set[str] = set()
    selected_newline = "\r\n" if "\r\n" in text else "\n"
    for line in text.splitlines(keepends=True):
        if line.endswith("\r\n"):
            content, ending = line[:-2], "\r\n"
        elif line.endswith("\n"):
            content, ending = line[:-1], "\n"
        else:
            content, ending = line, ""
        name, separator, _value = content.partition("=")
        key = name.strip()
        matching = tuple(
            target for target in targets if key.casefold() == target.casefold()
        )
        if matching:
            target = matching[0]
            if separator != "=" or key != target or target in replaced:
                _fail(PackageInputErrorCode.PACKAGE_INVALID)
            output.append(f"{target}={targets[target]}{ending}")
            replaced.add(target)
        else:
            output.append(line)
    updated = "".join(output)
    for target, value in targets.items():
        if target in replaced:
            continue
        if updated and not updated.endswith(("\r", "\n")):
            updated += selected_newline
        updated += f"{target}={value}{selected_newline}"
    encoded = updated.encode("utf-8", errors="strict")
    if has_bom:
        encoded = b"\xef\xbb\xbf" + encoded
    if not 1 <= len(encoded) <= _MAX_ENV_BYTES:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return hashlib.sha256(encoded).hexdigest()


def _reject_constant(value: str) -> NoReturn:
    del value
    _fail(PackageInputErrorCode.PACKAGE_INVALID)


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _fail(PackageInputErrorCode.PACKAGE_INVALID)
        result[key] = value
    return result


def _validate_json_shape(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            _fail(PackageInputErrorCode.PACKAGE_INVALID)
        if type(item) is dict:
            if len(item) > _MAX_JSON_CONTAINER_ITEMS:
                _fail(PackageInputErrorCode.PACKAGE_INVALID)
            for key, child in item.items():
                if type(key) is not str or len(key) > _MAX_JSON_STRING_CHARACTERS:
                    _fail(PackageInputErrorCode.PACKAGE_INVALID)
                pending.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > _MAX_JSON_CONTAINER_ITEMS:
                _fail(PackageInputErrorCode.PACKAGE_INVALID)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > _MAX_JSON_STRING_CHARACTERS or "\x00" in item:
                _fail(PackageInputErrorCode.PACKAGE_INVALID)
        elif type(item) is int:
            if not -(2**63) <= item < 2**63:
                _fail(PackageInputErrorCode.PACKAGE_INVALID)
        elif item is not None and type(item) is not bool:
            _fail(PackageInputErrorCode.PACKAGE_INVALID)


def _parse_manifest(contents: bytes) -> dict[str, object]:
    text = _decode_utf8(contents, _MAX_MANIFEST_BYTES)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
    except PackageInputError:
        raise
    except (json.JSONDecodeError, OverflowError, RecursionError, TypeError, ValueError):
        raise PackageInputError(PackageInputErrorCode.PACKAGE_INVALID) from None
    if type(parsed) is not dict or len(parsed) > 128:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    _validate_json_shape(parsed)
    return parsed


def _exact_text(mapping: dict[str, object], name: str, maximum: int = 512) -> str:
    value = mapping.get(name)
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return value


def _parse_package(manifest_bytes: bytes, env_bytes: bytes) -> _ParsedPackage:
    manifest = _parse_manifest(manifest_bytes)
    env = _parse_env(env_bytes)
    schema = manifest.get("schema_version")
    version = _exact_text(manifest, "release_version", 64)
    track = _exact_text(manifest, "track", 64)
    image = _exact_text(manifest, "image")
    digest = _exact_text(manifest, "image_digest", 71)
    flavor = _exact_text(manifest, "pytorch_flavor", 16)
    source = manifest.get("corresponding_source")
    if type(source) is not dict:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    source_ref = _exact_text(source, "source_ref", 40)
    if (
        type(schema) is not int
        or schema != 1
        or track != "agpl-yolo"
        or version == "template"
        or not _RELEASE_VERSION.fullmatch(version)
        or not _SOURCE_REF.fullmatch(source_ref)
        or not _OCI_DIGEST.fullmatch(digest)
        or not image.endswith("@" + digest)
        or not image.isascii()
        or any(character.isspace() or ord(character) < 0x21 for character in image)
        or flavor not in {"cpu", "cuda126"}
        or env["TOWERSCOUT_IMAGE"] != image
        or env["TOWERSCOUT_IMAGE_DIGEST"] != digest
        or env["TOWERSCOUT_PYTORCH_FLAVOR"] != flavor
    ):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    try:
        requested = GpuMode(env["TOWERSCOUT_GPU_MODE"])
        auto_overlay = {"0": False, "1": True}[env["TOWERSCOUT_GPU_AUTO_OVERLAY"]]
        podman_overlay = {"0": False, "1": True}[env["TOWERSCOUT_PODMAN_GPU_OVERLAY"]]
        engine = env.get("TOWERSCOUT_CONTAINER_ENGINE", "")
        if engine not in {"", "docker", "podman"}:
            raise ValueError
        project = env.get("COMPOSE_PROJECT_NAME", "towerscout")
        if not _COMPOSE_PROJECT.fullmatch(project):
            raise ValueError
        port_text = env.get("TOWERSCOUT_PORT", "5000")
        if not port_text.isascii() or not port_text.isdecimal():
            raise ValueError
        port = int(port_text, 10)
        if not 1 <= port <= 65_535:
            raise ValueError
        machine = env["TOWERSCOUT_PODMAN_MACHINE"]
        if not _MACHINE_NAME.fullmatch(machine):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise PackageInputError(PackageInputErrorCode.PACKAGE_INVALID) from None
    return _ParsedPackage(
        release_identity=f"{version}+{source_ref}",
        compose_project=project,
        requested_gpu_mode=requested,
        gpu_auto_overlay=auto_overlay,
        podman_gpu_overlay=podman_overlay,
        pytorch_flavor=flavor,
        engine_hint=engine,
        port=port,
        configured_image_reference=image,
        pinned_image_digest=digest,
        podman_machine=machine,
        planned_environment_sha256=_planned_environment_sha256(env_bytes),
    )


def _safe_entries(
    api: _DirectoryInventoryApi, path: PureWindowsPath
) -> tuple[DirectoryEntry, ...]:
    try:
        entries = api.list_directory(str(path))
    except (OSError, RuntimeError, TypeError, ValueError):
        raise PackageInputError(PackageInputErrorCode.PACKAGE_INVALID) from None
    if (
        type(entries) is not tuple
        or len(entries) > _MAX_DIRECTORY_ENTRIES
        or any(type(item) is not DirectoryEntry for item in entries)
    ):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    for item in entries:
        if item.reparse_tag and not (
            item.reparse_tag in KNOWN_CLOUD_REPARSE_TAGS
            and not item.attributes & _CLOUD_HYDRATION_MARKERS
        ):
            _fail(PackageInputErrorCode.PACKAGE_INVALID)
    folded = tuple(item.name.casefold() for item in entries)
    if len(folded) != len(set(folded)):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return tuple(sorted(entries, key=lambda item: (item.name.casefold(), item.name)))


def _entry(entries: Sequence[DirectoryEntry], name: str) -> DirectoryEntry | None:
    matches = tuple(item for item in entries if item.name.casefold() == name.casefold())
    if len(matches) > 1:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return matches[0] if matches else None


def _capture_file(
    root: PureWindowsPath,
    relative: PureWindowsPath,
    *,
    maximum: int,
    file_api: WindowsFileApi,
) -> _HeldPackageFile:
    expected = root.joinpath(*relative.parts)
    owner = capture_handle_bound_file(
        Path(str(expected)),
        api=file_api,
        policy=FileCapturePolicy(
            max_bytes=maximum,
            require_single_link=True,
            allow_hydrated_cloud_placeholder=True,
        ),
    )
    logical_name = relative.name
    if (
        _canonical_path(PureWindowsPath(owner.snapshot.final_path))
        != _canonical_path(expected)
        or owner.snapshot.size < 1
    ):
        owner.close()
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return _HeldPackageFile(logical_name, owner)


def _run_file_leases(
    files: Sequence[_HeldPackageFile],
    operation: Callable[[], _Result],
    index: int = 0,
) -> _Result:
    if index == len(files):
        return operation()
    return files[index].owner.run_while_held(
        lambda: _run_file_leases(files, operation, index + 1)
    )


class BoundPackageEnvironmentInputs:
    """Retain every package file and directory behind one coherent capture."""

    __slots__ = (
        "_active_owner",
        "_environment_file_present",
        "_files",
        "_inventory_api",
        "_lifetime_lock",
        "_package_entries",
        "_package_root",
        "_parsed",
        "_policy_directory",
        "_policy_entries",
    )

    def __init__(
        self,
        *,
        package_root: PathHierarchyTrust,
        policy_directory: PathHierarchyTrust,
        files: tuple[_HeldPackageFile, ...],
        package_entries: tuple[DirectoryEntry, ...],
        policy_entries: tuple[DirectoryEntry, ...],
        inventory_api: _DirectoryInventoryApi,
        parsed: _ParsedPackage,
        environment_file_present: bool,
    ) -> None:
        if (
            type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or type(policy_directory) is not PathHierarchyTrust
            or policy_directory.closed
            or type(files) is not tuple
            or not files
            or any(
                type(item) is not _HeldPackageFile or item.owner.closed
                for item in files
            )
            or type(package_entries) is not tuple
            or type(policy_entries) is not tuple
            or type(parsed) is not _ParsedPackage
            or type(environment_file_present) is not bool
        ):
            raise ValueError("Bound package environment inputs are invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._package_root: PathHierarchyTrust | None = package_root
        self._policy_directory: PathHierarchyTrust | None = policy_directory
        self._files: tuple[_HeldPackageFile, ...] | None = files
        self._package_entries = package_entries
        self._policy_entries = policy_entries
        self._inventory_api = inventory_api
        self._parsed = parsed
        self._environment_file_present = environment_file_present

    @property
    def supported(self) -> bool:
        with self._lifetime_lock:
            try:
                inventory_supported = self._inventory_api.supported is True
            except Exception:
                inventory_supported = False
            return bool(not self.closed and inventory_supported)

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            files = self._files
            return bool(
                (self._package_root is None or self._package_root.closed)
                and (self._policy_directory is None or self._policy_directory.closed)
                and (files is None or all(item.owner.closed for item in files))
            )

    def _capture_owned(
        self,
        package_root: PathHierarchyTrust,
        policy_directory: PathHierarchyTrust,
        files: tuple[_HeldPackageFile, ...],
    ) -> PackageEnvironmentInputs:
        package_path = PureWindowsPath(package_root.root_snapshot.final_path)
        policy_path = PureWindowsPath(policy_directory.root_snapshot.final_path)

        def build() -> PackageEnvironmentInputs:
            if (
                _safe_entries(self._inventory_api, package_path)
                != self._package_entries
                or _safe_entries(self._inventory_api, policy_path)
                != self._policy_entries
            ):
                _fail(PackageInputErrorCode.INPUTS_CHANGED)
            by_name = {item.logical_name: item.owner for item in files}
            manifest = _identity(
                "release-manifest.v1.json", by_name["release-manifest.v1.json"]
            )
            runtime_policy = _identity(
                "runtime-policy.v1.json", by_name["runtime-policy.v1.json"]
            )
            dependency_policy = _identity(
                "runtime-dependency-policy.v1.json",
                by_name["runtime-dependency-policy.v1.json"],
            )
            compose = tuple(_identity(name, by_name[name]) for name in _COMPOSE_FILES)
            source_name = ".env" if self._environment_file_present else ".env.example"
            source = _identity(source_name, by_name[source_name])
            environment_file = source if self._environment_file_present else None
            parsed = self._parsed
            package_root_identity = _directory_identity(package_root)
            environment_sha256 = (
                source.sha256 if self._environment_file_present else ABSENT_FILE_SHA256
            )
            bound_files = (
                manifest,
                runtime_policy,
                dependency_policy,
                *compose,
                source,
            )
            return PackageEnvironmentInputs(
                package_root=package_root_identity,
                release_identity=parsed.release_identity,
                security_artifacts=SecurityArtifactInventory(
                    release_manifest=manifest,
                    runtime_policy=runtime_policy,
                    runtime_dependency_policy=dependency_policy,
                ),
                compose_files=compose,
                environment_sha256=environment_sha256,
                planned_environment_sha256=parsed.planned_environment_sha256,
                environment_source=source,
                environment_file=environment_file,
                compose_project=parsed.compose_project,
                requested_gpu_mode=parsed.requested_gpu_mode,
                gpu_auto_overlay=parsed.gpu_auto_overlay,
                podman_gpu_overlay=parsed.podman_gpu_overlay,
                pytorch_flavor=parsed.pytorch_flavor,
                engine_hint=parsed.engine_hint,
                port=parsed.port,
                configured_image_reference=parsed.configured_image_reference,
                pinned_image_digest=parsed.pinned_image_digest,
                podman_machine=parsed.podman_machine,
                package_binding_sha256=_package_binding(
                    package_root_identity,
                    bound_files,
                    parsed,
                    environment_sha256,
                    parsed.planned_environment_sha256,
                ),
            )

        return package_root.run_while_held(
            lambda: policy_directory.run_while_held(
                lambda: _run_file_leases(files, build)
            )
        )

    def capture(self) -> PackageEnvironmentInputs:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(PackageInputErrorCode.INPUTS_CHANGED)
        package_root = self._package_root
        policy_directory = self._policy_directory
        files = self._files
        if (
            package_root is None
            or package_root.closed
            or policy_directory is None
            or policy_directory.closed
            or files is None
            or any(item.owner.closed for item in files)
        ):
            self._lifetime_lock.release()
            _fail(PackageInputErrorCode.INPUTS_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            return self._capture_owned(package_root, policy_directory, files)
        except PackageInputError:
            raise
        except WindowsSecurityError:
            raise PackageInputError(PackageInputErrorCode.INPUTS_CHANGED) from None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise PackageInputError(
                PackageInputErrorCode.VERIFICATION_UNAVAILABLE
            ) from None
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(PackageInputErrorCode.INPUTS_CHANGED)
            interruption: BaseException | None = None
            for _attempt in range(3):
                files = self._files
                if files is not None:
                    for item in reversed(files):
                        if item.owner.closed:
                            continue
                        try:
                            item.owner.close()
                        except BaseException as error:
                            if (
                                not isinstance(error, Exception)
                                and interruption is None
                            ):
                                interruption = error
                    if all(item.owner.closed for item in files):
                        self._files = None
                for attribute in ("_policy_directory", "_package_root"):
                    owner = getattr(self, attribute)
                    if owner is None or owner.closed:
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
                _fail(PackageInputErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundPackageEnvironmentInputs":
        if self.closed:
            _fail(PackageInputErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundPackageEnvironmentInputs(state={state!r}, <redacted>)"


def _close_partial(
    files: Sequence[_HeldPackageFile],
    directories: Sequence[PathHierarchyTrust],
) -> tuple[BaseException | None, bool]:
    interruption: BaseException | None = None
    for _attempt in range(3):
        for item in reversed(files):
            if item.owner.closed:
                continue
            try:
                item.owner.close()
            except BaseException as error:
                if not isinstance(error, Exception) and interruption is None:
                    interruption = error
        for owner in reversed(directories):
            if owner.closed:
                continue
            try:
                owner.close()
            except BaseException as error:
                if not isinstance(error, Exception) and interruption is None:
                    interruption = error
        if all(item.owner.closed for item in files) and all(
            owner.closed for owner in directories
        ):
            break
    incomplete = any(not item.owner.closed for item in files) or any(
        not owner.closed for owner in directories
    )
    return interruption, incomplete


def _environment_source_name(entries: Sequence[DirectoryEntry]) -> tuple[str, bool]:
    environment = _entry(entries, ".env")
    template = _entry(entries, ".env.example")
    if environment is not None and environment.is_directory:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    if environment is None and (template is None or template.is_directory):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return (".env", True) if environment is not None else (".env.example", False)


def _capture_policy_directory(
    root: PureWindowsPath,
    *,
    path_api: WindowsPathTrustApi,
    directories: list[PathHierarchyTrust],
) -> PathHierarchyTrust:
    candidates: list[PathHierarchyTrust] = []
    for relative in _POLICY_DIRECTORIES:
        try:
            candidate = capture_path_hierarchy(
                str(root.joinpath(*relative.parts)),
                purpose=PathTrustPurpose.PACKAGE_ROOT,
                api=path_api,
            )
        except WindowsSecurityError as error:
            if error.category != "path_open_failed":
                raise
            continue
        candidates.append(candidate)
        directories.append(candidate)
    if len(candidates) != 1:
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return candidates[0]


def _validated_policy_entries(
    inventory_api: _DirectoryInventoryApi,
    policy_path: PureWindowsPath,
) -> tuple[DirectoryEntry, ...]:
    entries = _safe_entries(inventory_api, policy_path)
    for name in _POLICY_FILES:
        entry = _entry(entries, name)
        if entry is None or entry.is_directory:
            _fail(PackageInputErrorCode.PACKAGE_INVALID)
    return entries


def _capture_package_files(
    root: PureWindowsPath,
    policy_path: PureWindowsPath,
    source_name: str,
    *,
    file_api: WindowsFileApi,
    files: list[_HeldPackageFile],
) -> None:
    requests = (
        (PureWindowsPath("release-manifest.v1.json"), _MAX_MANIFEST_BYTES),
        *((PureWindowsPath(name), _MAX_COMPOSE_BYTES) for name in _COMPOSE_FILES),
        *(
            (
                PureWindowsPath(ntpath.relpath(str(policy_path), str(root))) / name,
                _MAX_POLICY_BYTES,
            )
            for name in _POLICY_FILES
        ),
        (PureWindowsPath(source_name), _MAX_ENV_BYTES),
    )
    for relative, maximum in requests:
        files.append(
            _capture_file(
                root,
                relative,
                maximum=maximum,
                file_api=file_api,
            )
        )


def _new_bound_owner(
    *,
    package_owner: PathHierarchyTrust,
    policy_owner: PathHierarchyTrust,
    files: list[_HeldPackageFile],
    package_entries: tuple[DirectoryEntry, ...],
    policy_entries: tuple[DirectoryEntry, ...],
    inventory_api: _DirectoryInventoryApi,
    source_name: str,
    environment_present: bool,
) -> BoundPackageEnvironmentInputs:
    by_name = {item.logical_name: item.owner for item in files}
    parsed = _parse_package(
        _read_file(by_name["release-manifest.v1.json"], _MAX_MANIFEST_BYTES),
        _read_file(by_name[source_name], _MAX_ENV_BYTES),
    )
    return BoundPackageEnvironmentInputs(
        package_root=package_owner,
        policy_directory=policy_owner,
        files=tuple(files),
        package_entries=package_entries,
        policy_entries=policy_entries,
        inventory_api=inventory_api,
        parsed=parsed,
        environment_file_present=environment_present,
    )


def _capture_package_environment_inputs(
    package_root: PureWindowsPath,
    *,
    path_api: WindowsPathTrustApi,
    file_api: WindowsFileApi,
    inventory_api: _DirectoryInventoryApi,
) -> BoundPackageEnvironmentInputs:
    """Injectable test seam behind the fixed native public factory."""

    if (
        type(package_root) is not PureWindowsPath
        or not package_root.is_absolute()
        or not package_root.name
        or "\x00" in str(package_root)
        or len(str(package_root)) > 32_767
    ):
        _fail(PackageInputErrorCode.PACKAGE_INVALID)
    try:
        supported = (
            path_api.supported is True
            and file_api.supported is True
            and inventory_api.supported is True
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        supported = False
    if not supported:
        _fail(PackageInputErrorCode.VERIFICATION_UNAVAILABLE)

    directories: list[PathHierarchyTrust] = []
    files: list[_HeldPackageFile] = []
    owner: BoundPackageEnvironmentInputs | None = None
    primary: BaseException | None = None
    try:
        package_owner = capture_path_hierarchy(
            str(package_root),
            purpose=PathTrustPurpose.PACKAGE_ROOT,
            api=path_api,
        )
        directories.append(package_owner)
        resolved_root = PureWindowsPath(package_owner.root_snapshot.final_path)
        package_entries = _safe_entries(inventory_api, resolved_root)
        source_name, environment_present = _environment_source_name(package_entries)
        policy_owner = _capture_policy_directory(
            resolved_root,
            path_api=path_api,
            directories=directories,
        )
        policy_path = PureWindowsPath(policy_owner.root_snapshot.final_path)
        policy_entries = _validated_policy_entries(inventory_api, policy_path)
        _capture_package_files(
            resolved_root,
            policy_path,
            source_name,
            file_api=file_api,
            files=files,
        )
        owner = _new_bound_owner(
            package_owner=package_owner,
            policy_owner=policy_owner,
            files=files,
            package_entries=package_entries,
            policy_entries=policy_entries,
            inventory_api=inventory_api,
            source_name=source_name,
            environment_present=environment_present,
        )
        first = owner.capture()
        second = owner.capture()
        if first != second:
            _fail(PackageInputErrorCode.INPUTS_CHANGED)
        directories.clear()
        files.clear()
        return owner
    except BaseException as error:
        if isinstance(error, PackageInputError) or not isinstance(error, Exception):
            primary = error
        elif isinstance(error, WindowsSecurityError):
            primary = PackageInputError(PackageInputErrorCode.PACKAGE_INVALID)
        else:
            primary = PackageInputError(PackageInputErrorCode.VERIFICATION_UNAVAILABLE)

    if owner is not None:
        try:
            owner.close()
        except BaseException as error:
            if primary is None or isinstance(primary, Exception):
                primary = error
        incomplete = not owner.closed
    else:
        interruption, incomplete = _close_partial(files, directories)
        if interruption is not None and (
            primary is None or isinstance(primary, Exception)
        ):
            primary = interruption
    if primary is not None and not isinstance(primary, Exception):
        raise primary from None
    if incomplete:
        raise PackageInputError(PackageInputErrorCode.INPUTS_CHANGED) from None
    if isinstance(primary, PackageInputError):
        raise primary from None
    raise PackageInputError(PackageInputErrorCode.VERIFICATION_UNAVAILABLE) from None


def capture_native_windows_package_environment_inputs(
    package_root: PureWindowsPath,
) -> BoundPackageEnvironmentInputs:
    """Capture package inputs through fixed native Windows trust providers."""

    from .windows_path_trust import NativeWindowsPathTrustApi
    from .windows_security import NativeWindowsFileApi

    return _capture_package_environment_inputs(
        package_root,
        path_api=NativeWindowsPathTrustApi(),
        file_api=NativeWindowsFileApi(),
        inventory_api=NativeRuntimeLoadInventoryApi(),
    )


__all__ = [
    "BoundPackageEnvironmentInputs",
    "PackageEnvironmentInputs",
    "PackageInputError",
    "PackageInputErrorCode",
    "capture_native_windows_package_environment_inputs",
]
