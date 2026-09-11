"""Pure verification for the TowerScout-managed Podman Compose provider.

This source-only boundary authenticates the package provider catalog and the
exact pinned wheel bytes before reconstructing their allowed installed
``site-packages`` inventory.  It accepts only a complete observation of that
inventory and emits redacted evidence for a later handle-owning native source
adapter.  It does not discover Python, read ambient package metadata, execute a
provider, install files, access the network, or mutate launcher state.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import struct
import unicodedata
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, NoReturn, Sequence
from urllib.parse import urlsplit

from .runtime_policy import (
    CatalogAuthentication,
    DistributionPolicy,
    InvocationKind,
    PodmanComposePolicy,
    ProviderKind,
    RuntimePolicy,
    RuntimePolicyError,
    RuntimeProductId,
    load_package_bound_runtime_policy,
)

_MAX_CATALOG_BYTES = 1024 * 1024
_MAX_WHEEL_BYTES = 32 * 1024 * 1024
_MAX_WHEEL_FILES = 4096
_MAX_WHEEL_FILE_BYTES = 32 * 1024 * 1024
_MAX_WHEEL_EXPANDED_BYTES = 128 * 1024 * 1024
_MAX_INSTALLED_FILES = 8192
_MAX_RELATIVE_PATH_CHARACTERS = 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_SHA256 = re.compile(r"^sha256=([A-Za-z0-9_-]{43})$")
_DISTRIBUTION_SEPARATOR = re.compile(r"[-_.]+")
_WINDOWS_RESERVED = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE
)
_INVENTORY_DOMAIN = b"TowerScout.ManagedPodmanProviderInventory.v1"


class ManagedPodmanProviderErrorCode(str, Enum):
    POLICY_UNAVAILABLE = "policy_unavailable"
    CATALOG_INVALID = "catalog_invalid"
    WHEEL_INVALID = "wheel_invalid"
    INVENTORY_INVALID = "inventory_invalid"


class ManagedPodmanProviderError(RuntimeError):
    """Sanitized managed-provider source verification failure."""

    _MESSAGES = {
        ManagedPodmanProviderErrorCode.POLICY_UNAVAILABLE: (
            "The managed Podman Compose provider policy is unavailable."
        ),
        ManagedPodmanProviderErrorCode.CATALOG_INVALID: (
            "The managed Podman Compose provider catalog is invalid."
        ),
        ManagedPodmanProviderErrorCode.WHEEL_INVALID: (
            "A managed Podman Compose provider wheel is invalid."
        ),
        ManagedPodmanProviderErrorCode.INVENTORY_INVALID: (
            "The managed Podman Compose provider inventory is invalid."
        ),
    }

    def __init__(self, code: ManagedPodmanProviderErrorCode) -> None:
        if type(code) is not ManagedPodmanProviderErrorCode:
            raise ValueError("Unknown managed-provider error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"ManagedPodmanProviderError(code={self.code.value!r})"


def _fail(code: ManagedPodmanProviderErrorCode) -> NoReturn:
    raise ManagedPodmanProviderError(code)


def _is_sha256(value: object) -> bool:
    return type(value) is str and bool(_SHA256.fullmatch(value))


def _safe_wheel_filename(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 255
        and PurePosixPath(value).name == value
        and PureWindowsPath(value).name == value
        and value.casefold().endswith(".whl")
        and "\x00" not in value
    )


def _safe_windows_relative_path(value: object) -> bool:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_RELATIVE_PATH_CHARACTERS
        or "\x00" in value
        or "/" in value
        or value != unicodedata.normalize("NFC", value)
    ):
        return False
    path = PureWindowsPath(value)
    return bool(
        not path.is_absolute()
        and path.drive == ""
        and path.root == ""
        and path.parts
        and all(
            part not in {"", ".", ".."}
            and not part.endswith((".", " "))
            and not any(character in part for character in '<>:"|?*')
            and not _WINDOWS_RESERVED.fullmatch(part)
            for part in path.parts
        )
    )


@dataclass(frozen=True, slots=True, repr=False)
class ProviderWheel:
    filename: str
    contents: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _safe_wheel_filename(self.filename)
            or type(self.contents) is not bytes
            or not 1 <= len(self.contents) <= _MAX_WHEEL_BYTES
        ):
            raise ValueError("Provider wheel input is invalid.")

    def __repr__(self) -> str:
        return f"ProviderWheel(filename={self.filename!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class InstalledProviderFile:
    relative_path: str = field(repr=False)
    sha256: str = field(repr=False)
    size_bytes: int

    def __post_init__(self) -> None:
        path = PureWindowsPath(self.relative_path)
        if (
            not _safe_windows_relative_path(self.relative_path)
            or tuple(part.casefold() for part in path.parts[:3])
            != (".venv", "lib", "site-packages")
            or len(path.parts) < 4
            or not _is_sha256(self.sha256)
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= _MAX_WHEEL_FILE_BYTES
        ):
            raise ValueError("Installed provider file observation is invalid.")

    def __repr__(self) -> str:
        return f"InstalledProviderFile(size_bytes={self.size_bytes}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManagedPodmanProviderInventoryEvidence:
    provider_id: str
    provider_version: str
    policy_sha256: str = field(repr=False)
    catalog_sha256: str = field(repr=False)
    wheel_sha256s: tuple[str, ...] = field(repr=False)
    distribution_count: int
    installed_file_count: int
    loadable_artifacts: tuple[InstalledProviderFile, ...] = field(repr=False)
    inventory_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.provider_id) is not str
            or not self.provider_id
            or type(self.provider_version) is not str
            or not self.provider_version
            or not _is_sha256(self.policy_sha256)
            or not _is_sha256(self.catalog_sha256)
            or type(self.wheel_sha256s) is not tuple
            or not self.wheel_sha256s
            or any(not _is_sha256(value) for value in self.wheel_sha256s)
            or type(self.distribution_count) is not int
            or self.distribution_count != len(self.wheel_sha256s)
            or type(self.installed_file_count) is not int
            or not 1 <= self.installed_file_count <= _MAX_INSTALLED_FILES
            or type(self.loadable_artifacts) is not tuple
            or not self.loadable_artifacts
            or any(
                type(artifact) is not InstalledProviderFile
                for artifact in self.loadable_artifacts
            )
            or len(self.loadable_artifacts) > self.installed_file_count
            or not _is_sha256(self.inventory_sha256)
        ):
            raise ValueError("Managed-provider inventory evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "ManagedPodmanProviderInventoryEvidence("
            f"provider_id={self.provider_id!r}, "
            f"distributions={self.distribution_count}, "
            f"installed_files={self.installed_file_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _ExpectedFile:
    observation: InstalledProviderFile = field(repr=False)
    distribution_name: str


class _DocumentFailure(Exception):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in output:
            raise _DocumentFailure
        output[key] = value
    return output


def _load_catalog(contents: bytes) -> dict[str, Any]:
    if type(contents) is not bytes or not 1 <= len(contents) <= _MAX_CATALOG_BYTES:
        _fail(ManagedPodmanProviderErrorCode.CATALOG_INVALID)
    try:
        text = contents.decode("utf-8", errors="strict")
        if (
            text.startswith("\ufeff")
            or "\x00" in text
            or any(
                ord(character) < 0x20 and character not in {"\t", "\r", "\n"}
                for character in text
            )
        ):
            raise _DocumentFailure
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(_DocumentFailure()),
        )
    except (UnicodeError, json.JSONDecodeError, _DocumentFailure, RecursionError):
        _fail(ManagedPodmanProviderErrorCode.CATALOG_INVALID)
    if type(document) is not dict:
        _fail(ManagedPodmanProviderErrorCode.CATALOG_INVALID)
    return document


def _catalog_sha256(contents: object) -> str:
    if type(contents) is not bytes or not 1 <= len(contents) <= _MAX_CATALOG_BYTES:
        _fail(ManagedPodmanProviderErrorCode.CATALOG_INVALID)
    return hashlib.sha256(contents).hexdigest()


def _policy() -> tuple[RuntimePolicy, PodmanComposePolicy]:
    try:
        runtime_policy = load_package_bound_runtime_policy()
        provider = runtime_policy.podman_compose
    except (RuntimePolicyError, OSError, RuntimeError, TypeError, ValueError):
        _fail(ManagedPodmanProviderErrorCode.POLICY_UNAVAILABLE)
    verification = provider.verification
    inventory = provider.inventory
    interpreter = provider.interpreter
    if (
        provider.kind is not ProviderKind.TOWERSCOUT_MANAGED
        or provider.catalog.authentication
        is not CatalogAuthentication.RUNTIME_POLICY_EXACT_BYTES
        or provider.invocation.kind is not InvocationKind.PYTHON_ISOLATED_MODULE
        or provider.invocation.arguments != ("-I", "-B", "-m", "podman_compose")
        or provider.interpreter.base_product_id is not RuntimeProductId.CPYTHON
        or provider.allow_external
        or provider.allow_docker_desktop
        or provider.allow_command_wrapper
        or provider.allow_podman_compose_delegation
        or not all(
            (
                verification.require_hash_verified_installer_inputs,
                verification.require_fresh_reconstruction_comparison,
                verification.require_exact_distribution_inventory,
                verification.require_record_hashes,
                verification.require_module_hash,
                verification.require_generated_entrypoint_hash,
                verification.require_stable_file_identity,
                not verification.receipt_is_trust_anchor,
                inventory.require_exact_authenticated_install_tree,
                inventory.reject_unowned_loadable_files,
                inventory.reject_extra_distributions,
                inventory.reject_pth_files,
                inventory.reject_sitecustomize,
                inventory.reject_usercustomize,
                interpreter.require_same_authenticode_signer,
                interpreter.require_same_pe_product_version,
                interpreter.require_file_hash,
                interpreter.require_stable_file_identity,
                interpreter.require_authenticated_base_runtime_closure,
                interpreter.require_venv_config_base_path_match,
            )
        )
        or len(provider.distributions) != 3
    ):
        _fail(ManagedPodmanProviderErrorCode.POLICY_UNAVAILABLE)
    return runtime_policy, provider


def _require_dict(
    value: object, code: ManagedPodmanProviderErrorCode
) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(code)
    return value


def _require_list(value: object, code: ManagedPodmanProviderErrorCode) -> list[Any]:
    if type(value) is not list:
        _fail(code)
    return value


def _catalog_matches_policy(
    catalog: dict[str, Any], provider: PodmanComposePolicy
) -> None:
    code = ManagedPodmanProviderErrorCode.CATALOG_INVALID
    if (
        catalog.get("schema_version") != 1
        or type(catalog.get("schema_version")) is not int
    ):
        _fail(code)
    providers = _require_list(catalog.get("providers"), code)
    provider_ids: list[str] = []
    selected: list[dict[str, Any]] = []
    for candidate in providers:
        item = _require_dict(candidate, code)
        provider_id = item.get("id")
        if type(provider_id) is not str or not provider_id:
            _fail(code)
        provider_ids.append(provider_id.casefold())
        if provider_id == provider.provider_id:
            selected.append(item)
    if len(provider_ids) != len(set(provider_ids)) or len(selected) != 1:
        _fail(code)
    item = selected[0]
    primary = provider.distributions[0]
    parsed = urlsplit(primary.source_url)
    if (
        item.get("version") != provider.exact_version
        or item.get("source_url") != primary.source_url
        or item.get("package_sha256") != primary.wheel_sha256
        or PurePosixPath(parsed.path).name != primary.wheel_filename
    ):
        _fail(code)
    dependencies = _require_list(item.get("dependencies"), code)
    names: list[str] = []
    for dependency in dependencies:
        dependency_item = _require_dict(dependency, code)
        name = dependency_item.get("name")
        version = dependency_item.get("version")
        if type(name) is not str or type(version) is not str:
            _fail(code)
        names.append(_normalized_distribution(name))
    expected_dependencies = provider.distributions[1:]
    if len(names) != len(set(names)) or set(names) != {
        _normalized_distribution(value.name) for value in expected_dependencies
    }:
        _fail(code)
    for expected in expected_dependencies:
        matches = [
            _require_dict(candidate, code)
            for candidate in dependencies
            if _normalized_distribution(
                str(_require_dict(candidate, code).get("name", ""))
            )
            == _normalized_distribution(expected.name)
        ]
        if len(matches) != 1 or matches[0].get("version") != expected.version:
            _fail(code)
        artifacts = _require_list(matches[0].get("artifacts"), code)
        artifact_keys: set[tuple[object, object, object]] = set()
        expected_count = 0
        for artifact in artifacts:
            artifact_item = _require_dict(artifact, code)
            key = (
                artifact_item.get("filename"),
                artifact_item.get("source_url"),
                artifact_item.get("sha256"),
            )
            if key in artifact_keys:
                _fail(code)
            artifact_keys.add(key)
            if key == (
                expected.wheel_filename,
                expected.source_url,
                expected.wheel_sha256,
            ):
                expected_count += 1
        if expected_count != 1:
            _fail(code)


def _normalized_distribution(value: str) -> str:
    return _DISTRIBUTION_SEPARATOR.sub("-", value).casefold()


def _safe_archive_path(value: object) -> bool:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_RELATIVE_PATH_CHARACTERS
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
        or value.endswith("/")
        or value != unicodedata.normalize("NFC", value)
    ):
        return False
    path = PurePosixPath(value)
    return bool(
        not path.is_absolute()
        and path.parts
        and all(
            part not in {"", ".", ".."}
            and not part.endswith((".", " "))
            and not any(character in part for character in '<>:"|?*')
            and not _WINDOWS_RESERVED.fullmatch(part)
            for part in path.parts
        )
    )


def _record_digest(value: str) -> bytes:
    match = _RECORD_SHA256.fullmatch(value)
    if match is None:
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    try:
        digest = base64.urlsafe_b64decode(match.group(1) + "=")
    except (ValueError, TypeError):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    if len(digest) != 32:
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    return digest


def _metadata_identity(contents: bytes) -> tuple[str, str]:
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    names = [
        line[6:].strip() for line in text.splitlines() if line.startswith("Name: ")
    ]
    versions = [
        line[9:].strip() for line in text.splitlines() if line.startswith("Version: ")
    ]
    if len(names) != 1 or len(versions) != 1 or not names[0] or not versions[0]:
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    return names[0], versions[0]


def _parse_record(contents: bytes) -> dict[str, tuple[str, str]]:
    try:
        text = contents.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            raise ValueError
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeError, csv.Error, ValueError):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    output: dict[str, tuple[str, str]] = {}
    folded: set[str] = set()
    for row in rows:
        if len(row) != 3 or not _safe_archive_path(row[0]):
            _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        key = row[0].casefold()
        if key in folded:
            _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        folded.add(key)
        output[row[0]] = (row[1], row[2])
    return output


def _installed_relative(member: str) -> str:
    parts = PurePosixPath(member).parts
    data_indices = tuple(
        index for index, part in enumerate(parts) if part.casefold().endswith(".data")
    )
    if data_indices:
        if len(data_indices) != 1 or data_indices[0] != 0:
            _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        data_index = data_indices[0]
        if data_index + 2 > len(parts) or parts[data_index + 1].casefold() not in {
            "purelib",
            "platlib",
        }:
            _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        parts = parts[data_index + 2 :]
    if not parts:
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    return str(PureWindowsPath(".venv", "Lib", "site-packages", *parts))


def _wheel_inventory(
    wheel: ProviderWheel, distribution: DistributionPolicy
) -> tuple[_ExpectedFile, ...]:
    if (
        wheel.filename != distribution.wheel_filename
        or hashlib.sha256(wheel.contents).hexdigest() != distribution.wheel_sha256
    ):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    try:
        with zipfile.ZipFile(io.BytesIO(wheel.contents), "r") as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= _MAX_WHEEL_FILES:
                _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
            members: dict[str, bytes] = {}
            folded: set[str] = set()
            expanded = 0
            for info in infos:
                if (
                    info.is_dir()
                    or not _safe_archive_path(info.filename)
                    or info.flag_bits & 0x1
                    or info.compress_type
                    not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or info.file_size > _MAX_WHEEL_FILE_BYTES
                    or (info.external_attr >> 16) & 0xF000 == 0xA000
                ):
                    _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
                key = info.filename.casefold()
                if key in folded:
                    _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
                folded.add(key)
                expanded += info.file_size
                if expanded > _MAX_WHEEL_EXPANDED_BYTES:
                    _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
                contents = archive.read(info)
                if len(contents) != info.file_size:
                    _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
                members[info.filename] = contents
    except ManagedPodmanProviderError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)

    record_paths = [
        path for path in members if path.casefold().endswith(".dist-info/record")
    ]
    metadata_paths = [
        path for path in members if path.casefold().endswith(".dist-info/metadata")
    ]
    if len(record_paths) != 1 or len(metadata_paths) != 1:
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    metadata_name, metadata_version = _metadata_identity(members[metadata_paths[0]])
    if (
        _normalized_distribution(metadata_name)
        != _normalized_distribution(distribution.name)
        or metadata_version != distribution.version
    ):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
    record_path = record_paths[0]
    record = _parse_record(members[record_path])
    if set(record) != set(members):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)

    output: list[_ExpectedFile] = []
    seen_installed: set[str] = set()
    for member, contents in members.items():
        encoded_hash, encoded_size = record[member]
        if member == record_path:
            if encoded_hash or encoded_size:
                _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        else:
            if (
                _record_digest(encoded_hash) != hashlib.sha256(contents).digest()
                or not encoded_size.isascii()
                or not encoded_size.isdecimal()
                or int(encoded_size) != len(contents)
            ):
                _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        relative = _installed_relative(member)
        key = relative.casefold()
        installed_path = PureWindowsPath(relative)
        suffix = installed_path.suffix.casefold()
        top_level = installed_path.parts[3].casefold()
        if (
            key in seen_installed
            or suffix in {".pth", ".pyc"}
            or top_level in {"sitecustomize", "usercustomize"}
            or top_level.startswith(("sitecustomize.", "usercustomize."))
        ):
            _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)
        seen_installed.add(key)
        output.append(
            _ExpectedFile(
                InstalledProviderFile(
                    relative_path=relative,
                    sha256=hashlib.sha256(contents).hexdigest(),
                    size_bytes=len(contents),
                ),
                distribution.name,
            )
        )
    return tuple(output)


def _digest_inventory(
    policy_sha256: str,
    catalog_sha256: str,
    wheel_sha256s: tuple[str, ...],
    expected: Sequence[_ExpectedFile],
) -> str:
    digest = hashlib.sha256()
    values = (
        _INVENTORY_DOMAIN,
        policy_sha256.encode("ascii"),
        catalog_sha256.encode("ascii"),
        *(value.encode("ascii") for value in wheel_sha256s),
        *(
            value
            for expected_file in expected
            for value in (
                expected_file.distribution_name.encode("utf-8", errors="strict"),
                expected_file.observation.relative_path.encode(
                    "utf-16-le", errors="strict"
                ),
                expected_file.observation.sha256.encode("ascii"),
                expected_file.observation.size_bytes.to_bytes(8, "big"),
            )
        ),
    )
    for value in values:
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def verify_managed_podman_compose_source_inventory(
    *,
    catalog_bytes: bytes,
    wheels: tuple[ProviderWheel, ...],
    installed_files: tuple[InstalledProviderFile, ...],
) -> ManagedPodmanProviderInventoryEvidence:
    """Verify exact package-bound inputs without using ambient Python metadata."""

    runtime_policy, provider = _policy()
    catalog_sha256 = _catalog_sha256(catalog_bytes)
    if catalog_sha256 != provider.catalog.content_sha256:
        _fail(ManagedPodmanProviderErrorCode.CATALOG_INVALID)
    catalog = _load_catalog(catalog_bytes)
    _catalog_matches_policy(catalog, provider)
    if (
        type(wheels) is not tuple
        or len(wheels) != len(provider.distributions)
        or any(type(wheel) is not ProviderWheel for wheel in wheels)
        or type(installed_files) is not tuple
        or not 1 <= len(installed_files) <= _MAX_INSTALLED_FILES
        or any(
            type(installed_file) is not InstalledProviderFile
            for installed_file in installed_files
        )
    ):
        _fail(ManagedPodmanProviderErrorCode.INVENTORY_INVALID)

    expected: list[_ExpectedFile] = []
    for wheel, distribution in zip(wheels, provider.distributions, strict=True):
        expected.extend(_wheel_inventory(wheel, distribution))
    expected.sort(key=lambda item: item.observation.relative_path.casefold())
    expected_keys = [item.observation.relative_path.casefold() for item in expected]
    if len(expected_keys) != len(set(expected_keys)):
        _fail(ManagedPodmanProviderErrorCode.WHEEL_INVALID)

    observed: dict[str, InstalledProviderFile] = {}
    for installed in installed_files:
        key = installed.relative_path.casefold()
        if key in observed:
            _fail(ManagedPodmanProviderErrorCode.INVENTORY_INVALID)
        observed[key] = installed
    if set(observed) != set(expected_keys):
        _fail(ManagedPodmanProviderErrorCode.INVENTORY_INVALID)
    for expected_file in expected:
        expected_observation = expected_file.observation
        actual = observed[expected_observation.relative_path.casefold()]
        if (
            actual.sha256 != expected_observation.sha256
            or actual.size_bytes != expected_observation.size_bytes
        ):
            _fail(ManagedPodmanProviderErrorCode.INVENTORY_INVALID)

    module_path = provider.inventory.module_relative_path.casefold()
    loadable_suffixes = {".py", ".pyd", ".dll"}
    loadable = tuple(
        item.observation
        for item in expected
        if PureWindowsPath(item.observation.relative_path).suffix.casefold()
        in loadable_suffixes
    )
    if (
        module_path not in expected_keys
        or not loadable
        or any(
            PureWindowsPath(item.relative_path).suffix.casefold()
            not in provider.inventory.loadable_suffixes
            for item in loadable
        )
    ):
        _fail(ManagedPodmanProviderErrorCode.INVENTORY_INVALID)

    wheel_sha256s = tuple(
        hashlib.sha256(wheel.contents).hexdigest() for wheel in wheels
    )
    inventory_sha256 = _digest_inventory(
        runtime_policy.content_sha256,
        catalog_sha256,
        wheel_sha256s,
        expected,
    )
    return ManagedPodmanProviderInventoryEvidence(
        provider_id=provider.provider_id,
        provider_version=provider.exact_version,
        policy_sha256=runtime_policy.content_sha256,
        catalog_sha256=catalog_sha256,
        wheel_sha256s=wheel_sha256s,
        distribution_count=len(provider.distributions),
        installed_file_count=len(expected),
        loadable_artifacts=loadable,
        inventory_sha256=inventory_sha256,
    )


__all__ = [
    "InstalledProviderFile",
    "ManagedPodmanProviderError",
    "ManagedPodmanProviderErrorCode",
    "ManagedPodmanProviderInventoryEvidence",
    "ProviderWheel",
    "verify_managed_podman_compose_source_inventory",
]
