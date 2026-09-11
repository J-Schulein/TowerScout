"""Retained native source inputs for the managed Podman Compose target.

This source-only boundary authenticates the package-managed provider layout,
its virtual-environment interpreter, and the separately installed base CPython
runtime before joining them to the retained rootless Podman endpoint owner. It
does not execute Compose, resolve a container target, or mutate package state.
"""

from __future__ import annotations

import hashlib
import ntpath
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, Sequence, TypeVar, cast

from .authenticode import (
    AuthenticodeBackend,
    AuthenticodeVerificationError,
    VerificationClock,
    verify_package_bound_authenticode_signer,
)
from .runtime_dependency_capture import (
    CpythonDependencyCaptureError,
    HeldCpythonDependencyInventory,
    capture_package_bound_cpython_dependency_inventory,
)
from .runtime_identity import (
    _BoundFileTransferSlot,
    InstallationRecordBackend,
    PeProductBackend,
    RuntimeIdentityVerificationError,
    verify_package_bound_pe_product,
)
from .runtime_load_trust import (
    DirectoryEntry,
    NativeRuntimeLoadInventoryApi,
)
from .runtime_podman_endpoint import (
    BoundPodmanRuntimeEndpointInputs,
    PodmanEndpointError,
    capture_native_windows_podman_runtime_endpoint_inputs,
)
from .runtime_podman_provider import (
    InstalledProviderFile,
    ManagedPodmanProviderError,
    ManagedPodmanProviderInventoryEvidence,
    ProviderWheel,
    verify_managed_podman_compose_source_inventory,
)
from .runtime_policy import (
    RuntimePolicyError,
    RuntimeProductId,
    load_package_bound_runtime_policy,
)
from .runtime_verification import (
    BoundRuntimeEvidence,
    CombinedRuntimeEvidence,
    RuntimeVerificationError,
    open_package_bound_runtime_evidence,
)
from .target_contracts import (
    ComposeInvocationKind,
    ComposeProviderIdentity,
    EndpointBindingKind,
    EndpointIdentity,
    FileIdentity,
    RuntimeIdentity,
    RuntimeProduct,
)
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import (
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    RandomAccessFileReader,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_CATALOG_RELATIVE_PATH = PureWindowsPath(r"scripts\podman-compose-providers.v1.json")
_MAX_CATALOG_BYTES = 1024 * 1024
_MAX_WHEEL_BYTES = 32 * 1024 * 1024
_MAX_PROVIDER_FILE_BYTES = 32 * 1024 * 1024
_MAX_VENV_CONFIG_BYTES = 64 * 1024
_MAX_DIRECTORY_COUNT = 4096
_MAX_INSTALLED_FILES = 8192
_INTEGRITY_DOMAIN = b"TowerScout.ManagedPodmanProviderSource.v1"
_DIRECTORY_DOMAIN = b"TowerScout.ManagedPodmanProviderDirectories.v1"
_DENIED_SCRIPT_SUFFIXES = frozenset(
    {".dll", ".pyd", ".pth", "._pth", ".zip", ".py", ".pyc", ".pyo", ".pyw"}
)
_Result = TypeVar("_Result")


class PodmanInputErrorCode(str, Enum):
    PROVIDER_INVALID = "provider_invalid"
    INPUTS_CHANGED = "inputs_changed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class PodmanInputError(RuntimeError):
    """Sanitized failure from retained managed-Podman input capture."""

    _MESSAGES = {
        PodmanInputErrorCode.PROVIDER_INVALID: (
            "The TowerScout-managed Podman Compose provider is invalid."
        ),
        PodmanInputErrorCode.INPUTS_CHANGED: (
            "The authenticated Podman target inputs changed during verification."
        ),
        PodmanInputErrorCode.VERIFICATION_UNAVAILABLE: (
            "Managed Podman target input verification is unavailable."
        ),
    }

    def __init__(self, code: PodmanInputErrorCode) -> None:
        if type(code) is not PodmanInputErrorCode:
            raise ValueError("Unknown Podman target input error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"PodmanInputError(code={self.code.value!r})"


def _fail(code: PodmanInputErrorCode) -> NoReturn:
    raise PodmanInputError(code)


class _ProviderDirectoryApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]: ...


@dataclass(frozen=True, slots=True, repr=False)
class _HeldDirectoryInventory:
    path: PureWindowsPath = field(repr=False)
    entries: tuple[DirectoryEntry, ...] = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _HeldProviderFile:
    logical_name: str
    bound_file: HandleBoundFile = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class PodmanTargetSourceInputs:
    """Exact Podman fields emitted by the retained native source owners."""

    runtime: RuntimeIdentity = field(repr=False)
    endpoint: EndpointIdentity = field(repr=False)
    compose_provider: ComposeProviderIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.runtime) is not RuntimeIdentity
            or self.runtime.product is not RuntimeProduct.PODMAN
            or type(self.endpoint) is not EndpointIdentity
            or self.endpoint.product is not RuntimeProduct.PODMAN
            or type(self.compose_provider) is not ComposeProviderIdentity
            or self.compose_provider.invocation_kind
            is not ComposeInvocationKind.PODMAN_PYTHON_MODULE
            or self.compose_provider.endpoint_binding
            is not EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT
        ):
            raise ValueError("Podman target source inputs are invalid.")

    def __repr__(self) -> str:
        return "PodmanTargetSourceInputs(<redacted>)"


def _add(digest: Any, value: bytes) -> None:
    if type(value) is not bytes or len(value) > _MAX_WHEEL_BYTES:
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _canonical_path(path: PureWindowsPath | str) -> str:
    value = str(path).replace("/", "\\")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    normalized = ntpath.normpath(value)
    if not PureWindowsPath(normalized).is_absolute() or "\x00" in normalized:
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    return ntpath.normcase(normalized)


def _child(root: PureWindowsPath, relative: str) -> PureWindowsPath:
    try:
        candidate = root.joinpath(*PureWindowsPath(relative).parts)
        common = ntpath.commonpath((_canonical_path(root), _canonical_path(candidate)))
    except (TypeError, ValueError, UnicodeError):
        raise PodmanInputError(PodmanInputErrorCode.PROVIDER_INVALID) from None
    if common != _canonical_path(root):
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    return candidate


def _safe_entries(
    api: _ProviderDirectoryApi, path: PureWindowsPath
) -> tuple[DirectoryEntry, ...]:
    try:
        entries = api.list_directory(str(path))
    except (OSError, RuntimeError, TypeError, ValueError):
        raise PodmanInputError(PodmanInputErrorCode.PROVIDER_INVALID) from None
    if (
        type(entries) is not tuple
        or len(entries) > _MAX_INSTALLED_FILES
        or any(type(entry) is not DirectoryEntry for entry in entries)
        or any(entry.reparse_tag for entry in entries)
    ):
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    folded = tuple(entry.name.casefold() for entry in entries)
    if len(folded) != len(set(folded)):
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    return tuple(sorted(entries, key=lambda item: (item.name.casefold(), item.name)))


def _read_all(
    bound_file: HandleBoundFile,
    *,
    maximum: int,
) -> bytes:
    def read(reader: RandomAccessFileReader, _snapshot: FileSnapshot) -> bytes:
        if not 0 <= reader.size <= maximum:
            _fail(PodmanInputErrorCode.PROVIDER_INVALID)
        offset = 0
        chunks: list[bytes] = []
        while offset < reader.size:
            amount = min(64 * 1024, reader.size - offset)
            chunk = reader.read_at(offset, amount)
            if type(chunk) is not bytes or len(chunk) != amount:
                _fail(PodmanInputErrorCode.PROVIDER_INVALID)
            chunks.append(chunk)
            offset += amount
        return b"".join(chunks)

    return bound_file.inspect_same_handle_random_access(read)


def _file_identity(item: _HeldProviderFile) -> FileIdentity:
    snapshot = item.bound_file.snapshot
    return FileIdentity(
        logical_name=item.logical_name,
        final_path=PureWindowsPath(snapshot.final_path),
        volume_serial=snapshot.identity.volume_serial,
        file_id=snapshot.identity.file_id,
        sha256=snapshot.sha256,
        size_bytes=snapshot.size,
    )


def _directory_digest(inventories: Sequence[_HeldDirectoryInventory]) -> str:
    digest = hashlib.sha256()
    _add(digest, _DIRECTORY_DOMAIN)
    for inventory in inventories:
        _add(digest, _canonical_path(inventory.path).encode("utf-16-le"))
        for entry in inventory.entries:
            _add(digest, entry.name.encode("utf-8", errors="strict"))
            _add(digest, b"directory" if entry.is_directory else b"file")
            _add(digest, entry.attributes.to_bytes(4, "big"))
            _add(digest, entry.reparse_tag.to_bytes(4, "big"))
    return digest.hexdigest()


def _provider_integrity(
    *,
    inventory: ManagedPodmanProviderInventoryEvidence,
    base: CombinedRuntimeEvidence,
    base_inventory_sha256: str,
    venv_pe_sha256: str,
    venv_authenticode_sha256: str,
    directory_sha256: str,
    artifacts: tuple[FileIdentity, ...],
) -> str:
    digest = hashlib.sha256()
    for value in (
        _INTEGRITY_DOMAIN,
        inventory.inventory_sha256.encode("ascii"),
        base.evidence_sha256.encode("ascii"),
        base_inventory_sha256.encode("ascii"),
        venv_pe_sha256.encode("ascii"),
        venv_authenticode_sha256.encode("ascii"),
        directory_sha256.encode("ascii"),
        *(
            field
            for artifact in artifacts
            for field in (
                artifact.logical_name.encode("utf-8", errors="strict"),
                artifact.volume_serial.to_bytes(8, "big"),
                artifact.file_id,
                artifact.sha256.encode("ascii"),
                artifact.size_bytes.to_bytes(8, "big"),
                artifact.canonical_path_sha256.encode("ascii"),
            )
        ),
    ):
        _add(digest, value)
    return digest.hexdigest()


def _parse_venv_config(
    contents: bytes,
    *,
    base_executable: PureWindowsPath,
    expected_version: str,
) -> None:
    if not 1 <= len(contents) <= _MAX_VENV_CONFIG_BYTES:
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeError:
        raise PodmanInputError(PodmanInputErrorCode.PROVIDER_INVALID) from None
    if (
        text.startswith("\ufeff")
        or "\x00" in text
        or any(character in text for character in ("\x85", "\u2028", "\u2029"))
    ):
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    values: dict[str, str] = {}
    for line in normalized.split("\n"):
        if not line:
            continue
        name, separator, value = line.partition("=")
        key = name.strip().casefold()
        candidate = value.strip()
        if separator != "=" or not key or key in values or not candidate:
            _fail(PodmanInputErrorCode.PROVIDER_INVALID)
        values[key] = candidate
    required = {"home", "include-system-site-packages", "version", "executable"}
    if not required.issubset(values):
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    if (
        values["include-system-site-packages"].casefold() != "false"
        or values["version"] != expected_version
        or _canonical_path(values["home"]) != _canonical_path(base_executable.parent)
        or _canonical_path(values["executable"]) != _canonical_path(base_executable)
    ):
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)


def _run_nested(
    operations: Sequence[Callable[[Callable[[], _Result]], _Result]],
    index: int,
    operation: Callable[[], _Result],
) -> _Result:
    if index == len(operations):
        return operation()
    return operations[index](lambda: _run_nested(operations, index + 1, operation))


class BoundManagedPodmanComposeProvider:
    """Retain every authenticated managed-provider source and base runtime."""

    __slots__ = (
        "_active_owner",
        "_base_executable",
        "_base_inventory",
        "_directories",
        "_directory_api",
        "_directory_inventories",
        "_files",
        "_identity",
        "_lifetime_lock",
    )

    def __init__(
        self,
        *,
        directories: tuple[PathHierarchyTrust, ...],
        directory_inventories: tuple[_HeldDirectoryInventory, ...],
        directory_api: _ProviderDirectoryApi,
        files: tuple[_HeldProviderFile, ...],
        base_executable: HandleBoundFile,
        base_inventory: HeldCpythonDependencyInventory,
        identity: ComposeProviderIdentity,
    ) -> None:
        if (
            type(directories) is not tuple
            or not directories
            or any(
                type(item) is not PathHierarchyTrust or item.closed
                for item in directories
            )
            or type(directory_inventories) is not tuple
            or not directory_inventories
            or len(directory_inventories) > len(directories)
            or type(files) is not tuple
            or len(files) != len(identity.artifacts)
            or any(
                type(item) is not _HeldProviderFile or item.bound_file.closed
                for item in files
            )
            or type(base_executable) is not HandleBoundFile
            or base_executable.closed
            or type(base_inventory) is not HeldCpythonDependencyInventory
            or base_inventory.closed
            or type(identity) is not ComposeProviderIdentity
            or tuple(_file_identity(item) for item in files) != identity.artifacts
        ):
            raise ValueError("Bound managed Podman provider is invalid.")
        try:
            supported = directory_api.supported is True
        except Exception:
            supported = False
        if not supported:
            raise ValueError("Bound managed Podman provider is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._directories: tuple[PathHierarchyTrust, ...] | None = directories
        self._directory_inventories = directory_inventories
        self._directory_api = directory_api
        self._files: tuple[_HeldProviderFile, ...] | None = files
        self._base_executable: HandleBoundFile | None = base_executable
        self._base_inventory: HeldCpythonDependencyInventory | None = base_inventory
        self._identity = identity

    @property
    def identity(self) -> ComposeProviderIdentity:
        return self._identity

    @property
    def supported(self) -> bool:
        with self._lifetime_lock:
            return not self.closed

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            directories = self._directories
            files = self._files
            base = self._base_executable
            inventory = self._base_inventory
            return bool(
                (directories is None or all(item.closed for item in directories))
                and (files is None or all(item.bound_file.closed for item in files))
                and (base is None or base.closed)
                and (inventory is None or inventory.closed)
            )

    def _assert_inventories(self) -> None:
        for inventory in self._directory_inventories:
            if _safe_entries(self._directory_api, inventory.path) != inventory.entries:
                _fail(PodmanInputErrorCode.INPUTS_CHANGED)

    def capture(self) -> ComposeProviderIdentity:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        directories = self._directories
        files = self._files
        base = self._base_executable
        inventory = self._base_inventory
        if (
            directories is None
            or files is None
            or base is None
            or inventory is None
            or any(item.closed for item in directories)
            or any(item.bound_file.closed for item in files)
            or base.closed
            or inventory.closed
        ):
            self._lifetime_lock.release()
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            operations: tuple[Callable[[Callable[[], Any]], Any], ...] = (
                *(item.run_while_held for item in directories),
                *(item.bound_file.run_while_held for item in files),
                inventory.run_while_held,
            )

            def validate() -> ComposeProviderIdentity:
                base.assert_unchanged_while_held()
                self._assert_inventories()
                if (
                    tuple(_file_identity(item) for item in files)
                    != self._identity.artifacts
                ):
                    _fail(PodmanInputErrorCode.INPUTS_CHANGED)
                return self._identity

            return cast(ComposeProviderIdentity, _run_nested(operations, 0, validate))
        except PodmanInputError:
            raise
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise PodmanInputError(PodmanInputErrorCode.INPUTS_CHANGED) from None
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(PodmanInputErrorCode.INPUTS_CHANGED)
            inventory = self._base_inventory
            base = self._base_executable
            files = self._files
            directories = self._directories
            interruption: BaseException | None = None
            failed = False
            closeables: tuple[Any, ...] = (
                *((inventory,) if inventory is not None else ()),
                *((base,) if base is not None else ()),
                *(item.bound_file for item in reversed(files or ())),
                *reversed(directories or ()),
            )
            for closeable in closeables:
                try:
                    closeable.close()
                except BaseException as error:
                    if not isinstance(error, Exception) and interruption is None:
                        interruption = error
                    else:
                        failed = True
            if inventory is None or inventory.closed:
                self._base_inventory = None
            if base is None or base.closed:
                self._base_executable = None
            if files is None or all(item.bound_file.closed for item in files):
                self._files = None
            if directories is None or all(item.closed for item in directories):
                self._directories = None
            if interruption is not None:
                raise interruption
            if failed or not self.closed:
                _fail(PodmanInputErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundManagedPodmanComposeProvider":
        if self.closed:
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundManagedPodmanComposeProvider(state={state!r}, <redacted>)"


def _capture_file(
    path: PureWindowsPath,
    *,
    maximum: int,
    file_api: WindowsFileApi | None,
) -> HandleBoundFile:
    bound = capture_handle_bound_file(
        Path(str(path)),
        api=file_api,
        policy=FileCapturePolicy(
            max_bytes=maximum,
            require_single_link=True,
            allow_hydrated_cloud_placeholder=True,
        ),
    )
    if _canonical_path(bound.snapshot.final_path) != _canonical_path(path):
        bound.close()
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    return bound


def _capture_site_packages(
    provider_root: PureWindowsPath,
    site_packages: PureWindowsPath,
    *,
    path_api: WindowsPathTrustApi | None,
    directory_api: _ProviderDirectoryApi,
    file_api: WindowsFileApi | None,
    directories: list[PathHierarchyTrust],
    inventories: list[_HeldDirectoryInventory],
    files: list[_HeldProviderFile],
) -> tuple[InstalledProviderFile, ...]:
    pending = [site_packages]
    installed: list[InstalledProviderFile] = []
    inventory_start = len(inventories)
    while pending:
        path = pending.pop(0)
        if len(inventories) >= _MAX_DIRECTORY_COUNT:
            _fail(PodmanInputErrorCode.PROVIDER_INVALID)
        trust = capture_path_hierarchy(
            str(path), purpose=PathTrustPurpose.RUNTIME_INSTALL, api=path_api
        )
        directories.append(trust)
        entries = _safe_entries(directory_api, path)
        inventories.append(_HeldDirectoryInventory(path, entries))
        for entry in entries:
            child = path / entry.name
            if entry.is_directory:
                pending.append(child)
                continue
            if len(installed) >= _MAX_INSTALLED_FILES:
                _fail(PodmanInputErrorCode.PROVIDER_INVALID)
            bound = _capture_file(
                child, maximum=_MAX_PROVIDER_FILE_BYTES, file_api=file_api
            )
            try:
                relative = str(child.relative_to(provider_root))
            except ValueError:
                bound.close()
                _fail(PodmanInputErrorCode.PROVIDER_INVALID)
            if _canonical_path(bound.snapshot.final_path) != _canonical_path(child):
                bound.close()
                _fail(PodmanInputErrorCode.PROVIDER_INVALID)
            held = _HeldProviderFile(
                f"podman_provider_file_{len(installed):04d}", bound
            )
            files.append(held)
            installed.append(
                InstalledProviderFile(
                    relative_path=relative,
                    sha256=bound.snapshot.sha256,
                    size_bytes=bound.snapshot.size,
                )
            )
    expected_directories = {_canonical_path(site_packages)}
    for item in installed:
        parent = _child(provider_root, item.relative_path).parent
        while _canonical_path(parent) != _canonical_path(site_packages):
            expected_directories.add(_canonical_path(parent))
            parent = parent.parent
        expected_directories.add(_canonical_path(site_packages))
    observed_directories = {
        _canonical_path(item.path) for item in inventories[inventory_start:]
    }
    if observed_directories != expected_directories:
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    ordered = tuple(sorted(installed, key=lambda item: item.relative_path.casefold()))
    return ordered


def _reorder_provider_files(
    files: list[_HeldProviderFile],
    *,
    module_path: PureWindowsPath,
    venv_python: _HeldProviderFile,
    entrypoint: _HeldProviderFile,
    venv_config: _HeldProviderFile,
    catalog: _HeldProviderFile,
    wheels: tuple[_HeldProviderFile, ...],
) -> tuple[_HeldProviderFile, ...]:
    module = tuple(
        item
        for item in files
        if _canonical_path(item.bound_file.snapshot.final_path)
        == _canonical_path(module_path)
    )
    if len(module) != 1:
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    module_item = _HeldProviderFile("podman_compose_module", module[0].bound_file)
    remainder = tuple(item for item in files if item is not module[0])
    return (
        venv_python,
        module_item,
        *remainder,
        entrypoint,
        venv_config,
        catalog,
        *wheels,
    )


def _retry_failed_capture_cleanup(
    closeables: Sequence[tuple[Callable[[], None], Callable[[], bool]]],
) -> tuple[BaseException | None, bool]:
    """Retry every partial owner and preserve the first cleanup interruption."""

    cleanup_interruption: BaseException | None = None
    incomplete = False
    for close, fully_closed in closeables:
        for _attempt in range(3):
            if fully_closed():
                break
            try:
                close()
            except BaseException as error:
                if not isinstance(error, Exception) and cleanup_interruption is None:
                    cleanup_interruption = error
        if not fully_closed():
            incomplete = True
    return cleanup_interruption, incomplete


def _closed_check(value: Any) -> Callable[[], bool]:
    def closed() -> bool:
        return bool(value.closed)

    return closed


def _capture_managed_podman_compose_provider(
    package_root: PureWindowsPath,
    *,
    path_api: WindowsPathTrustApi | None = None,
    file_api: WindowsFileApi | None = None,
    directory_api: _ProviderDirectoryApi | None = None,
    installation_backend: InstallationRecordBackend | None = None,
    pe_backend: PeProductBackend | None = None,
    authenticode_backend: AuthenticodeBackend | None = None,
    clock: VerificationClock | None = None,
) -> BoundManagedPodmanComposeProvider:
    """Internal injectable adapter; the public native factory supplies no seams."""

    if type(package_root) is not PureWindowsPath or not package_root.is_absolute():
        _fail(PodmanInputErrorCode.PROVIDER_INVALID)
    try:
        policy = load_package_bound_runtime_policy()
        provider = policy.podman_compose
    except (OSError, RuntimeError, RuntimePolicyError, TypeError, ValueError):
        raise PodmanInputError(PodmanInputErrorCode.VERIFICATION_UNAVAILABLE) from None
    selected_directory_api = directory_api or NativeRuntimeLoadInventoryApi()
    try:
        supported = selected_directory_api.supported is True
    except Exception:
        supported = False
    if not supported:
        _fail(PodmanInputErrorCode.VERIFICATION_UNAVAILABLE)

    provider_root = _child(package_root, provider.managed_install_root)
    wheelhouse = _child(provider_root, provider.inventory.wheelhouse_relative_path)
    site_packages = _child(
        provider_root, provider.inventory.site_packages_relative_path
    )
    scripts = _child(
        provider_root, str(PureWindowsPath(provider.interpreter.relative_path).parent)
    )
    venv_python_path = _child(provider_root, provider.interpreter.relative_path)
    module_path = _child(provider_root, provider.inventory.module_relative_path)
    entrypoint_path = _child(
        provider_root, provider.inventory.generated_entrypoint_relative_path
    )
    venv_config_path = _child(
        provider_root, provider.inventory.venv_config_relative_path
    )
    catalog_path = package_root / _CATALOG_RELATIVE_PATH

    directories: list[PathHierarchyTrust] = []
    inventories: list[_HeldDirectoryInventory] = []
    captured_files: list[_HeldProviderFile] = []
    base_owner: BoundRuntimeEvidence | None = None
    base_inventory: HeldCpythonDependencyInventory | None = None
    slot = _BoundFileTransferSlot()
    owner: BoundManagedPodmanComposeProvider | None = None
    try:
        for directory in (provider_root, wheelhouse, scripts, catalog_path.parent):
            directories.append(
                capture_path_hierarchy(
                    str(directory),
                    purpose=PathTrustPurpose.RUNTIME_INSTALL,
                    api=path_api,
                )
            )
            inventories.append(
                _HeldDirectoryInventory(
                    directory, _safe_entries(selected_directory_api, directory)
                )
            )

        expected_wheels = tuple(item.wheel_filename for item in provider.distributions)
        wheel_entries = inventories[1].entries
        if any(item.is_directory for item in wheel_entries) or tuple(
            item.name for item in wheel_entries
        ) != tuple(
            sorted(expected_wheels, key=lambda value: (value.casefold(), value))
        ):
            _fail(PodmanInputErrorCode.PROVIDER_INVALID)
        if any(
            item.is_directory
            or item.name.casefold() == "pyvenv.cfg"
            or item.name.casefold().endswith(".exe.local")
            or PureWindowsPath(item.name).suffix.casefold() in _DENIED_SCRIPT_SUFFIXES
            for item in inventories[2].entries
        ):
            _fail(PodmanInputErrorCode.PROVIDER_INVALID)

        catalog_bound = _capture_file(
            catalog_path, maximum=_MAX_CATALOG_BYTES, file_api=file_api
        )
        catalog = _HeldProviderFile("podman_provider_catalog", catalog_bound)
        captured_files.append(catalog)
        wheel_items: list[_HeldProviderFile] = []
        wheel_inputs: list[ProviderWheel] = []
        for index, distribution in enumerate(provider.distributions):
            bound = _capture_file(
                wheelhouse / distribution.wheel_filename,
                maximum=_MAX_WHEEL_BYTES,
                file_api=file_api,
            )
            item = _HeldProviderFile(f"podman_provider_wheel_{index:02d}", bound)
            wheel_items.append(item)
            captured_files.append(item)
            wheel_inputs.append(
                ProviderWheel(
                    filename=distribution.wheel_filename,
                    contents=_read_all(bound, maximum=_MAX_WHEEL_BYTES),
                )
            )

        installed_files: list[_HeldProviderFile] = []
        observations = _capture_site_packages(
            provider_root,
            site_packages,
            path_api=path_api,
            directory_api=selected_directory_api,
            file_api=file_api,
            directories=directories,
            inventories=inventories,
            files=installed_files,
        )
        captured_files.extend(installed_files)
        inventory_evidence = verify_managed_podman_compose_source_inventory(
            catalog_bytes=_read_all(catalog_bound, maximum=_MAX_CATALOG_BYTES),
            wheels=tuple(wheel_inputs),
            installed_files=observations,
        )

        venv_python_bound = _capture_file(
            venv_python_path, maximum=_MAX_PROVIDER_FILE_BYTES, file_api=file_api
        )
        venv_python = _HeldProviderFile("python.exe", venv_python_bound)
        captured_files.append(venv_python)
        entrypoint_bound = _capture_file(
            entrypoint_path, maximum=_MAX_PROVIDER_FILE_BYTES, file_api=file_api
        )
        entrypoint = _HeldProviderFile("podman_compose_entrypoint", entrypoint_bound)
        captured_files.append(entrypoint)
        config_bound = _capture_file(
            venv_config_path, maximum=_MAX_VENV_CONFIG_BYTES, file_api=file_api
        )
        venv_config = _HeldProviderFile("podman_venv_config", config_bound)
        captured_files.append(venv_config)

        base_owner = open_package_bound_runtime_evidence(
            RuntimeProductId.CPYTHON,
            installation_backend=installation_backend,
            file_api=file_api,
            pe_backend=pe_backend,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )
        base_evidence = base_owner.evidence
        venv_pe = verify_package_bound_pe_product(venv_python_bound, backend=pe_backend)
        venv_authenticode = verify_package_bound_authenticode_signer(
            venv_python_bound, backend=authenticode_backend, clock=clock
        )
        if (
            base_evidence.product_id is not RuntimeProductId.CPYTHON
            or base_evidence.policy_sha256 != policy.content_sha256
            or venv_pe.product_id is not RuntimeProductId.CPYTHON
            or venv_pe.exact_version != base_evidence.exact_version
            or venv_pe.policy_sha256 != base_evidence.policy_sha256
            or RuntimeProductId.CPYTHON
            not in venv_authenticode.signer_policy_product_ids
            or venv_authenticode.policy_sha256 != base_evidence.policy_sha256
            or venv_authenticode.signer_certificate_sha256
            != base_evidence.authenticode.signer_certificate_sha256
        ):
            _fail(PodmanInputErrorCode.PROVIDER_INVALID)
        base_owner._transfer_bound_file(slot)  # noqa: SLF001
        base_executable = slot.bound_file
        if not base_owner.closed:
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        base_inventory = capture_package_bound_cpython_dependency_inventory(
            base_executable,
            path_api=path_api,
            file_api=file_api,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )
        _parse_venv_config(
            _read_all(config_bound, maximum=_MAX_VENV_CONFIG_BYTES),
            base_executable=PureWindowsPath(base_executable.snapshot.final_path),
            expected_version=base_evidence.exact_version,
        )

        ordered_files = _reorder_provider_files(
            installed_files,
            module_path=module_path,
            venv_python=venv_python,
            entrypoint=entrypoint,
            venv_config=venv_config,
            catalog=catalog,
            wheels=tuple(wheel_items),
        )
        artifacts = tuple(_file_identity(item) for item in ordered_files)
        identity = ComposeProviderIdentity(
            provider_id=inventory_evidence.provider_id,
            invocation_kind=ComposeInvocationKind.PODMAN_PYTHON_MODULE,
            endpoint_binding=EndpointBindingKind.PODMAN_CONTAINER_HOST_ENVIRONMENT,
            artifacts=artifacts,
            integrity_sha256=_provider_integrity(
                inventory=inventory_evidence,
                base=base_evidence,
                base_inventory_sha256=(
                    base_inventory.evidence.dependency.inventory_sha256
                ),
                venv_pe_sha256=venv_pe.evidence_sha256,
                venv_authenticode_sha256=venv_authenticode.evidence_sha256,
                directory_sha256=_directory_digest(inventories),
                artifacts=artifacts,
            ),
        )
        owner = BoundManagedPodmanComposeProvider(
            directories=tuple(directories),
            directory_inventories=tuple(inventories),
            directory_api=selected_directory_api,
            files=ordered_files,
            base_executable=base_executable,
            base_inventory=base_inventory,
            identity=identity,
        )
        owner.capture()
        slot._disarm(base_executable)  # noqa: SLF001
        directories = []
        captured_files = []
        base_inventory = None
        return owner
    except BaseException as error:
        closeables: list[tuple[Callable[[], None], Callable[[], bool]]] = []
        if owner is not None:
            closeables.append((owner.close, _closed_check(owner)))
        if base_inventory is not None:
            closeables.append((base_inventory.close, _closed_check(base_inventory)))
        closeables.append((slot.close, lambda: not slot._armed))  # noqa: SLF001
        if base_owner is not None:
            closeables.append((base_owner.close, _closed_check(base_owner)))
        closeables.extend(
            (item.bound_file.close, _closed_check(item.bound_file))
            for item in reversed(captured_files)
        )
        closeables.extend(
            (directory.close, _closed_check(directory))
            for directory in reversed(directories)
        )
        cleanup_interruption, cleanup_incomplete = _retry_failed_capture_cleanup(
            closeables
        )
        if not isinstance(error, Exception):
            raise
        if cleanup_interruption is not None:
            raise cleanup_interruption
        if cleanup_incomplete:
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        if isinstance(error, PodmanInputError):
            raise
        if isinstance(
            error,
            (
                AuthenticodeVerificationError,
                CpythonDependencyCaptureError,
                ManagedPodmanProviderError,
                RuntimeIdentityVerificationError,
                RuntimeVerificationError,
                WindowsSecurityError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
                UnicodeError,
            ),
        ):
            raise PodmanInputError(PodmanInputErrorCode.PROVIDER_INVALID) from None
        raise PodmanInputError(PodmanInputErrorCode.VERIFICATION_UNAVAILABLE) from None


def capture_native_windows_managed_podman_compose_provider(
    package_root: PureWindowsPath,
) -> BoundManagedPodmanComposeProvider:
    """Capture the fixed package-managed provider with native Windows proofs."""

    return _capture_managed_podman_compose_provider(package_root)


class BoundPodmanTargetSourceInputs:
    """Retain and coherently revalidate Podman runtime, endpoint, and provider."""

    __slots__ = ("_active_owner", "_lifetime_lock", "_provider", "_runtime_endpoint")

    def __init__(
        self,
        *,
        runtime_endpoint: BoundPodmanRuntimeEndpointInputs,
        provider: BoundManagedPodmanComposeProvider,
    ) -> None:
        if (
            type(runtime_endpoint) is not BoundPodmanRuntimeEndpointInputs
            or runtime_endpoint.closed
            or type(provider) is not BoundManagedPodmanComposeProvider
            or provider.closed
        ):
            raise ValueError("Bound Podman target source inputs are invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._runtime_endpoint: BoundPodmanRuntimeEndpointInputs | None = (
            runtime_endpoint
        )
        self._provider: BoundManagedPodmanComposeProvider | None = provider

    @property
    def supported(self) -> bool:
        with self._lifetime_lock:
            runtime_endpoint = self._runtime_endpoint
            provider = self._provider
            return bool(
                runtime_endpoint is not None
                and runtime_endpoint.supported
                and provider is not None
                and provider.supported
            )

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            runtime_endpoint = self._runtime_endpoint
            provider = self._provider
            return bool(
                (runtime_endpoint is None or runtime_endpoint.closed)
                and (provider is None or provider.closed)
            )

    def capture(self) -> PodmanTargetSourceInputs:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        runtime_endpoint = self._runtime_endpoint
        provider = self._provider
        if (
            runtime_endpoint is None
            or runtime_endpoint.closed
            or provider is None
            or provider.closed
        ):
            self._lifetime_lock.release()
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            first_runtime_endpoint = runtime_endpoint.capture()
            first_provider = provider.capture()
            second_runtime_endpoint = runtime_endpoint.capture()
            second_provider = provider.capture()
            if (
                first_runtime_endpoint != second_runtime_endpoint
                or first_provider != second_provider
                or second_runtime_endpoint.runtime.publisher_policy_sha256
                != load_package_bound_runtime_policy().content_sha256
            ):
                _fail(PodmanInputErrorCode.INPUTS_CHANGED)
            return PodmanTargetSourceInputs(
                runtime=second_runtime_endpoint.runtime,
                endpoint=second_runtime_endpoint.endpoint,
                compose_provider=second_provider,
            )
        except PodmanInputError:
            raise
        except (PodmanEndpointError, RuntimePolicyError):
            raise PodmanInputError(PodmanInputErrorCode.INPUTS_CHANGED) from None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise PodmanInputError(
                PodmanInputErrorCode.VERIFICATION_UNAVAILABLE
            ) from None
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(PodmanInputErrorCode.INPUTS_CHANGED)
            provider = self._provider
            runtime_endpoint = self._runtime_endpoint
            failed = False
            interruption: BaseException | None = None
            for closeable in (provider, runtime_endpoint):
                if closeable is None:
                    continue
                try:
                    closeable.close()
                except BaseException as error:
                    if not isinstance(error, Exception) and interruption is None:
                        interruption = error
                    else:
                        failed = True
            if provider is None or provider.closed:
                self._provider = None
            if runtime_endpoint is None or runtime_endpoint.closed:
                self._runtime_endpoint = None
            if interruption is not None:
                raise interruption
            if failed or not self.closed:
                _fail(PodmanInputErrorCode.INPUTS_CHANGED)

    def __enter__(self) -> "BoundPodmanTargetSourceInputs":
        if self.closed:
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"BoundPodmanTargetSourceInputs(state={state!r}, <redacted>)"


def capture_native_windows_podman_target_source_inputs(
    package_root: PureWindowsPath,
) -> BoundPodmanTargetSourceInputs:
    """Capture the fixed native Podman runtime, endpoint, and provider owner."""

    runtime_endpoint: BoundPodmanRuntimeEndpointInputs | None = None
    provider: BoundManagedPodmanComposeProvider | None = None
    owner: BoundPodmanTargetSourceInputs | None = None
    try:
        runtime_endpoint = capture_native_windows_podman_runtime_endpoint_inputs(
            package_root
        )
        provider = capture_native_windows_managed_podman_compose_provider(package_root)
        owner = BoundPodmanTargetSourceInputs(
            runtime_endpoint=runtime_endpoint,
            provider=provider,
        )
        owner.capture()
        runtime_endpoint = None
        provider = None
        return owner
    except BaseException as error:
        closeables: tuple[tuple[Callable[[], None], Callable[[], bool]], ...] = ()
        if owner is not None:
            closeables = ((owner.close, _closed_check(owner)),)
        else:
            if provider is not None:
                closeables += ((provider.close, _closed_check(provider)),)
            if runtime_endpoint is not None:
                closeables += (
                    (runtime_endpoint.close, _closed_check(runtime_endpoint)),
                )
        cleanup_interruption, cleanup_incomplete = _retry_failed_capture_cleanup(
            closeables
        )
        if not isinstance(error, Exception):
            raise
        if cleanup_interruption is not None:
            raise cleanup_interruption
        if cleanup_incomplete:
            _fail(PodmanInputErrorCode.INPUTS_CHANGED)
        if isinstance(error, PodmanInputError):
            raise
        if isinstance(error, PodmanEndpointError):
            raise PodmanInputError(PodmanInputErrorCode.INPUTS_CHANGED) from None
        raise PodmanInputError(PodmanInputErrorCode.VERIFICATION_UNAVAILABLE) from None


__all__ = [
    "BoundManagedPodmanComposeProvider",
    "BoundPodmanTargetSourceInputs",
    "PodmanInputError",
    "PodmanInputErrorCode",
    "PodmanTargetSourceInputs",
    "capture_native_windows_managed_podman_compose_provider",
    "capture_native_windows_podman_target_source_inputs",
]
