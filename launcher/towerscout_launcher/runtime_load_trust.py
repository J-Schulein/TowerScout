"""Inert, handle-bound Windows executable load-surface prerequisites.

This source-only slice binds the immediate application directory and OS search
roots for a later product-specific transitive dependency policy.  It does not
claim closure over private assemblies or dynamic relative loads, discover
runtimes, select a command, or execute a child process.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .authenticode import verify_package_bound_authenticode_signer
from .runtime_dependency_policy import load_package_bound_runtime_dependency_policy
from .runtime_policy import RuntimeProductId
from .runtime_provider_child import (
    ProcessImageBinding,
    ProcessImagePolicy,
    ProcessImageRole,
)
from .windows_path_trust import (
    NativeSecurityFacts,
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
    validate_security_facts,
)
from .windows_security import (
    FileCapturePolicy,
    FileSnapshot,
    HandleBoundFile,
    StableFileIdentity,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_MAX_DIRECTORY_CHARACTERS = 32_767
_MAX_DIRECTORY_ENTRIES = 16_384
_MAX_ENTRY_NAME_CHARACTERS = 255
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_MAX_LOADABLE_BYTES = 1024 * 1024 * 1024
_SHA256_CHARACTERS = 64
_WINDOWS_SYSTEM_BOOTSTRAP_IMAGES = (
    "kernelbase.dll",
    "ntdll.dll",
    "ucrtbase.dll",
)
_Result = TypeVar("_Result")


class RuntimeLoadTrustErrorCode(str, Enum):
    UNAVAILABLE = "unavailable"
    LOAD_PATH_UNSAFE = "load_path_unsafe"
    LOAD_PATH_CHANGED = "load_path_changed"


class RuntimeLoadTrustError(RuntimeError):
    _MESSAGES = {
        RuntimeLoadTrustErrorCode.UNAVAILABLE: (
            "Secure Windows runtime load-path inspection is unavailable."
        ),
        RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE: (
            "The Windows runtime load path is not trusted."
        ),
        RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED: (
            "The Windows runtime load path changed after inspection."
        ),
    }

    def __init__(self, code: RuntimeLoadTrustErrorCode) -> None:
        if type(code) is not RuntimeLoadTrustErrorCode:
            raise ValueError("Unknown runtime load-trust error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeLoadTrustError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryEntry:
    name: str
    is_directory: bool
    attributes: int
    reparse_tag: int

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or len(self.name) > _MAX_ENTRY_NAME_CHARACTERS
            or self.name in (".", "..")
            or any(character in self.name for character in ("\\", "/", "\x00"))
            or self.name.endswith((".", " "))
            or ":" in self.name
            or type(self.is_directory) is not bool
            or type(self.attributes) is not int
            or not 0 <= self.attributes < 2**32
            or bool(self.attributes & _FILE_ATTRIBUTE_DIRECTORY) != self.is_directory
            or type(self.reparse_tag) is not int
            or not 0 <= self.reparse_tag < 2**32
            or bool(self.attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
            != bool(self.reparse_tag)
        ):
            raise ValueError("Windows directory entry facts are invalid.")

    def __repr__(self) -> str:
        return (
            "DirectoryEntry("
            f"is_directory={self.is_directory}, attributes={self.attributes:#x}, "
            f"reparse_tag={self.reparse_tag:#x}, name=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class LoadableAuthentication:
    signer_product_ids: tuple[RuntimeProductId, ...]
    evidence_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.signer_product_ids) is not tuple
            or not self.signer_product_ids
            or any(
                type(product_id) is not RuntimeProductId
                for product_id in self.signer_product_ids
            )
            or len(set(self.signer_product_ids)) != len(self.signer_product_ids)
            or type(self.evidence_sha256) is not str
            or len(self.evidence_sha256) != _SHA256_CHARACTERS
            or any(
                character not in "0123456789abcdef"
                for character in self.evidence_sha256
            )
        ):
            raise ValueError("Loadable authentication evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "LoadableAuthentication("
            f"signer_policy_count={len(self.signer_product_ids)}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeLoadPrerequisiteEvidence:
    product_id: RuntimeProductId
    executable_identity: StableFileIdentity = field(repr=False)
    executable_sha256: str = field(repr=False)
    immediate_surface_sha256: str = field(repr=False)
    loadable_count: int
    held_application_file_count: int
    requires_empty_parent_dll_directory: bool
    requires_system32_working_directory: bool
    requires_empty_path: bool
    immediate_application_directory_bound: bool
    transitive_dependency_policy_required: bool

    def __post_init__(self) -> None:
        if (
            type(self.product_id) is not RuntimeProductId
            or type(self.executable_identity) is not StableFileIdentity
            or not _is_sha256(self.executable_sha256)
            or not _is_sha256(self.immediate_surface_sha256)
            or type(self.loadable_count) is not int
            or not 0 <= self.loadable_count <= _MAX_DIRECTORY_ENTRIES
            or type(self.held_application_file_count) is not int
            or not self.loadable_count
            <= self.held_application_file_count
            <= _MAX_DIRECTORY_ENTRIES
            or self.requires_empty_parent_dll_directory is not True
            or self.requires_system32_working_directory is not True
            or self.requires_empty_path is not True
            or self.immediate_application_directory_bound is not True
            or self.transitive_dependency_policy_required is not True
        ):
            raise ValueError("Runtime load trust evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "RuntimeLoadPrerequisiteEvidence("
            f"product_id={self.product_id.value!r}, "
            f"loadable_count={self.loadable_count}, "
            f"held_file_count={self.held_application_file_count}, <redacted>)"
        )


class RuntimeLoadInventoryApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]: ...

    def current_dll_directory(self) -> str: ...

    def system_directory(self) -> str: ...

    def windows_directory(self) -> str: ...


LoadableAuthenticator = Callable[
    [HandleBoundFile, RuntimeProductId], LoadableAuthentication
]


@dataclass(frozen=True, slots=True, repr=False)
class _HeldApplicationFile:
    name: str = field(repr=False)
    bound_file: HandleBoundFile = field(repr=False)
    security: NativeSecurityFacts = field(repr=False)
    is_pe_image: bool
    authentication: LoadableAuthentication | None = field(repr=False)

    def __repr__(self) -> str:
        return "_HeldApplicationFile(<redacted>)"


def _fail(code: RuntimeLoadTrustErrorCode) -> NoReturn:
    raise RuntimeLoadTrustError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_CHARACTERS
        and all(character in "0123456789abcdef" for character in value)
    )


def _immediate_surface_digest(
    product_id: RuntimeProductId,
    executable: HandleBoundFile,
    path_trusts: tuple[PathHierarchyTrust, ...],
    inventory: tuple[DirectoryEntry, ...],
    application_files: tuple[_HeldApplicationFile, ...],
) -> str:
    digest = hashlib.sha256()

    def add(value: bytes) -> None:
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)

    add(b"TowerScout.RuntimeImmediateLoadSurface.v1")
    add(product_id.value.encode("ascii"))
    add(executable.snapshot.identity.volume_serial.to_bytes(8, "big"))
    add(executable.snapshot.identity.file_id)
    add(executable.snapshot.sha256.encode("ascii"))
    for path_trust in path_trusts:
        identity = path_trust.evidence.root_identity
        add(identity.volume_serial.to_bytes(8, "big"))
        add(identity.file_id)
    for entry in inventory:
        add(entry.name.encode("utf-8", errors="strict"))
        add(b"directory" if entry.is_directory else b"file")
        add(entry.attributes.to_bytes(4, "big"))
        add(entry.reparse_tag.to_bytes(4, "big"))
    for held in application_files:
        snapshot = held.bound_file.snapshot
        add(held.name.encode("utf-8", errors="strict"))
        add(snapshot.identity.volume_serial.to_bytes(8, "big"))
        add(snapshot.identity.file_id)
        add(snapshot.sha256.encode("ascii"))
        add(b"pe" if held.is_pe_image else b"data")
        add(
            held.authentication.evidence_sha256.encode("ascii")
            if held.authentication is not None
            else b""
        )
    return digest.hexdigest()


def _default_authenticate(
    bound_file: HandleBoundFile, product_id: RuntimeProductId
) -> LoadableAuthentication:
    del product_id
    evidence = verify_package_bound_authenticode_signer(bound_file)
    return LoadableAuthentication(
        signer_product_ids=evidence.signer_policy_product_ids,
        evidence_sha256=evidence.evidence_sha256,
    )


def _normalized_windows_path(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return str(PureWindowsPath(path)).casefold()


def _parent_path(path: str) -> str:
    value = str(PureWindowsPath(path).parent)
    if not value or value == ".":
        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
    return value


def _safe_inventory(
    api: RuntimeLoadInventoryApi, app_directory: str
) -> tuple[DirectoryEntry, ...]:
    try:
        entries = api.list_directory(app_directory)
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail(RuntimeLoadTrustErrorCode.UNAVAILABLE)
    if (
        type(entries) is not tuple
        or len(entries) > _MAX_DIRECTORY_ENTRIES
        or any(type(entry) is not DirectoryEntry for entry in entries)
    ):
        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
    folded = tuple(entry.name.casefold() for entry in entries)
    if len(folded) != len(set(folded)):
        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
    return tuple(sorted(entries, key=lambda entry: (entry.name.casefold(), entry.name)))


def _inspect_security(
    bound_file: HandleBoundFile,
    *,
    path_api: WindowsPathTrustApi,
    current_user_sid: str,
) -> NativeSecurityFacts:
    def inspect(handle: object, _snapshot: FileSnapshot) -> NativeSecurityFacts:
        facts = path_api.query_security(handle)
        validate_security_facts(
            facts,
            current_user_sid=current_user_sid,
            trusted_root=True,
        )
        return facts

    return bound_file.inspect_same_handle(inspect)


def _authenticate_loadable(
    authenticator: LoadableAuthenticator,
    bound_file: HandleBoundFile,
    product_id: RuntimeProductId,
) -> LoadableAuthentication:
    result = authenticator(bound_file, product_id)
    if (
        type(result) is not LoadableAuthentication
        or product_id not in result.signer_product_ids
    ):
        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
    return result


def _is_pe_image(bound_file: HandleBoundFile, file_api: WindowsFileApi) -> bool:
    def inspect(handle: object, _snapshot: FileSnapshot) -> bool:
        file_api.rewind_file(handle)
        prefix = file_api.read_file(handle, 2)
        if type(prefix) is not bytes or len(prefix) > 2:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
        return prefix == b"MZ"

    return bound_file.inspect_same_handle(inspect)


def _validate_inventory_surface(
    entries: tuple[DirectoryEntry, ...], executable_name: str
) -> tuple[DirectoryEntry, ...]:
    local_redirection = (executable_name + ".local").casefold()
    external_manifest = (executable_name + ".manifest").casefold()
    application_files: list[DirectoryEntry] = []
    for entry in entries:
        folded = entry.name.casefold()
        if folded in {local_redirection, external_manifest}:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
        if entry.attributes & _FILE_ATTRIBUTE_REPARSE_POINT or entry.reparse_tag:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
        if entry.is_directory:
            if PureWindowsPath(entry.name).suffix.casefold() in {".dll", ".pyd"}:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
            continue
        if folded == executable_name.casefold():
            continue
        application_files.append(entry)
    return tuple(application_files)


def _capture_tracked_path(
    path_trusts: list[PathHierarchyTrust],
    path: str,
    *,
    api: WindowsPathTrustApi,
) -> PathHierarchyTrust:
    """Capture one hierarchy and either track or close it before propagating."""

    path_trust: PathHierarchyTrust | None = None
    try:
        path_trust = capture_path_hierarchy(
            path,
            purpose=PathTrustPurpose.RUNTIME_INSTALL,
            api=api,
        )
        path_trusts.append(path_trust)
        return path_trust
    except BaseException:
        if path_trust is not None and path_trust not in path_trusts:
            path_trust.close()
        raise


class RuntimeLoadPrerequisites:
    """Own immediate load-surface prerequisites until caller release."""

    __slots__ = (
        "_active_owner",
        "_app_directory",
        "_authenticate",
        "_current_user_sid",
        "_evidence",
        "_executable",
        "_executable_name",
        "_executable_security",
        "_file_api",
        "_inventory",
        "_inventory_api",
        "_application_files",
        "_lock",
        "_path_api",
        "_path_trusts",
        "_system_image_names",
    )

    def __init__(
        self,
        *,
        evidence: RuntimeLoadPrerequisiteEvidence,
        executable: HandleBoundFile,
        executable_name: str,
        executable_security: NativeSecurityFacts,
        app_directory: str,
        inventory: tuple[DirectoryEntry, ...],
        inventory_api: RuntimeLoadInventoryApi,
        file_api: WindowsFileApi,
        path_api: WindowsPathTrustApi,
        current_user_sid: str,
        path_trusts: tuple[PathHierarchyTrust, ...],
        application_files: tuple[_HeldApplicationFile, ...],
        authenticate: LoadableAuthenticator,
        system_image_names: tuple[str, ...],
    ) -> None:
        if (
            type(system_image_names) is not tuple
            or not system_image_names
            or system_image_names
            != tuple(sorted(set(system_image_names), key=str.casefold))
            or any(
                type(name) is not str
                or not name
                or name != name.casefold()
                or not name.endswith(".dll")
                for name in system_image_names
            )
        ):
            raise ValueError("Runtime system-image policy is invalid.")
        self._evidence = evidence
        self._active_owner: int | None = None
        self._executable = executable
        self._executable_name = executable_name
        self._executable_security = executable_security
        self._app_directory = app_directory
        self._inventory = inventory
        self._inventory_api = inventory_api
        self._file_api = file_api
        self._path_api = path_api
        self._current_user_sid = current_user_sid
        self._path_trusts: tuple[PathHierarchyTrust, ...] | None = path_trusts
        self._application_files: tuple[_HeldApplicationFile, ...] | None = (
            application_files
        )
        self._authenticate = authenticate
        self._system_image_names = system_image_names
        self._lock = threading.RLock()

    @property
    def evidence(self) -> RuntimeLoadPrerequisiteEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._path_trusts is None

    def _begin_use(
        self,
    ) -> tuple[tuple[PathHierarchyTrust, ...], tuple[_HeldApplicationFile, ...]]:
        self._lock.acquire()
        if self._active_owner is not None:
            self._lock.release()
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        path_trusts = self._path_trusts
        application_files = self._application_files
        if path_trusts is None or application_files is None:
            self._lock.release()
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        self._active_owner = threading.get_ident()
        return path_trusts, application_files

    def _end_use(self) -> None:
        self._active_owner = None
        self._lock.release()

    def _assert_unchanged_owned(
        self,
        path_trusts: tuple[PathHierarchyTrust, ...],
        application_files: tuple[_HeldApplicationFile, ...],
    ) -> RuntimeLoadPrerequisiteEvidence:
        try:
            if self._inventory_api.current_dll_directory() != "":
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            if (
                _safe_inventory(self._inventory_api, self._app_directory)
                != self._inventory
            ):
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            for path_trust in path_trusts:
                path_trust.assert_unchanged()
            self._executable.assert_unchanged()
            current_executable_security = _inspect_security(
                self._executable,
                path_api=self._path_api,
                current_user_sid=self._current_user_sid,
            )
            if current_executable_security != self._executable_security:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            for held in application_files:
                held.bound_file.assert_unchanged()
                current_security = _inspect_security(
                    held.bound_file,
                    path_api=self._path_api,
                    current_user_sid=self._current_user_sid,
                )
                if current_security != held.security:
                    _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
                if _is_pe_image(held.bound_file, self._file_api) != held.is_pe_image:
                    _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
                if held.is_pe_image:
                    authentication = _authenticate_loadable(
                        self._authenticate,
                        held.bound_file,
                        self._evidence.product_id,
                    )
                    if authentication != held.authentication:
                        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            if (
                self._executable.snapshot.identity != self._evidence.executable_identity
                or self._executable.snapshot.sha256 != self._evidence.executable_sha256
                or _immediate_surface_digest(
                    self._evidence.product_id,
                    self._executable,
                    path_trusts,
                    self._inventory,
                    application_files,
                )
                != self._evidence.immediate_surface_sha256
            ):
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        except RuntimeLoadTrustError as error:
            if error.code is RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED:
                raise
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        except Exception:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        return self._evidence

    def _held_file_security(
        self, application_files: tuple[_HeldApplicationFile, ...]
    ) -> tuple[tuple[HandleBoundFile, NativeSecurityFacts], ...]:
        return (
            (self._executable, self._executable_security),
            *((held.bound_file, held.security) for held in application_files),
        )

    def _run_under_file_leases(
        self,
        files: tuple[tuple[HandleBoundFile, NativeSecurityFacts], ...],
        index: int,
        operation: Callable[[], _Result],
    ) -> _Result:
        if index == len(files):
            return operation()
        bound_file, expected_security = files[index]

        def assert_security(handle: object, _snapshot: FileSnapshot) -> None:
            try:
                current = self._path_api.query_security(handle)
                validate_security_facts(
                    current,
                    current_user_sid=self._current_user_sid,
                    trusted_root=True,
                )
            except Exception:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            if current != expected_security:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)

        return bound_file._run_while_held_with_postvalidation(  # noqa: SLF001
            lambda: self._run_under_file_leases(files, index + 1, operation),
            assert_security,
        )

    def _run_under_path_leases(
        self,
        paths: tuple[PathHierarchyTrust, ...],
        index: int,
        operation: Callable[[], _Result],
    ) -> _Result:
        if index == len(paths):
            return operation()
        return paths[index].run_while_held(
            lambda: self._run_under_path_leases(paths, index + 1, operation)
        )

    def _run_and_revalidate_inventory(
        self, operation: Callable[[], _Result]
    ) -> _Result:
        def assert_inventory() -> None:
            try:
                changed = (
                    self._inventory_api.current_dll_directory() != ""
                    or _safe_inventory(self._inventory_api, self._app_directory)
                    != self._inventory
                )
            except Exception:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            if changed:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)

        assert_inventory()
        try:
            result = operation()
        except BaseException:
            assert_inventory()
            raise
        assert_inventory()
        return result

    def active_process_image_policy(self, role: ProcessImageRole) -> ProcessImagePolicy:
        """Return the exact executable image policy only inside the held callback."""

        application_files = self._application_files
        if (
            type(role) is not ProcessImageRole
            or self._active_owner != threading.get_ident()
            or application_files is None
        ):
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        try:
            return ProcessImagePolicy(
                role,
                (
                    ProcessImageBinding.from_snapshot(
                        self._executable.snapshot, entrypoint=True
                    ),
                    *(
                        ProcessImageBinding.from_snapshot(
                            held.bound_file.snapshot, entrypoint=False
                        )
                        for held in application_files
                        if held.is_pe_image
                    ),
                ),
                self._system_image_names,
            )
        except ValueError:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)

    def assert_unchanged(self) -> RuntimeLoadPrerequisiteEvidence:
        path_trusts, application_files = self._begin_use()
        try:
            return self._assert_unchanged_owned(path_trusts, application_files)
        finally:
            self._end_use()

    def run_while_held(self, operation: Callable[[], _Result]) -> _Result:
        """Run synchronously while every executable and directory stays bound."""

        if not callable(operation):
            raise ValueError("The held runtime-load operation is invalid.")
        path_trusts, application_files = self._begin_use()
        try:
            self._assert_unchanged_owned(path_trusts, application_files)
            return self._run_under_path_leases(
                path_trusts,
                0,
                lambda: self._run_under_file_leases(
                    self._held_file_security(application_files),
                    0,
                    lambda: self._run_and_revalidate_inventory(operation),
                ),
            )
        except RuntimeLoadTrustError:
            raise
        except WindowsSecurityError:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
        finally:
            self._end_use()

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED)
            path_trusts = self._path_trusts
            application_files = self._application_files
            self._path_trusts = None
            self._application_files = None
            if application_files is not None:
                for held in reversed(application_files):
                    held.bound_file.close()
            if path_trusts is not None:
                for path_trust in reversed(path_trusts):
                    path_trust.close()

    def __enter__(self) -> "RuntimeLoadPrerequisites":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"RuntimeLoadPrerequisites(state={state!r}, <redacted>)"


def capture_runtime_load_prerequisites(
    product_id: RuntimeProductId,
    executable: HandleBoundFile,
    *,
    path_api: WindowsPathTrustApi | None = None,
    inventory_api: RuntimeLoadInventoryApi | None = None,
    file_api: WindowsFileApi | None = None,
    authenticate: LoadableAuthenticator | None = None,
) -> RuntimeLoadPrerequisites:
    """Capture immediate load-path facts required by later closure policy."""

    if (
        type(product_id) is not RuntimeProductId
        or type(executable) is not HandleBoundFile
    ):
        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
    selected_path_api = path_api
    if selected_path_api is None:
        from .windows_path_trust import NativeWindowsPathTrustApi

        selected_path_api = NativeWindowsPathTrustApi()
    selected_inventory = (
        inventory_api if inventory_api is not None else NativeRuntimeLoadInventoryApi()
    )
    if file_api is None:
        from .windows_security import NativeWindowsFileApi

        selected_file_api: WindowsFileApi = NativeWindowsFileApi()
    else:
        selected_file_api = file_api
    selected_authenticate = authenticate or _default_authenticate
    try:
        supported = (
            selected_path_api.supported is True
            and selected_inventory.supported is True
            and selected_file_api.supported is True
        )
    except Exception:
        supported = False
    if not supported:
        _fail(RuntimeLoadTrustErrorCode.UNAVAILABLE)
    try:
        dependency_policy = load_package_bound_runtime_dependency_policy()
        product_policy = dependency_policy.product(product_id)
        system_image_names = tuple(
            sorted(
                {
                    *product_policy.declared_system_imports,
                    *product_policy.declared_api_set_imports,
                    *_WINDOWS_SYSTEM_BOOTSTRAP_IMAGES,
                },
                key=str.casefold,
            )
        )
    except Exception:
        _fail(RuntimeLoadTrustErrorCode.UNAVAILABLE)

    path_trusts: list[PathHierarchyTrust] = []
    application_files: list[_HeldApplicationFile] = []
    pending_file: HandleBoundFile | None = None

    def release_captured() -> None:
        nonlocal pending_file
        if pending_file is not None:
            pending_file.close()
            pending_file = None
        for held in reversed(application_files):
            held.bound_file.close()
        for path_trust in reversed(path_trusts):
            path_trust.close()

    try:
        if selected_inventory.current_dll_directory() != "":
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
        current_user_sid = selected_path_api.current_user_sid()
        executable.assert_unchanged()
        executable_path = executable.snapshot.final_path
        executable_name = PureWindowsPath(executable_path).name
        if not executable_name:
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
        app_directory = _parent_path(executable_path)
        app_trust = _capture_tracked_path(
            path_trusts,
            app_directory,
            api=selected_path_api,
        )
        if _normalized_windows_path(
            _parent_path(executable_path)
        ) != _normalized_windows_path(app_trust.root_snapshot.final_path):
            _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
        for directory in (
            selected_inventory.system_directory(),
            selected_inventory.windows_directory(),
        ):
            _capture_tracked_path(
                path_trusts,
                directory,
                api=selected_path_api,
            )
        executable_security = _inspect_security(
            executable,
            path_api=selected_path_api,
            current_user_sid=current_user_sid,
        )
        inventory = _safe_inventory(selected_inventory, app_directory)
        for entry in _validate_inventory_surface(inventory, executable_name):
            module_path = str(PureWindowsPath(app_directory) / entry.name)
            pending_file = capture_handle_bound_file(
                Path(module_path),
                api=selected_file_api,
                policy=FileCapturePolicy(
                    max_bytes=_MAX_LOADABLE_BYTES,
                    require_single_link=False,
                ),
            )
            bound_file = pending_file
            try:
                if _normalized_windows_path(
                    _parent_path(bound_file.snapshot.final_path)
                ) != _normalized_windows_path(app_trust.root_snapshot.final_path):
                    _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
                security = _inspect_security(
                    bound_file,
                    path_api=selected_path_api,
                    current_user_sid=current_user_sid,
                )
                is_pe_image = _is_pe_image(bound_file, selected_file_api)
                authentication = None
                if is_pe_image:
                    authentication = _authenticate_loadable(
                        selected_authenticate, bound_file, product_id
                    )
                elif not bound_file.snapshot.classification.single_link:
                    _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
            except BaseException:
                bound_file.close()
                raise
            held_file = _HeldApplicationFile(
                entry.name,
                bound_file,
                security,
                is_pe_image,
                authentication,
            )
            application_files.append(held_file)
            pending_file = None
        held_files = tuple(application_files)
        held_paths = tuple(path_trusts)
        evidence = RuntimeLoadPrerequisiteEvidence(
            product_id=product_id,
            executable_identity=executable.snapshot.identity,
            executable_sha256=executable.snapshot.sha256,
            immediate_surface_sha256=_immediate_surface_digest(
                product_id,
                executable,
                held_paths,
                inventory,
                held_files,
            ),
            loadable_count=sum(item.is_pe_image for item in application_files),
            held_application_file_count=len(application_files),
            requires_empty_parent_dll_directory=True,
            requires_system32_working_directory=True,
            requires_empty_path=True,
            immediate_application_directory_bound=True,
            transitive_dependency_policy_required=True,
        )
        result = RuntimeLoadPrerequisites(
            evidence=evidence,
            executable=executable,
            executable_name=executable_name,
            executable_security=executable_security,
            app_directory=app_directory,
            inventory=inventory,
            inventory_api=selected_inventory,
            file_api=selected_file_api,
            path_api=selected_path_api,
            current_user_sid=current_user_sid,
            path_trusts=held_paths,
            application_files=held_files,
            authenticate=selected_authenticate,
            system_image_names=system_image_names,
        )
        result.assert_unchanged()
        return result
    except RuntimeLoadTrustError:
        release_captured()
        raise
    except (OSError, RuntimeError, TypeError, ValueError, WindowsSecurityError):
        release_captured()
        _fail(RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE)
    except BaseException:
        release_captured()
        raise
    raise AssertionError("unreachable")


class NativeRuntimeLoadInventoryApi:
    """Native directory enumeration and process DLL-directory inspection."""

    __slots__ = ("_kernel32",)

    def __init__(self) -> None:
        self._kernel32 = None
        win_dll = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or win_dll is None:
            return
        kernel32 = win_dll("kernel32", use_last_error=True)
        kernel32.GetDllDirectoryW.argtypes = (ctypes.c_uint32, ctypes.c_wchar_p)
        kernel32.GetDllDirectoryW.restype = ctypes.c_uint32
        kernel32.GetWindowsDirectoryW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.GetWindowsDirectoryW.restype = ctypes.c_uint32
        kernel32.GetSystemDirectoryW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.GetSystemDirectoryW.restype = ctypes.c_uint32
        self._kernel32 = kernel32

    @property
    def supported(self) -> bool:
        return self._kernel32 is not None

    def _require(self) -> Any:
        if self._kernel32 is None:
            raise OSError("Native Windows load-path inspection is unavailable.")
        return self._kernel32

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]:
        if type(path) is not str or not path:
            raise ValueError("Windows directory inventory request is invalid.")
        entries: list[DirectoryEntry] = []
        with os.scandir(path) as iterator:
            for item in iterator:
                if len(entries) >= _MAX_DIRECTORY_ENTRIES:
                    raise OSError("Windows directory inventory is too large.")
                stat = item.stat(follow_symlinks=False)
                attributes = int(getattr(stat, "st_file_attributes", 0))
                reparse_tag = int(getattr(stat, "st_reparse_tag", 0))
                entries.append(
                    DirectoryEntry(
                        item.name,
                        item.is_dir(follow_symlinks=False),
                        attributes,
                        reparse_tag,
                    )
                )
        return tuple(entries)

    def current_dll_directory(self) -> str:
        kernel32 = self._require()
        ctypes.set_last_error(0)
        required = int(kernel32.GetDllDirectoryW(0, None))
        if required == 0:
            if ctypes.get_last_error() != 0:
                raise OSError("Native Windows DLL directory query failed.")
            return ""
        if required > _MAX_DIRECTORY_CHARACTERS:
            raise OSError("Native Windows DLL directory is too long.")
        buffer = ctypes.create_unicode_buffer(required + 1)
        ctypes.set_last_error(0)
        written = int(kernel32.GetDllDirectoryW(len(buffer), buffer))
        if written == 0:
            if ctypes.get_last_error() != 0 or buffer.value:
                raise OSError("Native Windows DLL directory query failed.")
            return ""
        if written >= len(buffer):
            raise OSError("Native Windows DLL directory query failed.")
        return buffer.value

    def _directory(self, function_name: str) -> str:
        kernel32 = self._require()
        buffer = ctypes.create_unicode_buffer(_MAX_DIRECTORY_CHARACTERS + 1)
        function = getattr(kernel32, function_name)
        length = int(function(buffer, len(buffer)))
        if length <= 0 or length >= len(buffer) or len(buffer.value) != length:
            raise OSError("Native Windows directory query failed.")
        return buffer.value

    def system_directory(self) -> str:
        return self._directory("GetSystemDirectoryW")

    def windows_directory(self) -> str:
        return self._directory("GetWindowsDirectoryW")

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeRuntimeLoadInventoryApi(state={state!r})"


__all__ = [
    "DirectoryEntry",
    "LoadableAuthentication",
    "NativeRuntimeLoadInventoryApi",
    "RuntimeLoadInventoryApi",
    "RuntimeLoadPrerequisiteEvidence",
    "RuntimeLoadPrerequisites",
    "RuntimeLoadTrustError",
    "RuntimeLoadTrustErrorCode",
    "capture_runtime_load_prerequisites",
]
