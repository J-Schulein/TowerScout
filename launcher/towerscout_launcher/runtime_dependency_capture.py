"""Held exact-artifact ownership for the CPython native dependency set.

The caller supplies an already authenticated, handle-bound ``python.exe``.
This module derives its installation root from that held file, binds every
package-policy native artifact through a no-write/no-delete-share handle, and
retains the trusted directory hierarchies and file handles through a caller's
synchronous child-operation boundary.  It does not discover Python, mutate DLL
search state, install packages, or execute a process itself.
"""

from __future__ import annotations

import ntpath
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, NoReturn, TypeVar

from .authenticode import (
    AuthenticodeBackend,
    VerificationClock,
    verify_package_bound_dependency_authenticode_signer,
)
from .pe_dependencies import PeImageMetadata, inspect_pe_image_metadata
from .runtime_dependency_policy import (
    ApprovedDependencyFile,
    DependencySignaturePolicy,
    NonAmd64PeFile,
    PeMachine,
    RuntimeDependencyPolicy,
    load_package_bound_runtime_dependency_policy,
)
from .runtime_dependency_trust import (
    CpythonDependencyEvidence,
    DependencyFileObservation,
    inspect_handle_bound_pe_dependencies,
    validate_package_bound_cpython_dependency_observations,
)
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import (
    FileCapturePolicy,
    HandleBoundFile,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_MAX_NATIVE_FILE_BYTES = 1024 * 1024 * 1024
_MACHINE_BY_CODE = {
    0x014C: PeMachine.I386,
    0x8664: PeMachine.AMD64,
    0xAA64: PeMachine.ARM64,
}
_Result = TypeVar("_Result")


class CpythonDependencyCaptureErrorCode(str, Enum):
    POLICY_UNAVAILABLE = "policy_unavailable"
    RUNTIME_MISMATCH = "runtime_mismatch"
    INVENTORY_UNSAFE = "inventory_unsafe"
    INVENTORY_CHANGED = "inventory_changed"


class CpythonDependencyCaptureError(RuntimeError):
    _MESSAGES = {
        CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE: (
            "The approved CPython dependency policy is unavailable."
        ),
        CpythonDependencyCaptureErrorCode.RUNTIME_MISMATCH: (
            "The authenticated CPython runtime is inconsistent."
        ),
        CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE: (
            "The CPython native dependency inventory is not trusted."
        ),
        CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED: (
            "The CPython native dependency inventory changed after inspection."
        ),
    }

    def __init__(self, code: CpythonDependencyCaptureErrorCode) -> None:
        if type(code) is not CpythonDependencyCaptureErrorCode:
            raise ValueError("Unknown CPython dependency-capture error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"CpythonDependencyCaptureError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class HeldCpythonDependencyEvidence:
    dependency: CpythonDependencyEvidence = field(repr=False)
    held_file_count: int
    held_directory_count: int
    exact_policy_paths_bound: bool
    unsigned_state_structurally_verified: bool
    handles_retained_through_operation: bool
    arbitrary_dynamic_destinations_denied_by_this_layer: bool

    def __post_init__(self) -> None:
        if (
            type(self.dependency) is not CpythonDependencyEvidence
            or self.held_file_count != self.dependency.pe_file_count
            or not 1 <= self.held_directory_count <= self.held_file_count
            or self.exact_policy_paths_bound is not True
            or self.unsigned_state_structurally_verified is not True
            or self.handles_retained_through_operation is not True
            # Holding exact files prevents replacement but cannot police an
            # arbitrary absolute LoadLibrary destination in the child.
            or self.arbitrary_dynamic_destinations_denied_by_this_layer is not False
        ):
            raise ValueError("Held CPython dependency evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "HeldCpythonDependencyEvidence("
            f"held_file_count={self.held_file_count}, "
            f"held_directory_count={self.held_directory_count}, <redacted>)"
        )


def _fail(code: CpythonDependencyCaptureErrorCode) -> NoReturn:
    raise CpythonDependencyCaptureError(code)


def _canonical_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(CpythonDependencyCaptureErrorCode.RUNTIME_MISMATCH)
    path = value.replace("/", "\\")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if not PureWindowsPath(normalized).is_absolute():
        _fail(CpythonDependencyCaptureErrorCode.RUNTIME_MISMATCH)
    return ntpath.normcase(normalized)


def _target(root: PureWindowsPath, relative: str) -> PureWindowsPath:
    parts = PurePosixPath(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail(CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE)
    target = root.joinpath(*parts)
    canonical_root = _canonical_path(str(root))
    canonical_target = _canonical_path(str(target))
    try:
        common = ntpath.commonpath((canonical_root, canonical_target))
    except ValueError:
        _fail(CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE)
    if common != canonical_root:
        _fail(CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE)
    return target


def _metadata(bound_file: HandleBoundFile) -> PeImageMetadata:
    try:
        result = bound_file.inspect_same_handle_random_access(
            lambda reader, _snapshot: inspect_pe_image_metadata(reader)
        )
    except Exception:
        _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
    if type(result) is not PeImageMetadata:
        _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
    return result


def _default_inspector(
    bound_file: HandleBoundFile,
    record: ApprovedDependencyFile | NonAmd64PeFile,
    *,
    authenticode_backend: AuthenticodeBackend | None,
    clock: VerificationClock | None,
) -> DependencyFileObservation:
    metadata = _metadata(bound_file)
    machine = _MACHINE_BY_CODE.get(metadata.machine_code)
    if machine is None:
        _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
    manifest = None
    signer: str | None = None
    if isinstance(record, ApprovedDependencyFile):
        if machine is not PeMachine.AMD64:
            _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
        manifest = inspect_handle_bound_pe_dependencies(bound_file)
        if (
            record.signature_policy
            is DependencySignaturePolicy.EXACT_AUTHENTICODE_SIGNER
        ):
            if (
                not metadata.embedded_certificate_table_present
                or record.signer_certificate_sha256 is None
            ):
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
            evidence = verify_package_bound_dependency_authenticode_signer(
                bound_file,
                record.signer_certificate_sha256,
                backend=authenticode_backend,
                clock=clock,
            )
            if evidence.file_sha256 != bound_file.snapshot.sha256:
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
            signer = evidence.signer_certificate_sha256
        elif (
            record.signature_policy
            is DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY
        ):
            if metadata.embedded_certificate_table_present:
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
        else:
            _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
    else:
        if machine is not record.machine or metadata.embedded_certificate_table_present:
            _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
    return DependencyFileObservation(
        path=record.path,
        sha256=bound_file.snapshot.sha256,
        machine=machine,
        signer_certificate_sha256=signer,
        dependency_manifest=manifest,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _HeldDependency:
    path: str = field(repr=False)
    bound_file: HandleBoundFile = field(repr=False)
    supplied_executable: bool


class HeldCpythonDependencyInventory:
    """Own exact CPython native files across one synchronous operation."""

    __slots__ = (
        "_active_owner",
        "_directories",
        "_evidence",
        "_executable",
        "_files",
        "_lifetime_lock",
    )

    def __init__(
        self,
        *,
        executable: HandleBoundFile,
        directories: tuple[PathHierarchyTrust, ...],
        files: tuple[_HeldDependency, ...],
        evidence: HeldCpythonDependencyEvidence,
    ) -> None:
        if (
            type(executable) is not HandleBoundFile
            or executable.closed
            or type(directories) is not tuple
            or type(files) is not tuple
            or type(evidence) is not HeldCpythonDependencyEvidence
            or any(type(item) is not PathHierarchyTrust for item in directories)
            or any(type(item) is not _HeldDependency for item in files)
            or len(directories) != evidence.held_directory_count
            or len(files) != evidence.held_file_count
            or sum(item.supplied_executable for item in files) != 1
            or not any(
                item.supplied_executable and item.bound_file is executable
                for item in files
            )
        ):
            raise ValueError("Held CPython dependency inventory is invalid.")
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None
        self._executable = executable
        self._directories = directories
        self._files = files
        self._evidence = evidence

    @property
    def evidence(self) -> HeldCpythonDependencyEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return not self._files

    def _begin_use(self) -> None:
        self._lifetime_lock.acquire()
        if self._active_owner is not None or not self._files:
            self._lifetime_lock.release()
            _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
        self._active_owner = threading.get_ident()

    def _end_use(self) -> None:
        self._active_owner = None
        self._lifetime_lock.release()

    def _assert_unchanged_owned(self) -> HeldCpythonDependencyEvidence:
        try:
            self._executable.assert_unchanged()
            for directory in self._directories:
                directory.assert_unchanged()
            for held in self._files:
                held.bound_file.assert_unchanged()
        except Exception:
            _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
        return self._evidence

    def _held_files(self) -> tuple[HandleBoundFile, ...]:
        output: list[HandleBoundFile] = []
        for held in self._files:
            if not any(present is held.bound_file for present in output):
                output.append(held.bound_file)
        return tuple(output)

    def _run_under_file_leases(
        self,
        files: tuple[HandleBoundFile, ...],
        index: int,
        operation: Callable[[], _Result],
    ) -> _Result:
        if index == len(files):
            return operation()
        return files[index].run_while_held(
            lambda: self._run_under_file_leases(files, index + 1, operation)
        )

    def assert_unchanged(self) -> HeldCpythonDependencyEvidence:
        self._begin_use()
        try:
            return self._assert_unchanged_owned()
        finally:
            self._end_use()

    def run_while_held(self, operation: Callable[[], _Result]) -> _Result:
        """Run one synchronous operation while every trusted handle is held."""

        if not callable(operation):
            raise ValueError("The held CPython operation is invalid.")
        self._begin_use()
        try:
            try:
                for directory in self._directories:
                    directory.assert_unchanged()
            except Exception:
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
            try:
                result = self._run_under_file_leases(self._held_files(), 0, operation)
            except WindowsSecurityError:
                try:
                    for directory in self._directories:
                        directory.assert_unchanged()
                except Exception:
                    pass
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
            except BaseException:
                try:
                    for directory in self._directories:
                        directory.assert_unchanged()
                except Exception:
                    _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
                raise
            try:
                for directory in self._directories:
                    directory.assert_unchanged()
            except Exception:
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
            return result
        finally:
            self._end_use()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
            files = self._files
            directories = self._directories
            self._files = ()
            self._directories = ()
            for held in reversed(files):
                if not held.supplied_executable:
                    try:
                        held.bound_file.close()
                    except BaseException:
                        pass
            for directory in reversed(directories):
                try:
                    directory.close()
                except BaseException:
                    pass

    def __enter__(self) -> "HeldCpythonDependencyInventory":
        if self.closed:
            _fail(CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"HeldCpythonDependencyInventory(state={state!r}, <redacted>)"


def _close_files(files: list[_HeldDependency]) -> None:
    for held in reversed(files):
        if not held.supplied_executable:
            try:
                held.bound_file.close()
            except BaseException:
                pass


def _close_directories(directories: list[PathHierarchyTrust]) -> None:
    for directory in reversed(directories):
        try:
            directory.close()
        except BaseException:
            pass


def capture_package_bound_cpython_dependency_inventory(
    executable: HandleBoundFile,
    *,
    path_api: WindowsPathTrustApi | None = None,
    file_api: WindowsFileApi | None = None,
    authenticode_backend: AuthenticodeBackend | None = None,
    clock: VerificationClock | None = None,
) -> HeldCpythonDependencyInventory:
    """Capture the exact packaged CPython native inventory from held python.exe."""

    if type(executable) is not HandleBoundFile or executable.closed:
        _fail(CpythonDependencyCaptureErrorCode.RUNTIME_MISMATCH)
    try:
        policy = load_package_bound_runtime_dependency_policy()
    except Exception:
        _fail(CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE)
    if type(policy) is not RuntimeDependencyPolicy:
        _fail(CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE)
    snapshot = executable.snapshot
    if PureWindowsPath(snapshot.final_path).name.casefold() != "python.exe":
        _fail(CpythonDependencyCaptureErrorCode.RUNTIME_MISMATCH)
    root = PureWindowsPath(snapshot.final_path).parent
    records: tuple[ApprovedDependencyFile | NonAmd64PeFile, ...] = tuple(
        sorted(
            (*policy.cpython.loadable_files, *policy.cpython.non_amd64_pe_files),
            key=lambda item: item.path.casefold(),
        )
    )
    if len(records) != policy.cpython.pe_file_count:
        _fail(CpythonDependencyCaptureErrorCode.POLICY_UNAVAILABLE)

    parent_paths = tuple(
        sorted(
            {str(_target(root, record.path).parent) for record in records},
            key=str.casefold,
        )
    )
    directories: list[PathHierarchyTrust] = []
    files: list[_HeldDependency] = []
    observations: list[DependencyFileObservation] = []
    try:
        for parent in parent_paths:
            directories.append(
                capture_path_hierarchy(
                    parent,
                    purpose=PathTrustPurpose.RUNTIME_INSTALL,
                    api=path_api,
                )
            )
        executable_key = _canonical_path(snapshot.final_path)
        for record in records:
            target = _target(root, record.path)
            supplied = _canonical_path(str(target)) == executable_key
            bound = (
                executable
                if supplied
                else capture_handle_bound_file(
                    Path(str(target)),
                    api=file_api,
                    policy=FileCapturePolicy(
                        max_bytes=_MAX_NATIVE_FILE_BYTES,
                        require_single_link=False,
                    ),
                )
            )
            held = _HeldDependency(record.path, bound, supplied)
            files.append(held)
            if _canonical_path(bound.snapshot.final_path) != _canonical_path(
                str(target)
            ):
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
            observation = _default_inspector(
                bound,
                record,
                authenticode_backend=authenticode_backend,
                clock=clock,
            )
            if (
                type(observation) is not DependencyFileObservation
                or observation.path != record.path
                or observation.sha256 != bound.snapshot.sha256
            ):
                _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)
            observations.append(observation)
        dependency = validate_package_bound_cpython_dependency_observations(
            tuple(observations)
        )
        evidence = HeldCpythonDependencyEvidence(
            dependency=dependency,
            held_file_count=len(files),
            held_directory_count=len(directories),
            exact_policy_paths_bound=True,
            unsigned_state_structurally_verified=True,
            handles_retained_through_operation=True,
            arbitrary_dynamic_destinations_denied_by_this_layer=False,
        )
        result = HeldCpythonDependencyInventory(
            executable=executable,
            directories=tuple(directories),
            files=tuple(files),
            evidence=evidence,
        )
        result.assert_unchanged()
        return result
    except CpythonDependencyCaptureError:
        _close_files(files)
        _close_directories(directories)
        raise
    except BaseException as error:
        _close_files(files)
        _close_directories(directories)
        if not isinstance(error, Exception):
            raise
        _fail(CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE)


__all__ = [
    "CpythonDependencyCaptureError",
    "CpythonDependencyCaptureErrorCode",
    "HeldCpythonDependencyEvidence",
    "HeldCpythonDependencyInventory",
    "capture_package_bound_cpython_dependency_inventory",
]
