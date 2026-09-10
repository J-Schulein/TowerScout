"""Owned native Windows execution boundary for exact target observations.

This module remains disconnected from launcher discovery and repair.  Its
factory recaptures every immutable plan input, retains executable load-surface
owners for the whole observation, and transfers that authority together with
one contained executor into the normalization backend.
"""

from __future__ import annotations

import ntpath
import threading
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, TypeVar, cast

from .authenticode import AuthenticodeBackend, VerificationClock
from .runtime_command_native import NativeWindowsTargetObservationCommandBackend
from .runtime_command_version import (
    BoundCommandRuntimeEvidence,
    CommandVersionBackend,
    open_package_bound_command_runtime_evidence,
)
from .runtime_dependency_capture import (
    HeldCpythonDependencyInventory,
    capture_package_bound_cpython_dependency_inventory,
)
from .runtime_identity import (
    InstallationRecordBackend,
    PeProductBackend,
    _BoundFileTransferSlot,
)
from .runtime_dynamic_load import (
    NativeWindowsProviderChildDynamicLoadBackend,
    TargetObservationProviderChildCommandResult,
)
from .runtime_load_trust import (
    LoadableAuthenticator,
    RuntimeLoadInventoryApi,
    RuntimeLoadPrerequisites,
    capture_runtime_load_prerequisites,
)
from .runtime_policy import RuntimeProductId
from .runtime_provider_child import (
    ProcessImagePolicy,
    ProcessImageRole,
    TargetObservationProviderChildProcessRequest,
)
from .runtime_target_observation import (
    ObservationOperation,
    TargetObservationExecutionBinding,
    TargetObservationProcessPlan,
    TargetObservationProcessRequest,
)
from .runtime_target_observation_backend import (
    OwnedTargetObservationBackend,
    TargetObservationProcessResult,
)
from .runtime_target_resolution import TargetResolutionPlan
from .runtime_verification import (
    BoundRuntimeEvidence,
    open_package_bound_runtime_evidence,
)
from .target_contracts import FileIdentity, RuntimeProduct
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
    capture_handle_bound_file,
)

_Result = TypeVar("_Result")
_MAX_OBSERVATION_FILE_BYTES = 1024 * 1024 * 1024


class TargetObservationNativeErrorCode(str, Enum):
    BINDING_INVALID = "binding_invalid"
    AUTHORITY_CHANGED = "authority_changed"
    UNAVAILABLE = "unavailable"


class TargetObservationNativeError(RuntimeError):
    _MESSAGES = {
        TargetObservationNativeErrorCode.BINDING_INVALID: (
            "The native target-observation binding is invalid."
        ),
        TargetObservationNativeErrorCode.AUTHORITY_CHANGED: (
            "A held target-observation input changed."
        ),
        TargetObservationNativeErrorCode.UNAVAILABLE: (
            "Secure native target observation is unavailable."
        ),
    }

    def __init__(self, code: TargetObservationNativeErrorCode) -> None:
        if type(code) is not TargetObservationNativeErrorCode:
            raise ValueError("Unknown native target-observation error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"TargetObservationNativeError(code={self.code.value!r})"


def _fail(code: TargetObservationNativeErrorCode) -> NoReturn:
    raise TargetObservationNativeError(code)


def _canonical_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
    path = value.replace("/", "\\")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if not PureWindowsPath(normalized).is_absolute():
        _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
    return ntpath.normcase(normalized)


def _same_identity(left: FileIdentity, right: FileIdentity) -> bool:
    return (
        left.logical_name == right.logical_name
        and left.final_path == right.final_path
        and left.volume_serial == right.volume_serial
        and left.file_id == right.file_id
        and left.is_directory == right.is_directory
        and left.sha256 == right.sha256
        and left.size_bytes == right.size_bytes
    )


def _snapshot_matches(bound_file: Any, identity: FileIdentity) -> bool:
    try:
        snapshot = bound_file.snapshot
        return (
            bound_file.closed is False
            and identity.is_directory is False
            and snapshot.identity.volume_serial == identity.volume_serial
            and snapshot.identity.file_id == identity.file_id
            and snapshot.sha256 == identity.sha256
            and snapshot.size == identity.size_bytes
            and _canonical_path(snapshot.final_path)
            == _canonical_path(str(identity.final_path))
        )
    except Exception:
        return False


def _path_matches(
    path: Any,
    identity: FileIdentity,
    purpose: PathTrustPurpose,
) -> bool:
    try:
        snapshot = path.root_snapshot
        return (
            path.closed is False
            and identity.is_directory is True
            and path.evidence.purpose is purpose
            and snapshot.identity.volume_serial == identity.volume_serial
            and snapshot.identity.file_id == identity.file_id
            and _canonical_path(snapshot.final_path)
            == _canonical_path(str(identity.final_path))
        )
    except Exception:
        return False


def _provider_base_eligible(handle: Any) -> bool:
    try:
        return bool(
            handle.closed is False
            and PureWindowsPath(handle.snapshot.final_path).name.casefold()
            == "python.exe"
        )
    except Exception:
        return False


def _close_distinct(
    resources: tuple[Any, ...],
) -> tuple[bool, BaseException | None]:
    failed = False
    interruption: BaseException | None = None
    seen: set[int] = set()
    for resource in resources:
        if resource is None or id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            resource.close()
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
    return failed, interruption


class _ObservationCommandBackend(Protocol):
    @property
    def supported(self) -> bool: ...

    def execute(
        self, request: TargetObservationProcessRequest
    ) -> TargetObservationProcessResult: ...


class _ProviderChildBackend(Protocol):
    @property
    def supported(self) -> bool: ...

    def execute_observation(
        self,
        plan: TargetObservationProcessPlan,
        provider_policy: ProcessImagePolicy,
        child_policy: ProcessImagePolicy,
    ) -> TargetObservationProviderChildCommandResult: ...


class HeldTargetObservationAuthority:
    """Retain every exact plan input and load surface through one capture."""

    __slots__ = (
        "_active_owner",
        "_authority_sha256",
        "_directory_identities",
        "_directory_paths",
        "_entrypoint_handles",
        "_general_file_identities",
        "_general_files",
        "_lock",
        "_plan",
        "_provider_entrypoint",
        "_provider_inventory",
        "_runtime_inventories",
    )

    def __init__(
        self,
        *,
        plan: TargetResolutionPlan,
        general_file_identities: tuple[FileIdentity, ...],
        general_files: tuple[Any, ...],
        directory_identities: tuple[FileIdentity, ...],
        directory_paths: tuple[Any, ...],
        entrypoint_handles: tuple[Any, ...],
        runtime_inventories: tuple[Any, ...],
        provider_inventory: Any | None,
        provider_entrypoint: Any | None,
    ) -> None:
        expected_general: tuple[FileIdentity, ...] = ()
        expected_directories: tuple[FileIdentity, ...] = ()
        entrypoint_identities: tuple[FileIdentity, ...] = ()
        try:
            all_identities = (
                TargetObservationExecutionBinding(plan)
                .container_list()
                .authenticated_files
            )
            entrypoint_identities = _entrypoint_identities(plan)
            expected_general = tuple(
                identity
                for identity in all_identities
                if not identity.is_directory
                and not any(
                    _same_identity(identity, entrypoint)
                    for entrypoint in entrypoint_identities
                )
            )
            expected_directories = tuple(
                identity for identity in all_identities if identity.is_directory
            )
        except Exception:
            pass
        if (
            type(plan) is not TargetResolutionPlan
            or type(general_file_identities) is not tuple
            or type(general_files) is not tuple
            or type(directory_identities) is not tuple
            or type(directory_paths) is not tuple
            or type(entrypoint_handles) is not tuple
            or type(runtime_inventories) is not tuple
            or len(general_file_identities) != len(general_files)
            or len(directory_identities) != len(directory_paths)
            or general_file_identities != expected_general
            or directory_identities != expected_directories
            or any(
                not _snapshot_matches(bound_file, identity)
                for bound_file, identity in zip(
                    general_files, general_file_identities, strict=True
                )
            )
            or any(
                not _path_matches(
                    path,
                    identity,
                    (
                        PathTrustPurpose.PACKAGE_ROOT
                        if identity is plan.package_root
                        else PathTrustPurpose.PROCESS_ENVIRONMENT
                    ),
                )
                for path, identity in zip(
                    directory_paths, directory_identities, strict=True
                )
            )
            or any(getattr(item, "closed", True) for item in runtime_inventories)
            or len({id(item) for item in general_files}) != len(general_files)
            or len({id(item) for item in directory_paths}) != len(directory_paths)
        ):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        podman = plan.runtime.product is RuntimeProduct.PODMAN
        expected_entrypoint_count = 3 if podman else 2
        expected_inventory_count = 1 if podman else 2
        if (
            len(entrypoint_handles) != expected_entrypoint_count
            or len(runtime_inventories) != expected_inventory_count
            or len({id(item) for item in entrypoint_handles}) != len(entrypoint_handles)
            or not _snapshot_matches(
                entrypoint_handles[0],
                entrypoint_identities[0],
            )
            or not _snapshot_matches(
                entrypoint_handles[1],
                entrypoint_identities[1],
            )
            or (podman and not _provider_base_eligible(entrypoint_handles[2]))
        ):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        if podman != (provider_inventory is not None):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        if podman != (provider_entrypoint is not None):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        if podman and (
            provider_inventory is None
            or getattr(provider_inventory, "closed", True)
            or provider_entrypoint not in entrypoint_handles
            or not _snapshot_matches(
                provider_entrypoint,
                plan.compose_provider.artifacts[0],
            )
        ):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        self._lock = threading.RLock()
        self._active_owner: int | None = None
        self._plan = plan
        self._authority_sha256 = plan.authority_sha256
        self._general_file_identities = general_file_identities
        self._general_files: tuple[Any, ...] | None = general_files
        self._directory_identities = directory_identities
        self._directory_paths: tuple[Any, ...] | None = directory_paths
        self._entrypoint_handles: tuple[Any, ...] | None = entrypoint_handles
        self._runtime_inventories: tuple[Any, ...] | None = runtime_inventories
        self._provider_inventory: Any | None = provider_inventory
        self._provider_entrypoint: Any | None = provider_entrypoint

    @property
    def authority_sha256(self) -> str:
        return self._authority_sha256

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._general_files is None

    @property
    def active(self) -> bool:
        with self._lock:
            return self._active_owner == threading.get_ident()

    def _assert_inputs(self) -> None:
        files = self._general_files
        paths = self._directory_paths
        inventories = self._runtime_inventories
        if files is None or paths is None or inventories is None:
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        if any(
            not _snapshot_matches(bound_file, identity)
            for bound_file, identity in zip(
                files, self._general_file_identities, strict=True
            )
        ) or any(
            not _path_matches(
                path,
                identity,
                (
                    PathTrustPurpose.PACKAGE_ROOT
                    if identity is self._plan.package_root
                    else PathTrustPurpose.PROCESS_ENVIRONMENT
                ),
            )
            for path, identity in zip(paths, self._directory_identities, strict=True)
        ):
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)

    @staticmethod
    def _run_leases(
        resources: tuple[Any, ...],
        index: int,
        operation: Callable[[], _Result],
    ) -> _Result:
        if index == len(resources):
            return operation()
        return cast(
            _Result,
            resources[index].run_while_held(
                lambda: HeldTargetObservationAuthority._run_leases(
                    resources,
                    index + 1,
                    operation,
                )
            ),
        )

    def run_while_held(self, operation: Callable[[], _Result]) -> _Result:
        if not callable(operation):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        self._lock.acquire()
        if self._active_owner is not None or self.closed:
            self._lock.release()
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        self._active_owner = threading.get_ident()
        try:
            self._assert_inputs()
            files = self._general_files or ()
            paths = self._directory_paths or ()
            inventories = self._runtime_inventories or ()
            provider = (
                () if self._provider_inventory is None else (self._provider_inventory,)
            )
            provider_entrypoint = (
                ()
                if self._provider_entrypoint is None
                else (self._provider_entrypoint,)
            )
            try:
                result = self._run_leases(
                    (*files, *paths, *inventories, *provider_entrypoint, *provider),
                    0,
                    operation,
                )
            except BaseException:
                self._assert_inputs()
                raise
            self._assert_inputs()
            return result
        finally:
            self._active_owner = None
            self._lock.release()

    def active_provider_policies(
        self, plan: TargetObservationProcessPlan
    ) -> tuple[ProcessImagePolicy, ProcessImagePolicy]:
        provider = self._provider_inventory
        entrypoint = self._provider_entrypoint
        inventories = self._runtime_inventories
        if (
            type(plan) is not TargetObservationProcessPlan
            or plan.target is not self._plan
            or self._active_owner != threading.get_ident()
            or provider is None
            or entrypoint is None
            or inventories is None
            or len(inventories) != 1
        ):
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        try:
            provider_policy = provider.active_process_image_policy(
                ProcessImageRole.PROVIDER,
                entrypoint=entrypoint,
            )
            child_policy = inventories[0].active_process_image_policy(
                ProcessImageRole.RUNTIME_CHILD
            )
        except Exception:
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        if (
            type(provider_policy) is not ProcessImagePolicy
            or type(child_policy) is not ProcessImagePolicy
        ):
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        return provider_policy, child_policy

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
            files = self._general_files
            paths = self._directory_paths
            handles = self._entrypoint_handles
            inventories = self._runtime_inventories
            provider = self._provider_inventory
            self._general_files = None
            self._directory_paths = None
            self._entrypoint_handles = None
            self._runtime_inventories = None
            self._provider_inventory = None
            self._provider_entrypoint = None
            if files is None:
                return
            failed, interruption = _close_distinct(
                (
                    provider,
                    *(reversed(inventories or ())),
                    *(reversed(paths or ())),
                    *(reversed(files)),
                    *(reversed(handles or ())),
                )
            )
            if interruption is not None:
                raise interruption
            if failed:
                _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "HeldTargetObservationAuthority("
            f"runtime={self._plan.runtime.product.value!r}, "
            f"state={state!r}, <redacted>)"
        )


class NativeWindowsTargetObservationExecutor:
    """Route exact plans to one of the two reviewed native process boundaries."""

    __slots__ = (
        "_authority",
        "_closed",
        "_command_backend",
        "_plan",
        "_provider_backend",
    )

    def __init__(
        self,
        *,
        plan: TargetResolutionPlan,
        authority: HeldTargetObservationAuthority,
        command_backend: _ObservationCommandBackend | None = None,
        provider_backend: _ProviderChildBackend | None = None,
    ) -> None:
        if (
            type(plan) is not TargetResolutionPlan
            or type(authority) is not HeldTargetObservationAuthority
            or authority.closed
            or authority.authority_sha256 != plan.authority_sha256
        ):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        self._plan = plan
        self._authority = authority
        self._command_backend = (
            command_backend
            if command_backend is not None
            else NativeWindowsTargetObservationCommandBackend()
        )
        self._provider_backend = (
            provider_backend
            if provider_backend is not None
            else NativeWindowsProviderChildDynamicLoadBackend()
        )
        self._closed = False
        if self.supported is not True:
            self._closed = True
            _fail(TargetObservationNativeErrorCode.UNAVAILABLE)

    @property
    def supported(self) -> bool:
        try:
            return (
                not self._closed
                and self._authority.closed is False
                and self._command_backend.supported is True
                and (
                    self._plan.runtime.product is RuntimeProduct.DOCKER
                    or self._provider_backend.supported is True
                )
            )
        except Exception:
            return False

    @property
    def closed(self) -> bool:
        return self._closed

    def execute(
        self, plan: TargetObservationProcessPlan
    ) -> TargetObservationProcessResult:
        if (
            self.supported is not True
            or type(plan) is not TargetObservationProcessPlan
            or plan.target is not self._plan
            or plan.authority_sha256 != self._authority.authority_sha256
            or self._authority.active is not True
        ):
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        try:
            provider_required = (
                self._plan.runtime.product is RuntimeProduct.PODMAN
                and plan.operation
                in {
                    ObservationOperation.COMPOSE_MODEL_CURRENT,
                    ObservationOperation.COMPOSE_MODEL_PLANNED,
                }
            )
            if provider_required:
                provider_policy, child_policy = (
                    self._authority.active_provider_policies(plan)
                )
                request = TargetObservationProviderChildProcessRequest.from_plan(plan)
                result = self._provider_backend.execute_observation(
                    plan,
                    provider_policy,
                    child_policy,
                )
                if (
                    type(result) is not TargetObservationProviderChildCommandResult
                    or result.enforcement.request_binding_sha256
                    != request.binding_sha256
                    or result.enforcement.provider_policy_sha256
                    != provider_policy.content_sha256
                    or result.enforcement.child_policy_sha256
                    != child_policy.content_sha256
                ):
                    _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
                output = result.command
            else:
                output = self._command_backend.execute(
                    TargetObservationProcessRequest.from_plan(plan)
                )
            if (
                type(output) is not TargetObservationProcessResult
                or output.operation is not plan.operation
                or output.authority_sha256 != plan.authority_sha256
                or output.provider_child_claimed is not provider_required
            ):
                _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
            return output
        except TargetObservationNativeError:
            raise

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "NativeWindowsTargetObservationExecutor("
            f"runtime={self._plan.runtime.product.value!r}, state={state!r})"
        )


def _entrypoint_identities(plan: TargetResolutionPlan) -> tuple[FileIdentity, ...]:
    provider = plan.compose_provider.artifacts[0]
    if _same_identity(plan.runtime.executable, provider):
        _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
    return (plan.runtime.executable, provider)


def _capture_file_default(
    identity: FileIdentity,
    *,
    entrypoint: bool,
    file_api: WindowsFileApi | None,
) -> HandleBoundFile:
    if (
        type(identity) is not FileIdentity
        or identity.is_directory
        or not 0 <= identity.size_bytes <= _MAX_OBSERVATION_FILE_BYTES
    ):
        _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
    return capture_handle_bound_file(
        Path(str(identity.final_path)),
        api=file_api,
        policy=FileCapturePolicy(
            max_bytes=max(1, identity.size_bytes),
            require_single_link=not entrypoint,
            allow_hydrated_cloud_placeholder=True,
        ),
    )


def _capture_provider_base_default(
    plan: TargetResolutionPlan,
    *,
    installation_backend: InstallationRecordBackend | None,
    file_api: WindowsFileApi | None,
    pe_backend: PeProductBackend | None,
    authenticode_backend: AuthenticodeBackend | None,
    clock: VerificationClock | None,
) -> HandleBoundFile:
    owner: BoundRuntimeEvidence | None = None
    slot = _BoundFileTransferSlot()
    transferred: HandleBoundFile | None = None
    try:
        owner = open_package_bound_runtime_evidence(
            RuntimeProductId.CPYTHON,
            installation_backend=installation_backend,
            file_api=file_api,
            pe_backend=pe_backend,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )
        if (
            type(owner) is not BoundRuntimeEvidence
            or owner.closed
            or owner.evidence.product_id is not RuntimeProductId.CPYTHON
            or owner.evidence.policy_sha256 != plan.runtime.publisher_policy_sha256
        ):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        owner._transfer_bound_file(slot)  # noqa: SLF001
        transferred = slot.bound_file
        if (
            not owner.closed
            or PureWindowsPath(transferred.snapshot.final_path).name.casefold()
            != "python.exe"
        ):
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        try:
            owner.close()
        finally:
            owner = None
        slot._disarm(transferred)  # noqa: SLF001
        return transferred
    finally:
        if owner is not None:
            owner.close()
        slot.close()


def _evidence_matches_identity(evidence: Any, identity: FileIdentity) -> bool:
    try:
        return bool(
            evidence.file_identity.volume_serial == identity.volume_serial
            and evidence.file_identity.file_id == identity.file_id
            and evidence.file_sha256 == identity.sha256
        )
    except Exception:
        return False


def _capture_verified_entrypoint_default(
    plan: TargetResolutionPlan,
    product_id: RuntimeProductId,
    identity: FileIdentity,
    expected_version: str | None,
    *,
    installation_backend: InstallationRecordBackend | None,
    file_api: WindowsFileApi | None,
    pe_backend: PeProductBackend | None,
    authenticode_backend: AuthenticodeBackend | None,
    version_command_backend: CommandVersionBackend | None,
    clock: VerificationClock | None,
) -> HandleBoundFile:
    owner: BoundRuntimeEvidence | BoundCommandRuntimeEvidence | None = None
    slot = _BoundFileTransferSlot()
    transferred: HandleBoundFile | None = None
    try:
        if product_id is RuntimeProductId.DOCKER_CLI:
            owner = open_package_bound_runtime_evidence(
                product_id,
                installation_backend=installation_backend,
                file_api=file_api,
                pe_backend=pe_backend,
                authenticode_backend=authenticode_backend,
                clock=clock,
            )
        elif product_id in {
            RuntimeProductId.DOCKER_COMPOSE,
            RuntimeProductId.PODMAN_CLI,
        }:
            owner = open_package_bound_command_runtime_evidence(
                product_id,
                installation_backend=installation_backend,
                file_api=file_api,
                authenticode_backend=authenticode_backend,
                command_backend=version_command_backend,
                clock=clock,
            )
        else:
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        evidence = owner.evidence
        if (
            owner.closed
            or evidence.product_id is not product_id
            or evidence.policy_sha256 != plan.runtime.publisher_policy_sha256
            or (
                expected_version is not None
                and evidence.exact_version != expected_version
            )
            or not _evidence_matches_identity(evidence, identity)
        ):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        owner._transfer_bound_file(slot)  # noqa: SLF001
        transferred = slot.bound_file
        if not owner.closed or not _snapshot_matches(transferred, identity):
            _fail(TargetObservationNativeErrorCode.AUTHORITY_CHANGED)
        try:
            owner.close()
        finally:
            owner = None
        slot._disarm(transferred)  # noqa: SLF001
        return transferred
    finally:
        if owner is not None:
            owner.close()
        slot.close()


def capture_native_windows_target_observation_backend(
    plan: TargetResolutionPlan,
    *,
    path_api: WindowsPathTrustApi | None = None,
    file_api: WindowsFileApi | None = None,
    installation_backend: InstallationRecordBackend | None = None,
    pe_backend: PeProductBackend | None = None,
    runtime_inventory_api: RuntimeLoadInventoryApi | None = None,
    loadable_authenticate: LoadableAuthenticator | None = None,
    authenticode_backend: AuthenticodeBackend | None = None,
    clock: VerificationClock | None = None,
    version_command_backend: CommandVersionBackend | None = None,
    command_backend: _ObservationCommandBackend | None = None,
    provider_backend: _ProviderChildBackend | None = None,
    _file_capture: Callable[[FileIdentity, bool], Any] | None = None,
    _path_capture: Callable[[FileIdentity, PathTrustPurpose], Any] | None = None,
    _runtime_capture: Callable[[RuntimeProductId, Any], Any] | None = None,
    _provider_capture: Callable[[Any], Any] | None = None,
    _provider_base_capture: Callable[[], Any] | None = None,
    _verified_entrypoint_capture: (
        Callable[[RuntimeProductId, FileIdentity, str | None], Any] | None
    ) = None,
) -> OwnedTargetObservationBackend:
    """Capture, retain, and transfer one complete native observation owner."""

    if type(plan) is not TargetResolutionPlan:
        _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
    try:
        all_identities = (
            TargetObservationExecutionBinding(plan).container_list().authenticated_files
        )
        entrypoint_identities = _entrypoint_identities(plan)
    except Exception:
        _fail(TargetObservationNativeErrorCode.BINDING_INVALID)

    def capture_file(identity: FileIdentity, entrypoint: bool) -> Any:
        if _file_capture is not None:
            return _file_capture(identity, entrypoint)
        return _capture_file_default(
            identity,
            entrypoint=entrypoint,
            file_api=file_api,
        )

    def capture_path(identity: FileIdentity, purpose: PathTrustPurpose) -> Any:
        if _path_capture is not None:
            return _path_capture(identity, purpose)
        return capture_path_hierarchy(
            str(identity.final_path),
            purpose=purpose,
            api=path_api,
        )

    def capture_runtime(product_id: RuntimeProductId, handle: Any) -> Any:
        if _runtime_capture is not None:
            return _runtime_capture(product_id, handle)
        return capture_runtime_load_prerequisites(
            product_id,
            handle,
            path_api=path_api,
            inventory_api=runtime_inventory_api,
            file_api=file_api,
            authenticate=loadable_authenticate,
        )

    def capture_provider(handle: Any) -> Any:
        if _provider_capture is not None:
            return _provider_capture(handle)
        return capture_package_bound_cpython_dependency_inventory(
            handle,
            path_api=path_api,
            file_api=file_api,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )

    def capture_provider_base() -> Any:
        if _provider_base_capture is not None:
            return _provider_base_capture()
        return _capture_provider_base_default(
            plan,
            installation_backend=installation_backend,
            file_api=file_api,
            pe_backend=pe_backend,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )

    def capture_verified_entrypoint(
        product_id: RuntimeProductId,
        identity: FileIdentity,
        expected_version: str | None,
    ) -> Any:
        if _verified_entrypoint_capture is not None:
            return _verified_entrypoint_capture(
                product_id,
                identity,
                expected_version,
            )
        return _capture_verified_entrypoint_default(
            plan,
            product_id,
            identity,
            expected_version,
            installation_backend=installation_backend,
            file_api=file_api,
            pe_backend=pe_backend,
            authenticode_backend=authenticode_backend,
            version_command_backend=version_command_backend,
            clock=clock,
        )

    entrypoint_handles: list[Any] = []
    general_files: list[Any] = []
    directory_paths: list[Any] = []
    runtime_inventories: list[Any] = []
    provider_inventory: Any | None = None
    authority: HeldTargetObservationAuthority | None = None
    executor: NativeWindowsTargetObservationExecutor | None = None
    transferred = False
    try:
        runtime_product_id = (
            RuntimeProductId.DOCKER_CLI
            if plan.runtime.product is RuntimeProduct.DOCKER
            else RuntimeProductId.PODMAN_CLI
        )
        runtime_handle = capture_verified_entrypoint(
            runtime_product_id,
            plan.runtime.executable,
            plan.runtime.version,
        )
        entrypoint_handles.append(runtime_handle)
        if not _snapshot_matches(runtime_handle, plan.runtime.executable):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        provider_identity = plan.compose_provider.artifacts[0]
        if plan.runtime.product is RuntimeProduct.DOCKER:
            provider_handle = capture_verified_entrypoint(
                RuntimeProductId.DOCKER_COMPOSE,
                provider_identity,
                None,
            )
        else:
            # The managed provider entrypoint is package state, not an
            # allowlisted vendor installation executable.  Keep it single-link.
            provider_handle = capture_file(provider_identity, False)
        entrypoint_handles.append(provider_handle)
        if not _snapshot_matches(provider_handle, provider_identity):
            _fail(TargetObservationNativeErrorCode.BINDING_INVALID)

        runtime_inventories.append(
            capture_runtime(runtime_product_id, entrypoint_handles[0])
        )
        if plan.runtime.product is RuntimeProduct.DOCKER:
            runtime_inventories.append(
                capture_runtime(
                    RuntimeProductId.DOCKER_COMPOSE,
                    entrypoint_handles[1],
                )
            )
        else:
            provider_base = capture_provider_base()
            entrypoint_handles.append(provider_base)
            provider_inventory = capture_provider(provider_base)

        general_identities = tuple(
            identity
            for identity in all_identities
            if not identity.is_directory
            and not any(
                _same_identity(identity, entrypoint)
                for entrypoint in entrypoint_identities
            )
        )
        directory_identities = tuple(
            identity for identity in all_identities if identity.is_directory
        )
        for identity in general_identities:
            handle = capture_file(identity, False)
            general_files.append(handle)
            if not _snapshot_matches(handle, identity):
                _fail(TargetObservationNativeErrorCode.BINDING_INVALID)
        for identity in directory_identities:
            purpose = (
                PathTrustPurpose.PACKAGE_ROOT
                if identity is plan.package_root
                else PathTrustPurpose.PROCESS_ENVIRONMENT
            )
            path = capture_path(identity, purpose)
            directory_paths.append(path)
            if not _path_matches(path, identity, purpose):
                _fail(TargetObservationNativeErrorCode.BINDING_INVALID)

        authority = HeldTargetObservationAuthority(
            plan=plan,
            general_file_identities=general_identities,
            general_files=tuple(general_files),
            directory_identities=directory_identities,
            directory_paths=tuple(directory_paths),
            entrypoint_handles=tuple(entrypoint_handles),
            runtime_inventories=tuple(runtime_inventories),
            provider_inventory=provider_inventory,
            provider_entrypoint=(
                entrypoint_handles[1]
                if plan.runtime.product is RuntimeProduct.PODMAN
                else None
            ),
        )
        executor = NativeWindowsTargetObservationExecutor(
            plan=plan,
            authority=authority,
            command_backend=command_backend,
            provider_backend=provider_backend,
        )
        backend = OwnedTargetObservationBackend(
            plan=plan,
            authority=authority,
            executor=executor,
        )
        transferred = True
        return backend
    except TargetObservationNativeError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(TargetObservationNativeErrorCode.UNAVAILABLE)
    finally:
        if not transferred:
            resources = (
                executor,
                authority,
                provider_inventory,
                *reversed(runtime_inventories),
                *reversed(directory_paths),
                *reversed(general_files),
                *reversed(entrypoint_handles),
            )
            _failed, interruption = _close_distinct(resources)
            if interruption is not None:
                raise interruption


__all__ = [
    "HeldTargetObservationAuthority",
    "NativeWindowsTargetObservationExecutor",
    "TargetObservationNativeError",
    "TargetObservationNativeErrorCode",
    "capture_native_windows_target_observation_backend",
]
