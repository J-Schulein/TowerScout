"""Held provider, runtime-child, and Podman endpoint execution inventory.

This source-only owner binds one already validated Podman Compose plan to the
authenticated provider artifacts, the provider's authenticated base CPython
closure, the authenticated Podman load surface, and the endpoint identity-key
artifacts.  It supplies role policies only while every underlying handle is
leased.  It does not discover a connection, install a provider, mutate runtime
state, or claim that the live network peer has been observed.
"""

from __future__ import annotations

import hashlib
import ntpath
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, NoReturn, TypeVar

from .authenticode import AuthenticodeBackend, VerificationClock
from .runtime_dependency_capture import (
    CpythonDependencyCaptureError,
    HeldCpythonDependencyInventory,
    capture_package_bound_cpython_dependency_inventory,
)
from .runtime_dynamic_load import (
    DynamicLoadEnforcementError,
    NativeWindowsProviderChildDynamicLoadBackend,
    ProviderChildCommandResult,
)
from .runtime_execution import CommandKind, ProcessCommandPlan
from .runtime_load_trust import (
    LoadableAuthenticator,
    RuntimeLoadInventoryApi,
    RuntimeLoadPrerequisites,
    RuntimeLoadTrustError,
    capture_runtime_load_prerequisites,
)
from .runtime_policy import RuntimeProductId, load_package_bound_runtime_policy
from .runtime_provider_child import (
    ProcessImageBinding,
    ProcessImagePolicy,
    ProcessImageRole,
    ProviderChildProcessRequest,
)
from .target_contracts import FileIdentity, RuntimeProduct
from .windows_path_trust import WindowsPathTrustApi
from .windows_security import (
    FileCapturePolicy,
    HandleBoundFile,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_BINDING_DOMAIN = b"TowerScout.HeldProviderChildInventory.v1"
_EVIDENCE_DOMAIN = b"TowerScout.ProviderChildInventoryEvidence.v1"
_MAX_PROVIDER_ARTIFACT_BYTES = 16 * 1024 * 1024
_Result = TypeVar("_Result")


class ProviderChildInventoryErrorCode(str, Enum):
    INVALID_BINDING = "invalid_binding"
    INVENTORY_MISMATCH = "inventory_mismatch"
    INVENTORY_CHANGED = "inventory_changed"


class ProviderChildInventoryError(RuntimeError):
    _MESSAGES = {
        ProviderChildInventoryErrorCode.INVALID_BINDING: (
            "The provider-child execution binding is invalid."
        ),
        ProviderChildInventoryErrorCode.INVENTORY_MISMATCH: (
            "The provider-child inventory does not match the resolved target."
        ),
        ProviderChildInventoryErrorCode.INVENTORY_CHANGED: (
            "The provider-child inventory changed during the operation."
        ),
    }

    def __init__(self, code: ProviderChildInventoryErrorCode) -> None:
        if type(code) is not ProviderChildInventoryErrorCode:
            raise ValueError("Unknown provider-child inventory error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"ProviderChildInventoryError(code={self.code.value!r})"


def _fail(code: ProviderChildInventoryErrorCode) -> NoReturn:
    raise ProviderChildInventoryError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _canonical_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
    path = value.replace("/", "\\")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if not PureWindowsPath(normalized).is_absolute():
        _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
    return ntpath.normcase(normalized)


def _snapshot_matches_identity(
    bound_file: HandleBoundFile, identity: FileIdentity
) -> bool:
    if (
        type(bound_file) is not HandleBoundFile
        or bound_file.closed
        or type(identity) is not FileIdentity
        or identity.is_directory
    ):
        return False
    snapshot = bound_file.snapshot
    try:
        return (
            ProcessImageBinding.from_snapshot(
                snapshot, entrypoint=False
            ).matches_file_identity(identity)
            and snapshot.size == identity.size_bytes
        )
    except (TypeError, ValueError, UnicodeError):
        return False


def _files_match(
    held: tuple[HandleBoundFile, ...], expected: tuple[FileIdentity, ...]
) -> bool:
    return len(held) == len(expected) and all(
        _snapshot_matches_identity(bound_file, identity)
        for bound_file, identity in zip(held, expected, strict=True)
    )


def _capture_exact_files(
    identities: tuple[FileIdentity, ...],
    *,
    file_api: WindowsFileApi | None,
) -> list[HandleBoundFile]:
    captured: list[HandleBoundFile] = []
    try:
        for identity in identities:
            if not 1 <= identity.size_bytes <= _MAX_PROVIDER_ARTIFACT_BYTES:
                _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
            bound_file = capture_handle_bound_file(
                Path(str(identity.final_path)),
                api=file_api,
                policy=FileCapturePolicy(
                    max_bytes=identity.size_bytes,
                    require_single_link=True,
                    allow_hydrated_cloud_placeholder=True,
                ),
            )
            captured.append(bound_file)
            if not _snapshot_matches_identity(bound_file, identity):
                _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
        return captured
    except BaseException as error:
        failed = False
        for bound_file in reversed(captured):
            try:
                bound_file.close()
            except BaseException:
                failed = True
        if failed and isinstance(error, Exception):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        raise


def _close_partial_provider_capture(
    provider_runtime_inventory: HeldCpythonDependencyInventory | None,
    child_runtime_inventory: RuntimeLoadPrerequisites | None,
    provider_artifacts: list[HandleBoundFile],
    endpoint_artifacts: list[HandleBoundFile],
) -> bool:
    failed = False
    closeables: tuple[Any, ...] = (
        *((child_runtime_inventory,) if child_runtime_inventory is not None else ()),
        *(
            (provider_runtime_inventory,)
            if provider_runtime_inventory is not None
            else ()
        ),
        *reversed(endpoint_artifacts),
        *reversed(provider_artifacts),
    )
    for closeable in closeables:
        try:
            closeable.close()
        except BaseException:
            failed = True
    return failed


def capture_provider_child_inventory(
    plan: ProcessCommandPlan,
    provider_base_executable: HandleBoundFile,
    child_executable: HandleBoundFile,
    *,
    path_api: WindowsPathTrustApi | None = None,
    file_api: WindowsFileApi | None = None,
    runtime_inventory_api: RuntimeLoadInventoryApi | None = None,
    loadable_authenticate: LoadableAuthenticator | None = None,
    authenticode_backend: AuthenticodeBackend | None = None,
    clock: VerificationClock | None = None,
) -> "HeldProviderChildInventory":
    """Capture one provider/runtime/endpoint owner from resolver-held inputs.

    The two executable handles remain caller-owned on failure. Successful
    construction transfers both handles and every newly captured prerequisite
    to the returned owner.
    """

    if (
        type(plan) is not ProcessCommandPlan
        or plan.kind is not CommandKind.PODMAN_COMPOSE
        or plan.target.runtime.product is not RuntimeProduct.PODMAN
        or type(provider_base_executable) is not HandleBoundFile
        or provider_base_executable.closed
        or type(child_executable) is not HandleBoundFile
        or child_executable.closed
        or provider_base_executable is child_executable
        or not _snapshot_matches_identity(
            child_executable, plan.target.runtime.executable
        )
        or plan.target.endpoint.identity_key is None
    ):
        _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
    try:
        ProviderChildProcessRequest.from_plan(plan)
    except (TypeError, ValueError):
        _fail(ProviderChildInventoryErrorCode.INVALID_BINDING)

    provider_runtime_inventory: HeldCpythonDependencyInventory | None = None
    child_runtime_inventory: RuntimeLoadPrerequisites | None = None
    provider_artifacts: list[HandleBoundFile] = []
    endpoint_artifacts: list[HandleBoundFile] = []
    try:
        provider_artifacts = _capture_exact_files(
            plan.target.compose_provider.artifacts,
            file_api=file_api,
        )
        endpoint_artifacts = _capture_exact_files(
            (
                plan.target.endpoint.identity_key,
                *plan.target.endpoint.discovery_artifacts,
            ),
            file_api=file_api,
        )
        provider_runtime_inventory = capture_package_bound_cpython_dependency_inventory(
            provider_base_executable,
            path_api=path_api,
            file_api=file_api,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )
        child_runtime_inventory = capture_runtime_load_prerequisites(
            RuntimeProductId.PODMAN_CLI,
            child_executable,
            path_api=path_api,
            inventory_api=runtime_inventory_api,
            file_api=file_api,
            authenticate=loadable_authenticate,
        )
        return HeldProviderChildInventory(
            plan=plan,
            provider_runtime_inventory=provider_runtime_inventory,
            child_runtime_inventory=child_runtime_inventory,
            provider_base_executable=provider_base_executable,
            child_executable=child_executable,
            provider_artifacts=tuple(provider_artifacts),
            endpoint_artifacts=tuple(endpoint_artifacts),
        )
    except ProviderChildInventoryError:
        if _close_partial_provider_capture(
            provider_runtime_inventory,
            child_runtime_inventory,
            provider_artifacts,
            endpoint_artifacts,
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        raise
    except (
        CpythonDependencyCaptureError,
        RuntimeLoadTrustError,
        WindowsSecurityError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        if _close_partial_provider_capture(
            provider_runtime_inventory,
            child_runtime_inventory,
            provider_artifacts,
            endpoint_artifacts,
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
    except BaseException:
        _close_partial_provider_capture(
            provider_runtime_inventory,
            child_runtime_inventory,
            provider_artifacts,
            endpoint_artifacts,
        )
        raise


def _binding_digest(
    plan: ProcessCommandPlan,
    request: ProviderChildProcessRequest,
    provider_artifacts: tuple[HandleBoundFile, ...],
    endpoint_artifacts: tuple[HandleBoundFile, ...],
    runtime_policy_sha256: str,
) -> str:
    digest = hashlib.sha256()
    values = (
        _BINDING_DOMAIN,
        plan.target.target_token.digest_sha256.encode("ascii"),
        plan.target.compose_provider.integrity_sha256.encode("ascii"),
        plan.target.endpoint.private_metadata_sha256.encode("ascii"),
        plan.target.endpoint.canonical_endpoint.encode("utf-8", errors="strict"),
        request.binding_sha256.encode("ascii"),
        runtime_policy_sha256.encode("ascii"),
        *(
            value
            for bound_file in (*provider_artifacts, *endpoint_artifacts)
            for value in (
                bound_file.snapshot.identity.volume_serial.to_bytes(8, "big"),
                bound_file.snapshot.identity.file_id,
                bound_file.snapshot.sha256.encode("ascii"),
                _canonical_path(bound_file.snapshot.final_path).encode(
                    "utf-16-le", errors="strict"
                ),
            )
        ),
    )
    for value in values:
        _add(digest, value)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ProviderChildInventoryEvidence:
    target_token: str
    inventory_binding_sha256: str = field(repr=False)
    request_binding_sha256: str = field(repr=False)
    provider_policy_sha256: str = field(repr=False)
    child_policy_sha256: str = field(repr=False)
    enforcement_evidence_sha256: str = field(repr=False)
    provider_artifact_count: int
    endpoint_artifact_count: int
    constructed_endpoint_environment: bool
    provider_rediscovery_denied_by_policy: bool
    endpoint_artifacts_held_through_execution: bool
    live_network_peer_observed: bool
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.target_token) is not str
            or not self.target_token.startswith("TSRT1-")
            or len(self.target_token) != 38
            or any(
                character not in "0123456789abcdef"
                for character in self.target_token[6:]
            )
            or any(
                not _is_sha256(value)
                for value in (
                    self.inventory_binding_sha256,
                    self.request_binding_sha256,
                    self.provider_policy_sha256,
                    self.child_policy_sha256,
                    self.enforcement_evidence_sha256,
                )
            )
            or type(self.provider_artifact_count) is not int
            or self.provider_artifact_count < 2
            or type(self.endpoint_artifact_count) is not int
            or self.endpoint_artifact_count < 1
            or self.constructed_endpoint_environment is not True
            or self.provider_rediscovery_denied_by_policy is not True
            or self.endpoint_artifacts_held_through_execution is not True
            or self.live_network_peer_observed is not False
        ):
            raise ValueError("Provider-child inventory evidence is invalid.")
        digest = hashlib.sha256()
        for value in (
            _EVIDENCE_DOMAIN,
            self.target_token.encode("ascii"),
            self.inventory_binding_sha256.encode("ascii"),
            self.request_binding_sha256.encode("ascii"),
            self.provider_policy_sha256.encode("ascii"),
            self.child_policy_sha256.encode("ascii"),
            self.enforcement_evidence_sha256.encode("ascii"),
            self.provider_artifact_count.to_bytes(4, "big"),
            self.endpoint_artifact_count.to_bytes(4, "big"),
            bytes(
                (
                    self.constructed_endpoint_environment,
                    self.provider_rediscovery_denied_by_policy,
                    self.endpoint_artifacts_held_through_execution,
                    self.live_network_peer_observed,
                )
            ),
        ):
            _add(digest, value)
        object.__setattr__(self, "evidence_sha256", digest.hexdigest())

    def __repr__(self) -> str:
        return (
            "ProviderChildInventoryEvidence("
            f"target_token={self.target_token!r}, "
            f"provider_artifacts={self.provider_artifact_count}, "
            f"endpoint_artifacts={self.endpoint_artifact_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class HeldProviderChildCommandResult:
    command: ProviderChildCommandResult = field(repr=False)
    evidence: ProviderChildInventoryEvidence

    def __post_init__(self) -> None:
        if (
            type(self.command) is not ProviderChildCommandResult
            or type(self.evidence) is not ProviderChildInventoryEvidence
            or self.command.enforcement.evidence_sha256
            != self.evidence.enforcement_evidence_sha256
        ):
            raise ValueError("Held provider-child result is invalid.")

    def __repr__(self) -> str:
        return (
            "HeldProviderChildCommandResult("
            f"target_token={self.evidence.target_token!r}, "
            f"exit_code={self.command.command.exit_code}, <redacted>)"
        )


class HeldProviderChildInventory:
    """Own and lease one exact provider/runtime/endpoint execution binding."""

    __slots__ = (
        "_active_owner",
        "_binding_sha256",
        "_child_executable",
        "_child_runtime_inventory",
        "_endpoint_artifacts",
        "_lock",
        "_plan",
        "_provider_artifacts",
        "_provider_base_executable",
        "_provider_runtime_inventory",
        "_request",
    )

    def __init__(
        self,
        *,
        plan: ProcessCommandPlan,
        provider_runtime_inventory: HeldCpythonDependencyInventory,
        child_runtime_inventory: RuntimeLoadPrerequisites,
        provider_base_executable: HandleBoundFile,
        child_executable: HandleBoundFile,
        provider_artifacts: tuple[HandleBoundFile, ...],
        endpoint_artifacts: tuple[HandleBoundFile, ...],
    ) -> None:
        try:
            request = ProviderChildProcessRequest.from_plan(plan)
            policy = load_package_bound_runtime_policy()
        except Exception:
            _fail(ProviderChildInventoryErrorCode.INVALID_BINDING)
        propagation = policy.podman_compose.endpoint_propagation
        if (
            type(plan) is not ProcessCommandPlan
            or plan.kind is not CommandKind.PODMAN_COMPOSE
            or plan.target.runtime.product is not RuntimeProduct.PODMAN
            or type(provider_runtime_inventory) is not HeldCpythonDependencyInventory
            or type(child_runtime_inventory) is not RuntimeLoadPrerequisites
            or child_runtime_inventory.evidence.product_id
            is not RuntimeProductId.PODMAN_CLI
            or type(provider_base_executable) is not HandleBoundFile
            or provider_base_executable.closed
            or PureWindowsPath(
                _canonical_path(provider_base_executable.snapshot.final_path)
            ).name.casefold()
            != "python.exe"
            or type(child_executable) is not HandleBoundFile
            or not _snapshot_matches_identity(
                child_executable, plan.target.runtime.executable
            )
            or type(provider_artifacts) is not tuple
            or any(type(item) is not HandleBoundFile for item in provider_artifacts)
            or type(endpoint_artifacts) is not tuple
            or any(type(item) is not HandleBoundFile for item in endpoint_artifacts)
            or not _files_match(
                provider_artifacts, plan.target.compose_provider.artifacts
            )
            or plan.target.endpoint.identity_key is None
            or not _files_match(
                endpoint_artifacts,
                (
                    plan.target.endpoint.identity_key,
                    *plan.target.endpoint.discovery_artifacts,
                ),
            )
            or len(
                {
                    id(item)
                    for item in (
                        provider_base_executable,
                        child_executable,
                        *provider_artifacts,
                        *endpoint_artifacts,
                    )
                }
            )
            != 2 + len(provider_artifacts) + len(endpoint_artifacts)
            or len(
                {
                    item.snapshot.identity
                    for item in (
                        provider_base_executable,
                        child_executable,
                        *provider_artifacts,
                        *endpoint_artifacts,
                    )
                }
            )
            != 2 + len(provider_artifacts) + len(endpoint_artifacts)
            or propagation.mechanism != "constructed_environment"
            or propagation.required_variables != ("CONTAINER_HOST", "CONTAINER_SSHKEY")
            or propagation.allow_provider_rediscovery is not False
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
        self._lock = threading.RLock()
        self._active_owner: int | None = None
        self._plan = plan
        self._request = request
        self._provider_runtime_inventory = provider_runtime_inventory
        self._child_runtime_inventory = child_runtime_inventory
        self._provider_base_executable = provider_base_executable
        self._child_executable = child_executable
        self._provider_artifacts: tuple[HandleBoundFile, ...] | None = (
            provider_artifacts
        )
        self._endpoint_artifacts: tuple[HandleBoundFile, ...] | None = (
            endpoint_artifacts
        )
        self._binding_sha256 = _binding_digest(
            plan,
            request,
            provider_artifacts,
            endpoint_artifacts,
            policy.content_sha256,
        )

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._provider_artifacts is None

    @property
    def target_token(self) -> str:
        return self._plan.target_token

    @property
    def request_binding_sha256(self) -> str:
        return self._request.binding_sha256

    def _begin_use(
        self,
    ) -> tuple[tuple[HandleBoundFile, ...], tuple[HandleBoundFile, ...]]:
        self._lock.acquire()
        provider_artifacts = self._provider_artifacts
        endpoint_artifacts = self._endpoint_artifacts
        if (
            self._active_owner is not None
            or provider_artifacts is None
            or endpoint_artifacts is None
        ):
            self._lock.release()
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        self._active_owner = threading.get_ident()
        return provider_artifacts, endpoint_artifacts

    def _end_use(self) -> None:
        self._active_owner = None
        self._lock.release()

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

    def _execute_under_inventories(
        self,
        backend: NativeWindowsProviderChildDynamicLoadBackend,
        pre_execute_validator: Callable[[], bool] | None,
    ) -> HeldProviderChildCommandResult:
        provider_policy, child_policy = self._active_policies()
        if pre_execute_validator is not None and pre_execute_validator() is not True:
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        result = backend.execute(self._plan, provider_policy, child_policy)
        if (
            type(result) is not ProviderChildCommandResult
            or result.enforcement.request_binding_sha256 != self._request.binding_sha256
            or result.enforcement.provider_policy_sha256
            != provider_policy.content_sha256
            or result.enforcement.child_policy_sha256 != child_policy.content_sha256
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        evidence = ProviderChildInventoryEvidence(
            target_token=self._plan.target_token,
            inventory_binding_sha256=self._binding_sha256,
            request_binding_sha256=self._request.binding_sha256,
            provider_policy_sha256=provider_policy.content_sha256,
            child_policy_sha256=child_policy.content_sha256,
            enforcement_evidence_sha256=result.enforcement.evidence_sha256,
            provider_artifact_count=len(self._plan.target.compose_provider.artifacts),
            endpoint_artifact_count=(
                1 + len(self._plan.target.endpoint.discovery_artifacts)
            ),
            constructed_endpoint_environment=True,
            provider_rediscovery_denied_by_policy=True,
            endpoint_artifacts_held_through_execution=True,
            live_network_peer_observed=False,
        )
        return HeldProviderChildCommandResult(result, evidence)

    def _active_policies(self) -> tuple[ProcessImagePolicy, ProcessImagePolicy]:
        """Reconstruct both exact policies while every inventory is leased."""

        cpython_policy = self._provider_runtime_inventory.active_dynamic_load_policy()
        cpython_entrypoint = next(
            binding for binding in cpython_policy.exact_files if binding.entrypoint
        )
        if not cpython_entrypoint.matches(self._provider_base_executable.snapshot):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
        provider_artifacts = self._provider_artifacts
        endpoint_artifacts = self._endpoint_artifacts
        if provider_artifacts is None or endpoint_artifacts is None:
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        provider_policy = self._provider_runtime_inventory.active_process_image_policy(
            ProcessImageRole.PROVIDER,
            entrypoint=provider_artifacts[0],
        )
        child_policy = self._child_runtime_inventory.active_process_image_policy(
            ProcessImageRole.RUNTIME_CHILD
        )
        if not child_policy.entrypoint.matches(
            self._child_executable.snapshot
        ) or not child_policy.entrypoint.matches_file_identity(
            self._plan.target.runtime.executable
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_MISMATCH)
        return provider_policy, child_policy

    def _current_artifacts_match(
        self,
        provider_artifacts: tuple[HandleBoundFile, ...],
        endpoint_artifacts: tuple[HandleBoundFile, ...],
    ) -> bool:
        identity_key = self._plan.target.endpoint.identity_key
        return (
            identity_key is not None
            and _files_match(
                provider_artifacts, self._plan.target.compose_provider.artifacts
            )
            and _files_match(
                endpoint_artifacts,
                (
                    identity_key,
                    *self._plan.target.endpoint.discovery_artifacts,
                ),
            )
        )

    def assert_unchanged(self) -> None:
        """Revalidate the full provider/runtime/endpoint inventory without execution."""

        provider_artifacts, endpoint_artifacts = self._begin_use()
        try:
            if not self._current_artifacts_match(
                provider_artifacts, endpoint_artifacts
            ):
                _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)

            def under_provider() -> None:
                def validate_child() -> None:
                    self._active_policies()

                self._child_runtime_inventory.run_while_held(validate_child)

            self._run_under_file_leases(
                (*provider_artifacts, *endpoint_artifacts),
                0,
                lambda: self._provider_runtime_inventory.run_while_held(under_provider),
            )
        except ProviderChildInventoryError:
            raise
        except (
            CpythonDependencyCaptureError,
            RuntimeLoadTrustError,
            WindowsSecurityError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        finally:
            self._end_use()

    def execute(
        self,
        backend: NativeWindowsProviderChildDynamicLoadBackend,
        *,
        pre_execute_validator: Callable[[], bool] | None = None,
    ) -> HeldProviderChildCommandResult:
        if type(backend) is not NativeWindowsProviderChildDynamicLoadBackend or (
            pre_execute_validator is not None and not callable(pre_execute_validator)
        ):
            _fail(ProviderChildInventoryErrorCode.INVALID_BINDING)
        provider_artifacts, endpoint_artifacts = self._begin_use()
        try:
            if not self._current_artifacts_match(
                provider_artifacts, endpoint_artifacts
            ):
                _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)

            def under_provider() -> HeldProviderChildCommandResult:
                return self._child_runtime_inventory.run_while_held(
                    lambda: self._execute_under_inventories(
                        backend, pre_execute_validator
                    )
                )

            return self._run_under_file_leases(
                (*provider_artifacts, *endpoint_artifacts),
                0,
                lambda: self._provider_runtime_inventory.run_while_held(under_provider),
            )
        except ProviderChildInventoryError:
            raise
        except DynamicLoadEnforcementError:
            raise
        except (
            CpythonDependencyCaptureError,
            RuntimeLoadTrustError,
            WindowsSecurityError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        finally:
            self._end_use()

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
            provider_artifacts = self._provider_artifacts
            endpoint_artifacts = self._endpoint_artifacts
            self._provider_artifacts = None
            self._endpoint_artifacts = None
            if provider_artifacts is None or endpoint_artifacts is None:
                return
            failures = False
            closeables: tuple[Any, ...] = (
                self._child_runtime_inventory,
                self._provider_runtime_inventory,
                *reversed(endpoint_artifacts),
                *reversed(provider_artifacts),
                self._child_executable,
                self._provider_base_executable,
            )
            for closeable in closeables:
                try:
                    closeable.close()
                except BaseException:
                    failures = True
            if failures:
                _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)

    def __enter__(self) -> "HeldProviderChildInventory":
        if self.closed:
            _fail(ProviderChildInventoryErrorCode.INVENTORY_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "HeldProviderChildInventory("
            f"target_token={self._plan.target_token!r}, state={state!r}, <redacted>)"
        )


__all__ = [
    "HeldProviderChildCommandResult",
    "HeldProviderChildInventory",
    "ProviderChildInventoryError",
    "ProviderChildInventoryErrorCode",
    "ProviderChildInventoryEvidence",
    "capture_provider_child_inventory",
]
