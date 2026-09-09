"""Held outer inventory for one exact Podman Compose execution transaction.

This source-only owner composes the provider/runtime/endpoint owner with every
remaining authenticated file and directory in the immutable command plan.  It
does not discover, repair, mutate, or authorize a live network peer.
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
from .runtime_dependency_policy import (
    load_package_bound_runtime_dependency_policy,
    package_bound_runtime_dependency_policy_path,
)
from .runtime_dynamic_load import (
    DynamicLoadEnforcementError,
    NativeWindowsProviderChildDynamicLoadBackend,
)
from .runtime_execution import CommandKind, ProcessCommandPlan
from .runtime_policy import (
    load_package_bound_runtime_policy,
    package_bound_runtime_policy_path,
)
from .runtime_load_trust import LoadableAuthenticator, RuntimeLoadInventoryApi
from .runtime_provider_child import ProcessImageBinding, ProviderChildProcessRequest
from .runtime_provider_inventory import (
    HeldProviderChildCommandResult,
    HeldProviderChildInventory,
    ProviderChildInventoryError,
    capture_provider_child_inventory,
)
from .target_contracts import FileIdentity
from .windows_path_trust import (
    PathHierarchyTrust,
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_mutex import (
    HeldRuntimeTransactionLocks,
    RuntimeTransactionLockBinding,
    RuntimeTransactionLockError,
    RuntimeTransactionLockErrorCode,
    WindowsMutexApi,
    acquire_ordered_runtime_transaction_locks,
    runtime_transaction_lock_binding,
)
from .windows_security import (
    FileCapturePolicy,
    HandleBoundFile,
    PathLocality,
    ReparseKind,
    WindowsFileApi,
    WindowsSecurityError,
    capture_handle_bound_file,
)

_BINDING_DOMAIN = b"TowerScout.HeldRuntimeTransactionInventory.v1"
_EVIDENCE_DOMAIN = b"TowerScout.RuntimeTransactionInventoryEvidence.v1"
_MAX_TRANSACTION_INPUT_BYTES = 16 * 1024 * 1024
_Result = TypeVar("_Result")


class RuntimeTransactionInventoryErrorCode(str, Enum):
    INVALID_BINDING = "invalid_binding"
    INVENTORY_MISMATCH = "inventory_mismatch"
    INVENTORY_CHANGED = "inventory_changed"


class RuntimeTransactionInventoryError(RuntimeError):
    """Sanitized outer-inventory failure."""

    _MESSAGES = {
        RuntimeTransactionInventoryErrorCode.INVALID_BINDING: (
            "The runtime transaction binding is invalid."
        ),
        RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH: (
            "The held runtime inputs do not match the resolved target."
        ),
        RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED: (
            "A held runtime input changed during the operation."
        ),
    }

    def __init__(self, code: RuntimeTransactionInventoryErrorCode) -> None:
        if type(code) is not RuntimeTransactionInventoryErrorCode:
            raise ValueError("Unknown runtime transaction inventory error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeTransactionInventoryError(code={self.code.value!r})"


def _fail(code: RuntimeTransactionInventoryErrorCode) -> NoReturn:
    raise RuntimeTransactionInventoryError(code)


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
        _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
    path = value.replace("/", "\\")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if not PureWindowsPath(normalized).is_absolute():
        _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
    return ntpath.normcase(normalized)


def _expected_input_files(plan: ProcessCommandPlan) -> tuple[FileIdentity, ...]:
    compose = plan.target.compose
    environment = (compose.environment_source,)
    return (
        *compose.ordered_files,
        *environment,
        *plan.target.security_artifacts.ordered_files,
    )


def _expected_directory_paths(plan: ProcessCommandPlan) -> tuple[FileIdentity, ...]:
    environment = plan.target.process_environment
    return (
        plan.target.package_root,
        environment.system_root,
        environment.temp_directory,
        environment.user_profile,
        environment.local_app_data,
        environment.roaming_app_data,
    )


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
    classification = snapshot.classification
    try:
        return (
            ProcessImageBinding.from_snapshot(
                snapshot, entrypoint=False
            ).matches_file_identity(identity)
            and snapshot.size == identity.size_bytes
            and classification.locality is PathLocality.FIXED_LOCAL
            and classification.reparse_kind
            in {ReparseKind.NONE, ReparseKind.KNOWN_CLOUD_PLACEHOLDER}
            and classification.hydrated is True
            and classification.regular_file is True
            and classification.single_link is True
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


def _path_matches_identity(
    path: PathHierarchyTrust,
    identity: FileIdentity,
    purpose: PathTrustPurpose,
) -> bool:
    if (
        type(path) is not PathHierarchyTrust
        or path.closed
        or type(identity) is not FileIdentity
        or not identity.is_directory
        or path.evidence.purpose is not purpose
    ):
        return False
    snapshot = path.root_snapshot
    try:
        return (
            snapshot.identity.volume_serial == identity.volume_serial
            and snapshot.identity.file_id == identity.file_id
            and _canonical_path(snapshot.final_path)
            == _canonical_path(str(identity.final_path))
        )
    except (TypeError, ValueError, UnicodeError):
        return False


def _paths_match(
    held: tuple[PathHierarchyTrust, ...], expected: tuple[FileIdentity, ...]
) -> bool:
    return len(held) == len(expected) and all(
        _path_matches_identity(
            path,
            identity,
            (
                PathTrustPurpose.PACKAGE_ROOT
                if index == 0
                else PathTrustPurpose.PROCESS_ENVIRONMENT
            ),
        )
        for index, (path, identity) in enumerate(zip(held, expected, strict=True))
    )


def _close_partial_capture(
    input_files: list[HandleBoundFile],
    directory_paths: list[PathHierarchyTrust],
) -> bool:
    failed = False
    for directory in reversed(directory_paths):
        try:
            directory.close()
        except BaseException:
            failed = True
    for bound_file in reversed(input_files):
        try:
            bound_file.close()
        except BaseException:
            failed = True
    return failed


def capture_runtime_transaction_inventory(
    plan: ProcessCommandPlan,
    provider_inventory: HeldProviderChildInventory,
    *,
    file_api: WindowsFileApi | None = None,
    path_api: WindowsPathTrustApi | None = None,
) -> "HeldRuntimeTransactionInventory":
    """Capture every outer plan input and transfer them into one owner.

    On success the returned owner owns ``provider_inventory`` and all newly
    captured objects.  On failure it closes only objects captured here; the
    caller retains ownership of ``provider_inventory``.  The caller must not
    use or close ``provider_inventory`` concurrently while this ownership
    transfer is in progress.
    """

    if (
        type(plan) is not ProcessCommandPlan
        or plan.kind is not CommandKind.PODMAN_COMPOSE
        or type(provider_inventory) is not HeldProviderChildInventory
        or provider_inventory.closed
    ):
        _fail(RuntimeTransactionInventoryErrorCode.INVALID_BINDING)
    try:
        request = ProviderChildProcessRequest.from_plan(plan)
    except Exception:
        _fail(RuntimeTransactionInventoryErrorCode.INVALID_BINDING)
    if (
        provider_inventory.target_token != plan.target_token
        or provider_inventory.request_binding_sha256 != request.binding_sha256
    ):
        _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
    expected_files = _expected_input_files(plan)
    expected_paths = _expected_directory_paths(plan)
    input_files: list[HandleBoundFile] = []
    directory_paths: list[PathHierarchyTrust] = []
    try:
        for identity in expected_files:
            if not 0 <= identity.size_bytes <= _MAX_TRANSACTION_INPUT_BYTES:
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
            bound_file = capture_handle_bound_file(
                Path(str(identity.final_path)),
                api=file_api,
                policy=FileCapturePolicy(
                    max_bytes=max(1, identity.size_bytes),
                    require_single_link=True,
                    allow_hydrated_cloud_placeholder=True,
                ),
            )
            input_files.append(bound_file)
            if not _snapshot_matches_identity(bound_file, identity):
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)

        for index, identity in enumerate(expected_paths):
            path = capture_path_hierarchy(
                str(identity.final_path),
                purpose=(
                    PathTrustPurpose.PACKAGE_ROOT
                    if index == 0
                    else PathTrustPurpose.PROCESS_ENVIRONMENT
                ),
                api=path_api,
            )
            directory_paths.append(path)
            if not _path_matches_identity(
                path,
                identity,
                (
                    PathTrustPurpose.PACKAGE_ROOT
                    if index == 0
                    else PathTrustPurpose.PROCESS_ENVIRONMENT
                ),
            ):
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)

        return HeldRuntimeTransactionInventory(
            plan=plan,
            provider_inventory=provider_inventory,
            input_files=tuple(input_files),
            directory_paths=tuple(directory_paths),
        )
    except RuntimeTransactionInventoryError:
        if _close_partial_capture(input_files, directory_paths):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        raise
    except (WindowsSecurityError, OSError, RuntimeError, TypeError, ValueError):
        if _close_partial_capture(input_files, directory_paths):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
    except BaseException:
        _close_partial_capture(input_files, directory_paths)
        raise


def _binding_digest(
    plan: ProcessCommandPlan,
    request_binding_sha256: str,
    input_files: tuple[HandleBoundFile, ...],
    directory_paths: tuple[PathHierarchyTrust, ...],
    runtime_policy_sha256: str,
    dependency_policy_sha256: str,
) -> str:
    digest = hashlib.sha256()
    values = (
        _BINDING_DOMAIN,
        plan.target.target_token.digest_sha256.encode("ascii"),
        request_binding_sha256.encode("ascii"),
        runtime_policy_sha256.encode("ascii"),
        dependency_policy_sha256.encode("ascii"),
        *(
            value
            for bound_file in input_files
            for value in (
                bound_file.snapshot.identity.volume_serial.to_bytes(8, "big"),
                bound_file.snapshot.identity.file_id,
                bound_file.snapshot.sha256.encode("ascii"),
                _canonical_path(bound_file.snapshot.final_path).encode(
                    "utf-16-le", errors="strict"
                ),
            )
        ),
        *(
            value
            for path in directory_paths
            for value in (
                path.root_snapshot.identity.volume_serial.to_bytes(8, "big"),
                path.root_snapshot.identity.file_id,
                path.evidence.purpose.value.encode("ascii"),
                _canonical_path(path.root_snapshot.final_path).encode(
                    "utf-16-le", errors="strict"
                ),
            )
        ),
    )
    for value in values:
        _add(digest, value)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeTransactionInventoryEvidence:
    target_token: str
    transaction_binding_sha256: str = field(repr=False)
    request_binding_sha256: str = field(repr=False)
    provider_inventory_evidence_sha256: str = field(repr=False)
    input_file_count: int
    directory_path_count: int
    compose_inputs_held_through_execution: bool
    security_artifacts_held_through_execution: bool
    process_environment_held_through_execution: bool
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
                    self.transaction_binding_sha256,
                    self.request_binding_sha256,
                    self.provider_inventory_evidence_sha256,
                )
            )
            or type(self.input_file_count) is not int
            or self.input_file_count < 5
            or self.directory_path_count != 6
            or self.compose_inputs_held_through_execution is not True
            or self.security_artifacts_held_through_execution is not True
            or self.process_environment_held_through_execution is not True
            or self.live_network_peer_observed is not False
        ):
            raise ValueError("Runtime transaction inventory evidence is invalid.")
        digest = hashlib.sha256()
        for value in (
            _EVIDENCE_DOMAIN,
            self.target_token.encode("ascii"),
            self.transaction_binding_sha256.encode("ascii"),
            self.request_binding_sha256.encode("ascii"),
            self.provider_inventory_evidence_sha256.encode("ascii"),
            self.input_file_count.to_bytes(4, "big"),
            self.directory_path_count.to_bytes(4, "big"),
            bytes(
                (
                    self.compose_inputs_held_through_execution,
                    self.security_artifacts_held_through_execution,
                    self.process_environment_held_through_execution,
                    self.live_network_peer_observed,
                )
            ),
        ):
            _add(digest, value)
        object.__setattr__(self, "evidence_sha256", digest.hexdigest())

    def __repr__(self) -> str:
        return (
            "RuntimeTransactionInventoryEvidence("
            f"target_token={self.target_token!r}, "
            f"input_files={self.input_file_count}, "
            f"directory_paths={self.directory_path_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True)
class RuntimeTransactionLockEvidence:
    target_token: str
    environment_abandoned: bool
    target_abandoned: bool
    held_inventory_revalidated: bool

    def __post_init__(self) -> None:
        if (
            type(self.target_token) is not str
            or not self.target_token.startswith("TSRT1-")
            or len(self.target_token) != 38
            or any(
                character not in "0123456789abcdef"
                for character in self.target_token[6:]
            )
            or type(self.environment_abandoned) is not bool
            or type(self.target_abandoned) is not bool
            or self.held_inventory_revalidated is not True
        ):
            raise ValueError("Runtime transaction lock evidence is invalid.")


@dataclass(frozen=True, slots=True, repr=False)
class HeldRuntimeTransactionCommandResult:
    provider_result: HeldProviderChildCommandResult = field(repr=False)
    evidence: RuntimeTransactionInventoryEvidence

    def __post_init__(self) -> None:
        if (
            type(self.provider_result) is not HeldProviderChildCommandResult
            or type(self.evidence) is not RuntimeTransactionInventoryEvidence
            or self.provider_result.evidence.target_token != self.evidence.target_token
            or self.provider_result.evidence.request_binding_sha256
            != self.evidence.request_binding_sha256
            or self.provider_result.evidence.evidence_sha256
            != self.evidence.provider_inventory_evidence_sha256
        ):
            raise ValueError("Held runtime transaction result is invalid.")

    def __repr__(self) -> str:
        return (
            "HeldRuntimeTransactionCommandResult("
            f"target_token={self.evidence.target_token!r}, "
            f"exit_code={self.provider_result.command.command.exit_code}, <redacted>)"
        )


class HeldRuntimeTransactionInventory:
    """Own every non-provider plan input around the exact provider owner."""

    __slots__ = (
        "_active_owner",
        "_binding_sha256",
        "_directory_paths",
        "_input_files",
        "_lock",
        "_plan",
        "_provider_inventory",
        "_request_binding_sha256",
        "_transaction_locks",
        "_transaction_lock_evidence",
        "_transaction_lock_owner_thread",
    )

    def __init__(
        self,
        *,
        plan: ProcessCommandPlan,
        provider_inventory: HeldProviderChildInventory,
        input_files: tuple[HandleBoundFile, ...],
        directory_paths: tuple[PathHierarchyTrust, ...],
    ) -> None:
        try:
            request = ProviderChildProcessRequest.from_plan(plan)
            runtime_policy = load_package_bound_runtime_policy()
            dependency_policy = load_package_bound_runtime_dependency_policy()
            runtime_policy_sha256 = runtime_policy.content_sha256
            dependency_policy_sha256 = dependency_policy.content_sha256
            runtime_policy_path = package_bound_runtime_policy_path()
            dependency_policy_path = package_bound_runtime_dependency_policy_path()
        except Exception:
            _fail(RuntimeTransactionInventoryErrorCode.INVALID_BINDING)
        expected_files = _expected_input_files(plan)
        expected_paths = _expected_directory_paths(plan)
        if (
            type(plan) is not ProcessCommandPlan
            or plan.kind is not CommandKind.PODMAN_COMPOSE
            or type(provider_inventory) is not HeldProviderChildInventory
            or provider_inventory.closed
            or provider_inventory.target_token != plan.target_token
            or provider_inventory.request_binding_sha256 != request.binding_sha256
            or type(input_files) is not tuple
            or type(directory_paths) is not tuple
            or not _files_match(input_files, expected_files)
            or not _paths_match(directory_paths, expected_paths)
            or len({id(item) for item in input_files}) != len(input_files)
            or len({item.snapshot.identity for item in input_files}) != len(input_files)
            or len({id(item) for item in directory_paths}) != len(directory_paths)
            or len({item.root_snapshot.identity for item in directory_paths})
            != len(directory_paths)
            or not _is_sha256(runtime_policy_sha256)
            or not _is_sha256(dependency_policy_sha256)
            or runtime_policy_sha256
            != plan.target.security_artifacts.runtime_policy.sha256
            or dependency_policy_sha256
            != plan.target.security_artifacts.runtime_dependency_policy.sha256
            or _canonical_path(str(runtime_policy_path))
            != _canonical_path(
                str(plan.target.security_artifacts.runtime_policy.final_path)
            )
            or _canonical_path(str(dependency_policy_path))
            != _canonical_path(
                str(plan.target.security_artifacts.runtime_dependency_policy.final_path)
            )
        ):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
        self._lock = threading.RLock()
        self._active_owner: int | None = None
        self._plan = plan
        self._provider_inventory: HeldProviderChildInventory | None = provider_inventory
        self._input_files: tuple[HandleBoundFile, ...] | None = input_files
        self._directory_paths: tuple[PathHierarchyTrust, ...] | None = directory_paths
        self._request_binding_sha256 = request.binding_sha256
        self._transaction_locks: HeldRuntimeTransactionLocks | None = None
        self._transaction_lock_evidence: RuntimeTransactionLockEvidence | None = None
        self._transaction_lock_owner_thread: int | None = None
        self._binding_sha256 = _binding_digest(
            plan,
            request.binding_sha256,
            input_files,
            directory_paths,
            runtime_policy_sha256,
            dependency_policy_sha256,
        )

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._provider_inventory is None

    @property
    def locks_acquired(self) -> bool:
        with self._lock:
            return (
                self._transaction_locks is not None
                and not self._transaction_locks.closed
            )

    @property
    def lock_evidence(self) -> RuntimeTransactionLockEvidence | None:
        with self._lock:
            if (
                self._transaction_locks is None
                or self._transaction_locks.closed
                or self._transaction_lock_evidence is None
            ):
                return None
            return self._transaction_lock_evidence

    def _begin_use(
        self,
    ) -> tuple[
        HeldProviderChildInventory,
        tuple[HandleBoundFile, ...],
        tuple[PathHierarchyTrust, ...],
    ]:
        self._lock.acquire()
        provider_inventory = self._provider_inventory
        input_files = self._input_files
        directory_paths = self._directory_paths
        if (
            self._active_owner is not None
            or provider_inventory is None
            or input_files is None
            or directory_paths is None
            or (
                self._transaction_locks is not None
                and self._transaction_lock_owner_thread != threading.get_ident()
            )
        ):
            self._lock.release()
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        self._active_owner = threading.get_ident()
        return provider_inventory, input_files, directory_paths

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

    def _execute_while_held(
        self,
        backend: NativeWindowsProviderChildDynamicLoadBackend,
        provider_inventory: HeldProviderChildInventory,
        input_files: tuple[HandleBoundFile, ...],
        directory_paths: tuple[PathHierarchyTrust, ...],
    ) -> HeldRuntimeTransactionCommandResult:
        if not self._active_inventory_matches(
            provider_inventory, input_files, directory_paths
        ):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        outer_validation_failed = False

        def validate_outer_inventory() -> bool:
            nonlocal outer_validation_failed
            valid = self._active_inventory_matches(
                provider_inventory, input_files, directory_paths
            )
            outer_validation_failed = not valid
            return valid

        try:
            provider_result = provider_inventory.execute(
                backend,
                pre_execute_validator=validate_outer_inventory,
            )
        except ProviderChildInventoryError:
            if outer_validation_failed:
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
            raise
        if (
            type(provider_result) is not HeldProviderChildCommandResult
            or provider_result.evidence.target_token != self._plan.target_token
            or provider_result.evidence.request_binding_sha256
            != self._request_binding_sha256
        ):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        evidence = RuntimeTransactionInventoryEvidence(
            target_token=self._plan.target_token,
            transaction_binding_sha256=self._binding_sha256,
            request_binding_sha256=self._request_binding_sha256,
            provider_inventory_evidence_sha256=(
                provider_result.evidence.evidence_sha256
            ),
            input_file_count=len(input_files),
            directory_path_count=len(directory_paths),
            compose_inputs_held_through_execution=True,
            security_artifacts_held_through_execution=True,
            process_environment_held_through_execution=True,
            live_network_peer_observed=False,
        )
        return HeldRuntimeTransactionCommandResult(provider_result, evidence)

    def _active_inventory_matches(
        self,
        provider_inventory: HeldProviderChildInventory,
        input_files: tuple[HandleBoundFile, ...],
        directory_paths: tuple[PathHierarchyTrust, ...],
    ) -> bool:
        try:
            for path in directory_paths:
                path.assert_unchanged_while_held()
            for bound_file in input_files:
                bound_file.assert_unchanged_while_held()
            for path in directory_paths:
                path.assert_unchanged_while_held()
            return (
                _files_match(input_files, _expected_input_files(self._plan))
                and _paths_match(directory_paths, _expected_directory_paths(self._plan))
                and provider_inventory.target_token == self._plan.target_token
                and provider_inventory.request_binding_sha256
                == self._request_binding_sha256
            )
        except (
            RuntimeTransactionInventoryError,
            WindowsSecurityError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            return False

    def _lock_binding_while_outer_inventory_held(
        self,
        provider_inventory: HeldProviderChildInventory,
        input_files: tuple[HandleBoundFile, ...],
        directory_paths: tuple[PathHierarchyTrust, ...],
    ) -> RuntimeTransactionLockBinding:
        if not self._active_inventory_matches(
            provider_inventory, input_files, directory_paths
        ):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        try:
            provider_inventory.assert_unchanged()
            if not self._active_inventory_matches(
                provider_inventory, input_files, directory_paths
            ):
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
            return runtime_transaction_lock_binding(
                self._plan.target,
                directory_paths[0].root_snapshot.identity,
            )
        except RuntimeTransactionInventoryError:
            raise
        except Exception:
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)

    def acquire_transaction_locks(
        self,
        *,
        api: WindowsMutexApi | None = None,
        timeout_ms: int = 0,
    ) -> RuntimeTransactionLockEvidence:
        """Acquire and retain the ordered lock pair after full revalidation.

        The current capture owner cannot yet prove that an absent ``.env`` leaf
        stayed absent. That state therefore remains fail-closed until the
        handle-safe atomic replacement slice supplies an absence proof.
        """

        provider_inventory, input_files, directory_paths = self._begin_use()
        try:
            if (
                self._transaction_locks is not None
                or self._plan.target.compose.environment_file is None
            ):
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)

            def revalidate() -> RuntimeTransactionLockBinding:
                return self._run_under_path_leases(
                    directory_paths,
                    0,
                    lambda: self._run_under_file_leases(
                        input_files,
                        0,
                        lambda: self._lock_binding_while_outer_inventory_held(
                            provider_inventory,
                            input_files,
                            directory_paths,
                        ),
                    ),
                )

            binding = revalidate()
            transaction_locks = acquire_ordered_runtime_transaction_locks(
                binding,
                revalidate,
                api=api,
                timeout_ms=timeout_ms,
            )
            self._transaction_locks = transaction_locks
            self._transaction_lock_owner_thread = threading.get_ident()
            evidence = RuntimeTransactionLockEvidence(
                target_token=self._plan.target_token,
                environment_abandoned=transaction_locks.environment_abandoned,
                target_abandoned=transaction_locks.target_abandoned,
                held_inventory_revalidated=True,
            )
            self._transaction_lock_evidence = evidence
            return evidence
        except (RuntimeTransactionInventoryError, RuntimeTransactionLockError):
            raise
        except Exception:
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        finally:
            self._end_use()

    def execute(
        self, backend: NativeWindowsProviderChildDynamicLoadBackend
    ) -> HeldRuntimeTransactionCommandResult:
        if type(backend) is not NativeWindowsProviderChildDynamicLoadBackend:
            _fail(RuntimeTransactionInventoryErrorCode.INVALID_BINDING)
        provider_inventory, input_files, directory_paths = self._begin_use()
        try:
            return self._run_under_path_leases(
                directory_paths,
                0,
                lambda: self._run_under_file_leases(
                    input_files,
                    0,
                    lambda: self._execute_while_held(
                        backend,
                        provider_inventory,
                        input_files,
                        directory_paths,
                    ),
                ),
            )
        except RuntimeTransactionInventoryError:
            raise
        except (DynamicLoadEnforcementError, ProviderChildInventoryError):
            raise
        except (
            WindowsSecurityError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        finally:
            self._end_use()

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
            if (
                self._transaction_locks is not None
                and self._transaction_lock_owner_thread != threading.get_ident()
            ):
                raise RuntimeTransactionLockError(
                    RuntimeTransactionLockErrorCode.WRONG_THREAD
                ) from None
            provider_inventory = self._provider_inventory
            input_files = self._input_files
            directory_paths = self._directory_paths
            transaction_locks = self._transaction_locks
            self._provider_inventory = None
            self._input_files = None
            self._directory_paths = None
            self._transaction_locks = None
            self._transaction_lock_evidence = None
            self._transaction_lock_owner_thread = None
            if (
                provider_inventory is None
                or input_files is None
                or directory_paths is None
            ):
                return
            failures = False
            closeables: tuple[Any, ...] = (
                provider_inventory,
                *reversed(input_files),
                *reversed(directory_paths),
                *((transaction_locks,) if transaction_locks is not None else ()),
            )
            for closeable in closeables:
                try:
                    closeable.close()
                except BaseException:
                    failures = True
            if failures:
                _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)

    def __enter__(self) -> "HeldRuntimeTransactionInventory":
        if self.closed:
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "HeldRuntimeTransactionInventory("
            f"target_token={self._plan.target_token!r}, "
            f"state={state!r}, <redacted>)"
        )


def _close_factory_owner(closeable: Any | None) -> bool:
    if closeable is None:
        return False
    try:
        closeable.close()
    except BaseException:
        return True
    return False


def capture_locked_runtime_transaction_inventory(
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
    mutex_api: WindowsMutexApi | None = None,
    lock_timeout_ms: int = 0,
) -> HeldRuntimeTransactionInventory:
    """Capture and lock one exact resolved Podman transaction inventory.

    The caller supplies two already-held executable identities from the secure
    resolver. Provider construction transfers them into the composite owner.
    Any later failure closes all transferred resources before returning a
    sanitized error. This function performs no child execution or mutation.
    """

    provider_inventory: HeldProviderChildInventory | None = None
    transaction_inventory: HeldRuntimeTransactionInventory | None = None
    try:
        provider_inventory = capture_provider_child_inventory(
            plan,
            provider_base_executable,
            child_executable,
            path_api=path_api,
            file_api=file_api,
            runtime_inventory_api=runtime_inventory_api,
            loadable_authenticate=loadable_authenticate,
            authenticode_backend=authenticode_backend,
            clock=clock,
        )
        transaction_inventory = capture_runtime_transaction_inventory(
            plan,
            provider_inventory,
            path_api=path_api,
            file_api=file_api,
        )
        provider_inventory = None
        evidence = transaction_inventory.acquire_transaction_locks(
            api=mutex_api,
            timeout_ms=lock_timeout_ms,
        )
        if (
            type(evidence) is not RuntimeTransactionLockEvidence
            or transaction_inventory.lock_evidence != evidence
            or not transaction_inventory.locks_acquired
        ):
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        return transaction_inventory
    except (
        ProviderChildInventoryError,
        RuntimeTransactionInventoryError,
        RuntimeTransactionLockError,
    ):
        failed = _close_factory_owner(transaction_inventory)
        if transaction_inventory is None:
            failed = _close_factory_owner(provider_inventory) or failed
        if failed:
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        failed = _close_factory_owner(transaction_inventory)
        if transaction_inventory is None:
            failed = _close_factory_owner(provider_inventory) or failed
        if failed:
            _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_CHANGED)
        _fail(RuntimeTransactionInventoryErrorCode.INVENTORY_MISMATCH)
    except BaseException:
        _close_factory_owner(transaction_inventory)
        if transaction_inventory is None:
            _close_factory_owner(provider_inventory)
        raise


__all__ = [
    "HeldRuntimeTransactionCommandResult",
    "HeldRuntimeTransactionInventory",
    "RuntimeTransactionInventoryError",
    "RuntimeTransactionInventoryErrorCode",
    "RuntimeTransactionInventoryEvidence",
    "RuntimeTransactionLockEvidence",
    "capture_locked_runtime_transaction_inventory",
    "capture_runtime_transaction_inventory",
]
