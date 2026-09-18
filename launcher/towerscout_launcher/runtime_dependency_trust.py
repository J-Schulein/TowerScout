"""Pure validation for package-bound runtime dependency observations.

This module compares already captured file hashes, signer fingerprints, PE
machine types, and dependency manifests with the package-bound policy.  It
does not open files, enumerate directories, invoke Authenticode, alter DLL
search state, load code, or execute a child.  Native capture and lifetime
ownership remain a later integration boundary.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import NoReturn, Protocol

from .pe_dependencies import PeDependencyManifest, parse_pe_dependencies
from .runtime_dependency_policy import (
    PeMachine,
    ProductDependencyPolicy,
    RuntimeDependencyPolicy,
    load_package_bound_runtime_dependency_policy,
)
from .runtime_policy import RuntimeProductId
from .windows_security import HandleBoundFile, WindowsSecurityError

_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_MAX_OBSERVATIONS = 64
_CPYTHON_EVIDENCE_DOMAIN = b"TowerScout.CpythonDependencyEvidence.v1"
_ENTRYPOINT_EVIDENCE_DOMAIN = b"TowerScout.EntrypointDependencyEvidence.v1"


class RuntimeDependencyTrustErrorCode(str, Enum):
    POLICY_UNAVAILABLE = "policy_unavailable"
    INSPECTION_UNAVAILABLE = "inspection_unavailable"
    INVENTORY_MISMATCH = "inventory_mismatch"
    DEPENDENCY_UNAPPROVED = "dependency_unapproved"


class RuntimeDependencyTrustError(RuntimeError):
    """Sanitized mismatch with no file path, import name, or fingerprint."""

    _MESSAGES = {
        RuntimeDependencyTrustErrorCode.POLICY_UNAVAILABLE: (
            "The approved runtime dependency policy is unavailable."
        ),
        RuntimeDependencyTrustErrorCode.INSPECTION_UNAVAILABLE: (
            "The held runtime dependency could not be inspected safely."
        ),
        RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH: (
            "The runtime native-file inventory does not match the approved artifact."
        ),
        RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED: (
            "The runtime dependency surface is not approved."
        ),
    }

    def __init__(self, code: RuntimeDependencyTrustErrorCode) -> None:
        if type(code) is not RuntimeDependencyTrustErrorCode:
            raise ValueError("Unknown runtime dependency-trust error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeDependencyTrustError(code={self.code.value!r})"


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


@dataclass(frozen=True, slots=True, repr=False)
class DependencyFileObservation:
    path: str = field(repr=False)
    sha256: str = field(repr=False)
    machine: PeMachine
    signer_certificate_sha256: str | None = field(repr=False)
    dependency_manifest: PeDependencyManifest | None = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not self.path
            or len(self.path) > 1024
            or self.path != self.path.strip()
            or "\x00" in self.path
            or type(self.machine) is not PeMachine
            or not _is_sha256(self.sha256)
            or (
                self.signer_certificate_sha256 is not None
                and not _is_sha256(self.signer_certificate_sha256)
            )
            or (
                self.dependency_manifest is not None
                and type(self.dependency_manifest) is not PeDependencyManifest
            )
        ):
            raise ValueError("Runtime dependency file observation is invalid.")

    def __repr__(self) -> str:
        return (
            "DependencyFileObservation("
            f"machine={self.machine.value!r}, "
            f"has_signer={self.signer_certificate_sha256 is not None}, "
            f"has_manifest={self.dependency_manifest is not None}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CpythonDependencyEvidence:
    product_id: RuntimeProductId
    exact_version: str
    policy_sha256: str = field(repr=False)
    archive_sha256: str = field(repr=False)
    inventory_sha256: str = field(repr=False)
    static_import_surface_sha256: str = field(repr=False)
    pe_file_count: int
    amd64_loadable_count: int
    signer_policy_count: int
    exact_native_inventory_bound: bool
    static_dependency_manifests_closed: bool
    dynamic_load_policy_required: bool

    def __post_init__(self) -> None:
        if (
            self.product_id is not RuntimeProductId.CPYTHON
            or self.exact_version != "3.12.10"
            or not _is_sha256(self.policy_sha256)
            or not _is_sha256(self.archive_sha256)
            or not _is_sha256(self.inventory_sha256)
            or not _is_sha256(self.static_import_surface_sha256)
            or self.pe_file_count != 47
            or self.amd64_loadable_count != 43
            or self.signer_policy_count != 5
            or self.exact_native_inventory_bound is not True
            or self.static_dependency_manifests_closed is not True
            or self.dynamic_load_policy_required is not True
        ):
            raise ValueError("CPython dependency evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "CpythonDependencyEvidence("
            f"exact_version={self.exact_version!r}, "
            f"pe_file_count={self.pe_file_count}, "
            f"amd64_loadable_count={self.amd64_loadable_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EntrypointDependencyEvidence:
    product_id: RuntimeProductId
    policy_sha256: str = field(repr=False)
    dependency_manifest_sha256: str = field(repr=False)
    evidence_sha256: str = field(repr=False)
    static_entrypoint_imports_approved: bool
    transitive_application_inventory_required: bool

    def __post_init__(self) -> None:
        if (
            self.product_id
            not in {
                RuntimeProductId.DOCKER_CLI,
                RuntimeProductId.DOCKER_COMPOSE,
                RuntimeProductId.PODMAN_CLI,
            }
            or not _is_sha256(self.policy_sha256)
            or not _is_sha256(self.dependency_manifest_sha256)
            or not _is_sha256(self.evidence_sha256)
            or self.static_entrypoint_imports_approved is not True
            or self.transitive_application_inventory_required is not True
        ):
            raise ValueError("Runtime entrypoint dependency evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "EntrypointDependencyEvidence("
            f"product_id={self.product_id.value!r}, <redacted>)"
        )


def _fail(code: RuntimeDependencyTrustErrorCode) -> NoReturn:
    raise RuntimeDependencyTrustError(code)


def inspect_handle_bound_pe_dependencies(
    bound_file: HandleBoundFile,
) -> PeDependencyManifest:
    """Parse dependency tables through one revalidated held-file handle."""

    if type(bound_file) is not HandleBoundFile:
        _fail(RuntimeDependencyTrustErrorCode.INSPECTION_UNAVAILABLE)
    try:
        result = bound_file.inspect_same_handle_random_access(
            lambda reader, _snapshot: parse_pe_dependencies(reader)
        )
    except WindowsSecurityError:
        _fail(RuntimeDependencyTrustErrorCode.INSPECTION_UNAVAILABLE)
    if type(result) is not PeDependencyManifest:
        _fail(RuntimeDependencyTrustErrorCode.INSPECTION_UNAVAILABLE)
    return result


class _Digest(Protocol):
    def update(self, value: bytes) -> None: ...


def _add_digest_value(digest: _Digest, value: bytes | str) -> None:
    encoded = value if isinstance(value, bytes) else value.encode("utf-8")
    digest.update(struct.pack(">Q", len(encoded)))
    digest.update(encoded)


def _inventory_digest(
    policy: RuntimeDependencyPolicy,
    observations: tuple[DependencyFileObservation, ...],
) -> str:
    digest = hashlib.sha256()
    _add_digest_value(digest, _CPYTHON_EVIDENCE_DOMAIN)
    _add_digest_value(digest, policy.content_sha256)
    for observation in observations:
        _add_digest_value(digest, observation.path)
        _add_digest_value(digest, observation.sha256)
        _add_digest_value(digest, observation.machine.value)
        _add_digest_value(
            digest,
            observation.signer_certificate_sha256 or b"unsigned",
        )
        _add_digest_value(
            digest,
            (
                observation.dependency_manifest.evidence_sha256
                if observation.dependency_manifest is not None
                else b"not-loadable"
            ),
        )
    return digest.hexdigest()


def _import_surface_digest(
    policy: RuntimeDependencyPolicy,
    observations: tuple[DependencyFileObservation, ...],
) -> str:
    digest = hashlib.sha256()
    _add_digest_value(digest, _CPYTHON_EVIDENCE_DOMAIN + b".Imports")
    _add_digest_value(digest, policy.content_sha256)
    for observation in observations:
        manifest = observation.dependency_manifest
        if manifest is None:
            continue
        _add_digest_value(digest, observation.path)
        _add_digest_value(digest, manifest.evidence_sha256)
    return digest.hexdigest()


def _validate_cpython_observations(
    policy: RuntimeDependencyPolicy,
    observations: tuple[DependencyFileObservation, ...],
) -> CpythonDependencyEvidence:
    if (
        type(policy) is not RuntimeDependencyPolicy
        or type(observations) is not tuple
        or len(observations) != policy.cpython.pe_file_count
        or len(observations) > _MAX_OBSERVATIONS
        or any(type(item) is not DependencyFileObservation for item in observations)
        or observations
        != tuple(sorted(observations, key=lambda item: item.path.casefold()))
        or len({item.path.casefold() for item in observations}) != len(observations)
    ):
        _fail(RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH)

    approved_loadable = {
        record.path.casefold(): record for record in policy.cpython.loadable_files
    }
    approved_non_amd64 = {
        record.path.casefold(): record for record in policy.cpython.non_amd64_pe_files
    }
    if set(item.path.casefold() for item in observations) != set(
        (*approved_loadable, *approved_non_amd64)
    ):
        _fail(RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH)

    observed_imports: set[str] = set()
    for observation in observations:
        key = observation.path.casefold()
        if key in approved_loadable:
            approved = approved_loadable[key]
            manifest = observation.dependency_manifest
            if (
                observation.path != approved.path
                or observation.sha256 != approved.sha256
                or observation.machine is not PeMachine.AMD64
                or observation.signer_certificate_sha256
                != approved.signer_certificate_sha256
                or manifest is None
                or manifest.evidence_sha256 != approved.dependency_manifest_sha256
            ):
                _fail(RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH)
            observed_imports.update(
                manifest.direct_imports
                + manifest.delay_imports
                + manifest.forwarded_imports
            )
            continue

        approved_other = approved_non_amd64[key]
        if (
            observation.path != approved_other.path
            or observation.sha256 != approved_other.sha256
            or observation.machine is not approved_other.machine
            or observation.signer_certificate_sha256 is not None
            or observation.dependency_manifest is not None
        ):
            _fail(RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH)

    system = set(policy.cpython.declared_system_imports)
    api_sets = set(policy.cpython.declared_api_set_imports)
    private = set(policy.cpython.declared_private_imports)
    if (
        not observed_imports.issubset(system | api_sets | private)
        or (observed_imports & system) != system
        or (observed_imports & api_sets) != api_sets
    ):
        _fail(RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED)
    loadable_leaves = {
        PurePosixPath(record.path).name.casefold()
        for record in policy.cpython.loadable_files
    }
    if not private.issubset(loadable_leaves):
        _fail(RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED)

    return CpythonDependencyEvidence(
        product_id=RuntimeProductId.CPYTHON,
        exact_version=policy.cpython.exact_version,
        policy_sha256=policy.content_sha256,
        archive_sha256=policy.cpython.archive_sha256,
        inventory_sha256=_inventory_digest(policy, observations),
        static_import_surface_sha256=_import_surface_digest(policy, observations),
        pe_file_count=len(observations),
        amd64_loadable_count=len(approved_loadable),
        signer_policy_count=len(policy.cpython.signers),
        exact_native_inventory_bound=True,
        static_dependency_manifests_closed=True,
        # Static PE tables cannot prove arbitrary absolute-path dynamic loads.
        dynamic_load_policy_required=True,
    )


def validate_package_bound_cpython_dependency_observations(
    observations: tuple[DependencyFileObservation, ...],
) -> CpythonDependencyEvidence:
    """Validate exact CPython native observations against the bundled policy."""

    try:
        policy = load_package_bound_runtime_dependency_policy()
    except Exception:
        _fail(RuntimeDependencyTrustErrorCode.POLICY_UNAVAILABLE)
    return _validate_cpython_observations(policy, observations)


def _entrypoint_digest(
    policy: RuntimeDependencyPolicy,
    product: ProductDependencyPolicy,
    manifest: PeDependencyManifest,
) -> str:
    digest = hashlib.sha256()
    for value in (
        _ENTRYPOINT_EVIDENCE_DOMAIN,
        policy.content_sha256,
        product.product_id.value,
        manifest.evidence_sha256,
    ):
        _add_digest_value(digest, value)
    return digest.hexdigest()


def validate_package_bound_entrypoint_dependencies(
    product_id: RuntimeProductId,
    manifest: PeDependencyManifest,
) -> EntrypointDependencyEvidence:
    """Validate one supported container-client entrypoint import manifest."""

    if (
        type(product_id) is not RuntimeProductId
        or type(manifest) is not PeDependencyManifest
        or product_id is RuntimeProductId.CPYTHON
    ):
        _fail(RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED)
    try:
        policy = load_package_bound_runtime_dependency_policy()
        product = policy.product(product_id)
    except Exception:
        _fail(RuntimeDependencyTrustErrorCode.POLICY_UNAVAILABLE)
    expected = product.entrypoint_imports
    if (
        manifest.direct_imports != expected.direct
        or manifest.delay_imports != expected.delay
        or manifest.forwarded_imports != expected.forwarded
    ):
        _fail(RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED)
    return EntrypointDependencyEvidence(
        product_id=product_id,
        policy_sha256=policy.content_sha256,
        dependency_manifest_sha256=manifest.evidence_sha256,
        evidence_sha256=_entrypoint_digest(policy, product, manifest),
        static_entrypoint_imports_approved=True,
        transitive_application_inventory_required=True,
    )


__all__ = [
    "CpythonDependencyEvidence",
    "DependencyFileObservation",
    "EntrypointDependencyEvidence",
    "RuntimeDependencyTrustError",
    "RuntimeDependencyTrustErrorCode",
    "inspect_handle_bound_pe_dependencies",
    "validate_package_bound_cpython_dependency_observations",
    "validate_package_bound_entrypoint_dependencies",
]
