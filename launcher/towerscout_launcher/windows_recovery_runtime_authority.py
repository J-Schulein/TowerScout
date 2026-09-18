"""Hashes-only authority for exact Windows rollback runtime recovery.

The original container may legitimately disappear after an authorized stop.
Recovery therefore cannot use the original container identifier as permanent
authority.  This module binds every stage-stable target input plus all eight
engine-specific volume identities before mutation.  Only the resulting hashes
are suitable for the protected journal; private paths, endpoints, and engine
identifiers remain transient.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import struct
from typing import Any, Iterable, NoReturn

from .runtime_target_resolution import AbsentResolvedRuntimeTarget
from .target_contracts import (
    EXPECTED_VOLUME_DESTINATIONS,
    FileIdentity,
    ResolvedRepairTarget,
)
from .windows_security import StableFileIdentity

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_DOMAIN = b"TowerScout.RollbackRuntimeRecovery.Runtime.v1"
_VOLUME_DOMAIN = b"TowerScout.RollbackRuntimeRecovery.Volume.v1"


def _invalid() -> NoReturn:
    raise ValueError("Rollback runtime recovery authority is invalid.")


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _digest(domain: bytes, values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    _add(digest, domain)
    for value in values:
        _add(digest, value.encode("utf-8", errors="strict"))
    return digest.hexdigest()


def _file_values(identity: FileIdentity | None) -> tuple[str, ...]:
    if identity is None:
        return ("absent",)
    if type(identity) is not FileIdentity:
        _invalid()
    return (
        "present",
        identity.logical_name,
        str(identity.volume_serial),
        identity.file_id.hex(),
        "directory" if identity.is_directory else "file",
        identity.sha256,
        str(identity.size_bytes),
        identity.canonical_path_sha256,
    )


def _files_values(identities: tuple[FileIdentity, ...]) -> tuple[str, ...]:
    if type(identities) is not tuple:
        _invalid()
    values: list[str] = [str(len(identities))]
    for identity in identities:
        values.extend(_file_values(identity))
    return tuple(values)


def _restorable_environment_values(identity: FileIdentity | None) -> tuple[str, ...]:
    if identity is None:
        return ("<absent>",)
    if identity.is_directory or identity.sha256 is None or identity.size_bytes is None:
        _invalid()
    return (
        identity.logical_name,
        identity.canonical_path_sha256,
        identity.sha256,
        str(identity.size_bytes),
    )


def _runtime_values(
    target_token_sha256: str,
    target: ResolvedRepairTarget | AbsentResolvedRuntimeTarget,
) -> tuple[str, ...]:
    plan = target if isinstance(target, ResolvedRepairTarget) else target.plan
    process = plan.process_environment
    runtime = plan.runtime
    endpoint = plan.endpoint
    compose_provider = plan.compose_provider
    compose = target.compose
    image = target.image
    return (
        target_token_sha256,
        *_file_values(plan.package_root),
        *_file_values(process.system_root),
        *_file_values(process.temp_directory),
        *_file_values(process.user_profile),
        *_file_values(process.local_app_data),
        *_file_values(process.roaming_app_data),
        plan.release_identity,
        *_files_values(plan.security_artifacts.ordered_files),
        runtime.product.value,
        *_file_values(runtime.executable),
        runtime.version,
        runtime.publisher_policy_sha256,
        endpoint.product.value,
        endpoint.kind.value,
        endpoint.canonical_endpoint,
        endpoint.private_metadata_sha256,
        *_file_values(endpoint.identity_key),
        *_files_values(endpoint.discovery_artifacts),
        "rootless" if endpoint.rootless else "rootful",
        compose_provider.provider_id,
        compose_provider.invocation_kind.value,
        compose_provider.endpoint_binding.value,
        *_files_values(compose_provider.artifacts),
        compose_provider.integrity_sha256,
        *_files_values(compose.ordered_files),
        compose.environment_sha256,
        compose.pre_model_sha256,
        *_restorable_environment_values(compose.environment_source),
        *_restorable_environment_values(compose.environment_file),
        plan.compose_project,
        "towerscout",
        plan.acceleration.requested.value,
        plan.acceleration.effective.value,
        plan.acceleration.overlay_logical_name,
        plan.provider.value,
        str(plan.port),
        image.configured_reference,
        image.pinned_digest,
        image.repository_digest,
        image.daemon_image_id,
        image.private_inspect_sha256,
    )


def _volume_evidence(
    target_token_sha256: str,
    target: ResolvedRepairTarget | AbsentResolvedRuntimeTarget,
) -> tuple[str, ...]:
    expected = EXPECTED_VOLUME_DESTINATIONS
    if len(target.volumes) != len(expected) or any(
        (volume.logical_name, volume.destination) != expected_item
        for volume, expected_item in zip(target.volumes, expected, strict=True)
    ):
        _invalid()
    evidence = tuple(
        _digest(
            _VOLUME_DOMAIN,
            (
                target_token_sha256,
                volume.logical_name,
                volume.runtime_name,
                volume.destination,
                volume.private_inspect_sha256,
            ),
        )
        for volume in target.volumes
    )
    if len(set(evidence)) != len(expected):
        _invalid()
    return evidence


@dataclass(frozen=True, slots=True, repr=False)
class RollbackRuntimeRecoveryAuthority:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)
    runtime_was_running: bool

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or _SHA256.fullmatch(self.runtime_evidence_sha256) is None
            or type(self.volume_evidence_sha256s) is not tuple
            or len(self.volume_evidence_sha256s) != len(EXPECTED_VOLUME_DESTINATIONS)
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in self.volume_evidence_sha256s
            )
            or len(set(self.volume_evidence_sha256s))
            != len(EXPECTED_VOLUME_DESTINATIONS)
            or type(self.runtime_was_running) is not bool
            or self.runtime_was_running is not True
        ):
            _invalid()

    def __repr__(self) -> str:
        return (
            "RollbackRuntimeRecoveryAuthority("
            f"runtime_was_running={self.runtime_was_running!r}, <redacted>)"
        )


def derive_rollback_runtime_recovery_authority(
    target: ResolvedRepairTarget,
) -> RollbackRuntimeRecoveryAuthority:
    """Bind the exact stage-stable recovery target before first mutation."""

    if type(target) is not ResolvedRepairTarget:
        _invalid()
    try:
        package_root_identity = StableFileIdentity(
            target.package_root.volume_serial,
            target.package_root.file_id,
        )
        return RollbackRuntimeRecoveryAuthority(
            1,
            target.target_token.digest_sha256,
            package_root_identity,
            _digest(
                _RUNTIME_DOMAIN,
                _runtime_values(target.target_token.digest_sha256, target),
            ),
            _volume_evidence(target.target_token.digest_sha256, target),
            True,
        )
    except (AttributeError, OverflowError, TypeError, UnicodeError, ValueError):
        _invalid()


def derive_absent_rollback_runtime_recovery_authority(
    target_token_sha256: str,
    target: AbsentResolvedRuntimeTarget,
) -> RollbackRuntimeRecoveryAuthority:
    """Re-derive pre-mutation authority from strict absent-container evidence."""

    if (
        type(target_token_sha256) is not str
        or _SHA256.fullmatch(target_token_sha256) is None
        or type(target) is not AbsentResolvedRuntimeTarget
    ):
        _invalid()
    try:
        return RollbackRuntimeRecoveryAuthority(
            1,
            target_token_sha256,
            StableFileIdentity(
                target.plan.package_root.volume_serial,
                target.plan.package_root.file_id,
            ),
            _digest(_RUNTIME_DOMAIN, _runtime_values(target_token_sha256, target)),
            _volume_evidence(target_token_sha256, target),
            True,
        )
    except (AttributeError, OverflowError, TypeError, UnicodeError, ValueError):
        _invalid()


def derive_recreated_rollback_runtime_recovery_authority(
    original_target_token_sha256: str,
    target: ResolvedRepairTarget,
) -> RollbackRuntimeRecoveryAuthority:
    """Bind a recreated container to the original stage-stable authority."""

    if (
        type(original_target_token_sha256) is not str
        or _SHA256.fullmatch(original_target_token_sha256) is None
        or type(target) is not ResolvedRepairTarget
    ):
        _invalid()
    try:
        return RollbackRuntimeRecoveryAuthority(
            1,
            original_target_token_sha256,
            StableFileIdentity(
                target.package_root.volume_serial,
                target.package_root.file_id,
            ),
            _digest(
                _RUNTIME_DOMAIN,
                _runtime_values(original_target_token_sha256, target),
            ),
            _volume_evidence(original_target_token_sha256, target),
            True,
        )
    except (AttributeError, OverflowError, TypeError, UnicodeError, ValueError):
        _invalid()


__all__ = [
    "RollbackRuntimeRecoveryAuthority",
    "derive_absent_rollback_runtime_recovery_authority",
    "derive_recreated_rollback_runtime_recovery_authority",
    "derive_rollback_runtime_recovery_authority",
]
