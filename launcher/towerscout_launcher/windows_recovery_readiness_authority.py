"""Authenticated pre-mutation readiness authority for checked rollback."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re

from .windows_recovery_journal import (
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from .windows_security import StableFileIdentity

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_READINESS_DOMAIN = b"TowerScout.RollbackReadinessEvidence.v1"


def _add(digest: object, value: bytes) -> None:
    updater = getattr(digest, "update")
    updater(len(value).to_bytes(8, "big"))
    updater(value)


def rollback_readiness_evidence_sha256(
    target_token_sha256: str,
    condition: RollbackReadinessCondition,
) -> str:
    """Bind one sanitized readiness condition to the original target token."""

    if (
        type(target_token_sha256) is not str
        or _SHA256.fullmatch(target_token_sha256) is None
        or type(condition) is not RollbackReadinessCondition
    ):
        raise ValueError("Rollback readiness evidence input is invalid.")
    digest = hashlib.sha256()
    _add(digest, _READINESS_DOMAIN)
    _add(digest, target_token_sha256.encode("ascii"))
    _add(digest, condition.value.encode("ascii"))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RollbackReadinessAuthority:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    condition: RollbackReadinessCondition
    evidence_sha256: str = field(repr=False)
    provider_outcome: RollbackProviderOutcome

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.target_token_sha256) is not str
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.condition) is not RollbackReadinessCondition
            or type(self.evidence_sha256) is not str
            or self.evidence_sha256
            != rollback_readiness_evidence_sha256(
                self.target_token_sha256,
                self.condition,
            )
            or self.provider_outcome
            is not RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE
        ):
            raise ValueError("Rollback readiness authority is invalid.")

    def __repr__(self) -> str:
        return (
            "RollbackReadinessAuthority("
            f"condition={self.condition.value!r}, "
            f"provider_outcome={self.provider_outcome.value!r}, <redacted>)"
        )


def derive_rollback_readiness_authority(
    *,
    target_token_sha256: str,
    package_root_identity: StableFileIdentity,
    condition: RollbackReadinessCondition,
    provider_outcome: RollbackProviderOutcome,
) -> RollbackReadinessAuthority:
    return RollbackReadinessAuthority(
        1,
        target_token_sha256,
        package_root_identity,
        condition,
        rollback_readiness_evidence_sha256(target_token_sha256, condition),
        provider_outcome,
    )


__all__ = [
    "RollbackReadinessAuthority",
    "derive_rollback_readiness_authority",
    "rollback_readiness_evidence_sha256",
]
