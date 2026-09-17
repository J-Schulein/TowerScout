"""Pure exact-state authority and decisions for certificate rollback."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re

from .windows_recovery_journal import (
    BackupPreparingRecord,
    CertificateRestoreTempPlanRecord,
    CertificateRestoreTempVerifiedRecord,
    JournalStreamIdentity,
    RollbackRuntimeAvailableRecord,
)
from .windows_security import StableFileIdentity

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TEMP_NAME = re.compile(r"^recovery-certificate-[0-9a-f]{32}\.tmp$")


class CertificateRestoreAction(str, Enum):
    ALREADY_RESTORED = "already_restored"
    RESTORE_ORIGINAL = "restore_original"
    REMOVE_CANDIDATE = "remove_candidate"
    BLOCK = "block"


@dataclass(frozen=True, slots=True, repr=False)
class CertificateDestinationRestoreAuthority:
    original_present: bool
    original_sha256: str | None = field(default=None, repr=False)
    original_size: int | None = None
    original_mode: int | None = None
    candidate_sha256: str = field(default="", repr=False)
    candidate_size: int = -1
    candidate_mode: int = -1
    restore_temp_name: str | None = field(default=None, repr=False)
    restore_temp_identity: StableFileIdentity | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        original_values = (
            self.original_sha256,
            self.original_size,
            self.original_mode,
            self.restore_temp_name,
            self.restore_temp_identity,
        )
        if (
            type(self.original_present) is not bool
            or _SHA256.fullmatch(self.candidate_sha256) is None
            or type(self.candidate_size) is not int
            or self.candidate_size < 1
            or type(self.candidate_mode) is not int
            or not 0 <= self.candidate_mode <= 0o7777
        ):
            raise ValueError("Certificate restore authority is invalid.")
        if self.original_present:
            if (
                type(self.original_sha256) is not str
                or _SHA256.fullmatch(self.original_sha256) is None
                or type(self.original_size) is not int
                or self.original_size < 0
                or type(self.original_mode) is not int
                or not 0 <= self.original_mode <= 0o7777
                or type(self.restore_temp_name) is not str
                or _TEMP_NAME.fullmatch(self.restore_temp_name) is None
                or type(self.restore_temp_identity) is not StableFileIdentity
            ):
                raise ValueError("Certificate restore authority is invalid.")
        elif any(value is not None for value in original_values):
            raise ValueError("Certificate restore authority is invalid.")

    def __repr__(self) -> str:
        return (
            "CertificateDestinationRestoreAuthority("
            f"original_present={self.original_present!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CertificateDestinationObservation:
    present: bool
    sha256: str | None = field(default=None, repr=False)
    size: int | None = None
    mode: int | None = None

    def __post_init__(self) -> None:
        values = (self.sha256, self.size, self.mode)
        if type(self.present) is not bool:
            raise ValueError("Certificate destination observation is invalid.")
        if self.present:
            if (
                type(self.sha256) is not str
                or _SHA256.fullmatch(self.sha256) is None
                or type(self.size) is not int
                or self.size < 0
                or type(self.mode) is not int
                or not 0 <= self.mode <= 0o7777
            ):
                raise ValueError("Certificate destination observation is invalid.")
        elif any(value is not None for value in values):
            raise ValueError("Certificate destination observation is invalid.")

    def __repr__(self) -> str:
        return (
            f"CertificateDestinationObservation(present={self.present!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CertificateRestoreDecision:
    action: CertificateRestoreAction
    observation: CertificateDestinationObservation = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.action) is not CertificateRestoreAction
            or type(self.observation) is not CertificateDestinationObservation
        ):
            raise ValueError("Certificate restore decision is invalid.")

    def __repr__(self) -> str:
        return f"CertificateRestoreDecision(action={self.action.value!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class CertificateRestorationAuthority:
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)
    local_ca: CertificateDestinationRestoreAuthority = field(repr=False)
    ca_bundle: CertificateDestinationRestoreAuthority = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.volume_evidence_sha256s) is not tuple:
            raise ValueError("Certificate restoration authority is invalid.")
        hashes = (
            self.target_token_sha256,
            self.runtime_evidence_sha256,
            self.container_evidence_sha256,
            *self.volume_evidence_sha256s,
        )
        if (
            any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in hashes
            )
            or type(self.package_root_identity) is not StableFileIdentity
            or len(self.volume_evidence_sha256s) != 8
            or len(set(self.volume_evidence_sha256s)) != 8
            or type(self.local_ca) is not CertificateDestinationRestoreAuthority
            or type(self.ca_bundle) is not CertificateDestinationRestoreAuthority
            or (
                self.local_ca.restore_temp_identity is not None
                and self.local_ca.restore_temp_identity
                == self.ca_bundle.restore_temp_identity
            )
        ):
            raise ValueError("Certificate restoration authority is invalid.")

    def __repr__(self) -> str:
        return "CertificateRestorationAuthority(<redacted>)"


def _matches(
    observation: CertificateDestinationObservation,
    *,
    present: bool,
    sha256: str | None,
    size: int | None,
    mode: int | None,
) -> bool:
    return (
        observation.present is present
        and observation.sha256 == sha256
        and observation.size == size
        and observation.mode == mode
    )


def decide_certificate_restore(
    authority: CertificateDestinationRestoreAuthority,
    observation: CertificateDestinationObservation,
) -> CertificateRestoreDecision:
    """Classify only original, repair candidate, or a blocked third state."""

    if (
        type(authority) is not CertificateDestinationRestoreAuthority
        or type(observation) is not CertificateDestinationObservation
    ):
        raise ValueError("Certificate restore input is invalid.")
    if _matches(
        observation,
        present=authority.original_present,
        sha256=authority.original_sha256,
        size=authority.original_size,
        mode=authority.original_mode,
    ):
        action = CertificateRestoreAction.ALREADY_RESTORED
    elif _matches(
        observation,
        present=True,
        sha256=authority.candidate_sha256,
        size=authority.candidate_size,
        mode=authority.candidate_mode,
    ):
        action = (
            CertificateRestoreAction.RESTORE_ORIGINAL
            if authority.original_present
            else CertificateRestoreAction.REMOVE_CANDIDATE
        )
    else:
        action = CertificateRestoreAction.BLOCK
    return CertificateRestoreDecision(action, observation)


def _destination_authority(
    *,
    original_present: bool,
    original_sha256: str | None,
    original_size: int | None,
    original_mode: int | None,
    candidate_sha256: str,
    candidate_size: int,
    candidate_mode: int,
    restore_temp_name: str | None,
    restore_temp_identity: StableFileIdentity | None,
) -> CertificateDestinationRestoreAuthority:
    return CertificateDestinationRestoreAuthority(
        original_present,
        original_sha256,
        original_size,
        original_mode,
        candidate_sha256,
        candidate_size,
        candidate_mode,
        restore_temp_name,
        restore_temp_identity,
    )


def derive_certificate_restoration_authority(
    stream: JournalStreamIdentity,
    preparing: BackupPreparingRecord,
    runtime: RollbackRuntimeAvailableRecord,
    plan: CertificateRestoreTempPlanRecord,
    verified: CertificateRestoreTempVerifiedRecord,
) -> CertificateRestorationAuthority:
    """Derive the exact original/candidate authority from authenticated records."""

    if (
        type(stream) is not JournalStreamIdentity
        or type(preparing) is not BackupPreparingRecord
        or type(runtime) is not RollbackRuntimeAvailableRecord
        or type(plan) is not CertificateRestoreTempPlanRecord
        or type(verified) is not CertificateRestoreTempVerifiedRecord
        or preparing.package_root_identity != stream.package_root_identity
        or runtime.package_root_identity != stream.package_root_identity
        or plan.package_root_identity != stream.package_root_identity
        or runtime.runtime_evidence_sha256 != preparing.rollback_runtime_evidence_sha256
        or runtime.volume_evidence_sha256s != preparing.rollback_volume_evidence_sha256s
        or plan.local_ca_present is not preparing.local_ca_present
        or plan.local_ca_sha256 != preparing.local_ca_sha256
        or plan.local_ca_mode != preparing.local_ca_mode
        or plan.ca_bundle_present is not preparing.ca_bundle_present
        or plan.ca_bundle_sha256 != preparing.ca_bundle_sha256
        or plan.ca_bundle_mode != preparing.ca_bundle_mode
        or (verified.local_ca_temp_identity is not None) is not plan.local_ca_present
        or (verified.ca_bundle_temp_identity is not None) is not plan.ca_bundle_present
    ):
        raise ValueError("Certificate restoration records do not match.")
    return CertificateRestorationAuthority(
        stream.target_token_sha256,
        stream.package_root_identity,
        runtime.runtime_evidence_sha256,
        runtime.container_evidence_sha256,
        runtime.volume_evidence_sha256s,
        _destination_authority(
            original_present=plan.local_ca_present,
            original_sha256=plan.local_ca_sha256,
            original_size=plan.local_ca_size,
            original_mode=plan.local_ca_mode,
            candidate_sha256=preparing.local_ca_candidate_sha256,
            candidate_size=preparing.local_ca_candidate_size,
            candidate_mode=preparing.local_ca_candidate_mode,
            restore_temp_name=plan.local_ca_temp_name,
            restore_temp_identity=verified.local_ca_temp_identity,
        ),
        _destination_authority(
            original_present=plan.ca_bundle_present,
            original_sha256=plan.ca_bundle_sha256,
            original_size=plan.ca_bundle_size,
            original_mode=plan.ca_bundle_mode,
            candidate_sha256=preparing.ca_bundle_candidate_sha256,
            candidate_size=preparing.ca_bundle_candidate_size,
            candidate_mode=preparing.ca_bundle_candidate_mode,
            restore_temp_name=plan.ca_bundle_temp_name,
            restore_temp_identity=verified.ca_bundle_temp_identity,
        ),
    )


__all__ = [
    "CertificateDestinationObservation",
    "CertificateDestinationRestoreAuthority",
    "CertificateRestorationAuthority",
    "CertificateRestoreAction",
    "CertificateRestoreDecision",
    "decide_certificate_restore",
    "derive_certificate_restoration_authority",
]
