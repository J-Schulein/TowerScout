"""Authenticated exact-state authority for terminal Windows rollback verification."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import struct
from typing import Any, NoReturn

from .target_contracts import EXPECTED_VOLUME_DESTINATIONS, MapProvider
from .windows_recovery_journal import (
    BackupPreparingRecord,
    CertificateRestoreTempPlanRecord,
    CertificatesRestoredRecord,
    EnvironmentJournalChainSelection,
    EnvironmentRestoredRecord,
    JournalStreamIdentity,
    RollbackProviderOutcome,
    RollbackReadinessCondition,
    RollbackRuntimeRestartedRecord,
    RollbackVerifyingRecord,
)
from .windows_recovery_readiness_authority import (
    rollback_readiness_evidence_sha256,
)
from .windows_security import StableFileIdentity

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT_DOMAIN = b"TowerScout.RollbackVerification.Environment.v1"
_CERTIFICATE_DOMAIN = b"TowerScout.RollbackVerification.Certificates.v1"


def _invalid() -> NoReturn:
    raise ValueError("Rollback verification authority is invalid.")


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _digest(domain: bytes, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    _add(digest, domain)
    for value in values:
        _add(digest, value.encode("ascii", errors="strict"))
    return digest.hexdigest()


def _identity_values(identity: StableFileIdentity | None) -> tuple[str, ...]:
    if identity is None:
        return ("absent",)
    if type(identity) is not StableFileIdentity:
        _invalid()
    return ("present", str(identity.volume_serial), identity.file_id.hex())


@dataclass(frozen=True, slots=True, repr=False)
class RollbackEnvironmentExpectation:
    present: bool
    sha256: str | None = field(default=None, repr=False)
    size: int | None = None
    file_attributes: int | None = None
    security_descriptor_sha256: str | None = field(default=None, repr=False)
    identity: StableFileIdentity | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.present) is not bool:
            _invalid()
        values = (
            self.sha256,
            self.size,
            self.file_attributes,
            self.security_descriptor_sha256,
            self.identity,
        )
        if self.present:
            if (
                type(self.sha256) is not str
                or _SHA256.fullmatch(self.sha256) is None
                or type(self.size) is not int
                or not 0 <= self.size
                or type(self.file_attributes) is not int
                or not 0 <= self.file_attributes <= 0xFFFFFFFF
                or type(self.security_descriptor_sha256) is not str
                or _SHA256.fullmatch(self.security_descriptor_sha256) is None
                or type(self.identity) is not StableFileIdentity
            ):
                _invalid()
        elif any(value is not None for value in values):
            _invalid()

    def __repr__(self) -> str:
        return f"RollbackEnvironmentExpectation(present={self.present!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RollbackCertificateExpectation:
    present: bool
    destination_evidence_sha256: str = field(repr=False)
    sha256: str | None = field(default=None, repr=False)
    size: int | None = None
    mode: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.present) is not bool
            or type(self.destination_evidence_sha256) is not str
            or _SHA256.fullmatch(self.destination_evidence_sha256) is None
        ):
            _invalid()
        values = (self.sha256, self.size, self.mode)
        if self.present:
            if (
                type(self.sha256) is not str
                or _SHA256.fullmatch(self.sha256) is None
                or type(self.size) is not int
                or not 0 <= self.size
                or type(self.mode) is not int
                or not 0 <= self.mode <= 0o7777
            ):
                _invalid()
        elif any(value is not None for value in values):
            _invalid()

    def __repr__(self) -> str:
        return f"RollbackCertificateExpectation(present={self.present!r}, <redacted>)"


def rollback_environment_evidence_sha256(
    target_token_sha256: str,
    expectation: RollbackEnvironmentExpectation,
) -> str:
    if (
        type(target_token_sha256) is not str
        or _SHA256.fullmatch(target_token_sha256) is None
        or type(expectation) is not RollbackEnvironmentExpectation
    ):
        _invalid()
    return _digest(
        _ENVIRONMENT_DOMAIN,
        (
            target_token_sha256,
            "present" if expectation.present else "absent",
            expectation.sha256 or "<none>",
            str(expectation.size) if expectation.size is not None else "<none>",
            (
                str(expectation.file_attributes)
                if expectation.file_attributes is not None
                else "<none>"
            ),
            expectation.security_descriptor_sha256 or "<none>",
            *_identity_values(expectation.identity),
        ),
    )


def rollback_certificate_evidence_sha256(
    target_token_sha256: str,
    provider: MapProvider,
    windows_root_fingerprint_sha256: str,
    local_ca: RollbackCertificateExpectation,
    ca_bundle: RollbackCertificateExpectation,
) -> str:
    if (
        type(target_token_sha256) is not str
        or _SHA256.fullmatch(target_token_sha256) is None
        or type(provider) is not MapProvider
        or type(windows_root_fingerprint_sha256) is not str
        or _SHA256.fullmatch(windows_root_fingerprint_sha256) is None
        or type(local_ca) is not RollbackCertificateExpectation
        or type(ca_bundle) is not RollbackCertificateExpectation
    ):
        _invalid()

    def values(expectation: RollbackCertificateExpectation) -> tuple[str, ...]:
        return (
            "present" if expectation.present else "absent",
            expectation.sha256 or "<none>",
            str(expectation.size) if expectation.size is not None else "<none>",
            str(expectation.mode) if expectation.mode is not None else "<none>",
            expectation.destination_evidence_sha256,
        )

    return _digest(
        _CERTIFICATE_DOMAIN,
        (
            target_token_sha256,
            provider.value,
            windows_root_fingerprint_sha256,
            "local-ca",
            *values(local_ca),
            "ca-bundle",
            *values(ca_bundle),
        ),
    )


@dataclass(frozen=True, slots=True, repr=False)
class RollbackVerificationAuthority:
    schema_version: int
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    provider: MapProvider
    windows_root_fingerprint_sha256: str = field(repr=False)
    environment: RollbackEnvironmentExpectation = field(repr=False)
    local_ca: RollbackCertificateExpectation = field(repr=False)
    ca_bundle: RollbackCertificateExpectation = field(repr=False)
    environment_evidence_sha256: str = field(repr=False)
    certificate_evidence_sha256: str = field(repr=False)
    runtime_evidence_sha256: str = field(repr=False)
    container_evidence_sha256: str = field(repr=False)
    volume_evidence_sha256s: tuple[str, ...] = field(repr=False)
    prior_readiness_condition: RollbackReadinessCondition
    prior_readiness_evidence_sha256: str = field(repr=False)
    prior_provider_outcome: RollbackProviderOutcome

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.target_token_sha256) is not str
            or _SHA256.fullmatch(self.target_token_sha256) is None
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.provider) is not MapProvider
            or type(self.windows_root_fingerprint_sha256) is not str
            or _SHA256.fullmatch(self.windows_root_fingerprint_sha256) is None
            or type(self.environment) is not RollbackEnvironmentExpectation
            or type(self.local_ca) is not RollbackCertificateExpectation
            or type(self.ca_bundle) is not RollbackCertificateExpectation
            or self.environment_evidence_sha256
            != rollback_environment_evidence_sha256(
                self.target_token_sha256,
                self.environment,
            )
            or self.certificate_evidence_sha256
            != rollback_certificate_evidence_sha256(
                self.target_token_sha256,
                self.provider,
                self.windows_root_fingerprint_sha256,
                self.local_ca,
                self.ca_bundle,
            )
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (
                    self.runtime_evidence_sha256,
                    self.container_evidence_sha256,
                    self.prior_readiness_evidence_sha256,
                )
            )
            or type(self.volume_evidence_sha256s) is not tuple
            or len(self.volume_evidence_sha256s) != len(EXPECTED_VOLUME_DESTINATIONS)
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in self.volume_evidence_sha256s
            )
            or len(set(self.volume_evidence_sha256s))
            != len(EXPECTED_VOLUME_DESTINATIONS)
            or type(self.prior_readiness_condition) is not RollbackReadinessCondition
            or self.prior_readiness_evidence_sha256
            != rollback_readiness_evidence_sha256(
                self.target_token_sha256,
                self.prior_readiness_condition,
            )
            or self.prior_provider_outcome
            is not RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE
        ):
            _invalid()

    def __repr__(self) -> str:
        return (
            "RollbackVerificationAuthority("
            f"provider={self.provider.value!r}, "
            f"prior_readiness_condition={self.prior_readiness_condition.value!r}, "
            "<redacted>)"
        )


def derive_rollback_verification_authority(
    stream: JournalStreamIdentity,
    selection: EnvironmentJournalChainSelection,
) -> RollbackVerificationAuthority:
    """Derive terminal verification authority from an authenticated chain."""

    if (
        type(stream) is not JournalStreamIdentity
        or type(selection) is not EnvironmentJournalChainSelection
        or len(selection.generations) not in {16, 17}
        or any(generation.stream != stream for generation in selection.generations)
    ):
        _invalid()
    preparing = selection.generations[0].record
    environment = selection.generations[7].record
    certificate_plan = selection.generations[9].record
    certificates = selection.generations[12].record
    restarted = selection.generations[14].record
    verifying = selection.generations[15].record
    if (
        type(preparing) is not BackupPreparingRecord
        or type(environment) is not EnvironmentRestoredRecord
        or type(certificate_plan) is not CertificateRestoreTempPlanRecord
        or type(certificates) is not CertificatesRestoredRecord
        or type(restarted) is not RollbackRuntimeRestartedRecord
        or type(verifying) is not RollbackVerifyingRecord
        or preparing.package_root_identity != stream.package_root_identity
        or environment.package_root_identity != stream.package_root_identity
        or certificate_plan.package_root_identity != stream.package_root_identity
        or certificates.package_root_identity != stream.package_root_identity
        or restarted.package_root_identity != stream.package_root_identity
        or verifying.package_root_identity != stream.package_root_identity
        or preparing.runtime_was_running is not True
    ):
        _invalid()
    environment_expectation = RollbackEnvironmentExpectation(
        environment.environment_present,
        environment.environment_sha256,
        environment.environment_size,
        environment.environment_file_attributes,
        environment.environment_security_descriptor_sha256,
        environment.environment_identity,
    )
    local_ca = RollbackCertificateExpectation(
        certificate_plan.local_ca_present,
        certificates.local_ca_destination_evidence_sha256,
        certificate_plan.local_ca_sha256,
        certificate_plan.local_ca_size,
        certificate_plan.local_ca_mode,
    )
    ca_bundle = RollbackCertificateExpectation(
        certificate_plan.ca_bundle_present,
        certificates.ca_bundle_destination_evidence_sha256,
        certificate_plan.ca_bundle_sha256,
        certificate_plan.ca_bundle_size,
        certificate_plan.ca_bundle_mode,
    )
    return RollbackVerificationAuthority(
        1,
        stream.target_token_sha256,
        stream.package_root_identity,
        preparing.certificate_provider,
        preparing.windows_root_fingerprint_sha256,
        environment_expectation,
        local_ca,
        ca_bundle,
        rollback_environment_evidence_sha256(
            stream.target_token_sha256,
            environment_expectation,
        ),
        rollback_certificate_evidence_sha256(
            stream.target_token_sha256,
            preparing.certificate_provider,
            preparing.windows_root_fingerprint_sha256,
            local_ca,
            ca_bundle,
        ),
        restarted.runtime_evidence_sha256,
        restarted.container_evidence_sha256,
        restarted.volume_evidence_sha256s,
        preparing.prior_readiness_condition,
        preparing.prior_readiness_evidence_sha256,
        preparing.prior_provider_outcome,
    )


def rollback_readiness_condition_restored(
    authority: RollbackVerificationAuthority,
    observed: RollbackReadinessCondition,
    provider_outcome: RollbackProviderOutcome,
) -> bool:
    """Accept exact readiness, or a healthy READY result after provider success."""

    if (
        type(authority) is not RollbackVerificationAuthority
        or type(observed) is not RollbackReadinessCondition
        or type(provider_outcome) is not RollbackProviderOutcome
    ):
        _invalid()
    return observed is authority.prior_readiness_condition or (
        provider_outcome is RollbackProviderOutcome.SUCCESS
        and observed is RollbackReadinessCondition.READY
    )


__all__ = [
    "RollbackCertificateExpectation",
    "RollbackEnvironmentExpectation",
    "RollbackVerificationAuthority",
    "derive_rollback_verification_authority",
    "rollback_certificate_evidence_sha256",
    "rollback_environment_evidence_sha256",
    "rollback_readiness_condition_restored",
]
