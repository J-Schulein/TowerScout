"""Authenticated write-ahead planning for encrypted Windows recovery backups.

This source-only Gate-A layer records unpredictable backup blob names and exact
pre-mutation state summaries before any backup file may be created. It does not
persist backup blobs, restore files, or enable repair/runtime mutation.
"""

from __future__ import annotations

from enum import Enum
import secrets
from typing import NoReturn, Protocol

from .windows_certificate_replacement import CertificateReplacementPlan
from .windows_environment_replacement import EnvironmentReplacementPlan
from .windows_recovery_backup import (
    BackupProtectionPort,
    SealedCertificateExactStateBackup,
    SealedEnvironmentExactStateBackup,
    authenticate_certificate_exact_state_backup,
    authenticate_environment_exact_state_backup,
)
from .windows_recovery_journal import (
    GENESIS_GENERATION_SHA256,
    BackupPreparingRecord,
    EnvironmentJournalGeneration,
    EnvironmentJournalState,
    JournalProtectionPort,
    JournalStreamIdentity,
    protect_environment_journal_generation,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    append_persisted_environment_journal_generation,
)
from .windows_recovery_runtime_authority import RollbackRuntimeRecoveryAuthority
from .windows_recovery_readiness_authority import RollbackReadinessAuthority


class RecoveryBackupPreparationErrorCode(str, Enum):
    INPUT_INVALID = "recovery_backup_preparation_input_invalid"
    NAME_GENERATION_FAILED = "recovery_backup_name_generation_failed"
    PLAN_INVALID = "recovery_backup_preparation_plan_invalid"
    VERIFY_FAILED = "recovery_backup_preparation_verify_failed"


class RecoveryBackupPreparationError(RuntimeError):
    """Sanitized failure while establishing backup write-ahead intent."""

    _MESSAGES = {
        RecoveryBackupPreparationErrorCode.INPUT_INVALID: (
            "The recovery backup preparation request is invalid."
        ),
        RecoveryBackupPreparationErrorCode.NAME_GENERATION_FAILED: (
            "Recovery backup names could not be generated."
        ),
        RecoveryBackupPreparationErrorCode.PLAN_INVALID: (
            "The recovery backup preparation plan is invalid."
        ),
        RecoveryBackupPreparationErrorCode.VERIFY_FAILED: (
            "The recovery backup preparation plan could not be verified durably."
        ),
    }

    def __init__(self, code: RecoveryBackupPreparationErrorCode) -> None:
        if type(code) is not RecoveryBackupPreparationErrorCode:
            raise ValueError("Unknown recovery backup preparation error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryBackupPreparationError(code={self.code.value!r})"


def _fail(code: RecoveryBackupPreparationErrorCode) -> NoReturn:
    raise RecoveryBackupPreparationError(code)


class RecoveryBackupNameSource(Protocol):
    def new_backup_name(self) -> str: ...


class NativeRecoveryBackupNameSource:
    def new_backup_name(self) -> str:
        return f"recovery-backup-{secrets.token_hex(16)}.blob"


def _new_backup_name(name_source: RecoveryBackupNameSource) -> str:
    try:
        operation = getattr(name_source, "new_backup_name")
        if not callable(operation):
            raise TypeError("Recovery backup name source is unavailable.")
        name = operation()
    except Exception:
        _fail(RecoveryBackupPreparationErrorCode.NAME_GENERATION_FAILED)
    if type(name) is not str:
        _fail(RecoveryBackupPreparationErrorCode.NAME_GENERATION_FAILED)
    return name


def persist_backup_preparing_generation(
    environment_sealed: SealedEnvironmentExactStateBackup,
    certificate_sealed: SealedCertificateExactStateBackup,
    *,
    environment_plan: EnvironmentReplacementPlan,
    certificate_plan: CertificateReplacementPlan,
    runtime_authority: RollbackRuntimeRecoveryAuthority,
    readiness_authority: RollbackReadinessAuthority,
    stream: JournalStreamIdentity,
    name_source: RecoveryBackupNameSource,
    root: JournalStorageRootPort,
    storage: JournalGenerationStoragePort,
    backup_protection: BackupProtectionPort,
    journal_protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Persist generation one after authenticating both exact-state envelopes."""

    if (
        type(environment_sealed) is not SealedEnvironmentExactStateBackup
        or type(certificate_sealed) is not SealedCertificateExactStateBackup
        or type(environment_plan) is not EnvironmentReplacementPlan
        or type(certificate_plan) is not CertificateReplacementPlan
        or type(runtime_authority) is not RollbackRuntimeRecoveryAuthority
        or type(readiness_authority) is not RollbackReadinessAuthority
        or type(stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryBackupPreparationErrorCode.INPUT_INVALID)
    environment = authenticate_environment_exact_state_backup(
        environment_sealed,
        expected_stream=stream,
        protection=backup_protection,
    )
    certificates = authenticate_certificate_exact_state_backup(
        certificate_sealed,
        expected_stream=stream,
        protection=backup_protection,
    )
    environment_security = environment.security
    if (environment.existed and environment_security is None) or (
        environment_plan.original_contents != environment.contents
        or runtime_authority.target_token_sha256 != stream.target_token_sha256
        or runtime_authority.package_root_identity != stream.package_root_identity
        or runtime_authority.runtime_was_running is not True
        or readiness_authority.target_token_sha256 != stream.target_token_sha256
        or readiness_authority.package_root_identity != stream.package_root_identity
    ):
        _fail(RecoveryBackupPreparationErrorCode.PLAN_INVALID)
    try:
        record = BackupPreparingRecord(
            schema_version=1,
            package_root_identity=stream.package_root_identity,
            environment_backup_name=_new_backup_name(name_source),
            certificate_backup_name=_new_backup_name(name_source),
            environment_candidate_sha256=environment_plan.candidate_sha256,
            environment_candidate_size=len(environment_plan.candidate_contents),
            environment_present=environment.existed,
            certificate_provider=certificate_plan.provider,
            windows_root_fingerprint_sha256=(
                certificate_plan.windows_root_fingerprint_sha256
            ),
            rollback_runtime_evidence_sha256=(
                runtime_authority.runtime_evidence_sha256
            ),
            rollback_volume_evidence_sha256s=(
                runtime_authority.volume_evidence_sha256s
            ),
            runtime_was_running=runtime_authority.runtime_was_running,
            prior_readiness_condition=readiness_authority.condition,
            prior_readiness_evidence_sha256=readiness_authority.evidence_sha256,
            prior_provider_outcome=readiness_authority.provider_outcome,
            environment_original_identity=environment.identity,
            environment_sha256=(
                environment.contents_sha256 if environment.existed else None
            ),
            environment_file_attributes=(
                environment_security.file_attributes
                if environment_security is not None
                else None
            ),
            environment_security_descriptor_sha256=(
                environment_security.security_descriptor_sha256
                if environment_security is not None
                else None
            ),
            local_ca_present=certificates.local_ca.existed,
            local_ca_sha256=(
                certificates.local_ca.contents_sha256
                if certificates.local_ca.existed
                else None
            ),
            local_ca_mode=(
                certificates.local_ca.mode if certificates.local_ca.existed else None
            ),
            ca_bundle_present=certificates.ca_bundle.existed,
            ca_bundle_sha256=(
                certificates.ca_bundle.contents_sha256
                if certificates.ca_bundle.existed
                else None
            ),
            ca_bundle_mode=(
                certificates.ca_bundle.mode if certificates.ca_bundle.existed else None
            ),
            local_ca_candidate_sha256=certificate_plan.local_ca_sha256,
            local_ca_candidate_size=len(certificate_plan.local_ca_contents),
            local_ca_candidate_mode=certificate_plan.local_ca_mode,
            ca_bundle_candidate_sha256=certificate_plan.ca_bundle_sha256,
            ca_bundle_candidate_size=len(certificate_plan.ca_bundle_contents),
            ca_bundle_candidate_mode=certificate_plan.ca_bundle_mode,
        )
        generation = EnvironmentJournalGeneration(
            1,
            stream,
            1,
            GENESIS_GENERATION_SHA256,
            EnvironmentJournalState.BACKUP_PREPARING,
            record,
        )
    except ValueError:
        _fail(RecoveryBackupPreparationErrorCode.PLAN_INVALID)
    sealed_generation = protect_environment_journal_generation(
        generation,
        protection=journal_protection,
    )
    persisted = append_persisted_environment_journal_generation(
        sealed_generation,
        stream=stream,
        root=root,
        storage=storage,
        protection=journal_protection,
    )
    if (
        persisted.selection.tip != generation
        or persisted.selection.tip_generation_sha256
        != sealed_generation.generation_sha256
    ):
        _fail(RecoveryBackupPreparationErrorCode.VERIFY_FAILED)
    return persisted


__all__ = [
    "NativeRecoveryBackupNameSource",
    "RecoveryBackupNameSource",
    "RecoveryBackupPreparationError",
    "RecoveryBackupPreparationErrorCode",
    "persist_backup_preparing_generation",
]
