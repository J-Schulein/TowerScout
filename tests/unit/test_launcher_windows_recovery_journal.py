from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentAppliedRecord,
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
    ProtectedStateError,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402
from towerscout_launcher.target_contracts import ABSENT_FILE_SHA256  # noqa: E402


class _Protection:
    def __init__(self) -> None:
        self._nonce = 0

    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        assert purpose is ProtectedDataPurpose.JOURNAL_GENERATION
        self._nonce += 1
        prefix = b"TSJ1" + self._nonce.to_bytes(4, "big")
        return CurrentUserProtectedBlob(purpose, prefix + plaintext)

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        assert purpose is ProtectedDataPurpose.JOURNAL_GENERATION
        if blob.purpose is not purpose or not blob.ciphertext.startswith(b"TSJ1"):
            raise ProtectedStateError("protected_data_invalid")
        return blob.ciphertext[8:]


class _RejectingProtection(_Protection):
    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        raise ProtectedStateError("protected_data_invalid")


class _PlaintextProtection(_Protection):
    def __init__(self, plaintext: bytes) -> None:
        super().__init__()
        self.plaintext = plaintext

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        return self.plaintext


class _UnexpectedProtection(_Protection):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        del plaintext, purpose
        raise KeyError("sensitive protection detail")

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        raise KeyError("sensitive authentication detail")


def _identity(seed: int) -> StableFileIdentity:
    return StableFileIdentity(seed, seed.to_bytes(16, "big"))


def _stream(*, journal_id: str = "a" * 32) -> journal.JournalStreamIdentity:
    return journal.JournalStreamIdentity(
        schema_version=1,
        journal_id=journal_id,
        target_token_sha256="b" * 64,
        package_root_identity=_identity(7),
    )


def _plan_record(
    *,
    candidate_sha256: str = "d" * 64,
    temp_name: str = ".towerscout-env-" + "e" * 32 + ".tmp",
    original_present: bool = True,
) -> EnvironmentTempPlanRecord:
    return EnvironmentTempPlanRecord(
        schema_version=1,
        package_root_identity=_identity(7),
        original_sha256="c" * 64 if original_present else ABSENT_FILE_SHA256,
        candidate_sha256=candidate_sha256,
        candidate_size=37,
        temp_name=temp_name,
        original_present=original_present,
        original_identity=_identity(8) if original_present else None,
        original_size=13 if original_present else None,
        original_file_attributes=0x20 if original_present else None,
        original_security_descriptor_sha256="f" * 64 if original_present else None,
    )


def _backup_preparing_record(
    *,
    environment_present: bool = True,
) -> journal.BackupPreparingRecord:
    return journal.BackupPreparingRecord(
        schema_version=1,
        package_root_identity=_identity(7),
        environment_backup_name="recovery-backup-" + "1" * 32 + ".blob",
        certificate_backup_name="recovery-backup-" + "2" * 32 + ".blob",
        environment_candidate_sha256="a" * 64,
        environment_candidate_size=37,
        environment_present=environment_present,
        rollback_runtime_evidence_sha256="1" * 64,
        rollback_volume_evidence_sha256s=tuple(
            f"{value:x}" * 64 for value in range(3, 11)
        ),
        runtime_was_running=True,
        environment_original_identity=_identity(8) if environment_present else None,
        environment_sha256="c" * 64 if environment_present else None,
        environment_file_attributes=0x20 if environment_present else None,
        environment_security_descriptor_sha256=(
            "d" * 64 if environment_present else None
        ),
        local_ca_present=True,
        local_ca_sha256="e" * 64,
        local_ca_mode=0o644,
        ca_bundle_present=False,
        local_ca_candidate_sha256="1" * 64,
        local_ca_candidate_size=100,
        local_ca_candidate_mode=0o644,
        ca_bundle_candidate_sha256="2" * 64,
        ca_bundle_candidate_size=200,
        ca_bundle_candidate_mode=0o644,
    )


def _backup_verified_record(
    preparing_generation_sha256: str,
) -> journal.BackupVerifiedRecord:
    return journal.BackupVerifiedRecord(
        schema_version=1,
        preparing_generation_sha256=preparing_generation_sha256,
        package_root_identity=_identity(7),
        environment_backup_identity=_identity(21),
        environment_ciphertext_sha256="f" * 64,
        environment_ciphertext_size=101,
        certificate_backup_identity=_identity(22),
        certificate_ciphertext_sha256="9" * 64,
        certificate_ciphertext_size=202,
    )


def _rollback_armed_record(
    backup_verified_generation_sha256: str,
    verified: journal.BackupVerifiedRecord,
) -> journal.RollbackArmedRecord:
    return journal.RollbackArmedRecord(
        schema_version=1,
        backup_verified_generation_sha256=backup_verified_generation_sha256,
        package_root_identity=verified.package_root_identity,
        environment_backup_identity=verified.environment_backup_identity,
        environment_ciphertext_sha256=verified.environment_ciphertext_sha256,
        environment_ciphertext_size=verified.environment_ciphertext_size,
        certificate_backup_identity=verified.certificate_backup_identity,
        certificate_ciphertext_sha256=verified.certificate_ciphertext_sha256,
        certificate_ciphertext_size=verified.certificate_ciphertext_size,
    )


def _rollback_started_record(
    rollback_armed_generation_sha256: str,
    armed: journal.RollbackArmedRecord,
) -> journal.RollbackStartedRecord:
    return journal.RollbackStartedRecord(
        schema_version=1,
        rollback_armed_generation_sha256=rollback_armed_generation_sha256,
        package_root_identity=armed.package_root_identity,
        environment_backup_identity=armed.environment_backup_identity,
        environment_ciphertext_sha256=armed.environment_ciphertext_sha256,
        environment_ciphertext_size=armed.environment_ciphertext_size,
        certificate_backup_identity=armed.certificate_backup_identity,
        certificate_ciphertext_sha256=armed.certificate_ciphertext_sha256,
        certificate_ciphertext_size=armed.certificate_ciphertext_size,
    )


def _environment_restore_temp_plan_record(
    rollback_started_generation_sha256: str,
    started: journal.RollbackStartedRecord,
    preparing: journal.BackupPreparingRecord,
) -> journal.EnvironmentRestoreTempPlanRecord:
    return journal.EnvironmentRestoreTempPlanRecord(
        schema_version=1,
        rollback_started_generation_sha256=rollback_started_generation_sha256,
        package_root_identity=started.package_root_identity,
        environment_backup_identity=started.environment_backup_identity,
        environment_ciphertext_sha256=started.environment_ciphertext_sha256,
        environment_ciphertext_size=started.environment_ciphertext_size,
        environment_present=preparing.environment_present,
        environment_sha256=preparing.environment_sha256,
        environment_size=17,
        environment_file_attributes=preparing.environment_file_attributes,
        environment_security_descriptor_sha256=(
            preparing.environment_security_descriptor_sha256
        ),
        temp_name=".towerscout-env-" + "a" * 32 + ".tmp",
    )


def _environment_restore_temp_created_record(
    planned_generation_sha256: str,
    planned: journal.EnvironmentRestoreTempPlanRecord,
) -> journal.EnvironmentRestoreTempCreatedRecord:
    return journal.EnvironmentRestoreTempCreatedRecord(
        schema_version=1,
        planned_generation_sha256=planned_generation_sha256,
        package_root_identity=planned.package_root_identity,
        environment_backup_identity=planned.environment_backup_identity,
        environment_ciphertext_sha256=planned.environment_ciphertext_sha256,
        environment_ciphertext_size=planned.environment_ciphertext_size,
        environment_present=planned.environment_present,
        environment_sha256=planned.environment_sha256,
        environment_size=planned.environment_size,
        environment_file_attributes=planned.environment_file_attributes,
        environment_security_descriptor_sha256=(
            planned.environment_security_descriptor_sha256
        ),
        temp_name=planned.temp_name,
        temp_identity=_identity(31),
    )


def _environment_restore_temp_verified_record(
    created_generation_sha256: str,
    created: journal.EnvironmentRestoreTempCreatedRecord,
) -> journal.EnvironmentRestoreTempVerifiedRecord:
    return journal.EnvironmentRestoreTempVerifiedRecord(
        schema_version=1,
        created_generation_sha256=created_generation_sha256,
        package_root_identity=created.package_root_identity,
        environment_backup_identity=created.environment_backup_identity,
        environment_ciphertext_sha256=created.environment_ciphertext_sha256,
        environment_ciphertext_size=created.environment_ciphertext_size,
        environment_present=created.environment_present,
        environment_sha256=created.environment_sha256,
        environment_size=created.environment_size,
        environment_file_attributes=created.environment_file_attributes,
        environment_security_descriptor_sha256=(
            created.environment_security_descriptor_sha256
        ),
        temp_name=created.temp_name,
        temp_identity=created.temp_identity,
    )


def _seal(
    generation: journal.EnvironmentJournalGeneration,
    protection: _Protection,
) -> journal.SealedEnvironmentJournalGeneration:
    return journal.protect_environment_journal_generation(
        generation,
        protection=protection,
    )


def _build_chain(
    protection: _Protection,
    *,
    stream: journal.JournalStreamIdentity | None = None,
    original_present: bool = True,
) -> tuple[
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
]:
    selected_stream = stream or _stream()
    planned_record = _plan_record(original_present=original_present)
    planned = _seal(
        journal.EnvironmentJournalGeneration(
            schema_version=1,
            stream=selected_stream,
            sequence=1,
            previous_generation_sha256=journal.GENESIS_GENERATION_SHA256,
            state=journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            record=planned_record,
        ),
        protection,
    )
    created_record = EnvironmentTempCreatedRecord(
        schema_version=1,
        planned_generation_sha256=planned.generation_sha256,
        package_root_identity=planned_record.package_root_identity,
        temp_identity=_identity(11),
        candidate_sha256=planned_record.candidate_sha256,
        candidate_size=planned_record.candidate_size,
        candidate_file_attributes=0x80,
        candidate_security_descriptor_sha256="f" * 64,
        temp_name=planned_record.temp_name,
    )
    created = _seal(
        journal.EnvironmentJournalGeneration(
            schema_version=1,
            stream=selected_stream,
            sequence=2,
            previous_generation_sha256=planned.generation_sha256,
            state=journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            record=created_record,
        ),
        protection,
    )
    verified_record = EnvironmentTempVerifiedRecord(
        schema_version=1,
        created_generation_sha256=created.generation_sha256,
        package_root_identity=created_record.package_root_identity,
        temp_identity=created_record.temp_identity,
        candidate_sha256=created_record.candidate_sha256,
        candidate_size=created_record.candidate_size,
        candidate_file_attributes=created_record.candidate_file_attributes,
        candidate_security_descriptor_sha256=(
            created_record.candidate_security_descriptor_sha256
        ),
        temp_name=created_record.temp_name,
    )
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            schema_version=1,
            stream=selected_stream,
            sequence=3,
            previous_generation_sha256=created.generation_sha256,
            state=journal.EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
            record=verified_record,
        ),
        protection,
    )
    return selected_stream, (planned, created, verified)


def _pointer(
    stream: journal.JournalStreamIdentity,
    generation: journal.SealedEnvironmentJournalGeneration,
    sequence: int,
) -> journal.EnvironmentJournalPointer:
    return journal.EnvironmentJournalPointer(
        schema_version=1,
        journal_id=stream.journal_id,
        sequence=sequence,
        generation_sha256=generation.generation_sha256,
    )


def _applied_generation(
    protection: _Protection,
    stream: journal.JournalStreamIdentity,
    generations: tuple[journal.SealedEnvironmentJournalGeneration, ...],
) -> journal.SealedEnvironmentJournalGeneration:
    selection = journal.select_environment_journal_chain(
        generations,
        None,
        expected_stream=stream,
        protection=protection,
    )
    verified = selection.tip.record
    plan = selection.generations[0].record
    assert type(verified) is EnvironmentTempVerifiedRecord
    assert type(plan) is EnvironmentTempPlanRecord
    record = EnvironmentAppliedRecord(
        1,
        selection.tip_generation_sha256,
        verified.package_root_identity,
        verified.temp_identity,
        verified.candidate_sha256,
        verified.candidate_size,
        (
            plan.original_file_attributes
            if plan.original_present
            else verified.candidate_file_attributes
        ),
        (
            plan.original_security_descriptor_sha256
            if plan.original_present
            else verified.candidate_security_descriptor_sha256
        ),
        verified.temp_name,
    )
    return _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            4,
            selection.tip_generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_APPLIED,
            record,
        ),
        protection,
    )


def test_generation_round_trip_is_canonical_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    record = _plan_record()
    generation = journal.EnvironmentJournalGeneration(
        schema_version=1,
        stream=stream,
        sequence=1,
        previous_generation_sha256=journal.GENESIS_GENERATION_SHA256,
        state=journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        record=record,
    )

    sealed = _seal(generation, protection)
    selection = journal.select_environment_journal_chain(
        (sealed,),
        None,
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == generation
    assert (
        selection.tip_generation_sha256
        == hashlib.sha256(sealed.protected_blob.ciphertext).hexdigest()
    )
    rendered = repr(stream) + repr(generation) + repr(sealed) + repr(selection)
    assert record.temp_name not in rendered
    assert record.candidate_sha256 not in rendered
    assert stream.target_token_sha256 not in rendered


def test_environment_applied_round_trip_binds_verified_identity_and_observation() -> (
    None
):
    protection = _Protection()
    stream, generations = _build_chain(protection)
    applied = _applied_generation(protection, stream, generations)

    selection = journal.select_environment_journal_chain(
        generations + (applied,),
        _pointer(stream, applied, 4),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip.state is journal.EnvironmentJournalState.ENVIRONMENT_APPLIED
    assert type(selection.tip.record) is EnvironmentAppliedRecord
    assert selection.tip.record.candidate_identity == _identity(11)
    assert selection.tip.record.candidate_file_attributes == 0x20
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    assert selection.tip.record.candidate_sha256 not in repr(selection)


def test_environment_applied_absent_original_requires_staged_metadata() -> None:
    protection = _Protection()
    stream, generations = _build_chain(protection, original_present=False)
    applied = _applied_generation(protection, stream, generations)

    selection = journal.select_environment_journal_chain(
        generations + (applied,),
        None,
        expected_stream=stream,
        protection=protection,
    )

    record = selection.tip.record
    verified = selection.generations[2].record
    assert type(record) is EnvironmentAppliedRecord
    assert type(verified) is EnvironmentTempVerifiedRecord
    assert record.candidate_file_attributes == verified.candidate_file_attributes
    assert (
        record.candidate_security_descriptor_sha256
        == verified.candidate_security_descriptor_sha256
    )


def test_environment_applied_rejects_wrong_verified_predecessor_or_identity() -> None:
    protection = _Protection()
    stream, generations = _build_chain(protection)
    applied = _applied_generation(protection, stream, generations)
    authenticated = journal.authenticate_environment_journal_generation(
        applied,
        protection=protection,
    )
    record = authenticated.record
    assert type(record) is EnvironmentAppliedRecord

    for drifted in (
        replace(record, verified_generation_sha256="8" * 64),
        replace(record, candidate_identity=_identity(99)),
        replace(record, candidate_file_attributes=0x21),
        replace(record, candidate_security_descriptor_sha256="9" * 64),
    ):
        sealed = _seal(replace(authenticated, record=drifted), protection)
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                generations + (sealed,),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_backup_preparing_round_trip_is_singleton_bound_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    record = _backup_preparing_record()
    generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        1,
        journal.GENESIS_GENERATION_SHA256,
        journal.EnvironmentJournalState.BACKUP_PREPARING,
        record,
    )

    sealed = _seal(generation, protection)
    selection = journal.select_environment_journal_chain(
        (sealed,),
        _pointer(stream, sealed, 1),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(generation) + repr(selection)
    assert record.environment_backup_name not in rendered
    assert record.certificate_backup_name not in rendered
    assert record.environment_candidate_sha256 not in rendered
    assert record.environment_sha256 not in rendered


def test_backup_verified_round_trip_is_bound_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    record = _backup_verified_record(prepared.generation_sha256)
    verified_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        2,
        prepared.generation_sha256,
        journal.EnvironmentJournalState.BACKUP_VERIFIED,
        record,
    )
    verified = _seal(verified_generation, protection)

    selection = journal.select_environment_journal_chain(
        (prepared, verified),
        _pointer(stream, verified, 2),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == verified_generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(verified_generation) + repr(selection)
    assert record.preparing_generation_sha256 not in rendered
    assert record.environment_ciphertext_sha256 not in rendered
    assert record.certificate_ciphertext_sha256 not in rendered
    assert repr(record.environment_backup_identity) not in rendered


def test_backup_verified_rejects_invalid_receipts_and_continuity() -> None:
    with pytest.raises(ValueError):
        journal.BackupVerifiedRecord(
            1,
            "1" * 64,
            _identity(7),
            _identity(21),
            "2" * 64,
            101,
            _identity(21),
            "3" * 64,
            202,
        )
    with pytest.raises(ValueError):
        journal.BackupVerifiedRecord(
            1,
            "1" * 64,
            _identity(7),
            _identity(21),
            "not-a-hash",
            101,
            _identity(22),
            "3" * 64,
            0,
        )

    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    for previous_sha256, record in (
        ("8" * 64, _backup_verified_record(prepared.generation_sha256)),
        (prepared.generation_sha256, _backup_verified_record("8" * 64)),
    ):
        verified = _seal(
            journal.EnvironmentJournalGeneration(
                1,
                stream,
                2,
                previous_sha256,
                journal.EnvironmentJournalState.BACKUP_VERIFIED,
                record,
            ),
            protection,
        )
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                (prepared, verified),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_rollback_armed_round_trip_is_bound_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    record = _rollback_armed_record(verified.generation_sha256, verified_record)
    armed_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        3,
        verified.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_ARMED,
        record,
    )
    armed = _seal(armed_generation, protection)

    selection = journal.select_environment_journal_chain(
        (prepared, verified, armed),
        _pointer(stream, armed, 3),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == armed_generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(armed_generation) + repr(selection)
    assert record.backup_verified_generation_sha256 not in rendered
    assert record.environment_ciphertext_sha256 not in rendered
    assert record.certificate_ciphertext_sha256 not in rendered
    assert repr(record.environment_backup_identity) not in rendered


def test_rollback_armed_rejects_receipt_drift_and_invalid_continuity() -> None:
    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    drifted = journal.RollbackArmedRecord(
        1,
        verified.generation_sha256,
        verified_record.package_root_identity,
        verified_record.environment_backup_identity,
        "8" * 64,
        verified_record.environment_ciphertext_size,
        verified_record.certificate_backup_identity,
        verified_record.certificate_ciphertext_sha256,
        verified_record.certificate_ciphertext_size,
    )
    for previous_sha256, record in (
        (verified.generation_sha256, drifted),
        (
            "7" * 64,
            _rollback_armed_record(verified.generation_sha256, verified_record),
        ),
        (
            verified.generation_sha256,
            _rollback_armed_record("7" * 64, verified_record),
        ),
    ):
        armed = _seal(
            journal.EnvironmentJournalGeneration(
                1,
                stream,
                3,
                previous_sha256,
                journal.EnvironmentJournalState.ROLLBACK_ARMED,
                record,
            ),
            protection,
        )
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                (prepared, verified, armed),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_rollback_started_round_trip_is_bound_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(
        verified.generation_sha256,
        verified_record,
    )
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    record = _rollback_started_record(armed.generation_sha256, armed_record)
    started_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        4,
        armed.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_STARTED,
        record,
    )
    started = _seal(started_generation, protection)

    selection = journal.select_environment_journal_chain(
        (prepared, verified, armed, started),
        _pointer(stream, started, 4),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == started_generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(started_generation) + repr(selection)
    assert record.rollback_armed_generation_sha256 not in rendered
    assert record.environment_ciphertext_sha256 not in rendered
    assert record.certificate_ciphertext_sha256 not in rendered
    assert repr(record.environment_backup_identity) not in rendered


def test_rollback_started_rejects_receipt_drift_and_invalid_continuity() -> None:
    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(
        verified.generation_sha256,
        verified_record,
    )
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    drifted = journal.RollbackStartedRecord(
        1,
        armed.generation_sha256,
        armed_record.package_root_identity,
        armed_record.environment_backup_identity,
        "8" * 64,
        armed_record.environment_ciphertext_size,
        armed_record.certificate_backup_identity,
        armed_record.certificate_ciphertext_sha256,
        armed_record.certificate_ciphertext_size,
    )
    for previous_sha256, record in (
        (armed.generation_sha256, drifted),
        (
            "7" * 64,
            _rollback_started_record(armed.generation_sha256, armed_record),
        ),
        (
            armed.generation_sha256,
            _rollback_started_record("7" * 64, armed_record),
        ),
    ):
        started = _seal(
            journal.EnvironmentJournalGeneration(
                1,
                stream,
                4,
                previous_sha256,
                journal.EnvironmentJournalState.ROLLBACK_STARTED,
                record,
            ),
            protection,
        )
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                (prepared, verified, armed, started),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_environment_restore_temp_planned_round_trip_is_bound_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    preparing_record = _backup_preparing_record()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            preparing_record,
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(verified.generation_sha256, verified_record)
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    started_record = _rollback_started_record(armed.generation_sha256, armed_record)
    started = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            4,
            armed.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_STARTED,
            started_record,
        ),
        protection,
    )
    record = _environment_restore_temp_plan_record(
        started.generation_sha256,
        started_record,
        preparing_record,
    )
    planned_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        5,
        started.generation_sha256,
        journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
        record,
    )
    planned = _seal(planned_generation, protection)

    selection = journal.select_environment_journal_chain(
        (prepared, verified, armed, started, planned),
        _pointer(stream, planned, 5),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == planned_generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(planned_generation) + repr(selection)
    assert record.rollback_started_generation_sha256 not in rendered
    assert record.environment_ciphertext_sha256 not in rendered
    assert record.environment_sha256 not in rendered
    assert record.temp_name not in rendered


def test_environment_restore_temp_planned_supports_absent_original() -> None:
    record = journal.EnvironmentRestoreTempPlanRecord(
        1,
        "1" * 64,
        _identity(7),
        _identity(21),
        "2" * 64,
        101,
        False,
    )

    assert record.environment_sha256 is None
    assert record.environment_size is None
    assert record.temp_name is None


def test_environment_restore_temp_planned_rejects_drift_and_invalid_shape() -> None:
    with pytest.raises(ValueError):
        journal.EnvironmentRestoreTempPlanRecord(
            1,
            "1" * 64,
            _identity(7),
            _identity(21),
            "2" * 64,
            101,
            False,
            environment_sha256="3" * 64,
        )

    protection = _Protection()
    stream = _stream()
    preparing_record = _backup_preparing_record()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            preparing_record,
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(verified.generation_sha256, verified_record)
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    started_record = _rollback_started_record(armed.generation_sha256, armed_record)
    started = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            4,
            armed.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_STARTED,
            started_record,
        ),
        protection,
    )
    valid = _environment_restore_temp_plan_record(
        started.generation_sha256,
        started_record,
        preparing_record,
    )
    drifted = journal.EnvironmentRestoreTempPlanRecord(
        1,
        started.generation_sha256,
        valid.package_root_identity,
        valid.environment_backup_identity,
        "8" * 64,
        valid.environment_ciphertext_size,
        valid.environment_present,
        valid.environment_sha256,
        valid.environment_size,
        valid.environment_file_attributes,
        valid.environment_security_descriptor_sha256,
        valid.temp_name,
    )
    for previous_sha256, record in (
        (started.generation_sha256, drifted),
        (
            "7" * 64,
            _environment_restore_temp_plan_record(
                started.generation_sha256,
                started_record,
                preparing_record,
            ),
        ),
        (
            started.generation_sha256,
            _environment_restore_temp_plan_record(
                "7" * 64,
                started_record,
                preparing_record,
            ),
        ),
    ):
        planned = _seal(
            journal.EnvironmentJournalGeneration(
                1,
                stream,
                5,
                previous_sha256,
                journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
                record,
            ),
            protection,
        )
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                (prepared, verified, armed, started, planned),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_environment_restore_temp_created_round_trip_is_bound_and_redacted() -> None:
    protection = _Protection()
    stream = _stream()
    preparing_record = _backup_preparing_record()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            preparing_record,
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(verified.generation_sha256, verified_record)
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    started_record = _rollback_started_record(armed.generation_sha256, armed_record)
    started = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            4,
            armed.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_STARTED,
            started_record,
        ),
        protection,
    )
    planned_record = _environment_restore_temp_plan_record(
        started.generation_sha256,
        started_record,
        preparing_record,
    )
    planned = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            5,
            started.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
            planned_record,
        ),
        protection,
    )
    record = _environment_restore_temp_created_record(
        planned.generation_sha256,
        planned_record,
    )
    created_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        6,
        planned.generation_sha256,
        journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
        record,
    )
    created = _seal(created_generation, protection)

    selection = journal.select_environment_journal_chain(
        (prepared, verified, armed, started, planned, created),
        _pointer(stream, created, 6),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == created_generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(created_generation) + repr(selection)
    assert record.planned_generation_sha256 not in rendered
    assert record.environment_ciphertext_sha256 not in rendered
    assert record.environment_sha256 not in rendered
    assert record.temp_name not in rendered
    assert repr(record.temp_identity) not in rendered


def test_environment_restore_temp_created_supports_absent_original() -> None:
    record = journal.EnvironmentRestoreTempCreatedRecord(
        1,
        "1" * 64,
        _identity(7),
        _identity(21),
        "2" * 64,
        101,
        False,
    )

    assert record.environment_sha256 is None
    assert record.environment_size is None
    assert record.temp_name is None
    assert record.temp_identity is None


def test_environment_restore_temp_created_requires_identity_when_present() -> None:
    with pytest.raises(ValueError):
        journal.EnvironmentRestoreTempCreatedRecord(
            1,
            "1" * 64,
            _identity(7),
            _identity(21),
            "2" * 64,
            101,
            True,
            "3" * 64,
            17,
            0x20,
            "4" * 64,
            ".towerscout-env-" + "a" * 32 + ".tmp",
            None,
        )


def test_environment_restore_temp_created_rejects_drift_and_invalid_shape() -> None:
    with pytest.raises(ValueError):
        journal.EnvironmentRestoreTempCreatedRecord(
            1,
            "1" * 64,
            _identity(7),
            _identity(21),
            "2" * 64,
            101,
            True,
            "3" * 64,
            17,
            0x20,
            "4" * 64,
            ".towerscout-env-" + "a" * 32 + ".tmp",
            _identity(21),
        )

    protection = _Protection()
    stream = _stream()
    preparing_record = _backup_preparing_record()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            preparing_record,
        ),
        protection,
    )
    verified_record = _backup_verified_record(prepared.generation_sha256)
    verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(verified.generation_sha256, verified_record)
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    started_record = _rollback_started_record(armed.generation_sha256, armed_record)
    started = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            4,
            armed.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_STARTED,
            started_record,
        ),
        protection,
    )
    planned_record = _environment_restore_temp_plan_record(
        started.generation_sha256,
        started_record,
        preparing_record,
    )
    planned = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            5,
            started.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
            planned_record,
        ),
        protection,
    )
    valid = _environment_restore_temp_created_record(
        planned.generation_sha256,
        planned_record,
    )
    drifted = journal.EnvironmentRestoreTempCreatedRecord(
        1,
        planned.generation_sha256,
        valid.package_root_identity,
        valid.environment_backup_identity,
        valid.environment_ciphertext_sha256,
        valid.environment_ciphertext_size,
        valid.environment_present,
        "8" * 64,
        valid.environment_size,
        valid.environment_file_attributes,
        valid.environment_security_descriptor_sha256,
        valid.temp_name,
        valid.temp_identity,
    )
    for previous_sha256, record in (
        (planned.generation_sha256, drifted),
        (
            "7" * 64,
            _environment_restore_temp_created_record(
                planned.generation_sha256,
                planned_record,
            ),
        ),
        (
            planned.generation_sha256,
            _environment_restore_temp_created_record(
                "7" * 64,
                planned_record,
            ),
        ),
    ):
        created = _seal(
            journal.EnvironmentJournalGeneration(
                1,
                stream,
                6,
                previous_sha256,
                journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
                record,
            ),
            protection,
        )
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                (prepared, verified, armed, started, planned, created),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_environment_restore_verified_and_restored_round_trip_is_bound() -> None:
    protection = _Protection()
    stream = _stream()
    preparing_record = _backup_preparing_record()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            preparing_record,
        ),
        protection,
    )
    backup_verified_record = _backup_verified_record(prepared.generation_sha256)
    backup_verified = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.BACKUP_VERIFIED,
            backup_verified_record,
        ),
        protection,
    )
    armed_record = _rollback_armed_record(
        backup_verified.generation_sha256,
        backup_verified_record,
    )
    armed = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            backup_verified.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_ARMED,
            armed_record,
        ),
        protection,
    )
    started_record = _rollback_started_record(armed.generation_sha256, armed_record)
    started = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            4,
            armed.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_STARTED,
            started_record,
        ),
        protection,
    )
    planned_record = _environment_restore_temp_plan_record(
        started.generation_sha256,
        started_record,
        preparing_record,
    )
    planned = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            5,
            started.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
            planned_record,
        ),
        protection,
    )
    created_record = _environment_restore_temp_created_record(
        planned.generation_sha256,
        planned_record,
    )
    created = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            6,
            planned.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
            created_record,
        ),
        protection,
    )
    record = _environment_restore_temp_verified_record(
        created.generation_sha256,
        created_record,
    )
    generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        7,
        created.generation_sha256,
        journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED,
        record,
    )
    verified = _seal(generation, protection)

    selection = journal.select_environment_journal_chain(
        (prepared, backup_verified, armed, started, planned, created, verified),
        _pointer(stream, verified, 7),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.tip == generation
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT
    rendered = repr(record) + repr(generation) + repr(selection)
    assert record.created_generation_sha256 not in rendered
    assert record.environment_ciphertext_sha256 not in rendered
    assert record.environment_sha256 is not None
    assert record.environment_sha256 not in rendered
    assert record.temp_name is not None
    assert record.temp_name not in rendered
    assert repr(record.temp_identity) not in rendered

    drifted = journal.EnvironmentRestoreTempVerifiedRecord(
        1,
        created.generation_sha256,
        record.package_root_identity,
        record.environment_backup_identity,
        record.environment_ciphertext_sha256,
        record.environment_ciphertext_size,
        record.environment_present,
        "8" * 64,
        record.environment_size,
        record.environment_file_attributes,
        record.environment_security_descriptor_sha256,
        record.temp_name,
        record.temp_identity,
    )
    for previous_sha256, candidate in (
        (created.generation_sha256, drifted),
        (
            "7" * 64,
            _environment_restore_temp_verified_record(
                created.generation_sha256,
                created_record,
            ),
        ),
        (
            created.generation_sha256,
            _environment_restore_temp_verified_record("7" * 64, created_record),
        ),
    ):
        invalid = _seal(
            journal.EnvironmentJournalGeneration(
                1,
                stream,
                7,
                previous_sha256,
                journal.EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_VERIFIED,
                candidate,
            ),
            protection,
        )
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                (
                    prepared,
                    backup_verified,
                    armed,
                    started,
                    planned,
                    created,
                    invalid,
                ),
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID

    restored_record = journal.EnvironmentRestoredRecord(
        1,
        verified.generation_sha256,
        record.package_root_identity,
        record.environment_present,
        record.environment_sha256,
        record.environment_size,
        record.environment_file_attributes,
        record.environment_security_descriptor_sha256,
        record.temp_identity,
    )
    restored_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        8,
        verified.generation_sha256,
        journal.EnvironmentJournalState.ENVIRONMENT_RESTORED,
        restored_record,
    )
    restored = _seal(restored_generation, protection)
    restored_selection = journal.select_environment_journal_chain(
        (
            prepared,
            backup_verified,
            armed,
            started,
            planned,
            created,
            verified,
            restored,
        ),
        _pointer(stream, restored, 8),
        expected_stream=stream,
        protection=protection,
    )

    assert restored_selection.tip == restored_generation
    assert (
        restored_selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    rendered = repr(restored_record) + repr(restored_generation)
    assert restored_record.verified_generation_sha256 not in rendered
    assert restored_record.environment_sha256 is not None
    assert restored_record.environment_sha256 not in rendered
    assert repr(restored_record.environment_identity) not in rendered

    runtime_record = journal.RollbackRuntimeAvailableRecord(
        1,
        restored.generation_sha256,
        record.package_root_identity,
        "1" * 64,
        "2" * 64,
        tuple(f"{value:x}" * 64 for value in range(3, 11)),
        True,
    )
    runtime_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        9,
        restored.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE,
        runtime_record,
    )
    runtime_available = _seal(runtime_generation, protection)
    runtime_selection = journal.select_environment_journal_chain(
        (
            prepared,
            backup_verified,
            armed,
            started,
            planned,
            created,
            verified,
            restored,
            runtime_available,
        ),
        _pointer(stream, runtime_available, 9),
        expected_stream=stream,
        protection=protection,
    )
    assert runtime_selection.tip == runtime_generation
    assert (
        runtime_selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    rendered = repr(runtime_record) + repr(runtime_generation)
    assert runtime_record.runtime_evidence_sha256 not in rendered
    assert runtime_record.container_evidence_sha256 not in rendered
    assert all(
        value not in rendered for value in runtime_record.volume_evidence_sha256s
    )

    certificate_plan_record = journal.CertificateRestoreTempPlanRecord(
        1,
        runtime_available.generation_sha256,
        record.package_root_identity,
        _identity(22),
        "9" * 64,
        202,
        True,
        "e" * 64,
        77,
        0o644,
        "recovery-certificate-" + "1" * 32 + ".tmp",
        False,
    )
    certificate_plan_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        10,
        runtime_available.generation_sha256,
        journal.EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_PLANNED,
        certificate_plan_record,
    )
    certificate_plan = _seal(certificate_plan_generation, protection)
    certificate_selection = journal.select_environment_journal_chain(
        (
            prepared,
            backup_verified,
            armed,
            started,
            planned,
            created,
            verified,
            restored,
            runtime_available,
            certificate_plan,
        ),
        _pointer(stream, certificate_plan, 10),
        expected_stream=stream,
        protection=protection,
    )
    assert certificate_selection.tip == certificate_plan_generation
    rendered = repr(certificate_plan_record) + repr(certificate_plan_generation)
    assert certificate_plan_record.local_ca_sha256 not in rendered
    assert certificate_plan_record.local_ca_temp_name not in rendered

    certificate_created_record = journal.CertificateRestoreTempCreatedRecord(
        1,
        certificate_plan.generation_sha256,
        _identity(23),
        None,
    )
    certificate_created_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        11,
        certificate_plan.generation_sha256,
        journal.EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_CREATED,
        certificate_created_record,
    )
    certificate_created = _seal(certificate_created_generation, protection)
    created_selection = journal.select_environment_journal_chain(
        (
            prepared,
            backup_verified,
            armed,
            started,
            planned,
            created,
            verified,
            restored,
            runtime_available,
            certificate_plan,
            certificate_created,
        ),
        _pointer(stream, certificate_created, 11),
        expected_stream=stream,
        protection=protection,
    )
    assert created_selection.tip == certificate_created_generation
    assert repr(certificate_created_record.local_ca_temp_identity) not in repr(
        certificate_created_record
    )

    certificate_verified_record = journal.CertificateRestoreTempVerifiedRecord(
        1,
        certificate_created.generation_sha256,
        certificate_created_record.local_ca_temp_identity,
        certificate_created_record.ca_bundle_temp_identity,
    )
    certificate_verified_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        12,
        certificate_created.generation_sha256,
        journal.EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_VERIFIED,
        certificate_verified_record,
    )
    certificate_verified = _seal(certificate_verified_generation, protection)
    verified_selection = journal.select_environment_journal_chain(
        (
            prepared,
            backup_verified,
            armed,
            started,
            planned,
            created,
            verified,
            restored,
            runtime_available,
            certificate_plan,
            certificate_created,
            certificate_verified,
        ),
        _pointer(stream, certificate_verified, 12),
        expected_stream=stream,
        protection=protection,
    )
    assert verified_selection.tip == certificate_verified_generation

    certificates_restored_record = journal.CertificatesRestoredRecord(
        1,
        certificate_verified.generation_sha256,
        record.package_root_identity,
        runtime_record.runtime_evidence_sha256,
        runtime_record.container_evidence_sha256,
        runtime_record.volume_evidence_sha256s,
        "b" * 64,
        "c" * 64,
    )
    certificates_restored_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        13,
        certificate_verified.generation_sha256,
        journal.EnvironmentJournalState.CERTIFICATES_RESTORED,
        certificates_restored_record,
    )
    certificates_restored = _seal(certificates_restored_generation, protection)
    restarting_record = journal.RollbackRuntimeRestartingRecord(
        1,
        certificates_restored.generation_sha256,
        record.package_root_identity,
        runtime_record.runtime_evidence_sha256,
        runtime_record.container_evidence_sha256,
        runtime_record.volume_evidence_sha256s,
    )
    restarting_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        14,
        certificates_restored.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTING,
        restarting_record,
    )
    restarting = _seal(restarting_generation, protection)
    restarted_record = journal.RollbackRuntimeRestartedRecord(
        1,
        restarting.generation_sha256,
        record.package_root_identity,
        "d" * 64,
        "e" * 64,
        tuple(f"{value:x}" * 64 for value in range(1, 9)),
    )
    restarted_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        15,
        restarting.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_RUNTIME_RESTARTED,
        restarted_record,
    )
    restarted = _seal(restarted_generation, protection)
    verifying_record = journal.RollbackVerifyingRecord(
        1,
        restarted.generation_sha256,
        record.package_root_identity,
    )
    verifying_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        16,
        restarted.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_VERIFYING,
        verifying_record,
    )
    verifying = _seal(verifying_generation, protection)
    rollback_verified_record = journal.RollbackVerifiedRecord(
        1,
        verifying.generation_sha256,
        record.package_root_identity,
        "f" * 64,
        "a" * 64,
        restarted_record.runtime_evidence_sha256,
        restarted_record.container_evidence_sha256,
        restarted_record.volume_evidence_sha256s,
        "b" * 64,
        journal.RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
    )
    rollback_verified_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        17,
        verifying.generation_sha256,
        journal.EnvironmentJournalState.ROLLBACK_VERIFIED,
        rollback_verified_record,
    )
    rollback_verified = _seal(rollback_verified_generation, protection)
    terminal_selection = journal.select_environment_journal_chain(
        (
            prepared,
            backup_verified,
            armed,
            started,
            planned,
            created,
            verified,
            restored,
            runtime_available,
            certificate_plan,
            certificate_created,
            certificate_verified,
            certificates_restored,
            restarting,
            restarted,
            verifying,
            rollback_verified,
        ),
        _pointer(stream, rollback_verified, 17),
        expected_stream=stream,
        protection=protection,
    )
    assert terminal_selection.tip == rollback_verified_generation
    terminal_rendered = repr(rollback_verified_record)
    assert rollback_verified_record.environment_evidence_sha256 not in terminal_rendered
    assert rollback_verified_record.readiness_evidence_sha256 not in terminal_rendered

    recovery_prefix = (
        prepared,
        backup_verified,
        armed,
        started,
        planned,
        created,
        verified,
        restored,
        runtime_available,
        certificate_plan,
        certificate_created,
        certificate_verified,
        certificates_restored,
        restarting,
        restarted,
        verifying,
        rollback_verified,
    )
    cleaned_record = journal.RecoveryCleanedRecord(
        1,
        rollback_verified.generation_sha256,
        record.package_root_identity,
        "c" * 64,
    )
    cleaned_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        18,
        rollback_verified.generation_sha256,
        journal.EnvironmentJournalState.CLEANED,
        cleaned_record,
    )
    cleaned = _seal(cleaned_generation, protection)
    assert (
        journal.select_environment_journal_chain(
            recovery_prefix + (cleaned,),
            _pointer(stream, cleaned, 18),
            expected_stream=stream,
            protection=protection,
        ).tip
        == cleaned_generation
    )

    pending_record = journal.RecoveryCleanupPendingRecord(
        1,
        rollback_verified.generation_sha256,
        record.package_root_identity,
    )
    pending_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        18,
        rollback_verified.generation_sha256,
        journal.EnvironmentJournalState.RECOVERY_CLEANUP_PENDING,
        pending_record,
    )
    pending = _seal(pending_generation, protection)
    cleaned_after_pending_record = journal.RecoveryCleanedRecord(
        1,
        pending.generation_sha256,
        record.package_root_identity,
        "d" * 64,
    )
    cleaned_after_pending_generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        19,
        pending.generation_sha256,
        journal.EnvironmentJournalState.CLEANED,
        cleaned_after_pending_record,
    )
    cleaned_after_pending = _seal(cleaned_after_pending_generation, protection)
    assert (
        journal.select_environment_journal_chain(
            recovery_prefix + (pending, cleaned_after_pending),
            _pointer(stream, cleaned_after_pending, 19),
            expected_stream=stream,
            protection=protection,
        ).tip
        == cleaned_after_pending_generation
    )

    invalid_created = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            11,
            certificate_plan.generation_sha256,
            journal.EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_CREATED,
            journal.CertificateRestoreTempCreatedRecord(
                1,
                certificate_plan.generation_sha256,
                None,
                None,
            ),
        ),
        protection,
    )
    with pytest.raises(journal.RecoveryJournalError) as created_failure:
        journal.select_environment_journal_chain(
            (
                prepared,
                backup_verified,
                armed,
                started,
                planned,
                created,
                verified,
                restored,
                runtime_available,
                certificate_plan,
                invalid_created,
            ),
            None,
            expected_stream=stream,
            protection=protection,
        )
    assert created_failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID

    drifted_certificate_plan = journal.CertificateRestoreTempPlanRecord(
        1,
        runtime_available.generation_sha256,
        record.package_root_identity,
        _identity(22),
        "9" * 64,
        202,
        True,
        "e" * 64,
        77,
        0o600,
        "recovery-certificate-" + "1" * 32 + ".tmp",
        False,
    )
    invalid_certificate_plan = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            10,
            runtime_available.generation_sha256,
            journal.EnvironmentJournalState.CERTIFICATE_RESTORE_TEMP_PLANNED,
            drifted_certificate_plan,
        ),
        protection,
    )
    with pytest.raises(journal.RecoveryJournalError) as certificate_failure:
        journal.select_environment_journal_chain(
            (
                prepared,
                backup_verified,
                armed,
                started,
                planned,
                created,
                verified,
                restored,
                runtime_available,
                invalid_certificate_plan,
            ),
            None,
            expected_stream=stream,
            protection=protection,
        )
    assert (
        certificate_failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID
    )

    wrong_runtime_predecessor = journal.RollbackRuntimeAvailableRecord(
        1,
        "f" * 64,
        record.package_root_identity,
        runtime_record.runtime_evidence_sha256,
        runtime_record.container_evidence_sha256,
        runtime_record.volume_evidence_sha256s,
        runtime_record.existing_container_retained,
    )
    invalid_runtime = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            9,
            restored.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE,
            wrong_runtime_predecessor,
        ),
        protection,
    )
    with pytest.raises(journal.RecoveryJournalError) as runtime_failure:
        journal.select_environment_journal_chain(
            (
                prepared,
                backup_verified,
                armed,
                started,
                planned,
                created,
                verified,
                restored,
                invalid_runtime,
            ),
            None,
            expected_stream=stream,
            protection=protection,
        )
    assert runtime_failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID

    drifted_runtime_authority = replace(
        runtime_record,
        runtime_evidence_sha256="8" * 64,
    )
    invalid_runtime_authority = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            9,
            restored.generation_sha256,
            journal.EnvironmentJournalState.ROLLBACK_RUNTIME_AVAILABLE,
            drifted_runtime_authority,
        ),
        protection,
    )
    with pytest.raises(journal.RecoveryJournalError) as authority_failure:
        journal.select_environment_journal_chain(
            (
                prepared,
                backup_verified,
                armed,
                started,
                planned,
                created,
                verified,
                restored,
                invalid_runtime_authority,
            ),
            None,
            expected_stream=stream,
            protection=protection,
        )
    assert (
        authority_failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID
    )

    drifted_restored = journal.EnvironmentRestoredRecord(
        1,
        verified.generation_sha256,
        record.package_root_identity,
        True,
        "8" * 64,
        record.environment_size,
        record.environment_file_attributes,
        record.environment_security_descriptor_sha256,
        record.temp_identity,
    )
    invalid_restored = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            8,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_RESTORED,
            drifted_restored,
        ),
        protection,
    )
    with pytest.raises(journal.RecoveryJournalError) as restored_failure:
        journal.select_environment_journal_chain(
            (
                prepared,
                backup_verified,
                armed,
                started,
                planned,
                created,
                verified,
                invalid_restored,
            ),
            None,
            expected_stream=stream,
            protection=protection,
        )
    assert restored_failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID

    unrelated_identity = journal.EnvironmentRestoredRecord(
        1,
        verified.generation_sha256,
        record.package_root_identity,
        record.environment_present,
        record.environment_sha256,
        record.environment_size,
        record.environment_file_attributes,
        record.environment_security_descriptor_sha256,
        _identity(41),
    )
    invalid_identity = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            8,
            verified.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_RESTORED,
            unrelated_identity,
        ),
        protection,
    )
    with pytest.raises(journal.RecoveryJournalError) as identity_failure:
        journal.select_environment_journal_chain(
            (
                prepared,
                backup_verified,
                armed,
                started,
                planned,
                created,
                verified,
                invalid_identity,
            ),
            None,
            expected_stream=stream,
            protection=protection,
        )
    assert identity_failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_environment_restore_temp_verified_supports_absent_original() -> None:
    record = journal.EnvironmentRestoreTempVerifiedRecord(
        1,
        "1" * 64,
        _identity(7),
        _identity(21),
        "2" * 64,
        101,
        False,
    )

    assert record.environment_sha256 is None
    assert record.environment_size is None
    assert record.temp_name is None
    assert record.temp_identity is None

    restored = journal.EnvironmentRestoredRecord(
        1,
        "3" * 64,
        _identity(7),
        False,
    )
    assert restored.environment_sha256 is None
    assert restored.environment_identity is None

    with pytest.raises(ValueError):
        journal.EnvironmentRestoredRecord(
            1,
            "3" * 64,
            _identity(7),
            False,
            environment_identity=_identity(41),
        )


def test_backup_preparing_rejects_inconsistent_state_and_names() -> None:
    with pytest.raises(ValueError):
        replace(
            _backup_preparing_record(environment_present=False),
            environment_candidate_sha256="not-a-hash",
            environment_candidate_size=0,
        )

    with pytest.raises(ValueError):
        replace(
            _backup_preparing_record(environment_present=False),
            certificate_backup_name="recovery-backup-" + "1" * 32 + ".blob",
        )

    with pytest.raises(ValueError):
        replace(
            _backup_preparing_record(environment_present=False),
            environment_backup_name="../recovery-backup-" + "1" * 32 + ".blob",
        )

    with pytest.raises(ValueError):
        replace(
            _backup_preparing_record(environment_present=False),
            environment_sha256="c" * 64,
        )

    for changes in (
        {"local_ca_candidate_sha256": "not-a-hash"},
        {"local_ca_candidate_mode": 0o600},
        {"ca_bundle_candidate_mode": 0o600},
        {"ca_bundle_candidate_size": 100},
        {"ca_bundle_candidate_sha256": "1" * 64},
    ):
        with pytest.raises(ValueError):
            replace(_backup_preparing_record(), **changes)


def test_backup_preparing_rejects_mixed_or_repeated_chain() -> None:
    protection = _Protection()
    stream = _stream()
    prepared = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.BACKUP_PREPARING,
            _backup_preparing_record(),
        ),
        protection,
    )
    environment = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            prepared.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            _plan_record(),
        ),
        protection,
    )

    for candidates in ((prepared, environment), (prepared, prepared)):
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                candidates,
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_equivalent_plaintext_uses_actual_ciphertext_identity() -> None:
    protection = _Protection()
    generation = journal.EnvironmentJournalGeneration(
        1,
        _stream(),
        1,
        journal.GENESIS_GENERATION_SHA256,
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        _plan_record(),
    )

    first = _seal(generation, protection)
    second = _seal(generation, protection)

    assert first.generation_sha256 != second.generation_sha256
    assert (
        journal.select_environment_journal_chain(
            (first,),
            None,
            expected_stream=generation.stream,
            protection=protection,
        ).tip
        == generation
    )
    assert (
        journal.select_environment_journal_chain(
            (second,),
            None,
            expected_stream=generation.stream,
            protection=protection,
        ).tip
        == generation
    )


@pytest.mark.parametrize(
    ("state", "record"),
    [
        (
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            EnvironmentTempCreatedRecord(
                1,
                "1" * 64,
                _identity(7),
                _identity(11),
                "d" * 64,
                37,
                0x80,
                "f" * 64,
                ".towerscout-env-" + "e" * 32 + ".tmp",
            ),
        ),
        (
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            _plan_record(),
        ),
        (
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
            _plan_record(),
        ),
    ],
)
def test_generation_rejects_state_record_type_mismatch(
    state: journal.EnvironmentJournalState,
    record: (
        EnvironmentTempPlanRecord
        | EnvironmentTempCreatedRecord
        | EnvironmentTempVerifiedRecord
    ),
) -> None:
    with pytest.raises(ValueError):
        journal.EnvironmentJournalGeneration(
            1,
            _stream(),
            1,
            journal.GENESIS_GENERATION_SHA256,
            state,
            record,
        )


def test_schema_versions_require_exact_integers() -> None:
    stream = _stream()
    record = _plan_record()

    for invalid in (cast(int, True), cast(int, 1.0)):
        with pytest.raises(ValueError):
            journal.JournalStreamIdentity(
                invalid,
                "a" * 32,
                "b" * 64,
                _identity(7),
            )
        with pytest.raises(ValueError):
            EnvironmentTempPlanRecord(
                invalid,
                _identity(7),
                "c" * 64,
                "d" * 64,
                37,
                ".towerscout-env-" + "e" * 32 + ".tmp",
                True,
                _identity(8),
                13,
                0x20,
                "f" * 64,
            )
        with pytest.raises(ValueError):
            EnvironmentTempCreatedRecord(
                invalid,
                "1" * 64,
                _identity(7),
                _identity(11),
                "d" * 64,
                37,
                0x80,
                "f" * 64,
                ".towerscout-env-" + "e" * 32 + ".tmp",
            )
        with pytest.raises(ValueError):
            EnvironmentTempVerifiedRecord(
                invalid,
                "2" * 64,
                _identity(7),
                _identity(11),
                "d" * 64,
                37,
                0x80,
                "f" * 64,
                ".towerscout-env-" + "e" * 32 + ".tmp",
            )
        with pytest.raises(ValueError):
            journal.EnvironmentRestoreTempPlanRecord(
                invalid,
                "3" * 64,
                _identity(7),
                _identity(21),
                "4" * 64,
                101,
                True,
                "5" * 64,
                17,
                0x20,
                "6" * 64,
                ".towerscout-env-" + "a" * 32 + ".tmp",
            )
        with pytest.raises(ValueError):
            journal.EnvironmentRestoreTempCreatedRecord(
                invalid,
                "7" * 64,
                _identity(7),
                _identity(21),
                "4" * 64,
                101,
                True,
                "5" * 64,
                17,
                0x20,
                "6" * 64,
                ".towerscout-env-" + "a" * 32 + ".tmp",
                _identity(31),
            )
        with pytest.raises(ValueError):
            journal.EnvironmentJournalGeneration(
                invalid,
                stream,
                1,
                journal.GENESIS_GENERATION_SHA256,
                journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
                record,
            )
        with pytest.raises(ValueError):
            journal.EnvironmentJournalPointer(invalid, "a" * 32, 1, "1" * 64)


def test_pointer_codec_is_canonical_and_strict() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    pointer = _pointer(stream, chain[-1], 3)

    encoded = journal.encode_environment_journal_pointer(pointer)

    assert journal.decode_environment_journal_pointer(encoded) == pointer
    with pytest.raises(journal.RecoveryJournalError) as noncanonical:
        journal.decode_environment_journal_pointer(encoded.replace(b"{", b"{ ", 1))
    assert noncanonical.value.code is journal.RecoveryJournalErrorCode.POINTER_INVALID
    with pytest.raises(journal.RecoveryJournalError):
        journal.decode_environment_journal_pointer(
            b'{"generation_sha256":"'
            + b"1" * 64
            + b'","generation_sha256":"'
            + b"2" * 64
            + b'","journal_id":"'
            + b"a" * 32
            + b'","schema_version":1,"sequence":1}'
        )


def test_complete_chain_selects_tip_with_current_pointer() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)

    selection = journal.select_environment_journal_chain(
        chain,
        _pointer(stream, chain[-1], 3),
        expected_stream=stream,
        protection=protection,
    )

    assert selection.generation_sha256s == tuple(
        item.generation_sha256 for item in chain
    )
    assert selection.tip_generation_sha256 == chain[-1].generation_sha256
    assert selection.tip.sequence == 3
    assert selection.pointer_disposition is journal.JournalPointerDisposition.CURRENT


def test_plan_only_and_created_tip_are_valid_crash_states() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)

    for expected_tip, candidates in enumerate((chain[:1], chain[:2]), start=1):
        selection = journal.select_environment_journal_chain(
            candidates,
            None,
            expected_stream=stream,
            protection=protection,
        )
        assert selection.tip.sequence == expected_tip
        assert (
            selection.pointer_disposition
            is journal.JournalPointerDisposition.MISSING_REPAIR
        )


def test_missing_and_stale_pointer_require_repair() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)

    missing = journal.select_environment_journal_chain(
        chain,
        None,
        expected_stream=stream,
        protection=protection,
    )
    stale = journal.select_environment_journal_chain(
        chain,
        _pointer(stream, chain[0], 1),
        expected_stream=stream,
        protection=protection,
    )

    assert (
        missing.pointer_disposition is journal.JournalPointerDisposition.MISSING_REPAIR
    )
    assert stale.pointer_disposition is journal.JournalPointerDisposition.STALE_REPAIR


def test_foreign_or_unknown_pointer_fails_closed() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    foreign = journal.EnvironmentJournalPointer(1, "f" * 32, 3, "9" * 64)
    unknown = journal.EnvironmentJournalPointer(1, stream.journal_id, 4, "9" * 64)

    for pointer in (foreign, unknown):
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                chain,
                pointer,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_branch_and_duplicate_generation_fail_closed() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    planned = chain[0]
    alternate_record = EnvironmentTempCreatedRecord(
        1,
        planned.generation_sha256,
        stream.package_root_identity,
        _identity(12),
        "d" * 64,
        37,
        0x80,
        "f" * 64,
        ".towerscout-env-" + "e" * 32 + ".tmp",
    )
    alternate = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            planned.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            alternate_record,
        ),
        protection,
    )

    for candidates in (chain + (alternate,), chain + (chain[-1],)):
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                candidates,
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_gap_or_cross_record_drift_fails_closed() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    drifted_record = EnvironmentTempCreatedRecord(
        1,
        chain[0].generation_sha256,
        stream.package_root_identity,
        _identity(11),
        "9" * 64,
        37,
        0x80,
        "f" * 64,
        ".towerscout-env-" + "e" * 32 + ".tmp",
    )
    drifted = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            chain[0].generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            drifted_record,
        ),
        protection,
    )

    for candidates in ((chain[0], chain[2]), (chain[0], drifted)):
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                candidates,
                None,
                expected_stream=stream,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("candidate_file_attributes", 0x20),
        ("candidate_security_descriptor_sha256", "e" * 64),
    ),
)
def test_verified_candidate_metadata_drift_fails_closed(
    field: str,
    value: object,
) -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    verified_generation = journal.authenticate_environment_journal_generation(
        chain[2],
        protection=protection,
    )
    assert type(verified_generation.record) is EnvironmentTempVerifiedRecord
    drifted_record = replace(verified_generation.record, **{field: value})
    drifted = _seal(
        replace(verified_generation, record=drifted_record),
        protection,
    )

    with pytest.raises(journal.RecoveryJournalError) as failure:
        journal.select_environment_journal_chain(
            (chain[0], chain[1], drifted),
            None,
            expected_stream=stream,
            protection=protection,
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_wrong_expected_stream_or_invalid_candidate_is_not_ignored() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    other_stream, other_chain = _build_chain(
        protection,
        stream=_stream(journal_id="f" * 32),
    )

    for expected, candidates in (
        (other_stream, chain),
        (stream, chain + (other_chain[0],)),
    ):
        with pytest.raises(journal.RecoveryJournalError) as failure:
            journal.select_environment_journal_chain(
                candidates,
                None,
                expected_stream=expected,
                protection=protection,
            )
        assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID


def test_selector_rejects_unsealed_caller_constructed_generation() -> None:
    stream = _stream()
    generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        1,
        journal.GENESIS_GENERATION_SHA256,
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        _plan_record(),
    )

    with pytest.raises(journal.RecoveryJournalError) as failure:
        journal.select_environment_journal_chain(
            cast(tuple[journal.SealedEnvironmentJournalGeneration, ...], (generation,)),
            None,
            expected_stream=stream,
            protection=_Protection(),
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.INPUT_INVALID
    assert "AuthenticatedEnvironmentJournalGeneration" not in journal.__all__


def test_authentication_and_malformed_plaintext_fail_without_detail() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    sealed = chain[0]

    with pytest.raises(journal.RecoveryJournalError) as authentication:
        journal.select_environment_journal_chain(
            (sealed,),
            None,
            expected_stream=stream,
            protection=_RejectingProtection(),
        )
    assert (
        authentication.value.code
        is journal.RecoveryJournalErrorCode.AUTHENTICATION_FAILED
    )

    malformed = _PlaintextProtection(b'{"schema_version":1, "unexpected":true}')
    with pytest.raises(journal.RecoveryJournalError) as invalid:
        journal.select_environment_journal_chain(
            (sealed,),
            None,
            expected_stream=stream,
            protection=malformed,
        )
    assert invalid.value.code is journal.RecoveryJournalErrorCode.GENERATION_INVALID
    assert "unexpected" not in str(invalid.value)


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("generation", True),
        ("generation", 1.0),
        ("record", True),
        ("record", 1.0),
        ("stream", True),
        ("stream", 1.0),
    ],
)
def test_decoded_schema_versions_require_exact_integers(
    member: str,
    value: bool | float,
) -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    sealed = chain[0]
    document = json.loads(
        protection.unprotect(
            sealed.protected_blob,
            ProtectedDataPurpose.JOURNAL_GENERATION,
        )
    )
    target = document if member == "generation" else document[member]
    target["schema_version"] = value
    malformed = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")

    with pytest.raises(journal.RecoveryJournalError) as failure:
        journal.select_environment_journal_chain(
            (sealed,),
            None,
            expected_stream=stream,
            protection=_PlaintextProtection(malformed),
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.GENERATION_INVALID


def test_deep_json_nesting_is_sanitized() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    deeply_nested = b'{"value":' + b"[" * 1_500 + b"0" + b"]" * 1_500 + b"}"

    with pytest.raises(journal.RecoveryJournalError) as failure:
        journal.select_environment_journal_chain(
            (chain[0],),
            None,
            expected_stream=stream,
            protection=_PlaintextProtection(deeply_nested),
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.GENERATION_INVALID


def test_invalid_or_failing_protection_port_is_sanitized() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    generation = journal.EnvironmentJournalGeneration(
        1,
        stream,
        1,
        journal.GENESIS_GENERATION_SHA256,
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        _plan_record(),
    )

    for invalid in (
        cast(journal.JournalProtectionPort, None),
        cast(journal.JournalProtectionPort, _UnexpectedProtection()),
    ):
        with pytest.raises(journal.RecoveryJournalError) as protect_failure:
            journal.protect_environment_journal_generation(
                generation,
                protection=invalid,
            )
        assert (
            protect_failure.value.code
            is journal.RecoveryJournalErrorCode.AUTHENTICATION_FAILED
        )
        assert "sensitive" not in str(protect_failure.value)

        with pytest.raises(journal.RecoveryJournalError) as unprotect_failure:
            journal.select_environment_journal_chain(
                (chain[0],),
                None,
                expected_stream=stream,
                protection=invalid,
            )
        assert (
            unprotect_failure.value.code
            is journal.RecoveryJournalErrorCode.AUTHENTICATION_FAILED
        )
        assert "sensitive" not in str(unprotect_failure.value)


def test_canonical_unknown_generation_member_is_sanitized() -> None:
    protection = _Protection()
    stream, chain = _build_chain(protection)
    sealed = chain[0]
    plaintext = protection.unprotect(
        sealed.protected_blob,
        ProtectedDataPurpose.JOURNAL_GENERATION,
    )
    document = json.loads(plaintext)
    document["unexpected"] = True
    malformed = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")

    with pytest.raises(journal.RecoveryJournalError) as invalid:
        journal.select_environment_journal_chain(
            (sealed,),
            None,
            expected_stream=stream,
            protection=_PlaintextProtection(malformed),
        )

    assert invalid.value.code is journal.RecoveryJournalErrorCode.GENERATION_INVALID
    assert "unexpected" not in str(invalid.value)


def test_record_link_must_equal_actual_predecessor_ciphertext_digest() -> None:
    protection = _Protection()
    stream = _stream()
    plan_record = _plan_record()
    first = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            plan_record,
        ),
        protection,
    )
    alternate_ciphertext = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            plan_record,
        ),
        protection,
    )
    created_record = EnvironmentTempCreatedRecord(
        1,
        first.generation_sha256,
        stream.package_root_identity,
        _identity(11),
        plan_record.candidate_sha256,
        plan_record.candidate_size,
        0x80,
        "f" * 64,
        plan_record.temp_name,
    )
    created = _seal(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            alternate_ciphertext.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            created_record,
        ),
        protection,
    )

    with pytest.raises(journal.RecoveryJournalError) as failure:
        journal.select_environment_journal_chain(
            (alternate_ciphertext, created),
            None,
            expected_stream=stream,
            protection=protection,
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID
