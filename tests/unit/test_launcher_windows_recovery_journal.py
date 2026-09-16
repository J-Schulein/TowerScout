from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
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
) -> EnvironmentTempPlanRecord:
    return EnvironmentTempPlanRecord(
        schema_version=1,
        package_root_identity=_identity(7),
        original_sha256="c" * 64,
        candidate_sha256=candidate_sha256,
        candidate_size=37,
        temp_name=temp_name,
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
        environment_present=environment_present,
        environment_sha256="c" * 64 if environment_present else None,
        environment_file_attributes=0x20 if environment_present else None,
        environment_security_descriptor_sha256=(
            "d" * 64 if environment_present else None
        ),
        local_ca_present=True,
        local_ca_sha256="e" * 64,
        local_ca_mode=0o644,
        ca_bundle_present=False,
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
) -> tuple[
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
]:
    selected_stream = stream or _stream()
    planned_record = _plan_record()
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
    assert record.environment_sha256 not in rendered


def test_backup_preparing_rejects_inconsistent_state_and_names() -> None:
    with pytest.raises(ValueError):
        journal.BackupPreparingRecord(
            1,
            _identity(7),
            "recovery-backup-" + "1" * 32 + ".blob",
            "recovery-backup-" + "1" * 32 + ".blob",
            False,
        )

    with pytest.raises(ValueError):
        journal.BackupPreparingRecord(
            1,
            _identity(7),
            "../recovery-backup-" + "1" * 32 + ".blob",
            "recovery-backup-" + "2" * 32 + ".blob",
            False,
        )

    with pytest.raises(ValueError):
        journal.BackupPreparingRecord(
            1,
            _identity(7),
            "recovery-backup-" + "1" * 32 + ".blob",
            "recovery-backup-" + "2" * 32 + ".blob",
            False,
            environment_sha256="c" * 64,
        )


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
            )
        with pytest.raises(ValueError):
            EnvironmentTempCreatedRecord(
                invalid,
                "1" * 64,
                _identity(7),
                _identity(11),
                "d" * 64,
                37,
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
                ".towerscout-env-" + "e" * 32 + ".tmp",
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
