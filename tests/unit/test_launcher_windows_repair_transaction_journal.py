from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_repair_transaction_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal as recovery_journal  # noqa: E402
from towerscout_launcher.target_contracts import ABSENT_FILE_SHA256  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentAppliedRecord,
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    PersistedEnvironmentJournalChain,
)


class _Protection:
    def __init__(self) -> None:
        self.nonce = 0

    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        assert purpose is ProtectedDataPurpose.JOURNAL_GENERATION
        self.nonce += 1
        return CurrentUserProtectedBlob(
            purpose,
            b"TSF1" + self.nonce.to_bytes(4, "big") + plaintext,
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        assert purpose is ProtectedDataPurpose.JOURNAL_GENERATION
        if blob.purpose is not purpose or not blob.ciphertext.startswith(b"TSF1"):
            raise ValueError("private authentication detail")
        return blob.ciphertext[8:]


class _RejectingProtection(_Protection):
    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        raise KeyError("private authentication detail")


def _identity(seed: int = 7) -> StableFileIdentity:
    return StableFileIdentity(seed, seed.to_bytes(16, "big"))


def _stream() -> journal.RepairTransactionStreamIdentity:
    return journal.RepairTransactionStreamIdentity(
        schema_version=1,
        journal_id="a" * 32,
        rollback_journal_id="b" * 32,
        rollback_armed_generation_sha256="c" * 64,
        target_token_sha256="d" * 64,
        package_root_identity=_identity(),
    )


def _states(
    *, cleanup_pending: bool = False
) -> tuple[journal.RepairTransactionState, ...]:
    forward = (
        journal.RepairTransactionState.CERTIFICATE_TEMP_PLANNED,
        journal.RepairTransactionState.CERTIFICATE_TEMP_CREATED,
        journal.RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
        journal.RepairTransactionState.CERTIFICATES_APPLIED,
        journal.RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
        journal.RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
        journal.RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
        journal.RepairTransactionState.ENVIRONMENT_APPLIED,
        journal.RepairTransactionState.RUNTIME_STOPPING,
        journal.RepairTransactionState.RUNTIME_STOPPED,
        journal.RepairTransactionState.RUNTIME_STARTING,
        journal.RepairTransactionState.RUNTIME_STARTED,
        journal.RepairTransactionState.SUCCESS_VERIFYING,
        journal.RepairTransactionState.COMMITTED,
    )
    if cleanup_pending:
        return forward + (
            journal.RepairTransactionState.RECOVERY_CLEANUP_PENDING,
            journal.RepairTransactionState.CLEANED,
        )
    return forward + (journal.RepairTransactionState.CLEANED,)


def _sealed_chain(
    states: tuple[journal.RepairTransactionState, ...],
    *,
    protection: _Protection,
    stream: journal.RepairTransactionStreamIdentity | None = None,
    provider_ids: tuple[str, ...] | None = None,
    provider_generation_sha256s: tuple[str, ...] | None = None,
) -> tuple[journal.SealedRepairTransactionGeneration, ...]:
    selected_stream = _stream() if stream is None else stream
    previous = selected_stream.rollback_armed_generation_sha256
    sealed: list[journal.SealedRepairTransactionGeneration] = []
    provider_index = 0
    for sequence, state in enumerate(states, start=1):
        provider_sequence = None
        provider_journal_id = None
        provider_generation_sha256 = None
        if state in {
            journal.RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
            journal.RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
            journal.RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
            journal.RepairTransactionState.ENVIRONMENT_APPLIED,
        }:
            provider_sequence = provider_index + 1
            provider_journal_id = (
                "e" * 32 if provider_ids is None else provider_ids[provider_index]
            )
            provider_generation_sha256 = (
                f"{provider_index + 1:064x}"
                if provider_generation_sha256s is None
                else provider_generation_sha256s[provider_index]
            )
            provider_index += 1
        record = journal.RepairTransitionRecord(
            schema_version=1,
            predecessor_generation_sha256=previous,
            package_root_identity=selected_stream.package_root_identity,
            evidence_sha256=f"{sequence:064x}",
            provider_journal_id=provider_journal_id,
            provider_sequence=provider_sequence,
            provider_generation_sha256=provider_generation_sha256,
        )
        generation = journal.RepairTransactionGeneration(
            schema_version=1,
            stream=selected_stream,
            sequence=sequence,
            previous_generation_sha256=previous,
            state=state,
            record=record,
        )
        protected = journal.protect_repair_transaction_generation(
            generation,
            protection=protection,
        )
        sealed.append(protected)
        previous = protected.generation_sha256
    return tuple(sealed)


def _provider_chain(
    protection: _Protection,
    *,
    journal_id: str = "e" * 32,
    target_token_sha256: str = "d" * 64,
    package_root_identity: StableFileIdentity | None = None,
    count: int = 4,
) -> PersistedEnvironmentJournalChain:
    package_identity = (
        _identity() if package_root_identity is None else package_root_identity
    )
    stream = recovery_journal.JournalStreamIdentity(
        1,
        journal_id,
        target_token_sha256,
        package_identity,
    )
    candidate_sha256 = "6" * 64
    temp_name = ".towerscout-env-" + "7" * 32 + ".tmp"
    records = [
        EnvironmentTempPlanRecord(
            1,
            package_identity,
            ABSENT_FILE_SHA256,
            candidate_sha256,
            37,
            temp_name,
            False,
        )
    ]
    sealed: list[recovery_journal.SealedEnvironmentJournalGeneration] = []
    previous = recovery_journal.GENESIS_GENERATION_SHA256
    states = (
        recovery_journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        recovery_journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
        recovery_journal.EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
        recovery_journal.EnvironmentJournalState.ENVIRONMENT_APPLIED,
    )
    for sequence, state in enumerate(states[:count], start=1):
        if sequence == 2:
            records.append(
                EnvironmentTempCreatedRecord(
                    1,
                    previous,
                    package_identity,
                    _identity(8),
                    candidate_sha256,
                    37,
                    0x20,
                    "8" * 64,
                    temp_name,
                )
            )
        elif sequence == 3:
            records.append(
                EnvironmentTempVerifiedRecord(
                    1,
                    previous,
                    package_identity,
                    _identity(8),
                    candidate_sha256,
                    37,
                    0x20,
                    "8" * 64,
                    temp_name,
                )
            )
        elif sequence == 4:
            records.append(
                EnvironmentAppliedRecord(
                    1,
                    previous,
                    package_identity,
                    _identity(8),
                    candidate_sha256,
                    37,
                    0x20,
                    "8" * 64,
                    temp_name,
                )
            )
        generation = recovery_journal.EnvironmentJournalGeneration(
            1,
            stream,
            sequence,
            previous,
            state,
            records[-1],
        )
        protected = recovery_journal.protect_environment_journal_generation(
            generation,
            protection=protection,
        )
        sealed.append(protected)
        previous = protected.generation_sha256
    selection = recovery_journal.select_environment_journal_chain(
        tuple(sealed),
        recovery_journal.EnvironmentJournalPointer(
            1,
            stream.journal_id,
            count,
            sealed[-1].generation_sha256,
        ),
        expected_stream=stream,
        protection=protection,
    )
    return PersistedEnvironmentJournalChain(
        tuple(sealed),
        tuple(_identity(value) for value in range(20, 20 + count)),
        selection,
    )


@pytest.mark.parametrize("length", range(1, 15))
def test_accepts_every_forward_write_ahead_prefix(length: int) -> None:
    protection = _Protection()
    sealed = _sealed_chain(_states()[:length], protection=protection)

    selected = journal.select_repair_transaction_chain(
        tuple(reversed(sealed)),
        None,
        expected_stream=_stream(),
        protection=protection,
    )

    assert selected.tip.sequence == length
    assert selected.pointer_disposition is (
        journal.RepairTransactionPointerDisposition.MISSING_REPAIR
    )


@pytest.mark.parametrize("cleanup_pending", [False, True])
def test_accepts_both_authenticated_cleanup_paths(cleanup_pending: bool) -> None:
    protection = _Protection()
    sealed = _sealed_chain(
        _states(cleanup_pending=cleanup_pending),
        protection=protection,
    )
    pointer = journal.RepairTransactionJournalPointer(
        1,
        "a" * 32,
        len(sealed),
        sealed[-1].generation_sha256,
    )

    selected = journal.select_repair_transaction_chain(
        sealed,
        journal.decode_repair_transaction_pointer(
            journal.encode_repair_transaction_pointer(pointer)
        ),
        expected_stream=_stream(),
        protection=protection,
    )

    assert selected.tip.state is journal.RepairTransactionState.CLEANED
    assert selected.pointer_disposition is (
        journal.RepairTransactionPointerDisposition.CURRENT
    )


def test_terminal_environment_link_is_exact_and_redacted() -> None:
    protection = _Protection()
    sealed = _sealed_chain(_states()[:8], protection=protection)

    selected = journal.select_repair_transaction_chain(
        sealed,
        None,
        expected_stream=_stream(),
        protection=protection,
    )
    record = selected.tip.record

    assert selected.tip.state is journal.RepairTransactionState.ENVIRONMENT_APPLIED
    assert record.provider_journal_id == "e" * 32
    assert record.provider_sequence == 4
    assert record.provider_generation_sha256 == f"{4:064x}"
    rendered = repr(selected) + repr(record) + repr(selected.tip)
    assert record.provider_journal_id not in rendered
    assert record.provider_generation_sha256 not in rendered
    assert _stream().rollback_armed_generation_sha256 not in rendered


def test_authenticates_exact_terminal_provider_chain_link() -> None:
    protection = _Protection()
    provider = _provider_chain(protection)
    sealed = _sealed_chain(
        _states()[:12],
        protection=protection,
        provider_generation_sha256s=provider.selection.generation_sha256s,
    )
    forward = journal.select_repair_transaction_chain(
        sealed,
        None,
        expected_stream=_stream(),
        protection=protection,
    )
    linked = journal.authenticate_terminal_provider_link(forward, provider)

    assert linked.provider_journal_id == provider.selection.tip.stream.journal_id
    assert linked.provider_generation_sha256 == provider.selection.tip_generation_sha256
    assert linked.provider_record is provider.selection.tip.record
    assert linked.provider_generation_sha256 not in repr(linked)


@pytest.mark.parametrize("provider_sequence", [1, 2, 3, 4])
def test_authenticates_each_exact_provider_write_ahead_link(
    provider_sequence: int,
) -> None:
    protection = _Protection()
    provider = _provider_chain(protection, count=provider_sequence)
    sealed = _sealed_chain(
        _states()[: 4 + provider_sequence],
        protection=protection,
        provider_generation_sha256s=provider.selection.generation_sha256s,
    )
    forward = journal.select_repair_transaction_chain(
        sealed,
        None,
        expected_stream=_stream(),
        protection=protection,
    )

    linked = journal.authenticate_provider_link(forward, provider)

    assert linked.provider_sequence == provider_sequence
    assert linked.provider_generation_sha256 == provider.selection.tip_generation_sha256


@pytest.mark.parametrize(
    ("journal_id", "target_token_sha256", "package_root_identity"),
    [
        ("f" * 32, "d" * 64, _identity()),
        ("e" * 32, "9" * 64, _identity()),
        ("e" * 32, "d" * 64, _identity(99)),
    ],
)
def test_rejects_ambient_terminal_provider_chain(
    journal_id: str,
    target_token_sha256: str,
    package_root_identity: StableFileIdentity,
) -> None:
    protection = _Protection()
    sealed = _sealed_chain(_states()[:8], protection=protection)
    forward = journal.select_repair_transaction_chain(
        sealed,
        None,
        expected_stream=_stream(),
        protection=protection,
    )
    provider = _provider_chain(
        protection,
        journal_id=journal_id,
        target_token_sha256=target_token_sha256,
        package_root_identity=package_root_identity,
    )

    with pytest.raises(journal.RepairTransactionJournalError) as captured:
        journal.authenticate_terminal_provider_link(forward, provider)

    assert (
        captured.value.code is journal.RepairTransactionJournalErrorCode.CHAIN_INVALID
    )


def test_rejects_provider_stream_switch_inside_forward_chain() -> None:
    protection = _Protection()
    provider_ids = ("e" * 32, "e" * 32, "f" * 32, "f" * 32)
    sealed = _sealed_chain(
        _states()[:8],
        protection=protection,
        provider_ids=provider_ids,
    )

    with pytest.raises(journal.RepairTransactionJournalError) as captured:
        journal.select_repair_transaction_chain(
            sealed,
            None,
            expected_stream=_stream(),
            protection=protection,
        )

    assert (
        captured.value.code is journal.RepairTransactionJournalErrorCode.CHAIN_INVALID
    )
    assert "f" * 32 not in str(captured.value)


def test_rejects_missing_or_self_referential_provider_link() -> None:
    stream = _stream()
    previous = "1" * 64
    missing = journal.RepairTransitionRecord(
        1,
        previous,
        stream.package_root_identity,
        "2" * 64,
    )
    self_link = journal.RepairTransitionRecord(
        1,
        previous,
        stream.package_root_identity,
        "2" * 64,
        stream.journal_id,
        1,
        "3" * 64,
    )

    for record in (missing, self_link):
        with pytest.raises(ValueError):
            journal.RepairTransactionGeneration(
                1,
                stream,
                5,
                previous,
                journal.RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
                record,
            )


def test_rejects_chain_not_anchored_to_exact_rollback_generation() -> None:
    protection = _Protection()
    sealed = _sealed_chain(_states()[:1], protection=protection)
    changed_stream = replace(_stream(), rollback_armed_generation_sha256="9" * 64)

    with pytest.raises(journal.RepairTransactionJournalError) as captured:
        journal.select_repair_transaction_chain(
            sealed,
            None,
            expected_stream=changed_stream,
            protection=protection,
        )

    assert (
        captured.value.code is journal.RepairTransactionJournalErrorCode.CHAIN_INVALID
    )


def test_rejects_skipped_state_and_stale_or_foreign_pointer() -> None:
    protection = _Protection()
    sealed = _sealed_chain(
        (
            journal.RepairTransactionState.CERTIFICATE_TEMP_PLANNED,
            journal.RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
        ),
        protection=protection,
    )
    with pytest.raises(journal.RepairTransactionJournalError):
        journal.select_repair_transaction_chain(
            sealed,
            None,
            expected_stream=_stream(),
            protection=protection,
        )

    valid = _sealed_chain(_states()[:3], protection=protection)
    stale = journal.RepairTransactionJournalPointer(
        1,
        "a" * 32,
        1,
        valid[0].generation_sha256,
    )
    selected = journal.select_repair_transaction_chain(
        valid,
        stale,
        expected_stream=_stream(),
        protection=protection,
    )
    assert selected.pointer_disposition is (
        journal.RepairTransactionPointerDisposition.STALE_REPAIR
    )
    foreign = replace(stale, journal_id="f" * 32)
    with pytest.raises(journal.RepairTransactionJournalError):
        journal.select_repair_transaction_chain(
            valid,
            foreign,
            expected_stream=_stream(),
            protection=protection,
        )


def test_authentication_failure_is_sanitized() -> None:
    protection = _Protection()
    sealed = _sealed_chain(_states()[:1], protection=protection)[0]

    with pytest.raises(journal.RepairTransactionJournalError) as captured:
        journal.authenticate_repair_transaction_generation(
            sealed,
            protection=_RejectingProtection(),
        )

    assert captured.value.code is (
        journal.RepairTransactionJournalErrorCode.AUTHENTICATION_FAILED
    )
    assert "private" not in str(captured.value)
