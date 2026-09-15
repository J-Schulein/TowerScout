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
import towerscout_launcher.windows_recovery_pointer_transition as transition  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
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
        assert purpose in (
            ProtectedDataPurpose.JOURNAL_GENERATION,
            ProtectedDataPurpose.POINTER_TRANSITION,
        )
        self._nonce += 1
        prefix = purpose.value.encode("ascii") + self._nonce.to_bytes(4, "big")
        return CurrentUserProtectedBlob(purpose, prefix + plaintext)

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        prefix_size = len(purpose.value.encode("ascii")) + 4
        if blob.purpose is not purpose:
            raise ProtectedStateError("protected_data_invalid")
        return blob.ciphertext[prefix_size:]


class _PointerPlaintextProtection(_Protection):
    def __init__(self, plaintext: bytes) -> None:
        super().__init__()
        self.plaintext = plaintext

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        if purpose is ProtectedDataPurpose.POINTER_TRANSITION:
            return self.plaintext
        return super().unprotect(blob, purpose)


class _RejectingPointerProtection(_Protection):
    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        if purpose is ProtectedDataPurpose.POINTER_TRANSITION:
            raise ProtectedStateError("protected_data_invalid")
        return super().unprotect(blob, purpose)


class _InterruptingProtection(_Protection):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        del plaintext, purpose
        raise KeyboardInterrupt()

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        raise KeyboardInterrupt()


def _identity(seed: int, *, volume_serial: int = 7) -> StableFileIdentity:
    return StableFileIdentity(volume_serial, seed.to_bytes(16, "big"))


def _environment_stream() -> journal.JournalStreamIdentity:
    return journal.JournalStreamIdentity(
        1,
        "a" * 32,
        "b" * 64,
        _identity(7),
    )


def _seal_environment(
    generation: journal.EnvironmentJournalGeneration,
    protection: _Protection,
) -> journal.SealedEnvironmentJournalGeneration:
    return journal.protect_environment_journal_generation(
        generation,
        protection=protection,
    )


def _environment_chain(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
]:
    stream = _environment_stream()
    plan_record = EnvironmentTempPlanRecord(
        1,
        stream.package_root_identity,
        "c" * 64,
        "d" * 64,
        37,
        ".towerscout-env-" + "e" * 32 + ".tmp",
    )
    planned = _seal_environment(
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
        planned.generation_sha256,
        stream.package_root_identity,
        _identity(11),
        plan_record.candidate_sha256,
        plan_record.candidate_size,
        plan_record.temp_name,
    )
    created = _seal_environment(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            planned.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            created_record,
        ),
        protection,
    )
    return stream, (planned, created)


def _pointer(
    stream: journal.JournalStreamIdentity,
    generation: journal.SealedEnvironmentJournalGeneration,
    sequence: int,
) -> journal.EnvironmentJournalPointer:
    return journal.EnvironmentJournalPointer(
        1,
        stream.journal_id,
        sequence,
        generation.generation_sha256,
    )


def _transition_stream(
    environment_stream: journal.JournalStreamIdentity,
) -> transition.JournalPointerTransitionStreamIdentity:
    return transition.JournalPointerTransitionStreamIdentity(
        1,
        "f" * 32,
        environment_stream.journal_id,
        environment_stream.package_root_identity,
    )


def _plan_record(
    environment_stream: journal.JournalStreamIdentity,
    environment_chain: tuple[journal.SealedEnvironmentJournalGeneration, ...],
    *,
    prior_present: bool = True,
) -> transition.JournalPointerTransitionPlanRecord:
    target = _pointer(environment_stream, environment_chain[-1], 2)
    target_bytes = journal.encode_environment_journal_pointer(target)
    values: dict[str, object] = {
        "schema_version": 1,
        "package_root_identity": environment_stream.package_root_identity,
        "pointer_name": f"journal-{environment_stream.journal_id}.pointer",
        "pointer_temp_name": ".journal-pointer-" + "1" * 32 + ".tmp",
        "intended_pointer_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "intended_pointer_size": len(target_bytes),
        "target_tip_sequence": target.sequence,
        "target_generation_sha256": target.generation_sha256,
        "prior_pointer_present": prior_present,
    }
    if prior_present:
        prior = _pointer(environment_stream, environment_chain[0], 1)
        prior_bytes = journal.encode_environment_journal_pointer(prior)
        values.update(
            {
                "prior_pointer_identity": _identity(21),
                "prior_pointer_sequence": prior.sequence,
                "prior_pointer_generation_sha256": prior.generation_sha256,
                "prior_pointer_sha256": hashlib.sha256(prior_bytes).hexdigest(),
                "prior_pointer_size": len(prior_bytes),
            }
        )
    return transition.JournalPointerTransitionPlanRecord(**values)


def _seal_transition(
    generation: transition.JournalPointerTransitionGeneration,
    protection: _Protection,
) -> transition.SealedJournalPointerTransitionGeneration:
    return transition.protect_journal_pointer_transition_generation(
        generation,
        protection=protection,
    )


def _transition_chain(
    protection: _Protection,
    *,
    prior_present: bool = True,
) -> tuple[
    transition.JournalPointerTransitionStreamIdentity,
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
    tuple[transition.SealedJournalPointerTransitionGeneration, ...],
]:
    environment_stream, environment_chain = _environment_chain(protection)
    stream = _transition_stream(environment_stream)
    plan_record = _plan_record(
        environment_stream,
        environment_chain,
        prior_present=prior_present,
    )
    planned = _seal_transition(
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            1,
            transition.GENESIS_POINTER_TRANSITION_SHA256,
            transition.JournalPointerTransitionState.POINTER_TEMP_PLANNED,
            plan_record,
        ),
        protection,
    )
    created_record = transition.JournalPointerTransitionCreatedRecord(
        schema_version=1,
        planned_generation_sha256=planned.generation_sha256,
        package_root_identity=plan_record.package_root_identity,
        pointer_temp_identity=_identity(22),
        pointer_name=plan_record.pointer_name,
        pointer_temp_name=plan_record.pointer_temp_name,
        intended_pointer_sha256=plan_record.intended_pointer_sha256,
        intended_pointer_size=plan_record.intended_pointer_size,
        target_tip_sequence=plan_record.target_tip_sequence,
        target_generation_sha256=plan_record.target_generation_sha256,
        prior_pointer_present=plan_record.prior_pointer_present,
        prior_pointer_identity=plan_record.prior_pointer_identity,
        prior_pointer_sequence=plan_record.prior_pointer_sequence,
        prior_pointer_generation_sha256=(plan_record.prior_pointer_generation_sha256),
        prior_pointer_sha256=plan_record.prior_pointer_sha256,
        prior_pointer_size=plan_record.prior_pointer_size,
    )
    created = _seal_transition(
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            2,
            planned.generation_sha256,
            transition.JournalPointerTransitionState.POINTER_TEMP_CREATED,
            created_record,
        ),
        protection,
    )
    return stream, environment_stream, environment_chain, (planned, created)


def _select(
    protection: _Protection,
    *,
    prior_present: bool = True,
    created: bool = True,
) -> transition.JournalPointerTransitionChainSelection:
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection,
        prior_present=prior_present,
    )
    candidates = pointer_chain if created else pointer_chain[:1]
    return transition.select_journal_pointer_transition_chain(
        candidates,
        expected_stream=stream,
        environment_generations=environment_chain,
        expected_environment_stream=environment_stream,
        protection=protection,
    )


def _absent() -> transition.JournalPointerPathObservation:
    return transition.JournalPointerPathObservation(False)


def _present(
    identity: StableFileIdentity,
    sha256: str,
    size: int,
) -> transition.JournalPointerPathObservation:
    return transition.JournalPointerPathObservation(True, identity, sha256, size)


def test_transition_chain_round_trip_is_authenticated_and_redacted() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )

    selection = transition.select_journal_pointer_transition_chain(
        pointer_chain,
        expected_stream=stream,
        environment_generations=environment_chain,
        expected_environment_stream=environment_stream,
        protection=protection,
    )

    assert selection.tip.sequence == 2
    assert selection.tip_generation_sha256 == pointer_chain[-1].generation_sha256
    reverse_selection = transition.select_journal_pointer_transition_chain(
        tuple(reversed(pointer_chain)),
        expected_stream=stream,
        environment_generations=environment_chain,
        expected_environment_stream=environment_stream,
        protection=protection,
    )
    assert reverse_selection == selection
    rendered = repr(stream) + repr(selection.tip.record) + repr(selection)
    assert "journal-" not in rendered
    assert "1" * 32 not in rendered
    assert selection.tip.record.intended_pointer_sha256 not in rendered


def test_plan_context_accepts_exact_missing_and_stale_pointer_states() -> None:
    protection = _Protection()
    environment_stream, environment_chain = _environment_chain(protection)
    stream = _transition_stream(environment_stream)
    missing = _plan_record(environment_stream, environment_chain, prior_present=False)

    transition.validate_journal_pointer_transition_plan_context(
        missing,
        transition_stream=stream,
        environment_generations=environment_chain,
        environment_pointer=None,
        expected_environment_stream=environment_stream,
        prior_pointer_observation=_absent(),
        protection=protection,
    )

    stale = _plan_record(environment_stream, environment_chain)
    transition.validate_journal_pointer_transition_plan_context(
        stale,
        transition_stream=stream,
        environment_generations=environment_chain,
        environment_pointer=_pointer(environment_stream, environment_chain[0], 1),
        expected_environment_stream=environment_stream,
        prior_pointer_observation=_present(
            cast(StableFileIdentity, stale.prior_pointer_identity),
            cast(str, stale.prior_pointer_sha256),
            cast(int, stale.prior_pointer_size),
        ),
        protection=protection,
    )


def test_plan_context_rejects_current_or_mismatched_prior_state() -> None:
    protection = _Protection()
    environment_stream, environment_chain = _environment_chain(protection)
    stream = _transition_stream(environment_stream)
    stale = _plan_record(environment_stream, environment_chain)
    missing = _plan_record(environment_stream, environment_chain, prior_present=False)

    cases = (
        (
            stale,
            _pointer(environment_stream, environment_chain[-1], 2),
            _present(
                cast(StableFileIdentity, stale.prior_pointer_identity),
                cast(str, stale.prior_pointer_sha256),
                cast(int, stale.prior_pointer_size),
            ),
        ),
        (stale, None, _absent()),
        (
            missing,
            _pointer(environment_stream, environment_chain[0], 1),
            _absent(),
        ),
        (
            stale,
            _pointer(environment_stream, environment_chain[0], 1),
            _present(
                _identity(99),
                cast(str, stale.prior_pointer_sha256),
                cast(int, stale.prior_pointer_size),
            ),
        ),
    )
    for record, pointer, observation in cases:
        with pytest.raises(transition.JournalPointerTransitionError) as failure:
            transition.validate_journal_pointer_transition_plan_context(
                record,
                transition_stream=stream,
                environment_generations=environment_chain,
                environment_pointer=pointer,
                expected_environment_stream=environment_stream,
                prior_pointer_observation=observation,
                protection=protection,
            )
        assert (
            failure.value.code
            is transition.JournalPointerTransitionErrorCode.CONTEXT_INVALID
        )


def test_selector_authenticates_environment_generations_itself() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    fabricated = journal.EnvironmentJournalChainSelection(
        generations=(
            journal.EnvironmentJournalGeneration(
                1,
                environment_stream,
                1,
                journal.GENESIS_GENERATION_SHA256,
                journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
                EnvironmentTempPlanRecord(
                    1,
                    environment_stream.package_root_identity,
                    "c" * 64,
                    "d" * 64,
                    37,
                    ".towerscout-env-" + "e" * 32 + ".tmp",
                ),
            ),
        ),
        generation_sha256s=("9" * 64,),
        tip=journal.EnvironmentJournalGeneration(
            1,
            environment_stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            EnvironmentTempPlanRecord(
                1,
                environment_stream.package_root_identity,
                "c" * 64,
                "d" * 64,
                37,
                ".towerscout-env-" + "e" * 32 + ".tmp",
            ),
        ),
        tip_generation_sha256="9" * 64,
        pointer_disposition=journal.JournalPointerDisposition.MISSING_REPAIR,
    )

    with pytest.raises(transition.JournalPointerTransitionError) as failure:
        transition.select_journal_pointer_transition_chain(
            pointer_chain,
            expected_stream=stream,
            environment_generations=cast(
                tuple[journal.SealedEnvironmentJournalGeneration, ...],
                (fabricated,),
            ),
            expected_environment_stream=environment_stream,
            protection=protection,
        )

    assert (
        failure.value.code
        is transition.JournalPointerTransitionErrorCode.CONTEXT_INVALID
    )
    assert environment_chain


def test_selector_rejects_wrong_target_and_unknown_prior_generation() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    plan = cast(
        transition.JournalPointerTransitionPlanRecord,
        pointer_chain[0]
        and transition._generation_from_bytes(
            protection.unprotect(
                pointer_chain[0].protected_blob,
                ProtectedDataPurpose.POINTER_TRANSITION,
            )
        ).record,
    )

    wrong_target_pointer = _pointer(environment_stream, environment_chain[0], 1)
    wrong_target_bytes = journal.encode_environment_journal_pointer(
        wrong_target_pointer
    )
    wrong_target = replace(
        plan,
        intended_pointer_sha256=hashlib.sha256(wrong_target_bytes).hexdigest(),
        intended_pointer_size=len(wrong_target_bytes),
        target_tip_sequence=wrong_target_pointer.sequence,
        target_generation_sha256=wrong_target_pointer.generation_sha256,
        prior_pointer_present=False,
        prior_pointer_identity=None,
        prior_pointer_sequence=None,
        prior_pointer_generation_sha256=None,
        prior_pointer_sha256=None,
        prior_pointer_size=None,
    )
    unknown_prior_pointer = journal.EnvironmentJournalPointer(
        1,
        environment_stream.journal_id,
        1,
        "8" * 64,
    )
    unknown_prior_bytes = journal.encode_environment_journal_pointer(
        unknown_prior_pointer
    )
    unknown_prior = replace(
        plan,
        prior_pointer_generation_sha256=unknown_prior_pointer.generation_sha256,
        prior_pointer_sha256=hashlib.sha256(unknown_prior_bytes).hexdigest(),
        prior_pointer_size=len(unknown_prior_bytes),
    )

    for drifted in (wrong_target, unknown_prior):
        generation = transition.JournalPointerTransitionGeneration(
            1,
            stream,
            1,
            transition.GENESIS_POINTER_TRANSITION_SHA256,
            transition.JournalPointerTransitionState.POINTER_TEMP_PLANNED,
            drifted,
        )
        sealed = _seal_transition(generation, protection)
        with pytest.raises(transition.JournalPointerTransitionError) as failure:
            transition.select_journal_pointer_transition_chain(
                (sealed,),
                expected_stream=stream,
                environment_generations=environment_chain,
                expected_environment_stream=environment_stream,
                protection=protection,
            )
        assert (
            failure.value.code
            is transition.JournalPointerTransitionErrorCode.CONTEXT_INVALID
        )


def test_created_chain_rejects_broken_link_duplicate_and_intent_drift() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    created_generation = transition._generation_from_bytes(
        protection.unprotect(
            pointer_chain[1].protected_blob,
            ProtectedDataPurpose.POINTER_TRANSITION,
        )
    )
    created_record = cast(
        transition.JournalPointerTransitionCreatedRecord,
        created_generation.record,
    )
    broken_record = replace(
        created_record, pointer_temp_name=".journal-pointer-" + "2" * 32 + ".tmp"
    )
    broken = _seal_transition(
        replace(created_generation, record=broken_record),
        protection,
    )

    for candidates in (
        pointer_chain + (pointer_chain[-1],),
        (pointer_chain[0], broken),
    ):
        with pytest.raises(transition.JournalPointerTransitionError) as failure:
            transition.select_journal_pointer_transition_chain(
                candidates,
                expected_stream=stream,
                environment_generations=environment_chain,
                expected_environment_stream=environment_stream,
                protection=protection,
            )
        assert (
            failure.value.code
            is transition.JournalPointerTransitionErrorCode.CHAIN_INVALID
        )


def test_authentication_and_noncanonical_plaintext_fail_without_detail() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )

    with pytest.raises(transition.JournalPointerTransitionError) as rejected:
        transition.select_journal_pointer_transition_chain(
            pointer_chain[:1],
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=_RejectingPointerProtection(),
        )
    assert (
        rejected.value.code
        is transition.JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED
    )

    plaintext = protection.unprotect(
        pointer_chain[0].protected_blob,
        ProtectedDataPurpose.POINTER_TRANSITION,
    )
    with pytest.raises(transition.JournalPointerTransitionError) as invalid:
        transition.select_journal_pointer_transition_chain(
            pointer_chain[:1],
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=_PointerPlaintextProtection(plaintext.replace(b"{", b"{ ", 1)),
        )
    assert (
        invalid.value.code
        is transition.JournalPointerTransitionErrorCode.GENERATION_INVALID
    )
    assert ".journal-pointer-" not in str(invalid.value)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda document: document.update({"unexpected": True}),
        lambda document: document.update({"schema_version": True}),
        lambda document: document["record"].update({"target_tip_sequence": 1.0}),
        lambda document: document["stream"].update({"schema_version": False}),
    ],
)
def test_canonical_unknown_or_wrong_scalar_members_are_rejected(mutator) -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    plaintext = protection.unprotect(
        pointer_chain[0].protected_blob,
        ProtectedDataPurpose.POINTER_TRANSITION,
    )
    document = json.loads(plaintext)
    mutator(document)
    malformed = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")

    with pytest.raises(transition.JournalPointerTransitionError) as failure:
        transition.select_journal_pointer_transition_chain(
            pointer_chain[:1],
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=_PointerPlaintextProtection(malformed),
        )
    assert (
        failure.value.code
        is transition.JournalPointerTransitionErrorCode.GENERATION_INVALID
    )


def test_duplicate_nested_member_and_deep_json_are_rejected() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    duplicate = (
        b'{"previous_generation_sha256":"'
        + b"1" * 64
        + b'","record":{"schema_version":1,"schema_version":1},'
        + b'"schema_version":1,"sequence":1,"state":"pointer_temp_planned",'
        + b'"stream":{}}'
    )
    deep = b'{"value":' + b"[" * 1_500 + b"0" + b"]" * 1_500 + b"}"

    for plaintext in (duplicate, deep):
        with pytest.raises(transition.JournalPointerTransitionError) as failure:
            transition.select_journal_pointer_transition_chain(
                pointer_chain[:1],
                expected_stream=stream,
                environment_generations=environment_chain,
                expected_environment_stream=environment_stream,
                protection=_PointerPlaintextProtection(plaintext),
            )
        assert (
            failure.value.code
            is transition.JournalPointerTransitionErrorCode.GENERATION_INVALID
        )


def test_record_invariants_reject_partial_prior_cross_volume_and_identity_alias() -> (
    None
):
    protection = _Protection()
    environment_stream, environment_chain = _environment_chain(protection)
    plan = _plan_record(environment_stream, environment_chain)
    stream = _transition_stream(environment_stream)

    with pytest.raises(ValueError):
        replace(plan, prior_pointer_sha256=None)
    with pytest.raises(ValueError):
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            1,
            transition.GENESIS_POINTER_TRANSITION_SHA256,
            transition.JournalPointerTransitionState.POINTER_TEMP_PLANNED,
            replace(plan, prior_pointer_identity=_identity(21, volume_serial=8)),
        )

    planned = _seal_transition(
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            1,
            transition.GENESIS_POINTER_TRANSITION_SHA256,
            transition.JournalPointerTransitionState.POINTER_TEMP_PLANNED,
            plan,
        ),
        protection,
    )
    created = transition.JournalPointerTransitionCreatedRecord(
        1,
        planned.generation_sha256,
        plan.package_root_identity,
        cast(StableFileIdentity, plan.prior_pointer_identity),
        plan.pointer_name,
        plan.pointer_temp_name,
        plan.intended_pointer_sha256,
        plan.intended_pointer_size,
        plan.target_tip_sequence,
        plan.target_generation_sha256,
        plan.prior_pointer_present,
        plan.prior_pointer_identity,
        plan.prior_pointer_sequence,
        plan.prior_pointer_generation_sha256,
        plan.prior_pointer_sha256,
        plan.prior_pointer_size,
    )
    with pytest.raises(ValueError):
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            2,
            planned.generation_sha256,
            transition.JournalPointerTransitionState.POINTER_TEMP_CREATED,
            created,
        )


def test_classifier_accepts_only_exact_source_or_completed_move_states() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    selection = transition.select_journal_pointer_transition_chain(
        pointer_chain,
        expected_stream=stream,
        environment_generations=environment_chain,
        expected_environment_stream=environment_stream,
        protection=protection,
    )
    created = cast(
        transition.JournalPointerTransitionCreatedRecord,
        selection.tip.record,
    )
    source = _present(
        created.pointer_temp_identity,
        created.intended_pointer_sha256,
        created.intended_pointer_size,
    )
    prior = _present(
        cast(StableFileIdentity, created.prior_pointer_identity),
        cast(str, created.prior_pointer_sha256),
        cast(int, created.prior_pointer_size),
    )
    destination = _present(
        created.pointer_temp_identity,
        created.intended_pointer_sha256,
        created.intended_pointer_size,
    )

    assert (
        transition.classify_journal_pointer_transition_restart(
            pointer_chain,
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=protection,
            source_temp_observation=source,
            destination_pointer_observation=prior,
        )
        is transition.JournalPointerRestartDisposition.SOURCE_TEMP_REMAINS
    )
    assert (
        transition.classify_journal_pointer_transition_restart(
            pointer_chain,
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=protection,
            source_temp_observation=_absent(),
            destination_pointer_observation=destination,
        )
        is transition.JournalPointerRestartDisposition.MOVE_COMPLETED
    )

    ambiguous = (
        (source, destination),
        (_absent(), prior),
        (_absent(), _absent()),
        (
            _present(
                _identity(99),
                created.intended_pointer_sha256,
                created.intended_pointer_size,
            ),
            prior,
        ),
        (prior, source),
    )
    for source_observation, destination_observation in ambiguous:
        assert (
            transition.classify_journal_pointer_transition_restart(
                pointer_chain,
                expected_stream=stream,
                environment_generations=environment_chain,
                expected_environment_stream=environment_stream,
                protection=protection,
                source_temp_observation=source_observation,
                destination_pointer_observation=destination_observation,
            )
            is transition.JournalPointerRestartDisposition.AMBIGUOUS
        )


def test_classifier_handles_missing_prior_and_plan_only_conservatively() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection,
        prior_present=False,
    )
    created_selection = transition.select_journal_pointer_transition_chain(
        pointer_chain,
        expected_stream=stream,
        environment_generations=environment_chain,
        expected_environment_stream=environment_stream,
        protection=protection,
    )
    created = cast(
        transition.JournalPointerTransitionCreatedRecord,
        created_selection.tip.record,
    )
    source = _present(
        created.pointer_temp_identity,
        created.intended_pointer_sha256,
        created.intended_pointer_size,
    )
    assert (
        transition.classify_journal_pointer_transition_restart(
            pointer_chain,
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=protection,
            source_temp_observation=source,
            destination_pointer_observation=_absent(),
        )
        is transition.JournalPointerRestartDisposition.SOURCE_TEMP_REMAINS
    )

    assert (
        transition.classify_journal_pointer_transition_restart(
            pointer_chain[:1],
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=protection,
            source_temp_observation=source,
            destination_pointer_observation=_absent(),
        )
        is transition.JournalPointerRestartDisposition.AMBIGUOUS
    )


def test_classifier_rejects_caller_constructed_selection() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    selection = transition.select_journal_pointer_transition_chain(
        pointer_chain,
        expected_stream=stream,
        environment_generations=environment_chain,
        expected_environment_stream=environment_stream,
        protection=protection,
    )

    with pytest.raises(transition.JournalPointerTransitionError) as failure:
        transition.classify_journal_pointer_transition_restart(
            cast(
                tuple[transition.SealedJournalPointerTransitionGeneration, ...],
                (selection,),
            ),
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=protection,
            source_temp_observation=_absent(),
            destination_pointer_observation=_absent(),
        )

    assert (
        failure.value.code is transition.JournalPointerTransitionErrorCode.INPUT_INVALID
    )


def test_cross_purpose_blob_and_process_control_exceptions_fail_safely() -> None:
    protection = _Protection()
    stream, environment_stream, environment_chain, pointer_chain = _transition_chain(
        protection
    )
    with pytest.raises(ValueError):
        transition.SealedJournalPointerTransitionGeneration(
            CurrentUserProtectedBlob(
                ProtectedDataPurpose.JOURNAL_GENERATION,
                b"wrong-purpose",
            ),
            hashlib.sha256(b"wrong-purpose").hexdigest(),
        )

    generation = transition._generation_from_bytes(
        protection.unprotect(
            pointer_chain[0].protected_blob,
            ProtectedDataPurpose.POINTER_TRANSITION,
        )
    )
    with pytest.raises(KeyboardInterrupt):
        transition.protect_journal_pointer_transition_generation(
            generation,
            protection=_InterruptingProtection(),
        )
    with pytest.raises(KeyboardInterrupt):
        transition.select_journal_pointer_transition_chain(
            pointer_chain[:1],
            expected_stream=stream,
            environment_generations=environment_chain,
            expected_environment_stream=environment_stream,
            protection=_InterruptingProtection(),
        )


def test_public_exports_do_not_expose_authenticated_wrapper() -> None:
    assert "_AuthenticatedJournalPointerTransitionGeneration" not in transition.__all__
