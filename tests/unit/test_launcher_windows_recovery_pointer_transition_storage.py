from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Callable, TypeVar, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher import (  # noqa: E402
    windows_environment_replacement_native as environment,
    windows_protected_state as protected_state,
    windows_recovery_journal as journal,
    windows_recovery_journal_storage as journal_storage,
    windows_recovery_pointer_transition as transition,
    windows_recovery_pointer_transition_storage as store,
    windows_security as security,
)

EnvironmentTempCreatedRecord = environment.EnvironmentTempCreatedRecord
EnvironmentTempPlanRecord = environment.EnvironmentTempPlanRecord
CurrentUserProtectedBlob = protected_state.CurrentUserProtectedBlob
ProtectedDataPurpose = protected_state.ProtectedDataPurpose
RecoveryJournalStorageError = journal_storage.RecoveryJournalStorageError
StorageErrorCode = journal_storage.RecoveryJournalStorageErrorCode
StoredJournalGenerationFile = journal_storage.StoredJournalGenerationFile
StableFileIdentity = security.StableFileIdentity
TransitionPlan = transition.JournalPointerTransitionPlanRecord
TransitionStream = transition.JournalPointerTransitionStreamIdentity
SealedTransition = transition.SealedJournalPointerTransitionGeneration
append_item = store.append_persisted_journal_pointer_transition_generation
load_transition = store.load_persisted_journal_pointer_transition_chain

_Result = TypeVar("_Result")


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


class _Protection:
    def __init__(self) -> None:
        self.nonce = 0

    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        self.nonce += 1
        return CurrentUserProtectedBlob(
            purpose,
            self.nonce.to_bytes(4, "big") + plaintext,
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        if blob.purpose is not purpose:
            raise ValueError("sensitive purpose detail")
        return blob.ciphertext[4:]


class _Root:
    def __init__(self) -> None:
        self.active = False

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        self.active = True
        try:
            root = r"C:\Users\private\AppData\Local" r"\TowerScout\Recovery\v1"
            return operation(root)
        finally:
            self.active = False


class _Storage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.files: dict[str, StoredJournalGenerationFile] = {}
        self.next_identity = 30
        self.return_wrong_write = False

    def _assert_held(self) -> None:
        assert self.root.active

    def list_names(self, root_path: str) -> tuple[str, ...]:
        self._assert_held()
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        return tuple(reversed(tuple(self.files)))

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalGenerationFile:
        self._assert_held()
        del root_path
        item = self.files[name]
        assert len(item.contents) <= maximum
        return item

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalGenerationFile:
        self._assert_held()
        del root_path
        if name in self.files:
            raise FileExistsError("sensitive existing path")
        self.next_identity += 1
        stored = StoredJournalGenerationFile(
            _identity(self.next_identity),
            b"wrong" if self.return_wrong_write else contents,
        )
        self.files[name] = stored
        return stored


def _environment_chain(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
]:
    stream = journal.JournalStreamIdentity(1, "a" * 32, "b" * 64, _identity(7))
    plan = EnvironmentTempPlanRecord(
        1,
        stream.package_root_identity,
        "c" * 64,
        "d" * 64,
        37,
        ".towerscout-env-" + "e" * 32 + ".tmp",
    )
    planned = journal.protect_environment_journal_generation(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            1,
            journal.GENESIS_GENERATION_SHA256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            plan,
        ),
        protection=protection,
    )
    created_record = EnvironmentTempCreatedRecord(
        1,
        planned.generation_sha256,
        stream.package_root_identity,
        _identity(11),
        plan.candidate_sha256,
        plan.candidate_size,
        plan.temp_name,
    )
    created = journal.protect_environment_journal_generation(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            2,
            planned.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            created_record,
        ),
        protection=protection,
    )
    return stream, (planned, created)


def _transition_chain(
    protection: _Protection,
) -> tuple[
    TransitionStream,
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
    tuple[SealedTransition, ...],
]:
    environment_stream, environment_chain = _environment_chain(protection)
    stream = transition.JournalPointerTransitionStreamIdentity(
        1,
        "f" * 32,
        environment_stream.journal_id,
        environment_stream.package_root_identity,
    )
    target_pointer = journal.EnvironmentJournalPointer(
        1,
        environment_stream.journal_id,
        2,
        environment_chain[-1].generation_sha256,
    )
    target_bytes = journal.encode_environment_journal_pointer(target_pointer)
    prior_pointer = journal.EnvironmentJournalPointer(
        1,
        environment_stream.journal_id,
        1,
        environment_chain[0].generation_sha256,
    )
    prior_bytes = journal.encode_environment_journal_pointer(prior_pointer)
    plan_record = transition.JournalPointerTransitionPlanRecord(
        1,
        environment_stream.package_root_identity,
        f"journal-{environment_stream.journal_id}.pointer",
        ".journal-pointer-" + "1" * 32 + ".tmp",
        hashlib.sha256(target_bytes).hexdigest(),
        len(target_bytes),
        2,
        environment_chain[-1].generation_sha256,
        True,
        _identity(21),
        1,
        environment_chain[0].generation_sha256,
        hashlib.sha256(prior_bytes).hexdigest(),
        len(prior_bytes),
    )
    planned = transition.protect_journal_pointer_transition_generation(
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            1,
            transition.GENESIS_POINTER_TRANSITION_SHA256,
            transition.JournalPointerTransitionState.POINTER_TEMP_PLANNED,
            plan_record,
        ),
        protection=protection,
    )
    created_record = transition.JournalPointerTransitionCreatedRecord(
        1,
        planned.generation_sha256,
        plan_record.package_root_identity,
        _identity(22),
        plan_record.pointer_name,
        plan_record.pointer_temp_name,
        plan_record.intended_pointer_sha256,
        plan_record.intended_pointer_size,
        plan_record.target_tip_sequence,
        plan_record.target_generation_sha256,
        plan_record.prior_pointer_present,
        plan_record.prior_pointer_identity,
        plan_record.prior_pointer_sequence,
        plan_record.prior_pointer_generation_sha256,
        plan_record.prior_pointer_sha256,
        plan_record.prior_pointer_size,
    )
    created = transition.protect_journal_pointer_transition_generation(
        transition.JournalPointerTransitionGeneration(
            1,
            stream,
            2,
            planned.generation_sha256,
            transition.JournalPointerTransitionState.POINTER_TEMP_CREATED,
            created_record,
        ),
        protection=protection,
    )
    return (
        stream,
        environment_stream,
        environment_chain,
        (planned, created),
    )


def test_append_and_restart_load_authenticates_transition() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)

    for generation in generations:
        persisted = append_item(
            generation,
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    restarted = _Root()
    backend.root = restarted
    loaded = load_transition(
        stream,
        root=restarted,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    assert loaded is not None
    assert loaded.selection.tip.state is (
        transition.JournalPointerTransitionState.POINTER_TEMP_CREATED
    )
    assert loaded.selection.generation_sha256s == tuple(
        generation.generation_sha256 for generation in generations
    )
    assert tuple(backend.files) == tuple(
        f"pointer-transition-{'f' * 32}-{sequence:020d}.generation"
        for sequence in range(1, 3)
    )
    assert persisted.selection == loaded.selection
    assert not restarted.active


def test_empty_transition_stream_loads_without_writing() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, _generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)

    loaded = load_transition(
        stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    assert loaded is None
    assert not backend.files
    assert not root.active


def test_append_rejects_returned_or_persisted_byte_drift() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    backend.return_wrong_write = True

    with pytest.raises(RecoveryJournalStorageError) as failure:
        append_item(
            generations[0],
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.VERIFY_FAILED
    assert "sensitive" not in str(failure.value)
    assert not root.active


def test_restart_load_rejects_duplicate_generation_file_identity() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    for generation in generations:
        append_item(
            generation,
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )
    names = tuple(backend.files)
    second = backend.files[names[1]]
    backend.files[names[1]] = StoredJournalGenerationFile(
        backend.files[names[0]].identity,
        second.contents,
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        load_transition(
            stream,
            root=root,
            storage=backend,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.STORAGE_INVALID
    assert not root.active


def test_persisted_transition_repr_is_redacted() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    persisted = append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    rendered = repr(persisted)
    assert "<redacted>" in rendered
    assert stream.transition_id not in rendered
    assert (
        cast(
            TransitionPlan,
            persisted.selection.tip.record,
        ).pointer_temp_name
        not in rendered
    )


def test_persisted_transition_rejects_non_tuple_collections() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    persisted = append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    with pytest.raises(ValueError, match="Persisted pointer transition"):
        storage_type = store.PersistedJournalPointerTransitionChain
        storage_type(
            cast(tuple[SealedTransition, ...], []),
            persisted.file_identities,
            persisted.selection,
        )
