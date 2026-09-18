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
StoredJournalPointerFile = journal_storage.StoredJournalPointerFile
StableFileIdentity = security.StableFileIdentity
TransitionPlan = transition.JournalPointerTransitionPlanRecord
TransitionStream = transition.JournalPointerTransitionStreamIdentity
SealedTransition = transition.SealedJournalPointerTransitionGeneration
append_item = store.append_persisted_journal_pointer_transition_generation
create_temp = store.create_persisted_journal_pointer_transition_temp
load_transition = store.load_persisted_journal_pointer_transition_chain
promote_temp = store.promote_persisted_journal_pointer_transition_temp

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
        self.pointer_events: list[str] = []

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


class _PointerTempStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.identity = _identity(22)
        self.files: dict[str, StoredJournalPointerFile] = {}
        self.return_wrong_contents = False
        self.error: BaseException | None = None
        self.calls = 0

    def create_pointer_temp(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalPointerFile:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.root.pointer_events.append("create")
        self.calls += 1
        if self.error is not None:
            raise self.error
        if name in self.files:
            raise FileExistsError("sensitive existing temp")
        stored = StoredJournalPointerFile(
            self.identity,
            b"wrong" if self.return_wrong_contents else contents,
        )
        self.files[name] = stored
        return stored


class _PointerTempCleanupStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.error: BaseException | None = None
        self.result: object | None = None
        self.calls: list[str] = []

    def remove_empty_pointer_temp_if_exists(
        self,
        root_path: str,
        name: str,
    ) -> None:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.root.pointer_events.append("cleanup")
        self.calls.append(name)
        if self.error is not None:
            raise self.error
        return cast(None, self.result)


class _PointerPromotionStorage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.return_identity = _identity(22)
        self.return_contents: bytes | None = None
        self.error: BaseException | None = None
        self.calls: list[tuple[object, ...]] = []

    def promote_pointer_temp(
        self,
        root_path: str,
        source_name: str,
        destination_name: str,
        source_identity: StableFileIdentity,
        contents: bytes,
        expected_destination: StoredJournalPointerFile | None,
    ) -> StoredJournalPointerFile:
        assert self.root.active
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        self.calls.append(
            (
                source_name,
                destination_name,
                source_identity,
                contents,
                expected_destination,
            )
        )
        if self.error is not None:
            raise self.error
        return StoredJournalPointerFile(
            self.return_identity,
            contents if self.return_contents is None else self.return_contents,
        )


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
        True,
        _identity(8),
        13,
        0x20,
        "f" * 64,
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
        0x80,
        "f" * 64,
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


def test_create_temp_persists_exact_identity_and_restart_chain() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    planned = append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    persisted = create_temp(
        stream,
        root=root,
        generation_storage=backend,
        pointer_temp_cleanup_storage=cleanup,
        pointer_temp_storage=pointer_temps,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    plan = cast(TransitionPlan, planned.selection.tip.record)
    stored = pointer_temps.files[plan.pointer_temp_name]
    created = cast(
        transition.JournalPointerTransitionCreatedRecord,
        persisted.selection.tip.record,
    )
    assert hashlib.sha256(stored.contents).hexdigest() == plan.intended_pointer_sha256
    assert len(stored.contents) == plan.intended_pointer_size
    assert created.pointer_temp_identity == pointer_temps.identity
    assert persisted.selection.tip.state is (
        transition.JournalPointerTransitionState.POINTER_TEMP_CREATED
    )
    assert len(backend.files) == 2
    assert cleanup.calls == [plan.pointer_temp_name]
    assert root.pointer_events == ["cleanup", "create"]
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
    assert loaded.selection == persisted.selection
    assert not restarted.active


def test_create_temp_cleanup_failure_prevents_creation_and_generation_append() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    cleanup.error = OSError("sensitive planned temp path")
    with pytest.raises(RecoveryJournalStorageError) as failure:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(failure.value)
    assert pointer_temps.calls == 0
    assert len(backend.files) == 1

    interruption = KeyboardInterrupt()
    cleanup.error = interruption
    with pytest.raises(KeyboardInterrupt) as raised:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )
    assert raised.value is interruption
    assert pointer_temps.calls == 0
    assert len(backend.files) == 1
    assert not root.active


def test_create_temp_rejects_malformed_cleanup_return_before_creation() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    cleanup.result = object()
    pointer_temps = _PointerTempStorage(root)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.VERIFY_FAILED
    assert pointer_temps.calls == 0
    assert len(backend.files) == 1
    assert not root.active


def test_promote_temp_uses_exact_created_identity_and_prior_pointer() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    promotions = _PointerPromotionStorage(root)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )
    created_chain = create_temp(
        stream,
        root=root,
        generation_storage=backend,
        pointer_temp_cleanup_storage=cleanup,
        pointer_temp_storage=pointer_temps,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    promoted = promote_temp(
        stream,
        root=root,
        generation_storage=backend,
        promotion_storage=promotions,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    created = cast(
        transition.JournalPointerTransitionCreatedRecord,
        created_chain.selection.tip.record,
    )
    target_pointer = journal.EnvironmentJournalPointer(
        1,
        stream.environment_journal_id,
        created.target_tip_sequence,
        created.target_generation_sha256,
    )
    prior_pointer = journal.EnvironmentJournalPointer(
        1,
        stream.environment_journal_id,
        cast(int, created.prior_pointer_sequence),
        cast(str, created.prior_pointer_generation_sha256),
    )
    assert promoted == StoredJournalPointerFile(
        created.pointer_temp_identity,
        journal.encode_environment_journal_pointer(target_pointer),
    )
    assert promotions.calls == [
        (
            created.pointer_temp_name,
            created.pointer_name,
            created.pointer_temp_identity,
            promoted.contents,
            StoredJournalPointerFile(
                cast(StableFileIdentity, created.prior_pointer_identity),
                journal.encode_environment_journal_pointer(prior_pointer),
            ),
        )
    ]
    assert len(backend.files) == 2
    assert not root.active


@pytest.mark.parametrize("existing_state", ("absent", "planned"))
def test_promote_temp_requires_persisted_created_state(existing_state: str) -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    promotions = _PointerPromotionStorage(root)
    cleanup = _PointerTempCleanupStorage(root)
    if existing_state == "planned":
        append_item(
            generations[0],
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        promote_temp(
            stream,
            root=root,
            generation_storage=backend,
            promotion_storage=promotions,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.STORAGE_INVALID
    assert promotions.calls == []
    assert not root.active


@pytest.mark.parametrize("drift", ("identity", "contents"))
def test_promote_temp_rejects_returned_destination_drift(drift: str) -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    promotions = _PointerPromotionStorage(root)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )
    create_temp(
        stream,
        root=root,
        generation_storage=backend,
        pointer_temp_cleanup_storage=cleanup,
        pointer_temp_storage=pointer_temps,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )
    if drift == "identity":
        promotions.return_identity = _identity(99)
    else:
        promotions.return_contents = b"wrong"

    with pytest.raises(RecoveryJournalStorageError) as failure:
        promote_temp(
            stream,
            root=root,
            generation_storage=backend,
            promotion_storage=promotions,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.VERIFY_FAILED
    assert len(backend.files) == 2
    assert not root.active


def test_promote_temp_sanitizes_dependency_failure_and_propagates_control() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    promotions = _PointerPromotionStorage(root)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )
    create_temp(
        stream,
        root=root,
        generation_storage=backend,
        pointer_temp_cleanup_storage=cleanup,
        pointer_temp_storage=pointer_temps,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    promotions.error = OSError("sensitive promotion path")
    with pytest.raises(RecoveryJournalStorageError) as failure:
        promote_temp(
            stream,
            root=root,
            generation_storage=backend,
            promotion_storage=promotions,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )
    assert failure.value.code is StorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(failure.value)

    interruption = KeyboardInterrupt()
    promotions.error = interruption
    with pytest.raises(KeyboardInterrupt) as raised:
        promote_temp(
            stream,
            root=root,
            generation_storage=backend,
            promotion_storage=promotions,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )
    assert raised.value is interruption
    assert len(backend.files) == 2
    assert not root.active


@pytest.mark.parametrize("existing_state", ("absent", "created"))
def test_create_temp_requires_exactly_one_persisted_plan(existing_state: str) -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    if existing_state == "created":
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

    with pytest.raises(RecoveryJournalStorageError) as failure:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.STORAGE_INVALID
    assert cleanup.calls == []
    assert pointer_temps.calls == 0
    assert not root.active


def test_create_temp_rejects_returned_byte_drift_without_generation_append() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    pointer_temps.return_wrong_contents = True
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.VERIFY_FAILED
    assert len(backend.files) == 1
    assert pointer_temps.calls == 1
    assert not root.active


def test_create_temp_rejects_cross_volume_identity_without_generation_append() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    pointer_temps.identity = StableFileIdentity(8, b"x" * 16)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )

    assert failure.value.code is StorageErrorCode.VERIFY_FAILED
    assert len(backend.files) == 1
    assert pointer_temps.calls == 1
    assert not root.active


def test_create_temp_sanitizes_dependency_failure_and_propagates_control() -> None:
    protection = _Protection()
    stream, environment_stream, environment_generations, generations = (
        _transition_chain(protection)
    )
    root = _Root()
    backend = _Storage(root)
    cleanup = _PointerTempCleanupStorage(root)
    pointer_temps = _PointerTempStorage(root)
    append_item(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
        environment_generations=environment_generations,
        expected_environment_stream=environment_stream,
    )

    pointer_temps.error = OSError("sensitive pointer-temp path")
    with pytest.raises(RecoveryJournalStorageError) as failure:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )
    assert failure.value.code is StorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(failure.value)

    interruption = KeyboardInterrupt()
    pointer_temps.error = interruption
    with pytest.raises(KeyboardInterrupt) as raised:
        create_temp(
            stream,
            root=root,
            generation_storage=backend,
            pointer_temp_cleanup_storage=cleanup,
            pointer_temp_storage=pointer_temps,
            protection=protection,
            environment_generations=environment_generations,
            expected_environment_stream=environment_stream,
        )
    assert raised.value is interruption
    assert len(backend.files) == 1
    assert not root.active


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
