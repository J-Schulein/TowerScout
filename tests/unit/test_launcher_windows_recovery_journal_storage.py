from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, TypeVar, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal_storage as storage  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_Result = TypeVar("_Result")


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _stream() -> journal.JournalStreamIdentity:
    return journal.JournalStreamIdentity(1, "a" * 32, "b" * 64, _identity(7))


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
        self.closed = False
        self.calls = 0

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        if self.closed:
            raise OSError("sensitive root detail")
        self.calls += 1
        self.active = True
        try:
            return operation(r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1")
        finally:
            self.active = False


class _Storage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.files: dict[str, storage.StoredJournalGenerationFile] = {}
        self.created: list[str] = []
        self.next_identity = 20
        self.fail_create: BaseException | None = None
        self.fail_pointer_read: BaseException | None = None
        self.fail_pointer_replace: BaseException | None = None
        self.return_wrong_write = False
        self.pointer: storage.StoredJournalPointerFile | None = None
        self.pointer_replacements = 0
        self.replace_pointer_identity: StableFileIdentity | None = None
        self.return_wrong_pointer = False
        self.persist_wrong_pointer = False

    def _assert_held(self) -> None:
        if not self.root.active:
            raise AssertionError("storage operation escaped root ownership")

    def list_names(self, root_path: str) -> tuple[str, ...]:
        self._assert_held()
        assert root_path.endswith(r"TowerScout\Recovery\v1")
        return tuple(reversed(tuple(self.files)))

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalGenerationFile:
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
    ) -> storage.StoredJournalGenerationFile:
        self._assert_held()
        del root_path
        if self.fail_create is not None:
            raise self.fail_create
        if name in self.files:
            raise FileExistsError("sensitive existing path")
        self.next_identity += 1
        persisted = storage.StoredJournalGenerationFile(
            _identity(self.next_identity),
            b"wrong" if self.return_wrong_write else contents,
        )
        self.files[name] = persisted
        self.created.append(name)
        return persisted

    def read_pointer(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalPointerFile | None:
        self._assert_held()
        del root_path
        assert name == f"journal-{'a' * 32}.pointer"
        if self.fail_pointer_read is not None:
            raise self.fail_pointer_read
        if self.pointer is not None:
            assert len(self.pointer.contents) <= maximum
        return self.pointer

    def replace_pointer(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> storage.StoredJournalPointerFile:
        self._assert_held()
        del root_path
        assert name == f"journal-{'a' * 32}.pointer"
        if self.fail_pointer_replace is not None:
            raise self.fail_pointer_replace
        self.pointer_replacements += 1
        self.next_identity += 1
        identity = _identity(self.next_identity)
        persisted_contents = b"wrong" if self.persist_wrong_pointer else contents
        self.pointer = storage.StoredJournalPointerFile(
            identity,
            persisted_contents,
        )
        return storage.StoredJournalPointerFile(
            self.replace_pointer_identity or identity,
            b"wrong" if self.return_wrong_pointer else contents,
        )


def _sealed_chain(
    protection: _Protection,
) -> tuple[
    journal.JournalStreamIdentity,
    tuple[journal.SealedEnvironmentJournalGeneration, ...],
]:
    stream = _stream()
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
    verified_record = EnvironmentTempVerifiedRecord(
        1,
        created.generation_sha256,
        stream.package_root_identity,
        created_record.temp_identity,
        plan.candidate_sha256,
        plan.candidate_size,
        plan.temp_name,
    )
    verified = journal.protect_environment_journal_generation(
        journal.EnvironmentJournalGeneration(
            1,
            stream,
            3,
            created.generation_sha256,
            journal.EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
            verified_record,
        ),
        protection=protection,
    )
    return stream, (planned, created, verified)


def test_append_and_restart_load_authenticate_complete_chain() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)

    for sequence, generation in enumerate(generations, start=1):
        persisted = storage.append_persisted_environment_journal_generation(
            generation,
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
        )
        assert persisted.selection.tip.sequence == sequence
        assert persisted.selection.tip_generation_sha256 == generation.generation_sha256

    restarted = _Root()
    backend.root = restarted
    loaded = storage.load_persisted_environment_journal_chain(
        stream,
        root=restarted,
        storage=backend,
        protection=protection,
    )

    assert loaded is not None
    assert loaded.selection.generation_sha256s == tuple(
        generation.generation_sha256 for generation in generations
    )
    assert (
        loaded.selection.pointer_disposition
        is journal.JournalPointerDisposition.MISSING_REPAIR
    )
    assert backend.created == [
        f"journal-{'a' * 32}-{sequence:020d}.generation" for sequence in range(1, 4)
    ]
    assert not restarted.active


def test_empty_stream_loads_without_creating_storage() -> None:
    root = _Root()
    backend = _Storage(root)

    loaded = storage.load_persisted_environment_journal_chain(
        _stream(),
        root=root,
        storage=backend,
        protection=_Protection(),
    )

    assert loaded is None
    assert not backend.created


def test_missing_pointer_is_created_and_reread_as_current() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    for generation in generations:
        storage.append_persisted_environment_journal_generation(
            generation,
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
        )

    repaired = storage.ensure_persisted_environment_journal_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )

    assert repaired is not None
    assert (
        repaired.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert repaired.selection.tip.sequence == 3
    assert backend.pointer_replacements == 1
    assert backend.pointer is not None
    assert journal.decode_environment_journal_pointer(backend.pointer.contents) == (
        journal.EnvironmentJournalPointer(
            1,
            stream.journal_id,
            3,
            generations[-1].generation_sha256,
        )
    )
    assert not root.active


def test_current_pointer_is_loaded_without_replacement() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    storage.append_persisted_environment_journal_generation(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )
    first = storage.ensure_persisted_environment_journal_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )

    loaded = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )
    second = storage.ensure_persisted_environment_journal_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )

    assert first is not None and loaded is not None and second is not None
    assert (
        loaded.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert (
        second.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert backend.pointer_replacements == 1


def test_stale_pointer_is_repaired_to_new_authenticated_tip() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    storage.append_persisted_environment_journal_generation(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )
    storage.ensure_persisted_environment_journal_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )
    storage.append_persisted_environment_journal_generation(
        generations[1],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )

    stale = storage.load_persisted_environment_journal_chain_with_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )
    repaired = storage.ensure_persisted_environment_journal_pointer(
        stream,
        root=root,
        generation_storage=backend,
        pointer_storage=backend,
        protection=protection,
    )

    assert stale is not None and repaired is not None
    assert (
        stale.selection.pointer_disposition
        is journal.JournalPointerDisposition.STALE_REPAIR
    )
    assert (
        repaired.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert repaired.selection.tip.sequence == 2
    assert backend.pointer_replacements == 2


def test_invalid_or_foreign_pointer_fails_without_replacement() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)

    for contents, expected in (
        (b"{}", journal.RecoveryJournalErrorCode.POINTER_INVALID),
        (
            journal.encode_environment_journal_pointer(
                journal.EnvironmentJournalPointer(
                    1,
                    "f" * 32,
                    1,
                    generations[0].generation_sha256,
                )
            ),
            journal.RecoveryJournalErrorCode.CHAIN_INVALID,
        ),
    ):
        root = _Root()
        backend = _Storage(root)
        storage.append_persisted_environment_journal_generation(
            generations[0],
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
        )
        backend.pointer = storage.StoredJournalPointerFile(_identity(91), contents)

        with pytest.raises(journal.RecoveryJournalError) as failure:
            storage.ensure_persisted_environment_journal_pointer(
                stream,
                root=root,
                generation_storage=backend,
                pointer_storage=backend,
                protection=protection,
            )

        assert failure.value.code is expected
        assert backend.pointer_replacements == 0


def test_pointer_without_generation_fails_closed() -> None:
    stream = _stream()
    root = _Root()
    backend = _Storage(root)
    backend.pointer = storage.StoredJournalPointerFile(
        _identity(91),
        journal.encode_environment_journal_pointer(
            journal.EnvironmentJournalPointer(1, stream.journal_id, 1, "1" * 64)
        ),
    )

    with pytest.raises(storage.RecoveryJournalStorageError) as failure:
        storage.load_persisted_environment_journal_chain_with_pointer(
            stream,
            root=root,
            generation_storage=backend,
            pointer_storage=backend,
            protection=_Protection(),
        )

    assert failure.value.code is storage.RecoveryJournalStorageErrorCode.STORAGE_INVALID


@pytest.mark.parametrize("failure_mode", ["identity", "returned", "persisted"])
def test_unverified_pointer_replacement_fails_closed(failure_mode: str) -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    storage.append_persisted_environment_journal_generation(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )
    if failure_mode == "identity":
        backend.replace_pointer_identity = _identity(92)
    elif failure_mode == "returned":
        backend.return_wrong_pointer = True
    else:
        backend.persist_wrong_pointer = True

    with pytest.raises(storage.RecoveryJournalStorageError) as failure:
        storage.ensure_persisted_environment_journal_pointer(
            stream,
            root=root,
            generation_storage=backend,
            pointer_storage=backend,
            protection=protection,
        )

    assert failure.value.code is storage.RecoveryJournalStorageErrorCode.VERIFY_FAILED


def test_pointer_read_failure_is_sanitized() -> None:
    root = _Root()
    backend = _Storage(root)
    backend.fail_pointer_read = OSError("sensitive pointer path")

    with pytest.raises(storage.RecoveryJournalStorageError) as failure:
        storage.load_persisted_environment_journal_chain_with_pointer(
            _stream(),
            root=root,
            generation_storage=backend,
            pointer_storage=backend,
            protection=_Protection(),
        )

    assert (
        failure.value.code
        is storage.RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE
    )
    assert "sensitive" not in str(failure.value)


def test_pointer_write_failures_are_sanitized_and_process_control_propagates() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)

    for failure, expected_exception in (
        (KeyError("sensitive pointer path"), storage.RecoveryJournalStorageError),
        (KeyboardInterrupt(), KeyboardInterrupt),
    ):
        root = _Root()
        backend = _Storage(root)
        storage.append_persisted_environment_journal_generation(
            generations[0],
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
        )
        backend.fail_pointer_replace = failure

        with pytest.raises(expected_exception) as raised:
            storage.ensure_persisted_environment_journal_pointer(
                stream,
                root=root,
                generation_storage=backend,
                pointer_storage=backend,
                protection=protection,
            )

        if isinstance(raised.value, storage.RecoveryJournalStorageError):
            assert (
                raised.value.code
                is storage.RecoveryJournalStorageErrorCode.WRITE_FAILED
            )
            assert "sensitive" not in str(raised.value)
        else:
            assert raised.value is failure
        assert not root.active


def test_out_of_order_generation_fails_before_write() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)

    with pytest.raises(journal.RecoveryJournalError) as failure:
        storage.append_persisted_environment_journal_generation(
            generations[1],
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID
    assert not backend.created


def test_tampered_existing_generation_fails_closed() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    storage.append_persisted_environment_journal_generation(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )
    name = backend.created[0]
    backend.files[name] = storage.StoredJournalGenerationFile(
        backend.files[name].identity,
        b"tampered",
    )

    with pytest.raises(journal.RecoveryJournalError) as failure:
        storage.load_persisted_environment_journal_chain(
            stream,
            root=root,
            storage=backend,
            protection=protection,
        )

    assert failure.value.code in {
        journal.RecoveryJournalErrorCode.AUTHENTICATION_FAILED,
        journal.RecoveryJournalErrorCode.GENERATION_INVALID,
    }


def test_malformed_stream_name_and_duplicate_identity_fail_closed() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    first = storage.append_persisted_environment_journal_generation(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )
    malformed = f"journal-{stream.journal_id}-not-a-sequence.generation"
    backend.files[malformed] = storage.StoredJournalGenerationFile(
        _identity(99),
        generations[0].protected_blob.ciphertext,
    )
    with pytest.raises(storage.RecoveryJournalStorageError) as invalid_name:
        storage.load_persisted_environment_journal_chain(
            stream,
            root=root,
            storage=backend,
            protection=protection,
        )
    assert (
        invalid_name.value.code
        is storage.RecoveryJournalStorageErrorCode.STORAGE_INVALID
    )

    del backend.files[malformed]
    second_name = f"journal-{stream.journal_id}-{2:020d}.generation"
    backend.files[second_name] = storage.StoredJournalGenerationFile(
        first.file_identities[0],
        generations[1].protected_blob.ciphertext,
    )
    with pytest.raises(storage.RecoveryJournalStorageError) as duplicate_identity:
        storage.load_persisted_environment_journal_chain(
            stream,
            root=root,
            storage=backend,
            protection=protection,
        )
    assert (
        duplicate_identity.value.code
        is storage.RecoveryJournalStorageErrorCode.STORAGE_INVALID
    )


def test_failed_or_unverified_write_is_sanitized() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)

    for backend_change, expected in (
        ("fail", storage.RecoveryJournalStorageErrorCode.WRITE_FAILED),
        ("wrong", storage.RecoveryJournalStorageErrorCode.VERIFY_FAILED),
    ):
        root = _Root()
        backend = _Storage(root)
        if backend_change == "fail":
            backend.fail_create = KeyError("sensitive write detail")
        else:
            backend.return_wrong_write = True
        with pytest.raises(storage.RecoveryJournalStorageError) as failure:
            storage.append_persisted_environment_journal_generation(
                generations[0],
                stream=stream,
                root=root,
                storage=backend,
                protection=protection,
            )
        assert failure.value.code is expected
        assert "sensitive" not in str(failure.value)


def test_invalid_ports_and_closed_root_fail_without_detail() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    root.closed = True

    with pytest.raises(storage.RecoveryJournalStorageError) as closed:
        storage.append_persisted_environment_journal_generation(
            generations[0],
            stream=stream,
            root=root,
            storage=_Storage(root),
            protection=protection,
        )
    assert (
        closed.value.code is storage.RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE
    )
    assert "sensitive" not in str(closed.value)

    with pytest.raises(storage.RecoveryJournalStorageError) as invalid:
        storage.load_persisted_environment_journal_chain(
            stream,
            root=cast(storage.JournalStorageRootPort, object()),
            storage=cast(storage.JournalGenerationStoragePort, object()),
            protection=protection,
        )
    assert (
        invalid.value.code
        is storage.RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE
    )


def test_storage_process_control_exception_propagates() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    interruption = KeyboardInterrupt()
    backend.fail_create = interruption

    with pytest.raises(KeyboardInterrupt) as raised:
        storage.append_persisted_environment_journal_generation(
            generations[0],
            stream=stream,
            root=root,
            storage=backend,
            protection=protection,
        )

    assert raised.value is interruption
    assert not root.active


def test_repr_redacts_root_names_ciphertext_and_identities() -> None:
    protection = _Protection()
    stream, generations = _sealed_chain(protection)
    root = _Root()
    backend = _Storage(root)
    persisted = storage.append_persisted_environment_journal_generation(
        generations[0],
        stream=stream,
        root=root,
        storage=backend,
        protection=protection,
    )

    rendered = repr(persisted) + repr(next(iter(backend.files.values())))
    assert "private" not in rendered
    assert stream.journal_id not in rendered
    assert generations[0].protected_blob.ciphertext.hex() not in rendered
