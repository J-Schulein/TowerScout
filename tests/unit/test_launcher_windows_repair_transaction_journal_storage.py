from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable, TypeVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_repair_transaction_journal as journal  # noqa: E402
import towerscout_launcher.windows_repair_transaction_journal_storage as storage  # noqa: E402
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    StoredJournalGenerationFile,
    StoredJournalPointerFile,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_Result = TypeVar("_Result")


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
            b"TSF1" + self.nonce.to_bytes(4, "big") + plaintext,
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        assert blob.purpose is purpose
        return blob.ciphertext[8:]


class _Root:
    def run_journal_storage(self, operation: Callable[[str], _Result]) -> _Result:
        return operation(r"C:\Protected\TowerScout\Recovery\v1")


class _Storage:
    def __init__(self) -> None:
        self.generations: dict[str, StoredJournalGenerationFile] = {}
        self.pointers: dict[str, StoredJournalPointerFile] = {}
        self.next_identity = 100
        self.corrupt_create = False
        self.corrupt_pointer = False

    def _identity(self) -> StableFileIdentity:
        self.next_identity += 1
        return StableFileIdentity(
            self.next_identity,
            self.next_identity.to_bytes(16, "big"),
        )

    def list_names(self, root_path: str) -> tuple[str, ...]:
        assert root_path
        return tuple(sorted((*self.generations, *self.pointers)))

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalGenerationFile:
        assert root_path and len(self.generations[name].contents) <= maximum
        return self.generations[name]

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalGenerationFile:
        assert root_path and name not in self.generations
        stored = StoredJournalGenerationFile(
            self._identity(),
            contents + b"corrupt" if self.corrupt_create else contents,
        )
        self.generations[name] = stored
        return stored

    def read_pointer(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalPointerFile | None:
        assert root_path
        stored = self.pointers.get(name)
        assert stored is None or len(stored.contents) <= maximum
        return stored

    def replace_pointer(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalPointerFile:
        assert root_path
        stored = StoredJournalPointerFile(
            self._identity(),
            contents + b"corrupt" if self.corrupt_pointer else contents,
        )
        self.pointers[name] = stored
        return stored


def _identity(seed: int = 7) -> StableFileIdentity:
    return StableFileIdentity(seed, seed.to_bytes(16, "big"))


def _stream(journal_id: str = "a" * 32) -> journal.RepairTransactionStreamIdentity:
    return journal.RepairTransactionStreamIdentity(
        1,
        journal_id,
        "b" * 32,
        "c" * 64,
        "d" * 64,
        _identity(),
    )


_STATES = (
    journal.RepairTransactionState.CERTIFICATE_TEMP_PLANNED,
    journal.RepairTransactionState.CERTIFICATE_TEMP_CREATED,
    journal.RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
    journal.RepairTransactionState.CERTIFICATES_APPLIED,
    journal.RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
    journal.RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
    journal.RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
    journal.RepairTransactionState.ENVIRONMENT_APPLIED,
)


def _generation(
    selected_stream: journal.RepairTransactionStreamIdentity,
    sequence: int,
    previous: str,
) -> journal.RepairTransactionGeneration:
    state = _STATES[sequence - 1]
    provider_sequence = sequence - 4 if 5 <= sequence <= 8 else None
    return journal.RepairTransactionGeneration(
        1,
        selected_stream,
        sequence,
        previous,
        state,
        journal.RepairTransitionRecord(
            1,
            previous,
            selected_stream.package_root_identity,
            f"{sequence:064x}",
            "e" * 32 if provider_sequence is not None else None,
            provider_sequence,
            f"{provider_sequence:064x}" if provider_sequence is not None else None,
        ),
    )


def _append_through(
    count: int,
    *,
    backing: _Storage,
    protection: _Protection,
    selected_stream: journal.RepairTransactionStreamIdentity | None = None,
) -> storage.PersistedRepairTransactionChain:
    stream = _stream() if selected_stream is None else selected_stream
    previous = stream.rollback_armed_generation_sha256
    persisted = None
    for sequence in range(1, count + 1):
        sealed = journal.protect_repair_transaction_generation(
            _generation(stream, sequence, previous),
            protection=protection,
        )
        persisted = (
            storage.append_persisted_repair_transaction_generation_from_held_root(
                r"C:\Protected\TowerScout\Recovery\v1",
                sealed,
                stream=stream,
                storage=backing,
                protection=protection,
            )
        )
        previous = sealed.generation_sha256
    assert persisted is not None
    return persisted


def test_persists_reloads_and_repairs_forward_pointer() -> None:
    backing = _Storage()
    protection = _Protection()
    persisted = _append_through(8, backing=backing, protection=protection)

    assert (
        persisted.selection.tip.state
        is journal.RepairTransactionState.ENVIRONMENT_APPLIED
    )
    assert persisted.selection.pointer_disposition is (
        journal.RepairTransactionPointerDisposition.MISSING_REPAIR
    )
    current = storage.ensure_persisted_repair_transaction_pointer_from_held_root(
        r"C:\Protected\TowerScout\Recovery\v1",
        _stream(),
        generation_storage=backing,
        pointer_storage=backing,
        protection=protection,
    )
    assert current is not None
    assert current.selection.pointer_disposition is (
        journal.RepairTransactionPointerDisposition.CURRENT
    )
    assert len(backing.generations) == 8
    assert tuple(backing.pointers) == ("repair-" + "a" * 32 + ".pointer",)


def test_discovers_only_forward_namespace_and_keeps_streams_separate() -> None:
    backing = _Storage()
    protection = _Protection()
    _append_through(2, backing=backing, protection=protection)
    _append_through(
        1,
        backing=backing,
        protection=protection,
        selected_stream=_stream("f" * 32),
    )
    backing.generations["journal-" + "9" * 32 + "-00000000000000000001.generation"] = (
        StoredJournalGenerationFile(_identity(90), b"unrelated")
    )

    discovered = storage.discover_persisted_repair_transaction_chains(
        root=_Root(),
        generation_storage=backing,
        pointer_storage=backing,
        protection=protection,
    )

    assert tuple(chain.selection.tip.stream.journal_id for chain in discovered) == (
        "a" * 32,
        "f" * 32,
    )


def test_rejects_out_of_order_append_without_writing() -> None:
    backing = _Storage()
    protection = _Protection()
    first = _append_through(1, backing=backing, protection=protection)
    skipped = journal.protect_repair_transaction_generation(
        _generation(_stream(), 3, first.selection.tip_generation_sha256),
        protection=protection,
    )

    with pytest.raises(RecoveryJournalStorageError) as captured:
        storage.append_persisted_repair_transaction_generation_from_held_root(
            r"C:\Protected\TowerScout\Recovery\v1",
            skipped,
            stream=_stream(),
            storage=backing,
            protection=protection,
        )

    assert captured.value.code is RecoveryJournalStorageErrorCode.STORAGE_INVALID
    assert len(backing.generations) == 1


@pytest.mark.parametrize("failure", ["generation", "pointer"])
def test_indeterminate_writes_fail_closed(failure: str) -> None:
    backing = _Storage()
    protection = _Protection()
    if failure == "generation":
        backing.corrupt_create = True
        sealed = journal.protect_repair_transaction_generation(
            _generation(_stream(), 1, _stream().rollback_armed_generation_sha256),
            protection=protection,
        )
        operation = lambda: storage.append_persisted_repair_transaction_generation_from_held_root(
            r"C:\Protected\TowerScout\Recovery\v1",
            sealed,
            stream=_stream(),
            storage=backing,
            protection=protection,
        )
    else:
        _append_through(1, backing=backing, protection=protection)
        backing.corrupt_pointer = True
        operation = (
            lambda: storage.ensure_persisted_repair_transaction_pointer_from_held_root(
                r"C:\Protected\TowerScout\Recovery\v1",
                _stream(),
                generation_storage=backing,
                pointer_storage=backing,
                protection=protection,
            )
        )

    with pytest.raises(RecoveryJournalStorageError) as captured:
        operation()

    assert captured.value.code is RecoveryJournalStorageErrorCode.VERIFY_FAILED
