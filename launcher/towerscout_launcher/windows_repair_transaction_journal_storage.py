"""Durable storage orchestration for authenticated forward repair journals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, NoReturn, TypeVar, cast

from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    StoredJournalGenerationFile,
    StoredJournalPointerFile,
)
from .windows_repair_transaction_journal import (
    RepairTransactionChainSelection,
    RepairTransactionJournalError,
    RepairTransactionJournalPointer,
    RepairTransactionPointerDisposition,
    RepairTransactionProtectionPort,
    RepairTransactionStreamIdentity,
    SealedRepairTransactionGeneration,
    authenticate_repair_transaction_generation,
    decode_repair_transaction_pointer,
    encode_repair_transaction_pointer,
    select_repair_transaction_chain,
)
from .windows_security import StableFileIdentity

_MAX_PROTECTED_GENERATION_BYTES = 4 * 1024 * 1024
_MAX_POINTER_BYTES = 1_024
_MAX_ROOT_ENTRIES = 256
_GENERATION_NAME = re.compile(r"^repair-([0-9a-f]{32})-([0-9]{20})\.generation$")
_POINTER_NAME = re.compile(r"^repair-([0-9a-f]{32})\.pointer$")
_Result = TypeVar("_Result")


@dataclass(frozen=True, slots=True, repr=False)
class PersistedRepairTransactionChain:
    sealed_generations: tuple[SealedRepairTransactionGeneration, ...] = field(
        repr=False
    )
    file_identities: tuple[StableFileIdentity, ...] = field(repr=False)
    selection: RepairTransactionChainSelection = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.sealed_generations) is not tuple
            or not self.sealed_generations
            or any(
                type(item) is not SealedRepairTransactionGeneration
                for item in self.sealed_generations
            )
            or type(self.file_identities) is not tuple
            or len(self.file_identities) != len(self.sealed_generations)
            or any(
                type(item) is not StableFileIdentity for item in self.file_identities
            )
            or len(set(self.file_identities)) != len(self.file_identities)
            or type(self.selection) is not RepairTransactionChainSelection
            or self.selection.generation_sha256s
            != tuple(item.generation_sha256 for item in self.sealed_generations)
        ):
            raise ValueError("Persisted repair transaction chain is invalid.")

    def __repr__(self) -> str:
        return (
            "PersistedRepairTransactionChain("
            f"generations={len(self.sealed_generations)}, <redacted>)"
        )


def _fail(code: RecoveryJournalStorageErrorCode) -> NoReturn:
    raise RecoveryJournalStorageError(code) from None


def _generation_name(journal_id: str, sequence: int) -> str:
    if (
        type(journal_id) is not str
        or re.fullmatch(r"[0-9a-f]{32}", journal_id) is None
        or type(sequence) is not int
        or not 1 <= sequence <= 16
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return f"repair-{journal_id}-{sequence:020d}.generation"


def _pointer_name(journal_id: str) -> str:
    if type(journal_id) is not str or re.fullmatch(r"[0-9a-f]{32}", journal_id) is None:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return f"repair-{journal_id}.pointer"


def _storage_call(
    storage: object,
    method: str,
    *arguments: object,
    code: RecoveryJournalStorageErrorCode,
) -> object:
    try:
        operation = getattr(storage, method)
        if not callable(operation):
            raise TypeError("Repair transaction storage operation is unavailable.")
        return operation(*arguments)
    except RecoveryJournalStorageError:
        raise
    except Exception:
        _fail(code)


def _listed_names(
    root_path: str,
    storage: JournalGenerationStoragePort,
) -> tuple[str, ...]:
    names = _storage_call(
        storage,
        "list_names",
        root_path,
        code=RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
    )
    if (
        type(names) is not tuple
        or len(names) > _MAX_ROOT_ENTRIES
        or any(type(name) is not str for name in names)
        or len(set(names)) != len(names)
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    return cast(tuple[str, ...], names)


def _names_for_stream(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    storage: JournalGenerationStoragePort,
) -> tuple[tuple[int, str], ...]:
    prefix = f"repair-{stream.journal_id}-"
    selected: list[tuple[int, str]] = []
    for name in _listed_names(root_path, storage):
        if not name.startswith(prefix):
            continue
        match = _GENERATION_NAME.fullmatch(name)
        if match is None or match.group(1) != stream.journal_id:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        sequence = int(match.group(2))
        if not 1 <= sequence <= 16:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        selected.append((sequence, name))
    selected.sort()
    if len({sequence for sequence, _name in selected}) != len(selected):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    return tuple(selected)


def _read_pointer(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    storage: JournalPointerStoragePort,
) -> tuple[RepairTransactionJournalPointer, StoredJournalPointerFile] | None:
    stored_value = _storage_call(
        storage,
        "read_pointer",
        root_path,
        _pointer_name(stream.journal_id),
        _MAX_POINTER_BYTES,
        code=RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
    )
    if stored_value is None:
        return None
    if type(stored_value) is not StoredJournalPointerFile:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    stored = stored_value
    try:
        return decode_repair_transaction_pointer(stored.contents), stored
    except RepairTransactionJournalError:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)


def _load(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: RepairTransactionProtectionPort,
    pointer: RepairTransactionJournalPointer | None = None,
) -> PersistedRepairTransactionChain | None:
    candidates = _names_for_stream(root_path, stream, storage)
    if not candidates:
        return None
    sealed: list[SealedRepairTransactionGeneration] = []
    identities: list[StableFileIdentity] = []
    for _sequence, name in candidates:
        stored_value = _storage_call(
            storage,
            "read_generation",
            root_path,
            name,
            _MAX_PROTECTED_GENERATION_BYTES,
            code=RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if type(stored_value) is not StoredJournalGenerationFile:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        stored = stored_value
        try:
            protected = CurrentUserProtectedBlob(
                ProtectedDataPurpose.JOURNAL_GENERATION,
                stored.contents,
            )
            sealed.append(
                SealedRepairTransactionGeneration(
                    protected,
                    protected.ciphertext_sha256,
                )
            )
        except ValueError:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        identities.append(stored.identity)
    if len(set(identities)) != len(identities):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    try:
        selection = select_repair_transaction_chain(
            tuple(sealed),
            pointer,
            expected_stream=stream,
            protection=protection,
        )
    except RepairTransactionJournalError:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    if tuple(sequence for sequence, _name in candidates) != tuple(
        generation.sequence for generation in selection.generations
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    try:
        return PersistedRepairTransactionChain(
            tuple(sealed),
            tuple(identities),
            selection,
        )
    except ValueError:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)


def _load_with_pointer(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> tuple[PersistedRepairTransactionChain | None, StoredJournalPointerFile | None]:
    persisted_pointer = _read_pointer(root_path, stream, pointer_storage)
    pointer = None if persisted_pointer is None else persisted_pointer[0]
    persisted = _load(
        root_path,
        stream,
        generation_storage,
        protection,
        pointer,
    )
    if persisted is None and persisted_pointer is not None:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    return persisted, None if persisted_pointer is None else persisted_pointer[1]


def _run_under_root(
    root: JournalStorageRootPort,
    operation: Callable[[str], _Result],
) -> _Result:
    try:
        run = cast(
            Callable[[Callable[[str], _Result]], _Result],
            getattr(root, "run_journal_storage"),
        )
        if not callable(run):
            raise TypeError("Protected repair transaction root is unavailable.")
        return run(operation)
    except (RecoveryJournalStorageError, RepairTransactionJournalError):
        raise
    except Exception:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)


def load_persisted_repair_transaction_chain_from_held_root(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    *,
    storage: JournalGenerationStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain | None:
    if (
        type(root_path) is not str
        or not root_path
        or type(stream) is not RepairTransactionStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _load(root_path, stream, storage, protection)


def append_persisted_repair_transaction_generation_from_held_root(
    root_path: str,
    sealed: SealedRepairTransactionGeneration,
    *,
    stream: RepairTransactionStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    if (
        type(root_path) is not str
        or not root_path
        or type(sealed) is not SealedRepairTransactionGeneration
        or type(stream) is not RepairTransactionStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    try:
        generation = authenticate_repair_transaction_generation(
            sealed,
            protection=protection,
        )
    except RepairTransactionJournalError:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    if generation.stream != stream:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    current = _load(root_path, stream, storage, protection)
    if current is None:
        if generation.sequence != 1:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    elif (
        generation.sequence != current.selection.tip.sequence + 1
        or generation.previous_generation_sha256
        != current.selection.tip_generation_sha256
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    name = _generation_name(stream.journal_id, generation.sequence)
    created_value = _storage_call(
        storage,
        "create_generation",
        root_path,
        name,
        sealed.protected_blob.ciphertext,
        code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if type(created_value) is not StoredJournalGenerationFile:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    created = created_value
    if created.contents != sealed.protected_blob.ciphertext:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    persisted = _load(root_path, stream, storage, protection)
    if (
        persisted is None
        or persisted.selection.tip != generation
        or persisted.selection.tip_generation_sha256 != sealed.generation_sha256
        or persisted.file_identities[-1] != created.identity
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    return persisted


def ensure_persisted_repair_transaction_pointer_from_held_root(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    *,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain | None:
    if (
        type(root_path) is not str
        or not root_path
        or type(stream) is not RepairTransactionStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    persisted, _stored_pointer = _load_with_pointer(
        root_path,
        stream,
        generation_storage,
        pointer_storage,
        protection,
    )
    if persisted is None:
        return None
    if (
        persisted.selection.pointer_disposition
        is RepairTransactionPointerDisposition.CURRENT
    ):
        return persisted
    try:
        pointer = RepairTransactionJournalPointer(
            1,
            stream.journal_id,
            persisted.selection.tip.sequence,
            persisted.selection.tip_generation_sha256,
        )
        encoded = encode_repair_transaction_pointer(pointer)
    except (RepairTransactionJournalError, ValueError):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    written_value = _storage_call(
        pointer_storage,
        "replace_pointer",
        root_path,
        _pointer_name(stream.journal_id),
        encoded,
        code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if type(written_value) is not StoredJournalPointerFile:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    written = written_value
    if written.contents != encoded:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    try:
        verified, reread = _load_with_pointer(
            root_path,
            stream,
            generation_storage,
            pointer_storage,
            protection,
        )
    except (RepairTransactionJournalError, RecoveryJournalStorageError):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    if (
        verified is None
        or reread is None
        or reread.identity != written.identity
        or reread.contents != encoded
        or verified.selection.pointer_disposition
        is not RepairTransactionPointerDisposition.CURRENT
        or verified.selection.generation_sha256s
        != persisted.selection.generation_sha256s
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    return verified


def discover_persisted_repair_transaction_chains_from_held_root(
    root_path: str,
    *,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> tuple[PersistedRepairTransactionChain, ...]:
    if type(root_path) is not str or not root_path:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    sequences_by_journal: dict[str, list[tuple[int, str]]] = {}
    pointer_journal_ids: set[str] = set()
    for name in _listed_names(root_path, generation_storage):
        if not name.startswith("repair-"):
            continue
        generation_match = _GENERATION_NAME.fullmatch(name)
        if generation_match is not None:
            sequences_by_journal.setdefault(generation_match.group(1), []).append(
                (int(generation_match.group(2)), name)
            )
            continue
        pointer_match = _POINTER_NAME.fullmatch(name)
        if pointer_match is not None:
            pointer_journal_ids.add(pointer_match.group(1))
            continue
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    if not pointer_journal_ids.issubset(sequences_by_journal):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    discovered: list[PersistedRepairTransactionChain] = []
    for journal_id in sorted(sequences_by_journal):
        candidates = sorted(sequences_by_journal[journal_id])
        if (
            not candidates
            or candidates[0][0] != 1
            or len({sequence for sequence, _name in candidates}) != len(candidates)
        ):
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        stored_value = _storage_call(
            generation_storage,
            "read_generation",
            root_path,
            candidates[0][1],
            _MAX_PROTECTED_GENERATION_BYTES,
            code=RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if type(stored_value) is not StoredJournalGenerationFile:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        stored = stored_value
        try:
            protected = CurrentUserProtectedBlob(
                ProtectedDataPurpose.JOURNAL_GENERATION,
                stored.contents,
            )
            first = authenticate_repair_transaction_generation(
                SealedRepairTransactionGeneration(
                    protected,
                    protected.ciphertext_sha256,
                ),
                protection=protection,
            )
        except (RepairTransactionJournalError, ValueError):
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        if first.sequence != 1 or first.stream.journal_id != journal_id:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        persisted, _pointer = _load_with_pointer(
            root_path,
            first.stream,
            generation_storage,
            pointer_storage,
            protection,
        )
        if persisted is None:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        discovered.append(persisted)
    return tuple(discovered)


def discover_persisted_repair_transaction_chains(
    *,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> tuple[PersistedRepairTransactionChain, ...]:
    return _run_under_root(
        root,
        lambda root_path: discover_persisted_repair_transaction_chains_from_held_root(
            root_path,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        ),
    )


__all__ = [
    "PersistedRepairTransactionChain",
    "append_persisted_repair_transaction_generation_from_held_root",
    "discover_persisted_repair_transaction_chains",
    "discover_persisted_repair_transaction_chains_from_held_root",
    "ensure_persisted_repair_transaction_pointer_from_held_root",
    "load_persisted_repair_transaction_chain_from_held_root",
]
