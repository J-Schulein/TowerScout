"""Root-owned persistence orchestration for recovery generations and pointers.

This source-only layer validates immutable create-only generation storage and
authenticated restart-style enumeration plus metadata-pointer repair through
injected ports. It does not implement native file I/O, cleanup, recovery,
package staging, or runtime mutation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, NoReturn, Protocol, TypeVar, cast

from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_journal import (
    EnvironmentJournalChainSelection,
    EnvironmentJournalPointer,
    JournalPointerDisposition,
    JournalProtectionPort,
    JournalStreamIdentity,
    RecoveryJournalError,
    SealedEnvironmentJournalGeneration,
    decode_environment_journal_pointer,
    encode_environment_journal_pointer,
    select_environment_journal_chain,
)
from .windows_security import StableFileIdentity

_MAX_PROTECTED_GENERATION_BYTES = 4 * 1024 * 1024
_MAX_POINTER_BYTES = 1_024
_MAX_ROOT_ENTRIES = 256
_MAX_SEQUENCE = 2**63 - 1
_GENERATION_NAME = re.compile(r"^journal-([0-9a-f]{32})-([0-9]{20})\.generation$")
_Result = TypeVar("_Result")


class RecoveryJournalStorageErrorCode(str, Enum):
    INPUT_INVALID = "recovery_journal_storage_input_invalid"
    STORAGE_UNAVAILABLE = "recovery_journal_storage_unavailable"
    STORAGE_INVALID = "recovery_journal_storage_invalid"
    WRITE_FAILED = "recovery_journal_storage_write_failed"
    VERIFY_FAILED = "recovery_journal_storage_verify_failed"


class RecoveryJournalStorageError(RuntimeError):
    """Sanitized failure at the recovery-journal storage boundary."""

    _MESSAGES = {
        RecoveryJournalStorageErrorCode.INPUT_INVALID: (
            "The recovery journal storage request is invalid."
        ),
        RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE: (
            "Protected recovery journal storage is unavailable."
        ),
        RecoveryJournalStorageErrorCode.STORAGE_INVALID: (
            "Protected recovery journal storage is invalid."
        ),
        RecoveryJournalStorageErrorCode.WRITE_FAILED: (
            "Recovery journal data could not be written durably."
        ),
        RecoveryJournalStorageErrorCode.VERIFY_FAILED: (
            "Recovery journal data could not be verified durably."
        ),
    }

    def __init__(self, code: RecoveryJournalStorageErrorCode) -> None:
        if type(code) is not RecoveryJournalStorageErrorCode:
            raise ValueError("Unknown recovery journal storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryJournalStorageError(code={self.code.value!r})"


def _fail(code: RecoveryJournalStorageErrorCode) -> NoReturn:
    raise RecoveryJournalStorageError(code)


@dataclass(frozen=True, slots=True, repr=False)
class StoredJournalGenerationFile:
    identity: StableFileIdentity = field(repr=False)
    contents: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not StableFileIdentity
            or type(self.contents) is not bytes
            or not 1 <= len(self.contents) <= _MAX_PROTECTED_GENERATION_BYTES
        ):
            raise ValueError("Stored recovery journal generation is invalid.")

    def __repr__(self) -> str:
        return "StoredJournalGenerationFile(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class StoredJournalPointerFile:
    identity: StableFileIdentity = field(repr=False)
    contents: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not StableFileIdentity
            or type(self.contents) is not bytes
            or not 1 <= len(self.contents) <= _MAX_POINTER_BYTES
        ):
            raise ValueError("Stored recovery journal pointer is invalid.")

    def __repr__(self) -> str:
        return "StoredJournalPointerFile(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PersistedEnvironmentJournalChain:
    sealed_generations: tuple[SealedEnvironmentJournalGeneration, ...] = field(
        repr=False
    )
    file_identities: tuple[StableFileIdentity, ...] = field(repr=False)
    selection: EnvironmentJournalChainSelection = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.sealed_generations) is not tuple
            or not self.sealed_generations
            or any(
                type(item) is not SealedEnvironmentJournalGeneration
                for item in self.sealed_generations
            )
            or type(self.file_identities) is not tuple
            or len(self.file_identities) != len(self.sealed_generations)
            or any(
                type(item) is not StableFileIdentity for item in self.file_identities
            )
            or len(set(self.file_identities)) != len(self.file_identities)
            or type(self.selection) is not EnvironmentJournalChainSelection
            or self.selection.generation_sha256s
            != tuple(item.generation_sha256 for item in self.sealed_generations)
        ):
            raise ValueError("Persisted recovery journal chain is invalid.")

    def __repr__(self) -> str:
        return (
            "PersistedEnvironmentJournalChain("
            f"generations={len(self.sealed_generations)}, <redacted>)"
        )


class JournalStorageRootPort(Protocol):
    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result: ...


class JournalGenerationStoragePort(Protocol):
    def list_names(self, root_path: str) -> tuple[str, ...]: ...

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalGenerationFile: ...

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalGenerationFile: ...


class JournalPointerStoragePort(Protocol):
    def read_pointer(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalPointerFile | None: ...

    def replace_pointer(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalPointerFile: ...


def _generation_name(journal_id: str, sequence: int) -> str:
    if (
        type(journal_id) is not str
        or re.fullmatch(r"[0-9a-f]{32}", journal_id) is None
        or type(sequence) is not int
        or not 1 <= sequence <= _MAX_SEQUENCE
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return f"journal-{journal_id}-{sequence:020d}.generation"


def _pointer_name(journal_id: str) -> str:
    if type(journal_id) is not str or re.fullmatch(r"[0-9a-f]{32}", journal_id) is None:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return f"journal-{journal_id}.pointer"


def _storage_call(
    storage: object,
    method: str,
    *arguments: object,
    code: RecoveryJournalStorageErrorCode,
) -> object:
    try:
        operation = getattr(storage, method)
        if not callable(operation):
            raise TypeError("Recovery journal storage operation is unavailable.")
        return operation(*arguments)
    except RecoveryJournalStorageError:
        raise
    except Exception:
        _fail(code)


def _names_for_stream(
    root_path: str,
    stream: JournalStreamIdentity,
    storage: JournalGenerationStoragePort,
) -> tuple[tuple[int, str], ...]:
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
    prefix = f"journal-{stream.journal_id}-"
    selected: list[tuple[int, str]] = []
    for name in names:
        if not name.startswith(prefix):
            continue
        match = _GENERATION_NAME.fullmatch(name)
        if match is None or match.group(1) != stream.journal_id:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        sequence = int(match.group(2))
        if not 1 <= sequence <= _MAX_SEQUENCE:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        selected.append((sequence, name))
    selected.sort()
    if len({sequence for sequence, _name in selected}) != len(selected):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    return tuple(selected)


def _load_while_root_held(
    root_path: str,
    stream: JournalStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
    pointer: EnvironmentJournalPointer | None = None,
) -> PersistedEnvironmentJournalChain | None:
    candidates = _names_for_stream(root_path, stream, storage)
    if not candidates:
        return None
    sealed: list[SealedEnvironmentJournalGeneration] = []
    identities: list[StableFileIdentity] = []
    for _sequence, name in candidates:
        stored = _storage_call(
            storage,
            "read_generation",
            root_path,
            name,
            _MAX_PROTECTED_GENERATION_BYTES,
            code=RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if type(stored) is not StoredJournalGenerationFile:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        try:
            protected = CurrentUserProtectedBlob(
                ProtectedDataPurpose.JOURNAL_GENERATION,
                stored.contents,
            )
            sealed.append(
                SealedEnvironmentJournalGeneration(
                    protected,
                    protected.ciphertext_sha256,
                )
            )
        except ValueError:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        identities.append(stored.identity)
    if len(set(identities)) != len(identities):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    selection = select_environment_journal_chain(
        tuple(sealed),
        pointer,
        expected_stream=stream,
        protection=protection,
    )
    if tuple(sequence for sequence, _name in candidates) != tuple(
        generation.sequence for generation in selection.generations
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    try:
        return PersistedEnvironmentJournalChain(
            tuple(sealed),
            tuple(identities),
            selection,
        )
    except ValueError:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)


def _read_pointer_while_root_held(
    root_path: str,
    stream: JournalStreamIdentity,
    pointer_storage: JournalPointerStoragePort,
) -> tuple[EnvironmentJournalPointer, StoredJournalPointerFile] | None:
    stored = _storage_call(
        pointer_storage,
        "read_pointer",
        root_path,
        _pointer_name(stream.journal_id),
        _MAX_POINTER_BYTES,
        code=RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
    )
    if stored is None:
        return None
    if type(stored) is not StoredJournalPointerFile:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    pointer = decode_environment_journal_pointer(stored.contents)
    return pointer, stored


def _load_with_pointer_while_root_held(
    root_path: str,
    stream: JournalStreamIdentity,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: JournalProtectionPort,
) -> tuple[
    PersistedEnvironmentJournalChain | None,
    StoredJournalPointerFile | None,
]:
    persisted_pointer = _read_pointer_while_root_held(
        root_path,
        stream,
        pointer_storage,
    )
    pointer = None if persisted_pointer is None else persisted_pointer[0]
    persisted = _load_while_root_held(
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
            raise TypeError("Protected recovery journal root is unavailable.")
        return run(operation)
    except (RecoveryJournalError, RecoveryJournalStorageError):
        raise
    except Exception:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)


def load_persisted_environment_journal_chain(
    stream: JournalStreamIdentity,
    *,
    root: JournalStorageRootPort,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain | None:
    """Load and authenticate one stream while its protected root stays held."""

    if type(stream) is not JournalStreamIdentity:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _run_under_root(
        root,
        lambda root_path: _load_while_root_held(
            root_path,
            stream,
            storage,
            protection,
        ),
    )


def load_persisted_environment_journal_chain_from_held_root(
    root_path: str,
    stream: JournalStreamIdentity,
    *,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain | None:
    """Load one stream through a root path already held by the caller."""

    if (
        type(root_path) is not str
        or not root_path
        or type(stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _load_while_root_held(
        root_path,
        stream,
        storage,
        protection,
    )


def load_persisted_environment_journal_chain_with_pointer(
    stream: JournalStreamIdentity,
    *,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain | None:
    """Load one authenticated stream and classify its persisted pointer."""

    if type(stream) is not JournalStreamIdentity:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _run_under_root(
        root,
        lambda root_path: _load_with_pointer_while_root_held(
            root_path,
            stream,
            generation_storage,
            pointer_storage,
            protection,
        )[0],
    )


def ensure_persisted_environment_journal_pointer(
    stream: JournalStreamIdentity,
    *,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain | None:
    """Create or repair a metadata pointer and prove it names the selected tip."""

    if type(stream) is not JournalStreamIdentity:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)

    def ensure(root_path: str) -> PersistedEnvironmentJournalChain | None:
        persisted, _stored_pointer = _load_with_pointer_while_root_held(
            root_path,
            stream,
            generation_storage,
            pointer_storage,
            protection,
        )
        if persisted is None:
            return None
        if persisted.selection.pointer_disposition is JournalPointerDisposition.CURRENT:
            return persisted
        try:
            pointer = EnvironmentJournalPointer(
                stream.schema_version,
                stream.journal_id,
                persisted.selection.tip.sequence,
                persisted.selection.tip_generation_sha256,
            )
        except ValueError:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        encoded = encode_environment_journal_pointer(pointer)
        decoded = decode_environment_journal_pointer(encoded)
        expected = select_environment_journal_chain(
            persisted.sealed_generations,
            decoded,
            expected_stream=stream,
            protection=protection,
        )
        if (
            expected.pointer_disposition is not JournalPointerDisposition.CURRENT
            or expected.generation_sha256s != persisted.selection.generation_sha256s
        ):
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        written = _storage_call(
            pointer_storage,
            "replace_pointer",
            root_path,
            _pointer_name(stream.journal_id),
            encoded,
            code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        if type(written) is not StoredJournalPointerFile or written.contents != encoded:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        try:
            verified, reread = _load_with_pointer_while_root_held(
                root_path,
                stream,
                generation_storage,
                pointer_storage,
                protection,
            )
        except (RecoveryJournalError, RecoveryJournalStorageError):
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        if (
            verified is None
            or reread is None
            or reread.identity != written.identity
            or reread.contents != encoded
            or verified.selection.pointer_disposition
            is not JournalPointerDisposition.CURRENT
            or verified.selection.generation_sha256s != expected.generation_sha256s
        ):
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        return verified

    return _run_under_root(root, ensure)


def append_persisted_environment_journal_generation(
    sealed: SealedEnvironmentJournalGeneration,
    *,
    stream: JournalStreamIdentity,
    root: JournalStorageRootPort,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Create one immutable generation and authenticate the complete reread."""

    if (
        type(sealed) is not SealedEnvironmentJournalGeneration
        or type(stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)

    return _run_under_root(
        root,
        lambda root_path: _append_while_root_held(
            root_path,
            sealed,
            stream,
            storage,
            protection,
        ),
    )


def _append_while_root_held(
    root_path: str,
    sealed: SealedEnvironmentJournalGeneration,
    stream: JournalStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    previous = _load_while_root_held(root_path, stream, storage, protection)
    existing = () if previous is None else previous.sealed_generations
    expected = select_environment_journal_chain(
        existing + (sealed,),
        None,
        expected_stream=stream,
        protection=protection,
    )
    if expected.tip_generation_sha256 != sealed.generation_sha256:
        _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
    name = _generation_name(stream.journal_id, expected.tip.sequence)
    written = _storage_call(
        storage,
        "create_generation",
        root_path,
        name,
        sealed.protected_blob.ciphertext,
        code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if (
        type(written) is not StoredJournalGenerationFile
        or written.contents != sealed.protected_blob.ciphertext
        or (previous is not None and written.identity in previous.file_identities)
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    verified = _load_while_root_held(root_path, stream, storage, protection)
    if (
        verified is None
        or verified.selection.generation_sha256s != expected.generation_sha256s
        or verified.file_identities[-1] != written.identity
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    return verified


def append_persisted_environment_journal_generation_from_held_root(
    root_path: str,
    sealed: SealedEnvironmentJournalGeneration,
    *,
    stream: JournalStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    """Append one generation through a root path already held by the caller."""

    if (
        type(root_path) is not str
        or not root_path
        or type(sealed) is not SealedEnvironmentJournalGeneration
        or type(stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _append_while_root_held(
        root_path,
        sealed,
        stream,
        storage,
        protection,
    )


__all__ = [
    "JournalGenerationStoragePort",
    "JournalPointerStoragePort",
    "JournalStorageRootPort",
    "PersistedEnvironmentJournalChain",
    "RecoveryJournalStorageError",
    "RecoveryJournalStorageErrorCode",
    "StoredJournalGenerationFile",
    "StoredJournalPointerFile",
    "append_persisted_environment_journal_generation",
    "append_persisted_environment_journal_generation_from_held_root",
    "ensure_persisted_environment_journal_pointer",
    "load_persisted_environment_journal_chain",
    "load_persisted_environment_journal_chain_from_held_root",
    "load_persisted_environment_journal_chain_with_pointer",
]
