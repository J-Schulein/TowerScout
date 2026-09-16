"""Durable orchestration for authenticated journal-pointer transitions.

This Gate-A layer stores create-only transition generations below the held
protected recovery root, creates and verifies the exact planned pointer temp,
and authenticates the complete chain after restart. It does not promote,
replace, or delete pointer files and does not authorize repair or runtime
mutation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, NoReturn, Protocol, TypeVar, cast

from .windows_protected_state import (
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from .windows_recovery_journal import (
    EnvironmentJournalPointer,
    JournalStreamIdentity,
    RecoveryJournalError,
    SealedEnvironmentJournalGeneration,
    encode_environment_journal_pointer,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalStorageRootPort,
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    StoredJournalGenerationFile,
    StoredJournalPointerFile,
)
from .windows_recovery_pointer_transition import (
    JournalPointerTransitionChainSelection as _TransitionSelection,
    JournalPointerTransitionCreatedRecord as _TransitionCreated,
    JournalPointerTransitionError,
    JournalPointerTransitionGeneration as _TransitionGeneration,
    JournalPointerTransitionPlanRecord as _TransitionPlan,
    JournalPointerTransitionState as _TransitionState,
    JournalPointerTransitionStreamIdentity as _TransitionStream,
    PointerTransitionProtectionPort as _TransitionProtection,
    SealedJournalPointerTransitionGeneration as _SealedTransition,
    protect_journal_pointer_transition_generation,
    select_journal_pointer_transition_chain,
)
from .windows_security import StableFileIdentity

_MAX_PROTECTED_GENERATION_BYTES = 4 * 1024 * 1024
_MAX_ROOT_ENTRIES = 256
_MAX_SEQUENCE = 2**63 - 1
_GENERATION_NAME = re.compile(
    r"^pointer-transition-([0-9a-f]{32})-([0-9]{20})\.generation$"
)
_Result = TypeVar("_Result")


def _fail(code: RecoveryJournalStorageErrorCode) -> NoReturn:
    raise RecoveryJournalStorageError(code)


@dataclass(frozen=True, slots=True, repr=False)
class PersistedJournalPointerTransitionChain:
    sealed_generations: tuple[_SealedTransition, ...] = field(repr=False)
    file_identities: tuple[StableFileIdentity, ...] = field(repr=False)
    selection: _TransitionSelection = field(repr=False)

    def __post_init__(self) -> None:
        sealed = self.sealed_generations
        identities = self.file_identities
        if type(sealed) is not tuple or type(identities) is not tuple:
            raise ValueError("Persisted pointer transition is invalid.")
        sealed_type = _SealedTransition
        invalid_sealed = any(type(item) is not sealed_type for item in sealed)
        invalid_identities = any(
            type(item) is not StableFileIdentity for item in identities
        )
        digests = tuple(item.generation_sha256 for item in sealed)
        if (
            not sealed
            or invalid_sealed
            or len(identities) != len(sealed)
            or invalid_identities
            or len(set(identities)) != len(identities)
            or type(self.selection) is not _TransitionSelection
            or self.selection.generation_sha256s != digests
        ):
            raise ValueError("Persisted pointer transition is invalid.")

    def __repr__(self) -> str:
        return (
            "PersistedJournalPointerTransitionChain("
            f"generations={len(self.sealed_generations)}, <redacted>)"
        )


class JournalPointerTempStoragePort(Protocol):
    def create_pointer_temp(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalPointerFile: ...


def _generation_name(transition_id: str, sequence: int) -> str:
    if (
        type(transition_id) is not str
        or re.fullmatch(r"[0-9a-f]{32}", transition_id) is None
        or type(sequence) is not int
        or not 1 <= sequence <= _MAX_SEQUENCE
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return f"pointer-transition-{transition_id}-{sequence:020d}.generation"


def _storage_call(
    storage: object,
    method: str,
    *arguments: object,
    code: RecoveryJournalStorageErrorCode,
) -> object:
    try:
        operation = getattr(storage, method)
        if not callable(operation):
            raise TypeError("Transition storage operation is unavailable.")
        return operation(*arguments)
    except RecoveryJournalStorageError:
        raise
    except Exception:
        _fail(code)


def _names_for_stream(
    root_path: str,
    stream: _TransitionStream,
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
    prefix = f"pointer-transition-{stream.transition_id}-"
    selected: list[tuple[int, str]] = []
    for name in names:
        if not name.startswith(prefix):
            continue
        match = _GENERATION_NAME.fullmatch(name)
        if match is None or match.group(1) != stream.transition_id:
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
    stream: _TransitionStream,
    storage: JournalGenerationStoragePort,
    protection: _TransitionProtection,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
) -> PersistedJournalPointerTransitionChain | None:
    candidates = _names_for_stream(root_path, stream, storage)
    if not candidates:
        return None
    sealed: list[_SealedTransition] = []
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
                ProtectedDataPurpose.POINTER_TRANSITION,
                stored.contents,
            )
            sealed.append(
                _SealedTransition(
                    protected,
                    protected.ciphertext_sha256,
                )
            )
        except ValueError:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        identities.append(stored.identity)
    if len(set(identities)) != len(identities):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    selection = select_journal_pointer_transition_chain(
        tuple(sealed),
        expected_stream=stream,
        environment_generations=environment_generations,
        expected_environment_stream=expected_environment_stream,
        protection=protection,
    )
    if tuple(sequence for sequence, _name in candidates) != tuple(
        generation.sequence for generation in selection.generations
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    try:
        return PersistedJournalPointerTransitionChain(
            tuple(sealed),
            tuple(identities),
            selection,
        )
    except ValueError:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)


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
    except (JournalPointerTransitionError, RecoveryJournalStorageError):
        raise
    except Exception:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)


def load_persisted_journal_pointer_transition_chain(
    stream: _TransitionStream,
    *,
    root: JournalStorageRootPort,
    storage: JournalGenerationStoragePort,
    protection: _TransitionProtection,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
) -> PersistedJournalPointerTransitionChain | None:
    """Load one transition while its protected root is held."""

    if (
        type(stream) is not _TransitionStream
        or type(environment_generations) is not tuple
        or any(
            type(item) is not SealedEnvironmentJournalGeneration
            for item in environment_generations
        )
        or type(expected_environment_stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _run_under_root(
        root,
        lambda root_path: _load_while_root_held(
            root_path,
            stream,
            storage,
            protection,
            environment_generations,
            expected_environment_stream,
        ),
    )


def _append_while_root_held(
    root_path: str,
    generation: _SealedTransition,
    stream: _TransitionStream,
    storage: JournalGenerationStoragePort,
    protection: _TransitionProtection,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
) -> PersistedJournalPointerTransitionChain:
    current = _load_while_root_held(
        root_path,
        stream,
        storage,
        protection,
        environment_generations,
        expected_environment_stream,
    )
    candidates: tuple[_SealedTransition, ...] = (generation,)
    if current is not None:
        candidates = current.sealed_generations + (generation,)
    selection = select_journal_pointer_transition_chain(
        candidates,
        expected_stream=stream,
        environment_generations=environment_generations,
        expected_environment_stream=expected_environment_stream,
        protection=protection,
    )
    if selection.tip_generation_sha256 != generation.generation_sha256:
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    name = _generation_name(stream.transition_id, selection.tip.sequence)
    stored = _storage_call(
        storage,
        "create_generation",
        root_path,
        name,
        generation.protected_blob.ciphertext,
        code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if (
        type(stored) is not StoredJournalGenerationFile
        or stored.contents != generation.protected_blob.ciphertext
        or (current is not None and stored.identity in current.file_identities)
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    reloaded = _load_while_root_held(
        root_path,
        stream,
        storage,
        protection,
        environment_generations,
        expected_environment_stream,
    )
    expected_digests = selection.generation_sha256s
    if (
        reloaded is None
        or reloaded.selection.generation_sha256s != expected_digests
        or reloaded.file_identities[-1] != stored.identity
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    return reloaded


def append_persisted_journal_pointer_transition_generation(
    generation: _SealedTransition,
    *,
    stream: _TransitionStream,
    root: JournalStorageRootPort,
    storage: JournalGenerationStoragePort,
    protection: _TransitionProtection,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
) -> PersistedJournalPointerTransitionChain:
    """Create one transition generation and verify a complete reload."""

    if (
        type(generation) is not _SealedTransition
        or type(stream) is not _TransitionStream
        or type(environment_generations) is not tuple
        or any(
            type(item) is not SealedEnvironmentJournalGeneration
            for item in environment_generations
        )
        or type(expected_environment_stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _run_under_root(
        root,
        lambda root_path: _append_while_root_held(
            root_path,
            generation,
            stream,
            storage,
            protection,
            environment_generations,
            expected_environment_stream,
        ),
    )


def _pointer_contents(
    plan: _TransitionPlan,
    stream: _TransitionStream,
) -> bytes:
    try:
        pointer = EnvironmentJournalPointer(
            plan.schema_version,
            stream.environment_journal_id,
            plan.target_tip_sequence,
            plan.target_generation_sha256,
        )
        contents = encode_environment_journal_pointer(pointer)
    except (RecoveryJournalError, ValueError):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    if (
        hashlib.sha256(contents).hexdigest() != plan.intended_pointer_sha256
        or len(contents) != plan.intended_pointer_size
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    return contents


def _created_record(
    plan: _TransitionPlan,
    *,
    planned_generation_sha256: str,
    pointer_temp_identity: StableFileIdentity,
) -> _TransitionCreated:
    try:
        return _TransitionCreated(
            plan.schema_version,
            planned_generation_sha256,
            plan.package_root_identity,
            pointer_temp_identity,
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
    except ValueError:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)


def _create_pointer_temp_while_root_held(
    root_path: str,
    stream: _TransitionStream,
    generation_storage: JournalGenerationStoragePort,
    pointer_temp_storage: JournalPointerTempStoragePort,
    protection: _TransitionProtection,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
) -> PersistedJournalPointerTransitionChain:
    current = _load_while_root_held(
        root_path,
        stream,
        generation_storage,
        protection,
        environment_generations,
        expected_environment_stream,
    )
    if (
        current is None
        or current.selection.tip.state is not _TransitionState.POINTER_TEMP_PLANNED
        or type(current.selection.tip.record) is not _TransitionPlan
    ):
        _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
    plan = current.selection.tip.record
    contents = _pointer_contents(plan, stream)
    stored = _storage_call(
        pointer_temp_storage,
        "create_pointer_temp",
        root_path,
        plan.pointer_temp_name,
        contents,
        code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if type(stored) is not StoredJournalPointerFile or stored.contents != contents:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    created = _created_record(
        plan,
        planned_generation_sha256=current.selection.tip_generation_sha256,
        pointer_temp_identity=stored.identity,
    )
    try:
        sealed = protect_journal_pointer_transition_generation(
            _TransitionGeneration(
                plan.schema_version,
                stream,
                2,
                current.selection.tip_generation_sha256,
                _TransitionState.POINTER_TEMP_CREATED,
                created,
            ),
            protection=protection,
        )
    except ValueError:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    persisted = _append_while_root_held(
        root_path,
        sealed,
        stream,
        generation_storage,
        protection,
        environment_generations,
        expected_environment_stream,
    )
    tip = persisted.selection.tip
    if (
        tip.state is not _TransitionState.POINTER_TEMP_CREATED
        or type(tip.record) is not _TransitionCreated
        or tip.record.pointer_temp_identity != stored.identity
    ):
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    return persisted


def create_persisted_journal_pointer_transition_temp(
    stream: _TransitionStream,
    *,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_temp_storage: JournalPointerTempStoragePort,
    protection: _TransitionProtection,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
) -> PersistedJournalPointerTransitionChain:
    """Create the exact planned pointer temp and persist its verified identity."""

    if (
        type(stream) is not _TransitionStream
        or type(environment_generations) is not tuple
        or any(
            type(item) is not SealedEnvironmentJournalGeneration
            for item in environment_generations
        )
        or type(expected_environment_stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return _run_under_root(
        root,
        lambda root_path: _create_pointer_temp_while_root_held(
            root_path,
            stream,
            generation_storage,
            pointer_temp_storage,
            protection,
            environment_generations,
            expected_environment_stream,
        ),
    )


__all__ = [
    "JournalPointerTempStoragePort",
    "PersistedJournalPointerTransitionChain",
    "append_persisted_journal_pointer_transition_generation",
    "create_persisted_journal_pointer_transition_temp",
    "load_persisted_journal_pointer_transition_chain",
]
