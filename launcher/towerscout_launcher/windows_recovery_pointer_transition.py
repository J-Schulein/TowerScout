"""Authenticated journal-pointer transition and restart-classification primitives.

This source-only Gate-A layer records the exact source temporary file and prior
pointer state for one metadata-pointer replacement. It authenticates the
environment journal it references, but performs no native I/O, cleanup,
recovery action, pointer replacement, package mutation, or runtime mutation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn, Protocol

from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_journal import (
    EnvironmentJournalChainSelection,
    EnvironmentJournalPointer,
    JournalPointerDisposition,
    JournalStreamIdentity,
    RecoveryJournalError,
    SealedEnvironmentJournalGeneration,
    encode_environment_journal_pointer,
    select_environment_journal_chain,
)
from .windows_security import StableFileIdentity

_SCHEMA_VERSION = 1
_MAX_GENERATION_BYTES = 32_768
_MAX_POINTER_BYTES = 1_024
_MAX_JSON_DEPTH = 8
_MAX_JSON_ITEMS = 32
_MAX_JSON_NODES = 256
_MAX_JSON_STRING_CHARACTERS = 1_024
_MAX_SEQUENCE = 2**63 - 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[0-9a-f]{32}$")
_POINTER_TEMP_NAME = re.compile(r"^\.journal-pointer-[0-9a-f]{32}\.tmp$")

GENESIS_POINTER_TRANSITION_SHA256 = hashlib.sha256(
    b"TowerScout.AbsentJournalPointerTransition.v1"
).hexdigest()


class JournalPointerTransitionErrorCode(str, Enum):
    INPUT_INVALID = "journal_pointer_transition_input_invalid"
    GENERATION_INVALID = "journal_pointer_transition_generation_invalid"
    AUTHENTICATION_FAILED = "journal_pointer_transition_authentication_failed"
    CHAIN_INVALID = "journal_pointer_transition_chain_invalid"
    CONTEXT_INVALID = "journal_pointer_transition_context_invalid"


class JournalPointerTransitionError(RuntimeError):
    """Sanitized failure at the journal-pointer transition boundary."""

    _MESSAGES = {
        JournalPointerTransitionErrorCode.INPUT_INVALID: (
            "The journal-pointer transition request is invalid."
        ),
        JournalPointerTransitionErrorCode.GENERATION_INVALID: (
            "A journal-pointer transition generation is invalid."
        ),
        JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED: (
            "A journal-pointer transition generation could not be authenticated."
        ),
        JournalPointerTransitionErrorCode.CHAIN_INVALID: (
            "The journal-pointer transition chain is invalid."
        ),
        JournalPointerTransitionErrorCode.CONTEXT_INVALID: (
            "The journal-pointer transition context is invalid."
        ),
    }

    def __init__(self, code: JournalPointerTransitionErrorCode) -> None:
        if type(code) is not JournalPointerTransitionErrorCode:
            raise ValueError("Unknown journal-pointer transition error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"JournalPointerTransitionError(code={self.code.value!r})"


def _fail(code: JournalPointerTransitionErrorCode) -> NoReturn:
    raise JournalPointerTransitionError(code)


def _valid_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_size(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAX_POINTER_BYTES


def _validate_prior_fields(record: JournalPointerTransitionRecord) -> None:
    optional_values = (
        record.prior_pointer_identity,
        record.prior_pointer_sequence,
        record.prior_pointer_generation_sha256,
        record.prior_pointer_sha256,
        record.prior_pointer_size,
    )
    if type(record.prior_pointer_present) is not bool:
        raise ValueError("Journal-pointer prior state is invalid.")
    if not record.prior_pointer_present:
        if any(value is not None for value in optional_values):
            raise ValueError("Journal-pointer prior state is invalid.")
        return
    if (
        type(record.prior_pointer_identity) is not StableFileIdentity
        or type(record.prior_pointer_sequence) is not int
        or not 1 <= record.prior_pointer_sequence < record.target_tip_sequence
        or not _valid_hash(record.prior_pointer_generation_sha256)
        or not _valid_hash(record.prior_pointer_sha256)
        or not _valid_size(record.prior_pointer_size)
    ):
        raise ValueError("Journal-pointer prior state is invalid.")


@dataclass(frozen=True, slots=True, repr=False)
class JournalPointerTransitionStreamIdentity:
    schema_version: int
    transition_id: str = field(repr=False)
    environment_journal_id: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_identifier(self.transition_id)
            or not _valid_identifier(self.environment_journal_id)
            or type(self.package_root_identity) is not StableFileIdentity
        ):
            raise ValueError("Journal-pointer transition stream is invalid.")

    def __repr__(self) -> str:
        return "JournalPointerTransitionStreamIdentity(schema_version=1, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class JournalPointerTransitionPlanRecord:
    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    pointer_name: str = field(repr=False)
    pointer_temp_name: str = field(repr=False)
    intended_pointer_sha256: str = field(repr=False)
    intended_pointer_size: int
    target_tip_sequence: int
    target_generation_sha256: str = field(repr=False)
    prior_pointer_present: bool
    prior_pointer_identity: StableFileIdentity | None = field(default=None, repr=False)
    prior_pointer_sequence: int | None = None
    prior_pointer_generation_sha256: str | None = field(default=None, repr=False)
    prior_pointer_sha256: str | None = field(default=None, repr=False)
    prior_pointer_size: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.pointer_name) is not str
            or type(self.pointer_temp_name) is not str
            or _POINTER_TEMP_NAME.fullmatch(self.pointer_temp_name) is None
            or not _valid_hash(self.intended_pointer_sha256)
            or not _valid_size(self.intended_pointer_size)
            or type(self.target_tip_sequence) is not int
            or not 1 <= self.target_tip_sequence <= _MAX_SEQUENCE
            or not _valid_hash(self.target_generation_sha256)
        ):
            raise ValueError("Journal-pointer transition plan is invalid.")
        _validate_prior_fields(self)

    def __repr__(self) -> str:
        return (
            "JournalPointerTransitionPlanRecord("
            f"schema_version={self.schema_version}, "
            f"target_tip_sequence={self.target_tip_sequence}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class JournalPointerTransitionCreatedRecord:
    schema_version: int
    planned_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    pointer_temp_identity: StableFileIdentity = field(repr=False)
    pointer_name: str = field(repr=False)
    pointer_temp_name: str = field(repr=False)
    intended_pointer_sha256: str = field(repr=False)
    intended_pointer_size: int
    target_tip_sequence: int
    target_generation_sha256: str = field(repr=False)
    prior_pointer_present: bool
    prior_pointer_identity: StableFileIdentity | None = field(default=None, repr=False)
    prior_pointer_sequence: int | None = None
    prior_pointer_generation_sha256: str | None = field(default=None, repr=False)
    prior_pointer_sha256: str | None = field(default=None, repr=False)
    prior_pointer_size: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.planned_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.pointer_temp_identity) is not StableFileIdentity
            or type(self.pointer_name) is not str
            or type(self.pointer_temp_name) is not str
            or _POINTER_TEMP_NAME.fullmatch(self.pointer_temp_name) is None
            or not _valid_hash(self.intended_pointer_sha256)
            or not _valid_size(self.intended_pointer_size)
            or type(self.target_tip_sequence) is not int
            or not 1 <= self.target_tip_sequence <= _MAX_SEQUENCE
            or not _valid_hash(self.target_generation_sha256)
        ):
            raise ValueError("Journal-pointer transition creation is invalid.")
        _validate_prior_fields(self)

    def __repr__(self) -> str:
        return (
            "JournalPointerTransitionCreatedRecord("
            f"schema_version={self.schema_version}, "
            f"target_tip_sequence={self.target_tip_sequence}, <redacted>)"
        )


JournalPointerTransitionRecord = (
    JournalPointerTransitionPlanRecord | JournalPointerTransitionCreatedRecord
)


class JournalPointerTransitionState(str, Enum):
    POINTER_TEMP_PLANNED = "pointer_temp_planned"
    POINTER_TEMP_CREATED = "pointer_temp_created"


_RECORD_TYPE_BY_STATE: dict[JournalPointerTransitionState, type[object]] = {
    JournalPointerTransitionState.POINTER_TEMP_PLANNED: (
        JournalPointerTransitionPlanRecord
    ),
    JournalPointerTransitionState.POINTER_TEMP_CREATED: (
        JournalPointerTransitionCreatedRecord
    ),
}

_SEQUENCE_BY_STATE = {
    JournalPointerTransitionState.POINTER_TEMP_PLANNED: 1,
    JournalPointerTransitionState.POINTER_TEMP_CREATED: 2,
}


def _canonical_pointer(
    journal_id: str,
    sequence: int,
    generation_sha256: str,
) -> bytes:
    return encode_environment_journal_pointer(
        EnvironmentJournalPointer(
            _SCHEMA_VERSION,
            journal_id,
            sequence,
            generation_sha256,
        )
    )


def _validate_record_against_stream(
    record: JournalPointerTransitionRecord,
    stream: JournalPointerTransitionStreamIdentity,
) -> None:
    if (
        record.package_root_identity != stream.package_root_identity
        or record.pointer_name != f"journal-{stream.environment_journal_id}.pointer"
    ):
        raise ValueError("Journal-pointer transition intent is invalid.")
    intended_pointer = _canonical_pointer(
        stream.environment_journal_id,
        record.target_tip_sequence,
        record.target_generation_sha256,
    )
    if (
        hashlib.sha256(intended_pointer).hexdigest() != record.intended_pointer_sha256
        or len(intended_pointer) != record.intended_pointer_size
    ):
        raise ValueError("Journal-pointer transition intent is invalid.")
    if record.prior_pointer_present:
        assert record.prior_pointer_identity is not None
        assert record.prior_pointer_sequence is not None
        assert record.prior_pointer_generation_sha256 is not None
        assert record.prior_pointer_sha256 is not None
        assert record.prior_pointer_size is not None
        prior_pointer = _canonical_pointer(
            stream.environment_journal_id,
            record.prior_pointer_sequence,
            record.prior_pointer_generation_sha256,
        )
        if (
            hashlib.sha256(prior_pointer).hexdigest() != record.prior_pointer_sha256
            or len(prior_pointer) != record.prior_pointer_size
            or record.prior_pointer_identity.volume_serial
            != stream.package_root_identity.volume_serial
        ):
            raise ValueError("Journal-pointer transition prior state is invalid.")
    if type(record) is JournalPointerTransitionCreatedRecord:
        if (
            record.pointer_temp_identity.volume_serial
            != stream.package_root_identity.volume_serial
            or record.pointer_temp_identity == record.prior_pointer_identity
        ):
            raise ValueError("Journal-pointer transition source is invalid.")


@dataclass(frozen=True, slots=True, repr=False)
class JournalPointerTransitionGeneration:
    schema_version: int
    stream: JournalPointerTransitionStreamIdentity = field(repr=False)
    sequence: int
    previous_generation_sha256: str = field(repr=False)
    state: JournalPointerTransitionState
    record: JournalPointerTransitionRecord = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.stream) is not JournalPointerTransitionStreamIdentity
            or type(self.state) is not JournalPointerTransitionState
            or type(self.record) is not _RECORD_TYPE_BY_STATE.get(self.state)
            or type(self.sequence) is not int
            or self.sequence != _SEQUENCE_BY_STATE.get(self.state)
            or not _valid_hash(self.previous_generation_sha256)
            or (
                self.sequence == 1
                and self.previous_generation_sha256 != GENESIS_POINTER_TRANSITION_SHA256
            )
        ):
            raise ValueError("Journal-pointer transition generation is invalid.")
        _validate_record_against_stream(self.record, self.stream)

    def __repr__(self) -> str:
        return (
            "JournalPointerTransitionGeneration("
            f"sequence={self.sequence}, state={self.state.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SealedJournalPointerTransitionGeneration:
    protected_blob: CurrentUserProtectedBlob = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.protected_blob) is not CurrentUserProtectedBlob
            or self.protected_blob.purpose
            is not ProtectedDataPurpose.POINTER_TRANSITION
            or not _valid_hash(self.generation_sha256)
            or self.generation_sha256 != self.protected_blob.ciphertext_sha256
        ):
            raise ValueError("Sealed journal-pointer transition is invalid.")

    def __repr__(self) -> str:
        return "SealedJournalPointerTransitionGeneration(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _AuthenticatedJournalPointerTransitionGeneration:
    generation: JournalPointerTransitionGeneration = field(repr=False)
    generation_sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class JournalPointerTransitionChainSelection:
    generations: tuple[JournalPointerTransitionGeneration, ...] = field(repr=False)
    generation_sha256s: tuple[str, ...] = field(repr=False)
    tip: JournalPointerTransitionGeneration = field(repr=False)
    tip_generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.generations) is not tuple
            or not self.generations
            or len(self.generations) > 2
            or any(
                type(item) is not JournalPointerTransitionGeneration
                for item in self.generations
            )
            or type(self.generation_sha256s) is not tuple
            or len(self.generation_sha256s) != len(self.generations)
            or any(not _valid_hash(value) for value in self.generation_sha256s)
            or type(self.tip) is not JournalPointerTransitionGeneration
            or self.tip != self.generations[-1]
            or not _valid_hash(self.tip_generation_sha256)
            or self.tip_generation_sha256 != self.generation_sha256s[-1]
        ):
            raise ValueError("Journal-pointer transition selection is invalid.")

    def __repr__(self) -> str:
        return (
            "JournalPointerTransitionChainSelection("
            f"generations={len(self.generations)}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class JournalPointerPathObservation:
    present: bool
    identity: StableFileIdentity | None = field(default=None, repr=False)
    sha256: str | None = field(default=None, repr=False)
    size: int | None = None

    def __post_init__(self) -> None:
        if type(self.present) is not bool:
            raise ValueError("Journal-pointer path observation is invalid.")
        values = (self.identity, self.sha256, self.size)
        if not self.present:
            if any(value is not None for value in values):
                raise ValueError("Journal-pointer path observation is invalid.")
            return
        if (
            type(self.identity) is not StableFileIdentity
            or not _valid_hash(self.sha256)
            or not _valid_size(self.size)
        ):
            raise ValueError("Journal-pointer path observation is invalid.")

    def __repr__(self) -> str:
        return f"JournalPointerPathObservation(present={self.present}, <redacted>)"


class JournalPointerRestartDisposition(str, Enum):
    SOURCE_TEMP_REMAINS = "source_temp_remains"
    MOVE_COMPLETED = "move_completed"
    AMBIGUOUS = "ambiguous"


class PointerTransitionProtectionPort(Protocol):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob: ...

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes: ...


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Non-finite JSON value.")


def _json_nodes(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeded.")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("JSON integer exceeded.")
        return 1
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING_CHARACTERS or "\x00" in value:
            raise ValueError("JSON string is invalid.")
        return 1
    if type(value) is list:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON list exceeded.")
        return 1 + sum(_json_nodes(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > _MAX_JSON_ITEMS:
            raise ValueError("JSON object exceeded.")
        return 1 + sum(_json_nodes(item, depth=depth + 1) for item in value.values())
    raise ValueError("JSON value type is invalid.")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii", errors="strict")


def _load_canonical_json(raw: bytes) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_GENERATION_BYTES:
            raise ValueError("JSON bytes are invalid.")
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            raise ValueError("JSON encoding is invalid.")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if type(parsed) is not dict or _json_nodes(parsed) > _MAX_JSON_NODES:
            raise ValueError("JSON root is invalid.")
        if _canonical_json(parsed) != raw:
            raise ValueError("JSON encoding is not canonical.")
        return parsed
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        _fail(JournalPointerTransitionErrorCode.GENERATION_INVALID)


def _exact_keys(value: object, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise ValueError("JSON object shape is invalid.")
    return value


def _identity_to_json(identity: StableFileIdentity) -> dict[str, Any]:
    return {
        "file_id": identity.file_id.hex(),
        "volume_serial": identity.volume_serial,
    }


def _identity_from_json(value: object) -> StableFileIdentity:
    item = _exact_keys(value, frozenset({"file_id", "volume_serial"}))
    if (
        type(item["file_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{32}", item["file_id"]) is None
        or type(item["volume_serial"]) is not int
    ):
        raise ValueError("File identity is invalid.")
    return StableFileIdentity(item["volume_serial"], bytes.fromhex(item["file_id"]))


def _optional_identity_from_json(value: object) -> StableFileIdentity | None:
    return None if value is None else _identity_from_json(value)


def _stream_to_json(
    stream: JournalPointerTransitionStreamIdentity,
) -> dict[str, Any]:
    return {
        "environment_journal_id": stream.environment_journal_id,
        "package_root_identity": _identity_to_json(stream.package_root_identity),
        "schema_version": stream.schema_version,
        "transition_id": stream.transition_id,
    }


def _stream_from_json(value: object) -> JournalPointerTransitionStreamIdentity:
    item = _exact_keys(
        value,
        frozenset(
            {
                "environment_journal_id",
                "package_root_identity",
                "schema_version",
                "transition_id",
            }
        ),
    )
    return JournalPointerTransitionStreamIdentity(
        item["schema_version"],
        item["transition_id"],
        item["environment_journal_id"],
        _identity_from_json(item["package_root_identity"]),
    )


def _record_to_json(record: JournalPointerTransitionRecord) -> dict[str, Any]:
    common: dict[str, Any] = {
        "intended_pointer_sha256": record.intended_pointer_sha256,
        "intended_pointer_size": record.intended_pointer_size,
        "package_root_identity": _identity_to_json(record.package_root_identity),
        "pointer_name": record.pointer_name,
        "pointer_temp_name": record.pointer_temp_name,
        "prior_pointer_generation_sha256": (record.prior_pointer_generation_sha256),
        "prior_pointer_identity": (
            None
            if record.prior_pointer_identity is None
            else _identity_to_json(record.prior_pointer_identity)
        ),
        "prior_pointer_present": record.prior_pointer_present,
        "prior_pointer_sequence": record.prior_pointer_sequence,
        "prior_pointer_sha256": record.prior_pointer_sha256,
        "prior_pointer_size": record.prior_pointer_size,
        "schema_version": record.schema_version,
        "target_generation_sha256": record.target_generation_sha256,
        "target_tip_sequence": record.target_tip_sequence,
    }
    if type(record) is JournalPointerTransitionCreatedRecord:
        common["planned_generation_sha256"] = record.planned_generation_sha256
        common["pointer_temp_identity"] = _identity_to_json(
            record.pointer_temp_identity
        )
    return common


def _record_from_json(
    value: object,
    state: JournalPointerTransitionState,
) -> JournalPointerTransitionRecord:
    common = frozenset(
        {
            "intended_pointer_sha256",
            "intended_pointer_size",
            "package_root_identity",
            "pointer_name",
            "pointer_temp_name",
            "prior_pointer_generation_sha256",
            "prior_pointer_identity",
            "prior_pointer_present",
            "prior_pointer_sequence",
            "prior_pointer_sha256",
            "prior_pointer_size",
            "schema_version",
            "target_generation_sha256",
            "target_tip_sequence",
        }
    )
    extra = (
        frozenset({"planned_generation_sha256", "pointer_temp_identity"})
        if state is JournalPointerTransitionState.POINTER_TEMP_CREATED
        else frozenset()
    )
    item = _exact_keys(value, common | extra)
    values: dict[str, Any] = {
        "schema_version": item["schema_version"],
        "package_root_identity": _identity_from_json(item["package_root_identity"]),
        "pointer_name": item["pointer_name"],
        "pointer_temp_name": item["pointer_temp_name"],
        "intended_pointer_sha256": item["intended_pointer_sha256"],
        "intended_pointer_size": item["intended_pointer_size"],
        "target_tip_sequence": item["target_tip_sequence"],
        "target_generation_sha256": item["target_generation_sha256"],
        "prior_pointer_present": item["prior_pointer_present"],
        "prior_pointer_identity": _optional_identity_from_json(
            item["prior_pointer_identity"]
        ),
        "prior_pointer_sequence": item["prior_pointer_sequence"],
        "prior_pointer_generation_sha256": item["prior_pointer_generation_sha256"],
        "prior_pointer_sha256": item["prior_pointer_sha256"],
        "prior_pointer_size": item["prior_pointer_size"],
    }
    if state is JournalPointerTransitionState.POINTER_TEMP_PLANNED:
        return JournalPointerTransitionPlanRecord(**values)
    return JournalPointerTransitionCreatedRecord(
        planned_generation_sha256=item["planned_generation_sha256"],
        pointer_temp_identity=_identity_from_json(item["pointer_temp_identity"]),
        **values,
    )


def _generation_to_bytes(generation: JournalPointerTransitionGeneration) -> bytes:
    return _canonical_json(
        {
            "previous_generation_sha256": generation.previous_generation_sha256,
            "record": _record_to_json(generation.record),
            "schema_version": generation.schema_version,
            "sequence": generation.sequence,
            "state": generation.state.value,
            "stream": _stream_to_json(generation.stream),
        }
    )


def _generation_from_bytes(raw: bytes) -> JournalPointerTransitionGeneration:
    try:
        item = _exact_keys(
            _load_canonical_json(raw),
            frozenset(
                {
                    "previous_generation_sha256",
                    "record",
                    "schema_version",
                    "sequence",
                    "state",
                    "stream",
                }
            ),
        )
        state = JournalPointerTransitionState(item["state"])
        return JournalPointerTransitionGeneration(
            item["schema_version"],
            _stream_from_json(item["stream"]),
            item["sequence"],
            item["previous_generation_sha256"],
            state,
            _record_from_json(item["record"], state),
        )
    except JournalPointerTransitionError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(JournalPointerTransitionErrorCode.GENERATION_INVALID)


def protect_journal_pointer_transition_generation(
    generation: JournalPointerTransitionGeneration,
    *,
    protection: PointerTransitionProtectionPort,
) -> SealedJournalPointerTransitionGeneration:
    if type(generation) is not JournalPointerTransitionGeneration:
        _fail(JournalPointerTransitionErrorCode.INPUT_INVALID)
    try:
        operation = getattr(protection, "protect")
        if not callable(operation):
            raise TypeError("Pointer-transition protection is unavailable.")
        protected = operation(
            _generation_to_bytes(generation),
            ProtectedDataPurpose.POINTER_TRANSITION,
        )
    except Exception:
        _fail(JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED)
    if type(protected) is not CurrentUserProtectedBlob:
        _fail(JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED)
    try:
        return SealedJournalPointerTransitionGeneration(
            protected,
            protected.ciphertext_sha256,
        )
    except ValueError:
        _fail(JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED)


def _authenticate_generation(
    sealed: SealedJournalPointerTransitionGeneration,
    *,
    protection: PointerTransitionProtectionPort,
) -> _AuthenticatedJournalPointerTransitionGeneration:
    if type(sealed) is not SealedJournalPointerTransitionGeneration:
        _fail(JournalPointerTransitionErrorCode.INPUT_INVALID)
    try:
        operation = getattr(protection, "unprotect")
        if not callable(operation):
            raise TypeError("Pointer-transition authentication is unavailable.")
        plaintext = operation(
            sealed.protected_blob,
            ProtectedDataPurpose.POINTER_TRANSITION,
        )
    except Exception:
        _fail(JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED)
    if type(plaintext) is not bytes:
        _fail(JournalPointerTransitionErrorCode.AUTHENTICATION_FAILED)
    generation = _generation_from_bytes(plaintext)
    return _AuthenticatedJournalPointerTransitionGeneration(
        generation,
        sealed.generation_sha256,
    )


def _record_intent(record: JournalPointerTransitionRecord) -> tuple[object, ...]:
    return (
        record.package_root_identity,
        record.pointer_name,
        record.pointer_temp_name,
        record.intended_pointer_sha256,
        record.intended_pointer_size,
        record.target_tip_sequence,
        record.target_generation_sha256,
        record.prior_pointer_present,
        record.prior_pointer_identity,
        record.prior_pointer_sequence,
        record.prior_pointer_generation_sha256,
        record.prior_pointer_sha256,
        record.prior_pointer_size,
    )


def _authenticate_environment_tip(
    sealed_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    *,
    expected_stream: JournalStreamIdentity,
    protection: PointerTransitionProtectionPort,
) -> EnvironmentJournalChainSelection:
    try:
        return select_environment_journal_chain(
            sealed_generations,
            None,
            expected_stream=expected_stream,
            protection=protection,
        )
    except RecoveryJournalError:
        _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)


def _validate_environment_binding(
    record: JournalPointerTransitionRecord,
    stream: JournalPointerTransitionStreamIdentity,
    environment_selection: Any,
) -> None:
    if (
        record.target_tip_sequence != environment_selection.tip.sequence
        or record.target_generation_sha256
        != environment_selection.tip_generation_sha256
    ):
        _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)
    if record.prior_pointer_present:
        prior_is_in_chain = any(
            generation.sequence == record.prior_pointer_sequence
            and digest == record.prior_pointer_generation_sha256
            for generation, digest in zip(
                environment_selection.generations,
                environment_selection.generation_sha256s,
                strict=True,
            )
        )
        if not prior_is_in_chain:
            _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)
    if (
        stream.environment_journal_id != environment_selection.tip.stream.journal_id
        or stream.package_root_identity
        != environment_selection.tip.stream.package_root_identity
    ):
        _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)


def validate_journal_pointer_transition_plan_context(
    record: JournalPointerTransitionPlanRecord,
    *,
    transition_stream: JournalPointerTransitionStreamIdentity,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    environment_pointer: EnvironmentJournalPointer | None,
    expected_environment_stream: JournalStreamIdentity,
    prior_pointer_observation: JournalPointerPathObservation,
    protection: PointerTransitionProtectionPort,
) -> None:
    """Validate one pre-write plan against the authenticated current pointer."""

    if (
        type(record) is not JournalPointerTransitionPlanRecord
        or type(transition_stream) is not JournalPointerTransitionStreamIdentity
        or type(prior_pointer_observation) is not JournalPointerPathObservation
    ):
        _fail(JournalPointerTransitionErrorCode.INPUT_INVALID)
    try:
        _validate_record_against_stream(record, transition_stream)
        environment_selection = select_environment_journal_chain(
            environment_generations,
            environment_pointer,
            expected_stream=expected_environment_stream,
            protection=protection,
        )
    except (RecoveryJournalError, ValueError):
        _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)
    _validate_environment_binding(record, transition_stream, environment_selection)
    disposition = environment_selection.pointer_disposition
    if disposition is JournalPointerDisposition.CURRENT:
        _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)
    if disposition is JournalPointerDisposition.MISSING_REPAIR:
        if record.prior_pointer_present or prior_pointer_observation.present:
            _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)
        return
    if (
        environment_pointer is None
        or not record.prior_pointer_present
        or environment_pointer.sequence != record.prior_pointer_sequence
        or environment_pointer.generation_sha256
        != record.prior_pointer_generation_sha256
        or not _observation_matches(
            prior_pointer_observation,
            record.prior_pointer_identity,
            record.prior_pointer_sha256,
            record.prior_pointer_size,
        )
    ):
        _fail(JournalPointerTransitionErrorCode.CONTEXT_INVALID)


def select_journal_pointer_transition_chain(
    sealed_generations: tuple[SealedJournalPointerTransitionGeneration, ...],
    *,
    expected_stream: JournalPointerTransitionStreamIdentity,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
    protection: PointerTransitionProtectionPort,
) -> JournalPointerTransitionChainSelection:
    """Authenticate one exact transition chain and its environment-journal tip."""

    if (
        type(sealed_generations) is not tuple
        or not sealed_generations
        or type(expected_stream) is not JournalPointerTransitionStreamIdentity
        or type(environment_generations) is not tuple
        or type(expected_environment_stream) is not JournalStreamIdentity
        or any(
            type(item) is not SealedJournalPointerTransitionGeneration
            for item in sealed_generations
        )
    ):
        _fail(JournalPointerTransitionErrorCode.INPUT_INVALID)
    if len(sealed_generations) > 2:
        _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)
    environment_selection = _authenticate_environment_tip(
        environment_generations,
        expected_stream=expected_environment_stream,
        protection=protection,
    )
    authenticated = tuple(
        _authenticate_generation(item, protection=protection)
        for item in sealed_generations
    )
    if any(item.generation.stream != expected_stream for item in authenticated):
        _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)
    digests = tuple(item.generation_sha256 for item in authenticated)
    if len(set(digests)) != len(digests):
        _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)
    ordered = tuple(sorted(authenticated, key=lambda item: item.generation.sequence))
    ordered_digests = tuple(item.generation_sha256 for item in ordered)
    expected_states = (
        JournalPointerTransitionState.POINTER_TEMP_PLANNED,
        JournalPointerTransitionState.POINTER_TEMP_CREATED,
    )
    if (
        tuple(item.generation.sequence for item in ordered)
        != tuple(range(1, len(ordered) + 1))
        or tuple(item.generation.state for item in ordered)
        != expected_states[: len(ordered)]
        or ordered[0].generation.previous_generation_sha256
        != GENESIS_POINTER_TRANSITION_SHA256
    ):
        _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)
    plan = ordered[0].generation.record
    if type(plan) is not JournalPointerTransitionPlanRecord:
        _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)
    if len(ordered) == 2:
        created = ordered[1].generation.record
        if (
            type(created) is not JournalPointerTransitionCreatedRecord
            or ordered[1].generation.previous_generation_sha256 != ordered_digests[0]
            or created.planned_generation_sha256 != ordered_digests[0]
            or _record_intent(created) != _record_intent(plan)
        ):
            _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)
    _validate_environment_binding(plan, expected_stream, environment_selection)
    tip = ordered[-1]
    try:
        return JournalPointerTransitionChainSelection(
            tuple(item.generation for item in ordered),
            ordered_digests,
            tip.generation,
            tip.generation_sha256,
        )
    except ValueError:
        _fail(JournalPointerTransitionErrorCode.CHAIN_INVALID)


def _observation_matches(
    observation: JournalPointerPathObservation,
    identity: StableFileIdentity | None,
    sha256: str | None,
    size: int | None,
) -> bool:
    return (
        observation.present
        and observation.identity == identity
        and observation.sha256 == sha256
        and observation.size == size
    )


def classify_journal_pointer_transition_restart(
    sealed_generations: tuple[SealedJournalPointerTransitionGeneration, ...],
    *,
    expected_stream: JournalPointerTransitionStreamIdentity,
    environment_generations: tuple[SealedEnvironmentJournalGeneration, ...],
    expected_environment_stream: JournalStreamIdentity,
    protection: PointerTransitionProtectionPort,
    source_temp_observation: JournalPointerPathObservation,
    destination_pointer_observation: JournalPointerPathObservation,
) -> JournalPointerRestartDisposition:
    """Authenticate and classify post-crash evidence without authorizing action."""

    if (
        type(source_temp_observation) is not JournalPointerPathObservation
        or type(destination_pointer_observation) is not JournalPointerPathObservation
    ):
        _fail(JournalPointerTransitionErrorCode.INPUT_INVALID)
    selection = select_journal_pointer_transition_chain(
        sealed_generations,
        expected_stream=expected_stream,
        environment_generations=environment_generations,
        expected_environment_stream=expected_environment_stream,
        protection=protection,
    )
    record = selection.tip.record
    if type(record) is not JournalPointerTransitionCreatedRecord:
        return JournalPointerRestartDisposition.AMBIGUOUS
    source_matches = _observation_matches(
        source_temp_observation,
        record.pointer_temp_identity,
        record.intended_pointer_sha256,
        record.intended_pointer_size,
    )
    prior_destination_matches = (
        not destination_pointer_observation.present
        if not record.prior_pointer_present
        else _observation_matches(
            destination_pointer_observation,
            record.prior_pointer_identity,
            record.prior_pointer_sha256,
            record.prior_pointer_size,
        )
    )
    if source_matches and prior_destination_matches:
        return JournalPointerRestartDisposition.SOURCE_TEMP_REMAINS
    destination_matches_source = _observation_matches(
        destination_pointer_observation,
        record.pointer_temp_identity,
        record.intended_pointer_sha256,
        record.intended_pointer_size,
    )
    if not source_temp_observation.present and destination_matches_source:
        return JournalPointerRestartDisposition.MOVE_COMPLETED
    return JournalPointerRestartDisposition.AMBIGUOUS


__all__ = [
    "GENESIS_POINTER_TRANSITION_SHA256",
    "JournalPointerPathObservation",
    "JournalPointerRestartDisposition",
    "JournalPointerTransitionChainSelection",
    "JournalPointerTransitionCreatedRecord",
    "JournalPointerTransitionError",
    "JournalPointerTransitionErrorCode",
    "JournalPointerTransitionGeneration",
    "JournalPointerTransitionPlanRecord",
    "JournalPointerTransitionState",
    "JournalPointerTransitionStreamIdentity",
    "PointerTransitionProtectionPort",
    "SealedJournalPointerTransitionGeneration",
    "classify_journal_pointer_transition_restart",
    "protect_journal_pointer_transition_generation",
    "select_journal_pointer_transition_chain",
    "validate_journal_pointer_transition_plan_context",
]
