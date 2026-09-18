"""Authenticated forward transaction journal for the Windows repair path.

The rollback journal remains the authority for encrypted backups and recovery.
This purpose-separated chain begins only after that journal has durably reached
``rollback_armed``.  Every forward transition is immutable, hash-linked, and
bound to the same exact target/package identity.  Environment transitions also
bind the exact provider mini-journal generation, so a terminal provider state
is never inferred from ambient protected-state contents.

This module is a pure codec and validator.  It performs no file, certificate,
environment, runtime, pointer, or cleanup mutation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn, Protocol

from .windows_environment_replacement_native import EnvironmentAppliedRecord
from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_journal import EnvironmentJournalState
from .windows_recovery_journal_storage import PersistedEnvironmentJournalChain
from .windows_security import StableFileIdentity

_SCHEMA_VERSION = 1
_MAX_GENERATION_BYTES = 65_536
_MAX_POINTER_BYTES = 1_024
_MAX_JSON_DEPTH = 6
_MAX_JSON_ITEMS = 24
_MAX_JSON_NODES = 160
_MAX_JSON_STRING_CHARACTERS = 1_024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JOURNAL_ID = re.compile(r"^[0-9a-f]{32}$")
_CERTIFICATE_TEMP_NAME = re.compile(r"^repair-certificate-[0-9a-f]{32}\.tmp$")


class RepairTransactionJournalErrorCode(str, Enum):
    INPUT_INVALID = "repair_transaction_journal_input_invalid"
    GENERATION_INVALID = "repair_transaction_journal_generation_invalid"
    AUTHENTICATION_FAILED = "repair_transaction_journal_authentication_failed"
    POINTER_INVALID = "repair_transaction_journal_pointer_invalid"
    CHAIN_INVALID = "repair_transaction_journal_chain_invalid"


class RepairTransactionJournalError(RuntimeError):
    """Sanitized failure at the forward transaction-journal boundary."""

    _MESSAGES = {
        RepairTransactionJournalErrorCode.INPUT_INVALID: (
            "The repair transaction journal request is invalid."
        ),
        RepairTransactionJournalErrorCode.GENERATION_INVALID: (
            "A repair transaction journal generation is invalid."
        ),
        RepairTransactionJournalErrorCode.AUTHENTICATION_FAILED: (
            "A repair transaction journal generation could not be authenticated."
        ),
        RepairTransactionJournalErrorCode.POINTER_INVALID: (
            "The repair transaction journal pointer is invalid."
        ),
        RepairTransactionJournalErrorCode.CHAIN_INVALID: (
            "The repair transaction journal chain is invalid."
        ),
    }

    def __init__(self, code: RepairTransactionJournalErrorCode) -> None:
        if type(code) is not RepairTransactionJournalErrorCode:
            raise ValueError("Unknown repair transaction journal error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RepairTransactionJournalError(code={self.code.value!r})"


def _fail(code: RepairTransactionJournalErrorCode) -> NoReturn:
    raise RepairTransactionJournalError(code) from None


def _valid_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_journal_id(value: object) -> bool:
    return type(value) is str and _JOURNAL_ID.fullmatch(value) is not None


class RepairTransactionState(str, Enum):
    CERTIFICATE_TEMP_PLANNED = "certificate_temp_planned"
    CERTIFICATE_TEMP_CREATED = "certificate_temp_created"
    CERTIFICATE_TEMP_VERIFIED = "certificate_temp_verified"
    CERTIFICATES_APPLIED = "certificates_applied"
    ENVIRONMENT_TEMP_PLANNED = "environment_temp_planned"
    ENVIRONMENT_TEMP_CREATED = "environment_temp_created"
    ENVIRONMENT_TEMP_VERIFIED = "environment_temp_verified"
    ENVIRONMENT_APPLIED = "environment_applied"
    RUNTIME_STOPPING = "runtime_stopping"
    RUNTIME_STOPPED = "runtime_stopped"
    RUNTIME_STARTING = "runtime_starting"
    RUNTIME_STARTED = "runtime_started"
    SUCCESS_VERIFYING = "success_verifying"
    COMMITTED = "committed"
    RECOVERY_CLEANUP_PENDING = "recovery_cleanup_pending"
    CLEANED = "cleaned"


_FORWARD_STATES = (
    RepairTransactionState.CERTIFICATE_TEMP_PLANNED,
    RepairTransactionState.CERTIFICATE_TEMP_CREATED,
    RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
    RepairTransactionState.CERTIFICATES_APPLIED,
    RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
    RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
    RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
    RepairTransactionState.ENVIRONMENT_APPLIED,
    RepairTransactionState.RUNTIME_STOPPING,
    RepairTransactionState.RUNTIME_STOPPED,
    RepairTransactionState.RUNTIME_STARTING,
    RepairTransactionState.RUNTIME_STARTED,
    RepairTransactionState.SUCCESS_VERIFYING,
    RepairTransactionState.COMMITTED,
)
_ENVIRONMENT_PROVIDER_SEQUENCE = {
    RepairTransactionState.ENVIRONMENT_TEMP_PLANNED: 1,
    RepairTransactionState.ENVIRONMENT_TEMP_CREATED: 2,
    RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED: 3,
    RepairTransactionState.ENVIRONMENT_APPLIED: 4,
}


@dataclass(frozen=True, slots=True, repr=False)
class RepairTransactionStreamIdentity:
    schema_version: int
    journal_id: str = field(repr=False)
    rollback_journal_id: str = field(repr=False)
    rollback_armed_generation_sha256: str = field(repr=False)
    target_token_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_journal_id(self.journal_id)
            or not _valid_journal_id(self.rollback_journal_id)
            or self.journal_id == self.rollback_journal_id
            or not _valid_hash(self.rollback_armed_generation_sha256)
            or not _valid_hash(self.target_token_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
        ):
            raise ValueError("Repair transaction stream identity is invalid.")

    def __repr__(self) -> str:
        return "RepairTransactionStreamIdentity(schema_version=1, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RepairTransitionRecord:
    schema_version: int
    predecessor_generation_sha256: str = field(repr=False)
    package_root_identity: StableFileIdentity = field(repr=False)
    evidence_sha256: str = field(repr=False)
    provider_journal_id: str | None = field(default=None, repr=False)
    provider_sequence: int | None = None
    provider_generation_sha256: str | None = field(default=None, repr=False)
    certificate_temp_names: tuple[str, str] | None = field(default=None, repr=False)
    certificate_temp_identities: (
        tuple[StableFileIdentity, StableFileIdentity] | None
    ) = field(default=None, repr=False)

    def __post_init__(self) -> None:
        provider_values = (
            self.provider_journal_id,
            self.provider_sequence,
            self.provider_generation_sha256,
        )
        names = self.certificate_temp_names
        identities = self.certificate_temp_identities
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_hash(self.predecessor_generation_sha256)
            or type(self.package_root_identity) is not StableFileIdentity
            or not _valid_hash(self.evidence_sha256)
            or (
                any(value is not None for value in provider_values)
                and (
                    not _valid_journal_id(self.provider_journal_id)
                    or type(self.provider_sequence) is not int
                    or not 1 <= self.provider_sequence <= 4
                    or not _valid_hash(self.provider_generation_sha256)
                )
            )
            or (
                names is not None
                and (
                    type(names) is not tuple
                    or len(names) != 2
                    or any(
                        type(name) is not str
                        or _CERTIFICATE_TEMP_NAME.fullmatch(name) is None
                        for name in names
                    )
                    or names[0] == names[1]
                )
            )
            or (
                identities is not None
                and (
                    type(identities) is not tuple
                    or len(identities) != 2
                    or any(
                        type(identity) is not StableFileIdentity
                        for identity in identities
                    )
                    or identities[0] == identities[1]
                )
            )
        ):
            raise ValueError("Repair transition record is invalid.")

    def __repr__(self) -> str:
        return "RepairTransitionRecord(schema_version=1, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RepairTransactionGeneration:
    schema_version: int
    stream: RepairTransactionStreamIdentity = field(repr=False)
    sequence: int
    previous_generation_sha256: str = field(repr=False)
    state: RepairTransactionState
    record: RepairTransitionRecord = field(repr=False)

    def __post_init__(self) -> None:
        expected_provider_sequence = _ENVIRONMENT_PROVIDER_SEQUENCE.get(self.state)
        provider_values = (
            self.record.provider_journal_id,
            self.record.provider_sequence,
            self.record.provider_generation_sha256,
        )
        expects_certificate_names = (
            self.state is RepairTransactionState.CERTIFICATE_TEMP_PLANNED
        )
        expects_certificate_identities = self.state in {
            RepairTransactionState.CERTIFICATE_TEMP_CREATED,
            RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
        }
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.stream) is not RepairTransactionStreamIdentity
            or type(self.sequence) is not int
            or not 1 <= self.sequence <= 16
            or not _valid_hash(self.previous_generation_sha256)
            or type(self.state) is not RepairTransactionState
            or type(self.record) is not RepairTransitionRecord
            or self.record.package_root_identity != self.stream.package_root_identity
            or self.record.predecessor_generation_sha256
            != self.previous_generation_sha256
            or (
                expected_provider_sequence is None
                and any(value is not None for value in provider_values)
            )
            or (
                expected_provider_sequence is not None
                and (
                    self.record.provider_sequence != expected_provider_sequence
                    or self.record.provider_journal_id
                    in {self.stream.journal_id, self.stream.rollback_journal_id}
                )
            )
            or (self.record.certificate_temp_names is not None)
            is not expects_certificate_names
            or (self.record.certificate_temp_identities is not None)
            is not expects_certificate_identities
        ):
            raise ValueError("Repair transaction generation is invalid.")

    def __repr__(self) -> str:
        return (
            "RepairTransactionGeneration("
            f"sequence={self.sequence}, state={self.state.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SealedRepairTransactionGeneration:
    protected_blob: CurrentUserProtectedBlob = field(repr=False)
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.protected_blob) is not CurrentUserProtectedBlob
            or self.protected_blob.purpose
            is not ProtectedDataPurpose.JOURNAL_GENERATION
            or not _valid_hash(self.generation_sha256)
            or self.generation_sha256 != self.protected_blob.ciphertext_sha256
        ):
            raise ValueError("Sealed repair transaction generation is invalid.")

    def __repr__(self) -> str:
        return "SealedRepairTransactionGeneration(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RepairTransactionJournalPointer:
    schema_version: int
    journal_id: str = field(repr=False)
    sequence: int
    generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_journal_id(self.journal_id)
            or type(self.sequence) is not int
            or not 1 <= self.sequence <= 16
            or not _valid_hash(self.generation_sha256)
        ):
            raise ValueError("Repair transaction journal pointer is invalid.")

    def __repr__(self) -> str:
        return f"RepairTransactionJournalPointer(sequence={self.sequence}, <redacted>)"


class RepairTransactionPointerDisposition(str, Enum):
    CURRENT = "current"
    MISSING_REPAIR = "missing_repair"
    STALE_REPAIR = "stale_repair"


@dataclass(frozen=True, slots=True, repr=False)
class RepairTransactionChainSelection:
    generations: tuple[RepairTransactionGeneration, ...] = field(repr=False)
    generation_sha256s: tuple[str, ...] = field(repr=False)
    tip: RepairTransactionGeneration = field(repr=False)
    tip_generation_sha256: str = field(repr=False)
    pointer_disposition: RepairTransactionPointerDisposition

    def __post_init__(self) -> None:
        if (
            type(self.generations) is not tuple
            or not self.generations
            or any(
                type(item) is not RepairTransactionGeneration
                for item in self.generations
            )
            or type(self.generation_sha256s) is not tuple
            or len(self.generation_sha256s) != len(self.generations)
            or any(not _valid_hash(item) for item in self.generation_sha256s)
            or self.tip != self.generations[-1]
            or self.tip_generation_sha256 != self.generation_sha256s[-1]
            or type(self.pointer_disposition) is not RepairTransactionPointerDisposition
        ):
            raise ValueError("Repair transaction chain selection is invalid.")

    def __repr__(self) -> str:
        return (
            "RepairTransactionChainSelection("
            f"generations={len(self.generations)}, "
            f"pointer_disposition={self.pointer_disposition.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedTerminalProviderLink:
    schema_version: int
    provider_journal_id: str = field(repr=False)
    provider_generation_sha256: str = field(repr=False)
    provider_record: EnvironmentAppliedRecord = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_journal_id(self.provider_journal_id)
            or not _valid_hash(self.provider_generation_sha256)
            or type(self.provider_record) is not EnvironmentAppliedRecord
        ):
            raise ValueError("Authenticated terminal provider link is invalid.")

    def __repr__(self) -> str:
        return "AuthenticatedTerminalProviderLink(schema_version=1, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedProviderLink:
    schema_version: int
    provider_journal_id: str = field(repr=False)
    provider_sequence: int
    provider_generation_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or not _valid_journal_id(self.provider_journal_id)
            or type(self.provider_sequence) is not int
            or not 1 <= self.provider_sequence <= 4
            or not _valid_hash(self.provider_generation_sha256)
        ):
            raise ValueError("Authenticated provider link is invalid.")

    def __repr__(self) -> str:
        return (
            "AuthenticatedProviderLink("
            f"provider_sequence={self.provider_sequence}, <redacted>)"
        )


class RepairTransactionProtectionPort(Protocol):
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
    if value is None or type(value) in {bool, int, str}:
        if type(value) is str and (
            len(value) > _MAX_JSON_STRING_CHARACTERS or "\x00" in value
        ):
            raise ValueError("JSON string is invalid.")
        if type(value) is int and not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("JSON integer exceeded.")
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


def _load_json(
    raw: bytes,
    *,
    maximum: int,
    code: RepairTransactionJournalErrorCode,
) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
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
        _fail(code)


def _exact_keys(value: object, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise ValueError("JSON object shape is invalid.")
    return value


def _identity_to_json(identity: StableFileIdentity) -> dict[str, Any]:
    return {"file_id": identity.file_id.hex(), "volume_serial": identity.volume_serial}


def _identity_from_json(value: object) -> StableFileIdentity:
    item = _exact_keys(value, frozenset({"file_id", "volume_serial"}))
    if (
        type(item["file_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{32}", item["file_id"]) is None
        or type(item["volume_serial"]) is not int
    ):
        raise ValueError("File identity is invalid.")
    return StableFileIdentity(item["volume_serial"], bytes.fromhex(item["file_id"]))


def _certificate_names_from_json(value: object) -> tuple[str, str] | None:
    if value is None:
        return None
    if type(value) is not list or len(value) != 2:
        raise ValueError("Certificate temp names are invalid.")
    if any(type(name) is not str for name in value):
        raise ValueError("Certificate temp names are invalid.")
    return (value[0], value[1])


def _certificate_identities_from_json(
    value: object,
) -> tuple[StableFileIdentity, StableFileIdentity] | None:
    if value is None:
        return None
    if type(value) is not list or len(value) != 2:
        raise ValueError("Certificate temp identities are invalid.")
    return (_identity_from_json(value[0]), _identity_from_json(value[1]))


def _generation_to_bytes(generation: RepairTransactionGeneration) -> bytes:
    record = generation.record
    return _canonical_json(
        {
            "previous_generation_sha256": generation.previous_generation_sha256,
            "record": {
                "certificate_temp_identities": (
                    None
                    if record.certificate_temp_identities is None
                    else [
                        _identity_to_json(identity)
                        for identity in record.certificate_temp_identities
                    ]
                ),
                "certificate_temp_names": (
                    None
                    if record.certificate_temp_names is None
                    else list(record.certificate_temp_names)
                ),
                "evidence_sha256": record.evidence_sha256,
                "package_root_identity": _identity_to_json(
                    record.package_root_identity
                ),
                "predecessor_generation_sha256": (record.predecessor_generation_sha256),
                "provider_generation_sha256": record.provider_generation_sha256,
                "provider_journal_id": record.provider_journal_id,
                "provider_sequence": record.provider_sequence,
                "schema_version": record.schema_version,
            },
            "schema_version": generation.schema_version,
            "sequence": generation.sequence,
            "state": generation.state.value,
            "stream": {
                "journal_id": generation.stream.journal_id,
                "package_root_identity": _identity_to_json(
                    generation.stream.package_root_identity
                ),
                "rollback_armed_generation_sha256": (
                    generation.stream.rollback_armed_generation_sha256
                ),
                "rollback_journal_id": generation.stream.rollback_journal_id,
                "schema_version": generation.stream.schema_version,
                "target_token_sha256": generation.stream.target_token_sha256,
            },
        }
    )


def _generation_from_bytes(raw: bytes) -> RepairTransactionGeneration:
    try:
        item = _exact_keys(
            _load_json(
                raw,
                maximum=_MAX_GENERATION_BYTES,
                code=RepairTransactionJournalErrorCode.GENERATION_INVALID,
            ),
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
        stream_item = _exact_keys(
            item["stream"],
            frozenset(
                {
                    "journal_id",
                    "package_root_identity",
                    "rollback_armed_generation_sha256",
                    "rollback_journal_id",
                    "schema_version",
                    "target_token_sha256",
                }
            ),
        )
        record_item = _exact_keys(
            item["record"],
            frozenset(
                {
                    "certificate_temp_identities",
                    "certificate_temp_names",
                    "evidence_sha256",
                    "package_root_identity",
                    "predecessor_generation_sha256",
                    "provider_generation_sha256",
                    "provider_journal_id",
                    "provider_sequence",
                    "schema_version",
                }
            ),
        )
        stream = RepairTransactionStreamIdentity(
            stream_item["schema_version"],
            stream_item["journal_id"],
            stream_item["rollback_journal_id"],
            stream_item["rollback_armed_generation_sha256"],
            stream_item["target_token_sha256"],
            _identity_from_json(stream_item["package_root_identity"]),
        )
        record = RepairTransitionRecord(
            record_item["schema_version"],
            record_item["predecessor_generation_sha256"],
            _identity_from_json(record_item["package_root_identity"]),
            record_item["evidence_sha256"],
            record_item["provider_journal_id"],
            record_item["provider_sequence"],
            record_item["provider_generation_sha256"],
            _certificate_names_from_json(record_item["certificate_temp_names"]),
            _certificate_identities_from_json(
                record_item["certificate_temp_identities"]
            ),
        )
        return RepairTransactionGeneration(
            item["schema_version"],
            stream,
            item["sequence"],
            item["previous_generation_sha256"],
            RepairTransactionState(item["state"]),
            record,
        )
    except RepairTransactionJournalError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(RepairTransactionJournalErrorCode.GENERATION_INVALID)


def protect_repair_transaction_generation(
    generation: RepairTransactionGeneration,
    *,
    protection: RepairTransactionProtectionPort,
) -> SealedRepairTransactionGeneration:
    if type(generation) is not RepairTransactionGeneration:
        _fail(RepairTransactionJournalErrorCode.INPUT_INVALID)
    try:
        blob = protection.protect(
            _generation_to_bytes(generation),
            ProtectedDataPurpose.JOURNAL_GENERATION,
        )
        return SealedRepairTransactionGeneration(blob, blob.ciphertext_sha256)
    except RepairTransactionJournalError:
        raise
    except Exception:
        _fail(RepairTransactionJournalErrorCode.AUTHENTICATION_FAILED)


def authenticate_repair_transaction_generation(
    sealed: SealedRepairTransactionGeneration,
    *,
    protection: RepairTransactionProtectionPort,
) -> RepairTransactionGeneration:
    if type(sealed) is not SealedRepairTransactionGeneration:
        _fail(RepairTransactionJournalErrorCode.INPUT_INVALID)
    try:
        if sealed.generation_sha256 != sealed.protected_blob.ciphertext_sha256:
            _fail(RepairTransactionJournalErrorCode.AUTHENTICATION_FAILED)
        plaintext = protection.unprotect(
            sealed.protected_blob,
            ProtectedDataPurpose.JOURNAL_GENERATION,
        )
        return _generation_from_bytes(plaintext)
    except RepairTransactionJournalError:
        raise
    except Exception:
        _fail(RepairTransactionJournalErrorCode.AUTHENTICATION_FAILED)


def encode_repair_transaction_pointer(
    pointer: RepairTransactionJournalPointer,
) -> bytes:
    if type(pointer) is not RepairTransactionJournalPointer:
        _fail(RepairTransactionJournalErrorCode.INPUT_INVALID)
    return _canonical_json(
        {
            "generation_sha256": pointer.generation_sha256,
            "journal_id": pointer.journal_id,
            "schema_version": pointer.schema_version,
            "sequence": pointer.sequence,
        }
    )


def decode_repair_transaction_pointer(raw: bytes) -> RepairTransactionJournalPointer:
    try:
        item = _exact_keys(
            _load_json(
                raw,
                maximum=_MAX_POINTER_BYTES,
                code=RepairTransactionJournalErrorCode.POINTER_INVALID,
            ),
            frozenset(
                {"generation_sha256", "journal_id", "schema_version", "sequence"}
            ),
        )
        return RepairTransactionJournalPointer(
            item["schema_version"],
            item["journal_id"],
            item["sequence"],
            item["generation_sha256"],
        )
    except RepairTransactionJournalError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(RepairTransactionJournalErrorCode.POINTER_INVALID)


def _valid_state_sequence(states: tuple[RepairTransactionState, ...]) -> bool:
    if states == _FORWARD_STATES[: len(states)]:
        return True
    direct_cleanup = _FORWARD_STATES + (RepairTransactionState.CLEANED,)
    pending_cleanup = _FORWARD_STATES + (
        RepairTransactionState.RECOVERY_CLEANUP_PENDING,
        RepairTransactionState.CLEANED,
    )
    return states in {direct_cleanup, pending_cleanup}


def select_repair_transaction_chain(
    sealed_generations: tuple[SealedRepairTransactionGeneration, ...],
    pointer: RepairTransactionJournalPointer | None,
    *,
    expected_stream: RepairTransactionStreamIdentity,
    protection: RepairTransactionProtectionPort,
) -> RepairTransactionChainSelection:
    if (
        type(sealed_generations) is not tuple
        or not sealed_generations
        or len(sealed_generations) > 16
        or type(expected_stream) is not RepairTransactionStreamIdentity
        or (
            pointer is not None and type(pointer) is not RepairTransactionJournalPointer
        )
        or any(
            type(item) is not SealedRepairTransactionGeneration
            for item in sealed_generations
        )
    ):
        _fail(RepairTransactionJournalErrorCode.INPUT_INVALID)
    authenticated = tuple(
        (
            authenticate_repair_transaction_generation(item, protection=protection),
            item.generation_sha256,
        )
        for item in sealed_generations
    )
    if any(item[0].stream != expected_stream for item in authenticated):
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    ordered = tuple(sorted(authenticated, key=lambda item: item[0].sequence))
    digests = tuple(item[1] for item in ordered)
    if len(set(digests)) != len(digests):
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    states = tuple(item[0].state for item in ordered)
    if (
        tuple(item[0].sequence for item in ordered) != tuple(range(1, len(ordered) + 1))
        or not _valid_state_sequence(states)
        or ordered[0][0].previous_generation_sha256
        != expected_stream.rollback_armed_generation_sha256
    ):
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    provider_journal_id: str | None = None
    for index, (generation, _digest) in enumerate(ordered):
        expected_previous = (
            expected_stream.rollback_armed_generation_sha256
            if index == 0
            else ordered[index - 1][1]
        )
        if generation.previous_generation_sha256 != expected_previous:
            _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
        linked_provider = generation.record.provider_journal_id
        if linked_provider is not None:
            if provider_journal_id is None:
                provider_journal_id = linked_provider
            elif linked_provider != provider_journal_id:
                _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    if len(ordered) >= 3:
        created_identities = ordered[1][0].record.certificate_temp_identities
        verified_identities = ordered[2][0].record.certificate_temp_identities
        if created_identities != verified_identities:
            _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    tip, tip_digest = ordered[-1]
    if pointer is None:
        disposition = RepairTransactionPointerDisposition.MISSING_REPAIR
    else:
        if pointer.journal_id != expected_stream.journal_id:
            _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
        pointed = next(
            (
                item
                for item in ordered
                if item[0].sequence == pointer.sequence
                and item[1] == pointer.generation_sha256
            ),
            None,
        )
        if pointed is None:
            _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
        disposition = (
            RepairTransactionPointerDisposition.CURRENT
            if pointed == ordered[-1]
            else RepairTransactionPointerDisposition.STALE_REPAIR
        )
    try:
        return RepairTransactionChainSelection(
            tuple(item[0] for item in ordered),
            digests,
            tip,
            tip_digest,
            disposition,
        )
    except ValueError:
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)


def authenticate_provider_link(
    forward: RepairTransactionChainSelection,
    provider: PersistedEnvironmentJournalChain,
) -> AuthenticatedProviderLink:
    """Bind the latest forward environment state to its exact provider tip."""

    if (
        type(forward) is not RepairTransactionChainSelection
        or type(provider) is not PersistedEnvironmentJournalChain
    ):
        _fail(RepairTransactionJournalErrorCode.INPUT_INVALID)
    linked = next(
        (
            generation
            for generation in reversed(forward.generations)
            if generation.state in _ENVIRONMENT_PROVIDER_SEQUENCE
        ),
        None,
    )
    generations = provider.selection.generations
    expected_provider_states = (
        EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
        EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
        EnvironmentJournalState.ENVIRONMENT_APPLIED,
    )
    if (
        linked is None
        or linked.record.provider_sequence is None
        or len(generations) != linked.record.provider_sequence
        or tuple(generation.state for generation in generations)
        != expected_provider_states[: linked.record.provider_sequence]
        or linked.record.provider_journal_id != provider.selection.tip.stream.journal_id
        or linked.record.provider_generation_sha256
        != provider.selection.tip_generation_sha256
        or linked.stream.target_token_sha256
        != provider.selection.tip.stream.target_token_sha256
        or linked.stream.package_root_identity
        != provider.selection.tip.stream.package_root_identity
    ):
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    try:
        return AuthenticatedProviderLink(
            _SCHEMA_VERSION,
            provider.selection.tip.stream.journal_id,
            provider.selection.tip.sequence,
            provider.selection.tip_generation_sha256,
        )
    except ValueError:
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)


def authenticate_terminal_provider_link(
    forward: RepairTransactionChainSelection,
    provider: PersistedEnvironmentJournalChain,
) -> AuthenticatedTerminalProviderLink:
    """Bind one terminal provider mini-journal to its forward transition."""

    linked = authenticate_provider_link(forward, provider)
    if (
        linked.provider_sequence != 4
        or provider.selection.tip.state
        is not EnvironmentJournalState.ENVIRONMENT_APPLIED
        or type(provider.selection.tip.record) is not EnvironmentAppliedRecord
    ):
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)
    try:
        return AuthenticatedTerminalProviderLink(
            _SCHEMA_VERSION,
            linked.provider_journal_id,
            linked.provider_generation_sha256,
            provider.selection.tip.record,
        )
    except ValueError:
        _fail(RepairTransactionJournalErrorCode.CHAIN_INVALID)


__all__ = [
    "AuthenticatedProviderLink",
    "AuthenticatedTerminalProviderLink",
    "RepairTransactionChainSelection",
    "RepairTransactionGeneration",
    "RepairTransactionJournalError",
    "RepairTransactionJournalErrorCode",
    "RepairTransactionJournalPointer",
    "RepairTransactionPointerDisposition",
    "RepairTransactionProtectionPort",
    "RepairTransactionState",
    "RepairTransactionStreamIdentity",
    "RepairTransitionRecord",
    "SealedRepairTransactionGeneration",
    "authenticate_repair_transaction_generation",
    "authenticate_provider_link",
    "authenticate_terminal_provider_link",
    "decode_repair_transaction_pointer",
    "encode_repair_transaction_pointer",
    "protect_repair_transaction_generation",
    "select_repair_transaction_chain",
]
