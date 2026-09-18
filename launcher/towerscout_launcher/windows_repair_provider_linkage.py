"""Durably mirror authenticated provider mini-journal progress forward."""

from __future__ import annotations

from enum import Enum
import hashlib
import struct
from typing import Any, NoReturn

from .windows_recovery_journal import (
    EnvironmentJournalState,
    JournalPointerDisposition,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    RecoveryJournalStorageError,
)
from .windows_repair_transaction_journal import (
    AuthenticatedProviderLink,
    RepairTransactionGeneration,
    RepairTransactionJournalError,
    RepairTransactionPointerDisposition,
    RepairTransactionProtectionPort,
    RepairTransactionState,
    RepairTransitionRecord,
    authenticate_provider_link,
    protect_repair_transaction_generation,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
    append_persisted_repair_transaction_generation_from_held_root,
    ensure_persisted_repair_transaction_pointer_from_held_root,
    load_persisted_repair_transaction_chain_from_held_root,
)

_EVIDENCE_DOMAIN = b"TowerScout.RepairProviderForwardLink.v1"
_PROVIDER_STATES = (
    EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
    EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
    EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
    EnvironmentJournalState.ENVIRONMENT_APPLIED,
)
_FORWARD_STATES = (
    RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
    RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
    RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
    RepairTransactionState.ENVIRONMENT_APPLIED,
)


class RepairProviderLinkageErrorCode(str, Enum):
    INPUT_INVALID = "repair_provider_linkage_input_invalid"
    JOURNAL_INVALID = "repair_provider_linkage_journal_invalid"
    WRITE_FAILED = "repair_provider_linkage_write_failed"
    VERIFY_FAILED = "repair_provider_linkage_verify_failed"


class RepairProviderLinkageError(RuntimeError):
    _MESSAGES = {
        RepairProviderLinkageErrorCode.INPUT_INVALID: (
            "The repair provider linkage request is invalid."
        ),
        RepairProviderLinkageErrorCode.JOURNAL_INVALID: (
            "The repair provider linkage authority is invalid."
        ),
        RepairProviderLinkageErrorCode.WRITE_FAILED: (
            "The repair provider linkage could not be written durably."
        ),
        RepairProviderLinkageErrorCode.VERIFY_FAILED: (
            "The repair provider linkage could not be verified durably."
        ),
    }

    def __init__(self, code: RepairProviderLinkageErrorCode) -> None:
        if type(code) is not RepairProviderLinkageErrorCode:
            raise ValueError("Unknown repair provider linkage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RepairProviderLinkageError(code={self.code.value!r})"


def _fail(code: RepairProviderLinkageErrorCode) -> NoReturn:
    raise RepairProviderLinkageError(code) from None


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _evidence(
    provider_id: str,
    sequence: int,
    generation_sha256: str,
) -> str:
    digest = hashlib.sha256()
    for value in (
        _EVIDENCE_DOMAIN,
        provider_id.encode("ascii"),
        str(sequence).encode("ascii"),
        generation_sha256.encode("ascii"),
    ):
        _add(digest, value)
    return digest.hexdigest()


def _validate_inputs(
    forward: PersistedRepairTransactionChain,
    provider: PersistedEnvironmentJournalChain,
) -> None:
    if (
        type(forward) is not PersistedRepairTransactionChain
        or type(provider) is not PersistedEnvironmentJournalChain
        or forward.selection.pointer_disposition
        is not RepairTransactionPointerDisposition.CURRENT
        or provider.selection.pointer_disposition
        is not JournalPointerDisposition.CURRENT
        or not 1 <= len(provider.selection.generations) <= 4
        or tuple(item.state for item in provider.selection.generations)
        != _PROVIDER_STATES[: len(provider.selection.generations)]
        or forward.selection.tip.stream.target_token_sha256
        != provider.selection.tip.stream.target_token_sha256
        or forward.selection.tip.stream.package_root_identity
        != provider.selection.tip.stream.package_root_identity
        or provider.selection.tip.stream.journal_id
        in {
            forward.selection.tip.stream.journal_id,
            forward.selection.tip.stream.rollback_journal_id,
        }
    ):
        _fail(RepairProviderLinkageErrorCode.INPUT_INVALID)
    generations = forward.selection.generations
    if (
        not 4 <= len(generations) <= 8
        or generations[3].state is not RepairTransactionState.CERTIFICATES_APPLIED
        or tuple(item.state for item in generations[4:])
        != _FORWARD_STATES[: len(generations) - 4]
        or len(generations) - 4 > len(provider.selection.generations)
    ):
        _fail(RepairProviderLinkageErrorCode.INPUT_INVALID)
    provider_id = provider.selection.tip.stream.journal_id
    for index, generation in enumerate(generations[4:], start=1):
        if (
            generation.record.provider_journal_id != provider_id
            or generation.record.provider_sequence != index
            or generation.record.provider_generation_sha256
            != provider.selection.generation_sha256s[index - 1]
            or generation.record.evidence_sha256
            != _evidence(
                provider_id,
                index,
                provider.selection.generation_sha256s[index - 1],
            )
        ):
            _fail(RepairProviderLinkageErrorCode.INPUT_INVALID)


def persist_forward_provider_linkage(
    forward: PersistedRepairTransactionChain,
    provider: PersistedEnvironmentJournalChain,
    *,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    """Append exact provider links through its current authenticated tip."""

    _validate_inputs(forward, provider)
    stream = forward.selection.tip.stream

    def link(root_path: str) -> PersistedRepairTransactionChain:
        try:
            current = ensure_persisted_repair_transaction_pointer_from_held_root(
                root_path,
                stream,
                generation_storage=generation_storage,
                pointer_storage=pointer_storage,
                protection=protection,
            )
        except RecoveryJournalStorageError:
            _fail(RepairProviderLinkageErrorCode.JOURNAL_INVALID)
        if (
            current is None
            or current.selection.generation_sha256s
            != forward.selection.generation_sha256s
            or current.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
        ):
            _fail(RepairProviderLinkageErrorCode.JOURNAL_INVALID)
        provider_id = provider.selection.tip.stream.journal_id
        while len(current.selection.generations) - 4 < len(
            provider.selection.generations
        ):
            provider_sequence = len(current.selection.generations) - 3
            provider_sha256 = provider.selection.generation_sha256s[
                provider_sequence - 1
            ]
            previous = current.selection.tip_generation_sha256
            try:
                generation = RepairTransactionGeneration(
                    1,
                    stream,
                    len(current.selection.generations) + 1,
                    previous,
                    _FORWARD_STATES[provider_sequence - 1],
                    RepairTransitionRecord(
                        1,
                        previous,
                        stream.package_root_identity,
                        _evidence(provider_id, provider_sequence, provider_sha256),
                        provider_id,
                        provider_sequence,
                        provider_sha256,
                    ),
                )
                sealed = protect_repair_transaction_generation(
                    generation,
                    protection=protection,
                )
                current = append_persisted_repair_transaction_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=generation_storage,
                    protection=protection,
                )
                selected = ensure_persisted_repair_transaction_pointer_from_held_root(
                    root_path,
                    stream,
                    generation_storage=generation_storage,
                    pointer_storage=pointer_storage,
                    protection=protection,
                )
            except (
                RepairTransactionJournalError,
                RecoveryJournalStorageError,
                ValueError,
            ):
                _fail(RepairProviderLinkageErrorCode.WRITE_FAILED)
            if selected is None or selected.selection.tip != generation:
                _fail(RepairProviderLinkageErrorCode.VERIFY_FAILED)
            current = selected
        try:
            authenticated = authenticate_provider_link(current.selection, provider)
            reloaded = load_persisted_repair_transaction_chain_from_held_root(
                root_path,
                stream,
                storage=generation_storage,
                protection=protection,
            )
        except (RepairTransactionJournalError, RecoveryJournalStorageError):
            _fail(RepairProviderLinkageErrorCode.VERIFY_FAILED)
        expected = AuthenticatedProviderLink(
            1,
            provider_id,
            len(provider.selection.generations),
            provider.selection.tip_generation_sha256,
        )
        if (
            authenticated != expected
            or reloaded is None
            or reloaded.selection.generation_sha256s
            != current.selection.generation_sha256s
        ):
            _fail(RepairProviderLinkageErrorCode.VERIFY_FAILED)
        return current

    try:
        return root.run_journal_storage(link)
    except RepairProviderLinkageError:
        raise
    except Exception:
        _fail(RepairProviderLinkageErrorCode.WRITE_FAILED)


__all__ = [
    "RepairProviderLinkageError",
    "RepairProviderLinkageErrorCode",
    "persist_forward_provider_linkage",
]
