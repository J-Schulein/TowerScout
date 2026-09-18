"""Durable forward staging for exact certificate repair candidates.

The rollback journal must already be armed before this boundary is called.  The
forward journal records both unpredictable protected-root names before file
creation, both stable zero-byte identities before content writes, and both
verified identities after exact flushed/reopened verification.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from enum import Enum
from typing import NoReturn, Protocol, TypeVar, cast

from .windows_certificate_replacement import (
    CertificateReplacementPlan,
    certificate_replacement_evidence_sha256,
)
from .windows_recovery_certificate_storage import CertificateRestoreTempIdentities
from .windows_recovery_journal import EnvironmentJournalState, JournalPointerDisposition
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    RecoveryJournalStorageError,
)
from .windows_repair_transaction_journal import (
    RepairTransactionChainSelection,
    RepairTransactionGeneration,
    RepairTransactionJournalError,
    RepairTransactionState,
    RepairTransactionStreamIdentity,
    RepairTransactionProtectionPort,
    RepairTransitionRecord,
    protect_repair_transaction_generation,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
    append_persisted_repair_transaction_generation_from_held_root,
    ensure_persisted_repair_transaction_pointer_from_held_root,
    load_persisted_repair_transaction_chain_from_held_root,
)
from .windows_security import StableFileIdentity

_Result = TypeVar("_Result")
_TEMP_NAME = re.compile(r"^repair-certificate-[0-9a-f]{32}\.tmp$")


class RepairCertificateStagingErrorCode(str, Enum):
    INPUT_INVALID = "repair_certificate_staging_input_invalid"
    NAME_GENERATION_FAILED = "repair_certificate_staging_name_generation_failed"
    JOURNAL_INVALID = "repair_certificate_staging_journal_invalid"
    STORAGE_FAILED = "repair_certificate_staging_storage_failed"
    VERIFY_FAILED = "repair_certificate_staging_verify_failed"


class RepairCertificateStagingError(RuntimeError):
    _MESSAGES = {
        RepairCertificateStagingErrorCode.INPUT_INVALID: (
            "The repair certificate staging request is invalid."
        ),
        RepairCertificateStagingErrorCode.NAME_GENERATION_FAILED: (
            "Repair certificate temporary names could not be generated."
        ),
        RepairCertificateStagingErrorCode.JOURNAL_INVALID: (
            "The repair certificate staging journal is invalid."
        ),
        RepairCertificateStagingErrorCode.STORAGE_FAILED: (
            "Repair certificate temporary storage is unavailable."
        ),
        RepairCertificateStagingErrorCode.VERIFY_FAILED: (
            "Repair certificate staging could not be verified durably."
        ),
    }

    def __init__(self, code: RepairCertificateStagingErrorCode) -> None:
        if type(code) is not RepairCertificateStagingErrorCode:
            raise ValueError("Unknown repair certificate staging error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RepairCertificateStagingError(code={self.code.value!r})"


def _fail(code: RepairCertificateStagingErrorCode) -> NoReturn:
    raise RepairCertificateStagingError(code) from None


class RepairCertificateTempNameSource(Protocol):
    def new_certificate_temp_name(self) -> str: ...


class NativeRepairCertificateTempNameSource:
    def new_certificate_temp_name(self) -> str:
        return f"repair-certificate-{secrets.token_hex(16)}.tmp"


class RepairCertificateTempStoragePort(Protocol):
    def create_repair_certificate_temps(
        self,
        root_path: str,
        forward: RepairTransactionChainSelection,
    ) -> CertificateRestoreTempIdentities: ...

    def verify_created_repair_certificate_temps(
        self,
        root_path: str,
        forward: RepairTransactionChainSelection,
    ) -> CertificateRestoreTempIdentities: ...

    def write_and_verify_repair_certificate_temps(
        self,
        root_path: str,
        forward: RepairTransactionChainSelection,
        plan: CertificateReplacementPlan,
    ) -> CertificateRestoreTempIdentities: ...

    def verify_written_repair_certificate_temps(
        self,
        root_path: str,
        forward: RepairTransactionChainSelection,
        plan: CertificateReplacementPlan,
    ) -> CertificateRestoreTempIdentities: ...


def _call(operation: object, code: RepairCertificateStagingErrorCode) -> object:
    try:
        if not callable(operation):
            raise TypeError("Repair certificate staging operation is unavailable.")
        return operation()
    except RepairCertificateStagingError:
        raise
    except Exception:
        _fail(code)


def _names(name_source: RepairCertificateTempNameSource) -> tuple[str, str]:
    first = _call(
        getattr(name_source, "new_certificate_temp_name", None),
        RepairCertificateStagingErrorCode.NAME_GENERATION_FAILED,
    )
    second = _call(
        getattr(name_source, "new_certificate_temp_name", None),
        RepairCertificateStagingErrorCode.NAME_GENERATION_FAILED,
    )
    if (
        type(first) is not str
        or type(second) is not str
        or _TEMP_NAME.fullmatch(first) is None
        or _TEMP_NAME.fullmatch(second) is None
        or first == second
    ):
        _fail(RepairCertificateStagingErrorCode.NAME_GENERATION_FAILED)
    return (first, second)


def _identity_evidence_sha256(
    identities: tuple[StableFileIdentity, StableFileIdentity],
) -> str:
    digest = hashlib.sha256(b"TowerScout.RepairCertificateTempIdentities.v1")
    for identity in identities:
        digest.update(identity.volume_serial.to_bytes(8, "big", signed=False))
        digest.update(identity.file_id)
    return digest.hexdigest()


def _exact_identities(
    value: object,
) -> tuple[StableFileIdentity, StableFileIdentity]:
    if type(value) is not CertificateRestoreTempIdentities:
        _fail(RepairCertificateStagingErrorCode.VERIFY_FAILED)
    identities = cast(CertificateRestoreTempIdentities, value)
    if identities.local_ca is None or identities.ca_bundle is None:
        _fail(RepairCertificateStagingErrorCode.VERIFY_FAILED)
    return (identities.local_ca, identities.ca_bundle)


def _append(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    state: RepairTransactionState,
    record: RepairTransitionRecord,
    *,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    current = load_persisted_repair_transaction_chain_from_held_root(
        root_path,
        stream,
        storage=generation_storage,
        protection=protection,
    )
    sequence = 1 if current is None else current.selection.tip.sequence + 1
    previous = (
        stream.rollback_armed_generation_sha256
        if current is None
        else current.selection.tip_generation_sha256
    )
    try:
        generation = RepairTransactionGeneration(
            1,
            stream,
            sequence,
            previous,
            state,
            record,
        )
        sealed = protect_repair_transaction_generation(
            generation,
            protection=protection,
        )
        append_persisted_repair_transaction_generation_from_held_root(
            root_path,
            sealed,
            stream=stream,
            storage=generation_storage,
            protection=protection,
        )
        persisted = ensure_persisted_repair_transaction_pointer_from_held_root(
            root_path,
            stream,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    except (RepairTransactionJournalError, RecoveryJournalStorageError, ValueError):
        _fail(RepairCertificateStagingErrorCode.JOURNAL_INVALID)
    if persisted is None or persisted.selection.tip != generation:
        _fail(RepairCertificateStagingErrorCode.VERIFY_FAILED)
    return persisted


def _stage_from_held_root(
    root_path: str,
    stream: RepairTransactionStreamIdentity,
    plan: CertificateReplacementPlan,
    *,
    name_source: RepairCertificateTempNameSource,
    certificate_storage: RepairCertificateTempStoragePort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    try:
        current = load_persisted_repair_transaction_chain_from_held_root(
            root_path,
            stream,
            storage=generation_storage,
            protection=protection,
        )
    except RecoveryJournalStorageError:
        _fail(RepairCertificateStagingErrorCode.JOURNAL_INVALID)
    evidence = certificate_replacement_evidence_sha256(plan)
    if current is None:
        selected_names = _names(name_source)
        record = RepairTransitionRecord(
            1,
            stream.rollback_armed_generation_sha256,
            stream.package_root_identity,
            evidence,
            certificate_temp_names=selected_names,
        )
        current = _append(
            root_path,
            stream,
            RepairTransactionState.CERTIFICATE_TEMP_PLANNED,
            record,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    if (
        current.selection.generations[0].record.evidence_sha256 != evidence
        or current.selection.tip.sequence > 3
    ):
        _fail(RepairCertificateStagingErrorCode.JOURNAL_INVALID)
    if current.selection.tip.state is RepairTransactionState.CERTIFICATE_TEMP_PLANNED:
        created_value = _call(
            lambda: certificate_storage.create_repair_certificate_temps(
                root_path,
                current.selection,
            ),
            RepairCertificateStagingErrorCode.STORAGE_FAILED,
        )
        identities = _exact_identities(created_value)
        current = _append(
            root_path,
            stream,
            RepairTransactionState.CERTIFICATE_TEMP_CREATED,
            RepairTransitionRecord(
                1,
                current.selection.tip_generation_sha256,
                stream.package_root_identity,
                _identity_evidence_sha256(identities),
                certificate_temp_identities=identities,
            ),
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    if current.selection.tip.state is RepairTransactionState.CERTIFICATE_TEMP_CREATED:
        written = _exact_identities(
            _call(
                lambda: certificate_storage.write_and_verify_repair_certificate_temps(
                    root_path,
                    current.selection,
                    plan,
                ),
                RepairCertificateStagingErrorCode.STORAGE_FAILED,
            )
        )
        current = _append(
            root_path,
            stream,
            RepairTransactionState.CERTIFICATE_TEMP_VERIFIED,
            RepairTransitionRecord(
                1,
                current.selection.tip_generation_sha256,
                stream.package_root_identity,
                _identity_evidence_sha256(written),
                certificate_temp_identities=written,
            ),
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    if (
        current.selection.tip.state
        is not RepairTransactionState.CERTIFICATE_TEMP_VERIFIED
    ):
        _fail(RepairCertificateStagingErrorCode.JOURNAL_INVALID)
    verified = _exact_identities(
        _call(
            lambda: certificate_storage.verify_written_repair_certificate_temps(
                root_path,
                current.selection,
                plan,
            ),
            RepairCertificateStagingErrorCode.VERIFY_FAILED,
        )
    )
    if verified != current.selection.tip.record.certificate_temp_identities:
        _fail(RepairCertificateStagingErrorCode.VERIFY_FAILED)
    try:
        durable = ensure_persisted_repair_transaction_pointer_from_held_root(
            root_path,
            stream,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    except RecoveryJournalStorageError:
        _fail(RepairCertificateStagingErrorCode.JOURNAL_INVALID)
    if (
        durable is None
        or durable.selection.generation_sha256s != current.selection.generation_sha256s
        or durable.selection.tip != current.selection.tip
    ):
        _fail(RepairCertificateStagingErrorCode.VERIFY_FAILED)
    return durable


def stage_repair_certificate_candidates(
    stream: RepairTransactionStreamIdentity,
    rollback: PersistedEnvironmentJournalChain,
    plan: CertificateReplacementPlan,
    *,
    root: JournalStorageRootPort,
    name_source: RepairCertificateTempNameSource,
    certificate_storage: RepairCertificateTempStoragePort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    if (
        type(stream) is not RepairTransactionStreamIdentity
        or type(rollback) is not PersistedEnvironmentJournalChain
        or type(plan) is not CertificateReplacementPlan
        or len(rollback.selection.generations) != 3
        or rollback.selection.tip.state is not EnvironmentJournalState.ROLLBACK_ARMED
        or rollback.selection.pointer_disposition
        is not JournalPointerDisposition.CURRENT
        or stream.rollback_journal_id != rollback.selection.tip.stream.journal_id
        or stream.rollback_armed_generation_sha256
        != rollback.selection.tip_generation_sha256
        or stream.target_token_sha256
        != rollback.selection.tip.stream.target_token_sha256
        or stream.package_root_identity
        != rollback.selection.tip.stream.package_root_identity
    ):
        _fail(RepairCertificateStagingErrorCode.INPUT_INVALID)
    try:
        run = getattr(root, "run_journal_storage")
        if not callable(run):
            raise TypeError("Protected repair storage root is unavailable.")
        result = run(
            lambda root_path: _stage_from_held_root(
                root_path,
                stream,
                plan,
                name_source=name_source,
                certificate_storage=certificate_storage,
                generation_storage=generation_storage,
                pointer_storage=pointer_storage,
                protection=protection,
            )
        )
    except RepairCertificateStagingError:
        raise
    except Exception:
        _fail(RepairCertificateStagingErrorCode.STORAGE_FAILED)
    if type(result) is not PersistedRepairTransactionChain:
        _fail(RepairCertificateStagingErrorCode.VERIFY_FAILED)
    return result


__all__ = [
    "NativeRepairCertificateTempNameSource",
    "RepairCertificateStagingError",
    "RepairCertificateStagingErrorCode",
    "RepairCertificateTempNameSource",
    "RepairCertificateTempStoragePort",
    "stage_repair_certificate_candidates",
]
