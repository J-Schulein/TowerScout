"""Retry-safe cleanup of exact forward certificate candidate temp files."""

from __future__ import annotations

from enum import Enum
from typing import NoReturn, Protocol

from .windows_certificate_replacement import (
    CertificateReplacementPlan,
    certificate_replacement_evidence_sha256,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    RecoveryJournalStorageError,
)
from .windows_repair_transaction_journal import (
    RepairTransactionChainSelection,
    RepairTransactionPointerDisposition,
    RepairTransactionProtectionPort,
    RepairTransactionState,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
    ensure_persisted_repair_transaction_pointer_from_held_root,
)


class RepairCertificateCleanupErrorCode(str, Enum):
    INPUT_INVALID = "repair_certificate_cleanup_input_invalid"
    JOURNAL_INVALID = "repair_certificate_cleanup_journal_invalid"
    CLEANUP_FAILED = "repair_certificate_cleanup_failed"


class RepairCertificateCleanupError(RuntimeError):
    _MESSAGES = {
        RepairCertificateCleanupErrorCode.INPUT_INVALID: (
            "The repair certificate cleanup request is invalid."
        ),
        RepairCertificateCleanupErrorCode.JOURNAL_INVALID: (
            "The repair certificate cleanup journal is invalid."
        ),
        RepairCertificateCleanupErrorCode.CLEANUP_FAILED: (
            "The repair certificate temporary files could not be cleaned safely."
        ),
    }

    def __init__(self, code: RepairCertificateCleanupErrorCode) -> None:
        if type(code) is not RepairCertificateCleanupErrorCode:
            raise ValueError("Unknown repair certificate cleanup error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RepairCertificateCleanupError(code={self.code.value!r})"


class RepairCertificateCleanupStoragePort(Protocol):
    def delete_applied_repair_certificate_temps(
        self,
        root_path: str,
        forward: RepairTransactionChainSelection,
        plan: CertificateReplacementPlan,
    ) -> None: ...


def _fail(code: RepairCertificateCleanupErrorCode) -> NoReturn:
    raise RepairCertificateCleanupError(code) from None


def cleanup_applied_repair_certificate_candidates(
    forward: PersistedRepairTransactionChain,
    plan: CertificateReplacementPlan,
    *,
    root: JournalStorageRootPort,
    certificate_storage: RepairCertificateCleanupStoragePort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    """Delete only exact recorded candidate identities; exact absence is success."""

    if (
        type(forward) is not PersistedRepairTransactionChain
        or type(plan) is not CertificateReplacementPlan
        or len(forward.selection.generations) != 4
        or forward.selection.tip.state
        is not RepairTransactionState.CERTIFICATES_APPLIED
        or forward.selection.pointer_disposition
        is not RepairTransactionPointerDisposition.CURRENT
        or forward.selection.generations[0].record.evidence_sha256
        != certificate_replacement_evidence_sha256(plan)
    ):
        _fail(RepairCertificateCleanupErrorCode.INPUT_INVALID)
    stream = forward.selection.tip.stream

    def run(root_path: str) -> PersistedRepairTransactionChain:
        try:
            current = ensure_persisted_repair_transaction_pointer_from_held_root(
                root_path,
                stream,
                generation_storage=generation_storage,
                pointer_storage=pointer_storage,
                protection=protection,
            )
        except RecoveryJournalStorageError:
            _fail(RepairCertificateCleanupErrorCode.JOURNAL_INVALID)
        if (
            current is None
            or current.selection.generation_sha256s
            != forward.selection.generation_sha256s
            or current.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
        ):
            _fail(RepairCertificateCleanupErrorCode.JOURNAL_INVALID)
        try:
            certificate_storage.delete_applied_repair_certificate_temps(
                root_path,
                current.selection,
                plan,
            )
        except RepairCertificateCleanupError:
            raise
        except Exception:
            _fail(RepairCertificateCleanupErrorCode.CLEANUP_FAILED)
        return current

    try:
        result = root.run_journal_storage(run)
    except RepairCertificateCleanupError:
        raise
    except Exception:
        _fail(RepairCertificateCleanupErrorCode.CLEANUP_FAILED)
    if type(result) is not PersistedRepairTransactionChain:
        _fail(RepairCertificateCleanupErrorCode.CLEANUP_FAILED)
    return result


__all__ = [
    "RepairCertificateCleanupError",
    "RepairCertificateCleanupErrorCode",
    "RepairCertificateCleanupStoragePort",
    "cleanup_applied_repair_certificate_candidates",
]
