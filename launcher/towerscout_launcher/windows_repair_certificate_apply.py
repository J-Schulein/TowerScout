"""Apply authenticated repair certificate candidates to one retained target."""

from __future__ import annotations

import hashlib
import struct
from enum import Enum
from pathlib import PureWindowsPath
from typing import NoReturn, Protocol, TypeVar

from .runtime_target_observation import (
    CertificateTargetDestination,
    ObservationOperation,
)
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_certificate_replacement import (
    CertificateReplacementPlan,
    certificate_replacement_evidence_sha256,
)
from .windows_recovery import CertificateDestinationRestoreEvidence
from .windows_recovery_certificate_restore_native import (
    observe_certificate_destination_while_target_held,
)
from .windows_recovery_certificate_storage_native import (
    HeldCertificateRestoreTempPaths,
    HeldCertificateRestoreTemps,
    capture_held_repair_certificate_temps,
)
from .windows_recovery_journal import (
    BackupPreparingRecord,
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
    RepairTransactionChainSelection,
    RepairTransactionGeneration,
    RepairTransactionJournalError,
    RepairTransactionPointerDisposition,
    RepairTransactionProtectionPort,
    RepairTransactionState,
    RepairTransitionRecord,
    protect_repair_transaction_generation,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
    append_persisted_repair_transaction_generation_from_held_root,
    ensure_persisted_repair_transaction_pointer_from_held_root,
)

_Result = TypeVar("_Result")
_APPLIED_EVIDENCE_DOMAIN = b"TowerScout.RepairCertificatesApplied.v1"


class RepairCertificateApplyErrorCode(str, Enum):
    INPUT_INVALID = "repair_certificate_apply_input_invalid"
    JOURNAL_INVALID = "repair_certificate_apply_journal_invalid"
    TARGET_MISMATCH = "repair_certificate_apply_target_mismatch"
    APPLY_FAILED = "repair_certificate_apply_failed"
    VERIFY_FAILED = "repair_certificate_apply_verify_failed"


class RepairCertificateApplyError(RuntimeError):
    _MESSAGES = {
        RepairCertificateApplyErrorCode.INPUT_INVALID: (
            "The repair certificate apply request is invalid."
        ),
        RepairCertificateApplyErrorCode.JOURNAL_INVALID: (
            "The repair certificate apply journal is invalid."
        ),
        RepairCertificateApplyErrorCode.TARGET_MISMATCH: (
            "The authenticated repair certificate target changed."
        ),
        RepairCertificateApplyErrorCode.APPLY_FAILED: (
            "The repair certificates could not be applied safely."
        ),
        RepairCertificateApplyErrorCode.VERIFY_FAILED: (
            "The applied repair certificates could not be verified."
        ),
    }

    def __init__(self, code: RepairCertificateApplyErrorCode) -> None:
        if type(code) is not RepairCertificateApplyErrorCode:
            raise ValueError("Unknown repair certificate apply error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RepairCertificateApplyError(code={self.code.value!r})"


class RepairCertificateTempCapture(Protocol):
    def __call__(
        self,
        root_path: str,
        forward: RepairTransactionChainSelection,
        plan: CertificateReplacementPlan,
    ) -> HeldCertificateRestoreTemps: ...


def _fail(code: RepairCertificateApplyErrorCode) -> NoReturn:
    raise RepairCertificateApplyError(code) from None


def _result(value: object, operation: ObservationOperation) -> None:
    if (
        type(value) is not TargetObservationProcessResult
        or value.operation is not operation
        or value.exit_code != 0
    ):
        _fail(RepairCertificateApplyErrorCode.APPLY_FAILED)


def _is_candidate(
    value: CertificateDestinationRestoreEvidence,
    sha256: str,
    size: int,
    mode: int,
) -> bool:
    return (
        value.present
        and value.contents_sha256 == sha256
        and value.size == size
        and value.mode == mode
    )


def _has_candidate_contents(
    value: CertificateDestinationRestoreEvidence,
    sha256: str,
    size: int,
) -> bool:
    return (
        value.present
        and value.contents_sha256 == sha256
        and value.size == size
        and value.mode is not None
    )


def _is_original(
    value: CertificateDestinationRestoreEvidence,
    *,
    present: bool,
    sha256: str | None,
    mode: int | None,
) -> bool:
    return value.present is present and (
        not present or (value.contents_sha256 == sha256 and value.mode == mode)
    )


def _apply_destination(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
    temp_name: str,
    source_path: PureWindowsPath,
    *,
    original_present: bool,
    original_sha256: str | None,
    original_mode: int | None,
    candidate_sha256: str,
    candidate_size: int,
    candidate_mode: int,
) -> CertificateDestinationRestoreEvidence:
    before = observe_certificate_destination_while_target_held(owner, destination)
    staged = observe_certificate_destination_while_target_held(
        owner,
        destination,
        restore_temp_name=temp_name,
    )

    if _is_candidate(before, candidate_sha256, candidate_size, candidate_mode):
        if staged.present:
            staged_mode = staged.mode
            if (
                not _has_candidate_contents(staged, candidate_sha256, candidate_size)
                or staged_mode is None
            ):
                _fail(RepairCertificateApplyErrorCode.TARGET_MISMATCH)
            _result(
                owner.execute_scoped_process(
                    "certificate_remove_staged_candidate",
                    (
                        owner.target.container.container_id,
                        destination,
                        temp_name,
                        candidate_sha256,
                        candidate_size,
                        staged_mode,
                    ),
                ),
                ObservationOperation.CERTIFICATE_REMOVE_STAGED_CANDIDATE,
            )
        final = observe_certificate_destination_while_target_held(owner, destination)
        staged_final = observe_certificate_destination_while_target_held(
            owner,
            destination,
            restore_temp_name=temp_name,
        )
        if (
            not _is_candidate(final, candidate_sha256, candidate_size, candidate_mode)
            or staged_final.present
        ):
            _fail(RepairCertificateApplyErrorCode.VERIFY_FAILED)
        return final

    if not _is_original(
        before,
        present=original_present,
        sha256=original_sha256,
        mode=original_mode,
    ):
        _fail(RepairCertificateApplyErrorCode.TARGET_MISMATCH)
    if staged.present:
        if not _has_candidate_contents(staged, candidate_sha256, candidate_size):
            _fail(RepairCertificateApplyErrorCode.TARGET_MISMATCH)
    else:
        _result(
            owner.execute_scoped_process(
                "certificate_stage_candidate",
                (
                    owner.target.container.container_id,
                    destination,
                    temp_name,
                    source_path,
                ),
            ),
            ObservationOperation.CERTIFICATE_STAGE_CANDIDATE,
        )
        staged = observe_certificate_destination_while_target_held(
            owner,
            destination,
            restore_temp_name=temp_name,
        )
        if not _has_candidate_contents(staged, candidate_sha256, candidate_size):
            _fail(RepairCertificateApplyErrorCode.VERIFY_FAILED)
    _result(
        owner.execute_scoped_process(
            "certificate_apply_candidate",
            (
                owner.target.container.container_id,
                destination,
                temp_name,
                before.contents_sha256,
                before.size,
                before.mode,
                candidate_sha256,
                candidate_size,
                candidate_mode,
            ),
        ),
        ObservationOperation.CERTIFICATE_APPLY_CANDIDATE,
    )
    final = observe_certificate_destination_while_target_held(owner, destination)
    staged_final = observe_certificate_destination_while_target_held(
        owner,
        destination,
        restore_temp_name=temp_name,
    )
    if (
        not _is_candidate(final, candidate_sha256, candidate_size, candidate_mode)
        or staged_final.present
    ):
        _fail(RepairCertificateApplyErrorCode.VERIFY_FAILED)
    return final


def _evidence_sha256(
    local_ca: CertificateDestinationRestoreEvidence,
    ca_bundle: CertificateDestinationRestoreEvidence,
) -> str:
    digest = hashlib.sha256(_APPLIED_EVIDENCE_DOMAIN)
    for value in (
        local_ca.destination_evidence_sha256,
        ca_bundle.destination_evidence_sha256,
    ):
        raw = value.encode("ascii")
        digest.update(struct.pack(">I", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def _append_applied(
    root_path: str,
    current: PersistedRepairTransactionChain,
    evidence_sha256: str,
    *,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
) -> PersistedRepairTransactionChain:
    stream = current.selection.tip.stream
    generation = RepairTransactionGeneration(
        1,
        stream,
        4,
        current.selection.tip_generation_sha256,
        RepairTransactionState.CERTIFICATES_APPLIED,
        RepairTransitionRecord(
            1,
            current.selection.tip_generation_sha256,
            stream.package_root_identity,
            evidence_sha256,
        ),
    )
    try:
        sealed = protect_repair_transaction_generation(
            generation, protection=protection
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
        _fail(RepairCertificateApplyErrorCode.JOURNAL_INVALID)
    if persisted is None or persisted.selection.tip != generation:
        _fail(RepairCertificateApplyErrorCode.VERIFY_FAILED)
    return persisted


def apply_repair_certificates(
    owner: BoundResolvedRepairTarget,
    rollback: PersistedEnvironmentJournalChain,
    forward: PersistedRepairTransactionChain,
    plan: CertificateReplacementPlan,
    *,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: RepairTransactionProtectionPort,
    temp_capture: RepairCertificateTempCapture = capture_held_repair_certificate_temps,
) -> PersistedRepairTransactionChain:
    """Apply or reconcile both candidates, then durably record exact proof."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(rollback) is not PersistedEnvironmentJournalChain
        or type(forward) is not PersistedRepairTransactionChain
        or type(plan) is not CertificateReplacementPlan
        or not callable(temp_capture)
        or len(rollback.selection.generations) != 3
        or rollback.selection.tip.state is not EnvironmentJournalState.ROLLBACK_ARMED
        or rollback.selection.pointer_disposition
        is not JournalPointerDisposition.CURRENT
        or len(forward.selection.generations) != 3
        or forward.selection.tip.state
        is not RepairTransactionState.CERTIFICATE_TEMP_VERIFIED
        or forward.selection.pointer_disposition
        is not RepairTransactionPointerDisposition.CURRENT
    ):
        _fail(RepairCertificateApplyErrorCode.INPUT_INVALID)
    stream = forward.selection.tip.stream
    preparing = rollback.selection.generations[0].record
    if (
        type(preparing) is not BackupPreparingRecord
        or stream.rollback_journal_id != rollback.selection.tip.stream.journal_id
        or stream.rollback_armed_generation_sha256
        != rollback.selection.tip_generation_sha256
        or stream.target_token_sha256
        != rollback.selection.tip.stream.target_token_sha256
        or stream.package_root_identity
        != rollback.selection.tip.stream.package_root_identity
        or stream.target_token_sha256 != owner.target.target_token.digest_sha256
        or plan.provider is not owner.target.provider
        or preparing.certificate_provider is not plan.provider
        or preparing.windows_root_fingerprint_sha256
        != plan.windows_root_fingerprint_sha256
        or preparing.local_ca_candidate_sha256 != plan.local_ca_sha256
        or preparing.local_ca_candidate_size != len(plan.local_ca_contents)
        or preparing.local_ca_candidate_mode != plan.local_ca_mode
        or preparing.ca_bundle_candidate_sha256 != plan.ca_bundle_sha256
        or preparing.ca_bundle_candidate_size != len(plan.ca_bundle_contents)
        or preparing.ca_bundle_candidate_mode != plan.ca_bundle_mode
        or forward.selection.generations[0].record.evidence_sha256
        != certificate_replacement_evidence_sha256(plan)
    ):
        _fail(RepairCertificateApplyErrorCode.JOURNAL_INVALID)

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
            _fail(RepairCertificateApplyErrorCode.JOURNAL_INVALID)
        if (
            current is None
            or current.selection.generation_sha256s
            != forward.selection.generation_sha256s
            or current.selection.pointer_disposition
            is not RepairTransactionPointerDisposition.CURRENT
        ):
            _fail(RepairCertificateApplyErrorCode.JOURNAL_INVALID)
        temps: HeldCertificateRestoreTemps | None = None
        try:
            temps = temp_capture(root_path, current.selection, plan)
            names = current.selection.generations[0].record.certificate_temp_names
            if names is None:
                _fail(RepairCertificateApplyErrorCode.JOURNAL_INVALID)

            def mutate(paths: HeldCertificateRestoreTempPaths) -> tuple[
                CertificateDestinationRestoreEvidence,
                CertificateDestinationRestoreEvidence,
            ]:
                if paths.local_ca is None or paths.ca_bundle is None:
                    _fail(RepairCertificateApplyErrorCode.JOURNAL_INVALID)
                local_ca = _apply_destination(
                    owner,
                    CertificateTargetDestination.LOCAL_CA,
                    names[0],
                    paths.local_ca,
                    original_present=preparing.local_ca_present,
                    original_sha256=preparing.local_ca_sha256,
                    original_mode=preparing.local_ca_mode,
                    candidate_sha256=plan.local_ca_sha256,
                    candidate_size=len(plan.local_ca_contents),
                    candidate_mode=plan.local_ca_mode,
                )
                ca_bundle = _apply_destination(
                    owner,
                    CertificateTargetDestination.CA_BUNDLE,
                    names[1],
                    paths.ca_bundle,
                    original_present=preparing.ca_bundle_present,
                    original_sha256=preparing.ca_bundle_sha256,
                    original_mode=preparing.ca_bundle_mode,
                    candidate_sha256=plan.ca_bundle_sha256,
                    candidate_size=len(plan.ca_bundle_contents),
                    candidate_mode=plan.ca_bundle_mode,
                )
                owner.assert_unchanged()
                return local_ca, ca_bundle

            local_ca, ca_bundle = temps.run_while_held(mutate)
            return _append_applied(
                root_path,
                current,
                _evidence_sha256(local_ca, ca_bundle),
                generation_storage=generation_storage,
                pointer_storage=pointer_storage,
                protection=protection,
            )
        finally:
            if temps is not None:
                temps.close()

    try:
        result = root.run_journal_storage(run)
    except RepairCertificateApplyError:
        raise
    except Exception:
        _fail(RepairCertificateApplyErrorCode.APPLY_FAILED)
    if type(result) is not PersistedRepairTransactionChain:
        _fail(RepairCertificateApplyErrorCode.VERIFY_FAILED)
    return result


__all__ = [
    "RepairCertificateApplyError",
    "RepairCertificateApplyErrorCode",
    "RepairCertificateTempCapture",
    "apply_repair_certificates",
]
