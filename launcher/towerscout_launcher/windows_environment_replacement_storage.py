"""Restart-safe provider environment staging over authenticated storage.

This orchestration keeps the package root and protected journal root held while
it loads the current provider mini-journal, reconciles only its exact planned
or created temp, and returns only after generation 3 is authenticated/current.
It exposes no installer or repair call site.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable, NoReturn, cast

from .windows_environment_replacement import EnvironmentReplacementPlan
from .windows_environment_replacement_journal import (
    EnvironmentReplacementJournalError,
    EnvironmentReplacementJournalErrorCode,
    PersistedEnvironmentReplacementJournal,
)
from .windows_environment_replacement_native import (
    EnvironmentReplacementJournalPort,
    EnvironmentTempCreatedReceipt,
    EnvironmentTempCreatedRecord,
    EnvironmentTempNameSource,
    EnvironmentTempPlannedReceipt,
    EnvironmentTempPlanRecord,
    EnvironmentTempStageError,
    EnvironmentTempStageErrorCode,
    EnvironmentTempVerifiedReceipt,
    EnvironmentTempVerifiedRecord,
    NativeEnvironmentTempNameSource,
    NativeWindowsEnvironmentReplacementApi,
    StagedEnvironmentCandidate,
    _WindowsEnvironmentReplacementApi,
    _resume_environment_candidate_while_root_held,
    _stage_while_root_held,
    _verify_environment_candidate_while_root_held,
)
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_recovery_journal import (
    EnvironmentJournalState,
    JournalPointerDisposition,
)
from .windows_recovery_journal_storage import PersistedEnvironmentJournalChain
from .windows_security import WindowsSecurityError


class EnvironmentReplacementStorageErrorCode(str, Enum):
    INPUT_INVALID = "environment_replacement_storage_input_invalid"
    AUTHORITY_INVALID = "environment_replacement_storage_authority_invalid"
    STORAGE_UNAVAILABLE = "environment_replacement_storage_unavailable"
    WRITE_FAILED = "environment_replacement_storage_write_failed"
    VERIFY_FAILED = "environment_replacement_storage_verify_failed"


class EnvironmentReplacementStorageError(RuntimeError):
    """Sanitized failure at restart-safe provider staging."""

    _MESSAGES = {
        EnvironmentReplacementStorageErrorCode.INPUT_INVALID: (
            "The environment replacement storage request is invalid."
        ),
        EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID: (
            "The environment replacement storage authority is invalid."
        ),
        EnvironmentReplacementStorageErrorCode.STORAGE_UNAVAILABLE: (
            "Protected environment replacement storage is unavailable."
        ),
        EnvironmentReplacementStorageErrorCode.WRITE_FAILED: (
            "The environment candidate could not be staged durably."
        ),
        EnvironmentReplacementStorageErrorCode.VERIFY_FAILED: (
            "The environment candidate could not be verified durably."
        ),
    }

    def __init__(self, code: EnvironmentReplacementStorageErrorCode) -> None:
        if type(code) is not EnvironmentReplacementStorageErrorCode:
            raise ValueError("Unknown environment replacement storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentReplacementStorageError(code={self.code.value!r})"


def _fail(code: EnvironmentReplacementStorageErrorCode) -> NoReturn:
    raise EnvironmentReplacementStorageError(code) from None


class _HeldEnvironmentReplacementJournal(EnvironmentReplacementJournalPort):
    __slots__ = ("_journal", "_root_path")

    def __init__(
        self,
        journal: PersistedEnvironmentReplacementJournal,
        root_path: str,
    ) -> None:
        self._journal = journal
        self._root_path = root_path

    def record_environment_temp_planned(
        self,
        record: EnvironmentTempPlanRecord,
    ) -> EnvironmentTempPlannedReceipt:
        digest = self._journal._record_from_held_root(
            self._root_path,
            EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            record,
            1,
        )
        return EnvironmentTempPlannedReceipt(record, digest)

    def record_environment_temp_created(
        self,
        record: EnvironmentTempCreatedRecord,
    ) -> EnvironmentTempCreatedReceipt:
        digest = self._journal._record_from_held_root(
            self._root_path,
            EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            record,
            2,
        )
        return EnvironmentTempCreatedReceipt(record, digest)

    def record_environment_temp_verified(
        self,
        record: EnvironmentTempVerifiedRecord,
    ) -> EnvironmentTempVerifiedReceipt:
        digest = self._journal._record_from_held_root(
            self._root_path,
            EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
            record,
            3,
        )
        return EnvironmentTempVerifiedReceipt(record, digest)


def _translate_journal_error(error: EnvironmentReplacementJournalError) -> NoReturn:
    if error.code is EnvironmentReplacementJournalErrorCode.STORAGE_UNAVAILABLE:
        _fail(EnvironmentReplacementStorageErrorCode.STORAGE_UNAVAILABLE)
    if error.code is EnvironmentReplacementJournalErrorCode.WRITE_FAILED:
        _fail(EnvironmentReplacementStorageErrorCode.WRITE_FAILED)
    if error.code is EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID:
        _fail(EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID)
    _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)


def _translate_stage_error(error: EnvironmentTempStageError) -> NoReturn:
    if error.code in {
        EnvironmentTempStageErrorCode.INPUT_INVALID,
        EnvironmentTempStageErrorCode.JOURNAL_FAILED,
    }:
        _fail(EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID)
    if error.code in {
        EnvironmentTempStageErrorCode.CREATE_FAILED,
        EnvironmentTempStageErrorCode.WRITE_FAILED,
    }:
        _fail(EnvironmentReplacementStorageErrorCode.WRITE_FAILED)
    _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)


def _receipts(
    chain: PersistedEnvironmentJournalChain,
) -> tuple[
    EnvironmentTempPlannedReceipt,
    EnvironmentTempCreatedReceipt | None,
    EnvironmentTempVerifiedReceipt | None,
]:
    generations = chain.selection.generations
    digests = chain.selection.generation_sha256s
    if (
        not 1 <= len(generations) <= 3
        or generations[0].state is not EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED
        or type(generations[0].record) is not EnvironmentTempPlanRecord
    ):
        _fail(EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID)
    planned = EnvironmentTempPlannedReceipt(generations[0].record, digests[0])
    created: EnvironmentTempCreatedReceipt | None = None
    verified: EnvironmentTempVerifiedReceipt | None = None
    if len(generations) >= 2:
        if (
            generations[1].state is not EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED
            or type(generations[1].record) is not EnvironmentTempCreatedRecord
        ):
            _fail(EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID)
        created = EnvironmentTempCreatedReceipt(generations[1].record, digests[1])
    if len(generations) == 3:
        if (
            generations[2].state
            is not EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED
            or type(generations[2].record) is not EnvironmentTempVerifiedRecord
        ):
            _fail(EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID)
        verified = EnvironmentTempVerifiedReceipt(generations[2].record, digests[2])
    return planned, created, verified


def stage_or_resume_persisted_environment_candidate(
    plan: EnvironmentReplacementPlan,
    original: EnvironmentDestinationObservation,
    package_root: PathHierarchyTrust,
    journal: PersistedEnvironmentReplacementJournal,
    *,
    api: _WindowsEnvironmentReplacementApi | None = None,
    name_source: EnvironmentTempNameSource | None = None,
) -> StagedEnvironmentCandidate:
    """Create, resume, or reverify one authenticated provider candidate."""

    if (
        type(plan) is not EnvironmentReplacementPlan
        or type(original) is not EnvironmentDestinationObservation
        or type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or type(journal) is not PersistedEnvironmentReplacementJournal
    ):
        _fail(EnvironmentReplacementStorageErrorCode.INPUT_INVALID)
    selected_api = NativeWindowsEnvironmentReplacementApi() if api is None else api
    selected_names = (
        NativeEnvironmentTempNameSource() if name_source is None else name_source
    )
    if selected_api is None or selected_names is None:
        _fail(EnvironmentReplacementStorageErrorCode.INPUT_INVALID)
    try:
        if selected_api.supported is not True:
            _fail(EnvironmentReplacementStorageErrorCode.STORAGE_UNAVAILABLE)
    except EnvironmentReplacementStorageError:
        raise
    except Exception:
        _fail(EnvironmentReplacementStorageErrorCode.STORAGE_UNAVAILABLE)

    def while_root_held(root_path: str) -> StagedEnvironmentCandidate:
        try:
            chain = journal._load(root_path)
            held_journal = _HeldEnvironmentReplacementJournal(journal, root_path)
            if chain is None:
                result = _stage_while_root_held(
                    plan,
                    original,
                    package_root,
                    held_journal,
                    selected_api,
                    selected_names,
                )
            else:
                chain = journal._ensure_pointer(
                    root_path,
                    chain.selection.tip_generation_sha256,
                )
                planned, created, verified = _receipts(chain)
                if verified is None:
                    result = _resume_environment_candidate_while_root_held(
                        plan,
                        original,
                        package_root,
                        held_journal,
                        planned,
                        created,
                        api=selected_api,
                    )
                else:
                    if created is None:
                        _fail(EnvironmentReplacementStorageErrorCode.AUTHORITY_INVALID)
                    result = _verify_environment_candidate_while_root_held(
                        plan,
                        original,
                        package_root,
                        planned,
                        created,
                        verified,
                        api=selected_api,
                    )
            completed = journal._load(root_path)
            if completed is None or len(completed.selection.generations) != 3:
                _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)
            completed = journal._ensure_pointer(
                root_path,
                completed.selection.tip_generation_sha256,
            )
            if (
                completed.selection.pointer_disposition
                is not JournalPointerDisposition.CURRENT
                or completed.selection.tip.state
                is not EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED
                or completed.selection.tip.record != result.verified_receipt.record
                or completed.selection.tip_generation_sha256
                != result.verified_receipt.generation_sha256
            ):
                _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)
            package_root.assert_unchanged_while_held()
            return result
        except EnvironmentReplacementStorageError:
            raise
        except EnvironmentReplacementJournalError as exc:
            _translate_journal_error(exc)
        except EnvironmentTempStageError as exc:
            _translate_stage_error(exc)
        except WindowsSecurityError:
            _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)
        except Exception:
            _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)

    try:
        protected_root = getattr(journal, "_root")
        run = cast(
            Callable[
                [Callable[[str], StagedEnvironmentCandidate]],
                StagedEnvironmentCandidate,
            ],
            getattr(protected_root, "run_journal_storage"),
        )
        if not callable(run):
            _fail(EnvironmentReplacementStorageErrorCode.STORAGE_UNAVAILABLE)
        return package_root.run_while_held(lambda: run(while_root_held))
    except EnvironmentReplacementStorageError:
        raise
    except EnvironmentReplacementJournalError as exc:
        _translate_journal_error(exc)
    except WindowsSecurityError:
        _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(EnvironmentReplacementStorageErrorCode.VERIFY_FAILED)


__all__ = [
    "EnvironmentReplacementStorageError",
    "EnvironmentReplacementStorageErrorCode",
    "stage_or_resume_persisted_environment_candidate",
]
