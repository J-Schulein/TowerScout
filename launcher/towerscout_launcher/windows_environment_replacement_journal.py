"""Durable adapter for provider ``.env`` staging journal transitions.

Each receipt is returned only after its immutable generation and metadata
pointer have been reread and authenticated under the protected journal root.
Exact retries are idempotent; conflicting or skipped transitions fail closed.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable, NoReturn, TypeVar, cast

from .windows_environment_replacement_native import (
    EnvironmentReplacementJournalPort,
    EnvironmentTempCreatedReceipt,
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlannedReceipt,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedReceipt,
    EnvironmentTempVerifiedRecord,
)
from .windows_recovery_journal import (
    EnvironmentJournalGeneration,
    EnvironmentJournalState,
    GENESIS_GENERATION_SHA256,
    JournalPointerDisposition,
    JournalProtectionPort,
    JournalStreamIdentity,
    RecoveryJournalError,
    protect_environment_journal_generation,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    append_persisted_environment_journal_generation_from_held_root,
    ensure_persisted_environment_journal_pointer_from_held_root,
    load_persisted_environment_journal_chain_from_held_root,
)

_Result = TypeVar("_Result")


class EnvironmentReplacementJournalErrorCode(str, Enum):
    INPUT_INVALID = "environment_replacement_journal_input_invalid"
    AUTHORITY_INVALID = "environment_replacement_journal_authority_invalid"
    STORAGE_UNAVAILABLE = "environment_replacement_journal_storage_unavailable"
    WRITE_FAILED = "environment_replacement_journal_write_failed"
    VERIFY_FAILED = "environment_replacement_journal_verify_failed"


class EnvironmentReplacementJournalError(RuntimeError):
    """Sanitized durable provider-environment journal failure."""

    _MESSAGES = {
        EnvironmentReplacementJournalErrorCode.INPUT_INVALID: (
            "The environment replacement journal request is invalid."
        ),
        EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID: (
            "The environment replacement journal authority is invalid."
        ),
        EnvironmentReplacementJournalErrorCode.STORAGE_UNAVAILABLE: (
            "Protected environment replacement storage is unavailable."
        ),
        EnvironmentReplacementJournalErrorCode.WRITE_FAILED: (
            "The environment replacement journal could not be advanced durably."
        ),
        EnvironmentReplacementJournalErrorCode.VERIFY_FAILED: (
            "The environment replacement journal could not be verified durably."
        ),
    }

    def __init__(self, code: EnvironmentReplacementJournalErrorCode) -> None:
        if type(code) is not EnvironmentReplacementJournalErrorCode:
            raise ValueError("Unknown environment replacement journal error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentReplacementJournalError(code={self.code.value!r})"


def _fail(code: EnvironmentReplacementJournalErrorCode) -> NoReturn:
    raise EnvironmentReplacementJournalError(code) from None


class PersistedEnvironmentReplacementJournal(EnvironmentReplacementJournalPort):
    """Append and activate the three write-ahead staging generations."""

    __slots__ = (
        "_generation_storage",
        "_pointer_storage",
        "_protection",
        "_root",
        "_stream",
    )

    def __init__(
        self,
        *,
        stream: JournalStreamIdentity,
        root: JournalStorageRootPort,
        generation_storage: JournalGenerationStoragePort,
        pointer_storage: JournalPointerStoragePort,
        protection: JournalProtectionPort,
    ) -> None:
        if (
            type(stream) is not JournalStreamIdentity
            or root is None
            or generation_storage is None
            or pointer_storage is None
            or protection is None
        ):
            raise ValueError("Environment replacement journal is invalid.")
        self._stream = stream
        self._root = root
        self._generation_storage = generation_storage
        self._pointer_storage = pointer_storage
        self._protection = protection

    def _run_under_root(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        try:
            run = cast(
                Callable[[Callable[[str], _Result]], _Result],
                getattr(self._root, "run_journal_storage"),
            )
            if not callable(run):
                raise TypeError("Protected journal root is unavailable.")
            return run(operation)
        except EnvironmentReplacementJournalError:
            raise
        except Exception:
            _fail(EnvironmentReplacementJournalErrorCode.STORAGE_UNAVAILABLE)

    def _load(
        self,
        root_path: str,
    ) -> PersistedEnvironmentJournalChain | None:
        try:
            return load_persisted_environment_journal_chain_from_held_root(
                root_path,
                self._stream,
                storage=self._generation_storage,
                protection=self._protection,
            )
        except RecoveryJournalStorageError as exc:
            if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                _fail(EnvironmentReplacementJournalErrorCode.STORAGE_UNAVAILABLE)
            _fail(EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID)
        except RecoveryJournalError:
            _fail(EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID)

    def _ensure_pointer(
        self,
        root_path: str,
        expected_tip: str,
    ) -> PersistedEnvironmentJournalChain:
        try:
            selected = ensure_persisted_environment_journal_pointer_from_held_root(
                root_path,
                self._stream,
                generation_storage=self._generation_storage,
                pointer_storage=self._pointer_storage,
                protection=self._protection,
            )
        except RecoveryJournalStorageError as exc:
            if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                _fail(EnvironmentReplacementJournalErrorCode.STORAGE_UNAVAILABLE)
            if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                _fail(EnvironmentReplacementJournalErrorCode.WRITE_FAILED)
            _fail(EnvironmentReplacementJournalErrorCode.VERIFY_FAILED)
        except RecoveryJournalError:
            _fail(EnvironmentReplacementJournalErrorCode.VERIFY_FAILED)
        if (
            type(selected) is not PersistedEnvironmentJournalChain
            or selected.selection.pointer_disposition
            is not JournalPointerDisposition.CURRENT
            or selected.selection.tip_generation_sha256 != expected_tip
        ):
            _fail(EnvironmentReplacementJournalErrorCode.VERIFY_FAILED)
        return selected

    def _record(
        self,
        state: EnvironmentJournalState,
        record: object,
        sequence: int,
    ) -> str:
        def append_or_reconcile(root_path: str) -> str:
            chain = self._load(root_path)
            if chain is not None and len(chain.selection.generations) == sequence:
                if (
                    chain.selection.tip.state is not state
                    or chain.selection.tip.record != record
                ):
                    _fail(EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID)
                return self._ensure_pointer(
                    root_path,
                    chain.selection.tip_generation_sha256,
                ).selection.tip_generation_sha256

            prior_count = sequence - 1
            if (prior_count == 0 and chain is not None) or (
                prior_count > 0
                and (chain is None or len(chain.selection.generations) != prior_count)
            ):
                _fail(EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID)
            previous = (
                GENESIS_GENERATION_SHA256
                if chain is None
                else chain.selection.tip_generation_sha256
            )
            if chain is not None:
                self._ensure_pointer(root_path, previous)
            try:
                generation = EnvironmentJournalGeneration(
                    1,
                    self._stream,
                    sequence,
                    previous,
                    state,
                    record,  # type: ignore[arg-type]
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=self._protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID)
            try:
                appended = (
                    append_persisted_environment_journal_generation_from_held_root(
                        root_path,
                        sealed,
                        stream=self._stream,
                        storage=self._generation_storage,
                        protection=self._protection,
                    )
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(EnvironmentReplacementJournalErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(EnvironmentReplacementJournalErrorCode.WRITE_FAILED)
                _fail(EnvironmentReplacementJournalErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(EnvironmentReplacementJournalErrorCode.VERIFY_FAILED)
            if appended.selection.tip != generation:
                _fail(EnvironmentReplacementJournalErrorCode.VERIFY_FAILED)
            return self._ensure_pointer(
                root_path,
                appended.selection.tip_generation_sha256,
            ).selection.tip_generation_sha256

        return self._run_under_root(append_or_reconcile)

    def record_environment_temp_planned(
        self,
        record: EnvironmentTempPlanRecord,
    ) -> EnvironmentTempPlannedReceipt:
        if type(record) is not EnvironmentTempPlanRecord:
            _fail(EnvironmentReplacementJournalErrorCode.INPUT_INVALID)
        digest = self._record(
            EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
            record,
            1,
        )
        return EnvironmentTempPlannedReceipt(record, digest)

    def record_environment_temp_created(
        self,
        record: EnvironmentTempCreatedRecord,
    ) -> EnvironmentTempCreatedReceipt:
        if type(record) is not EnvironmentTempCreatedRecord:
            _fail(EnvironmentReplacementJournalErrorCode.INPUT_INVALID)
        digest = self._record(
            EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
            record,
            2,
        )
        return EnvironmentTempCreatedReceipt(record, digest)

    def record_environment_temp_verified(
        self,
        record: EnvironmentTempVerifiedRecord,
    ) -> EnvironmentTempVerifiedReceipt:
        if type(record) is not EnvironmentTempVerifiedRecord:
            _fail(EnvironmentReplacementJournalErrorCode.INPUT_INVALID)
        digest = self._record(
            EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
            record,
            3,
        )
        return EnvironmentTempVerifiedReceipt(record, digest)


__all__ = [
    "EnvironmentReplacementJournalError",
    "EnvironmentReplacementJournalErrorCode",
    "PersistedEnvironmentReplacementJournal",
]
