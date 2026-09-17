"""Durable provider-environment promotion orchestration for Windows.

This layer reconstructs promotion authority only from an authenticated
provider mini-journal, requires its verified generation to be current before
the destination operation, and appends ``environment_applied`` exactly once.
It exposes no product repair or installer call site.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable, NoReturn, Protocol, TypeVar, cast

from .windows_environment_promotion import EnvironmentPromotionAuthority
from .windows_environment_replacement_native import (
    EnvironmentAppliedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_recovery_journal import (
    EnvironmentJournalGeneration,
    EnvironmentJournalState,
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
from .windows_security import WindowsSecurityError

_Result = TypeVar("_Result")


class EnvironmentPromotionJournalErrorCode(str, Enum):
    INPUT_INVALID = "environment_promotion_journal_input_invalid"
    AUTHORITY_INVALID = "environment_promotion_journal_authority_invalid"
    STORAGE_UNAVAILABLE = "environment_promotion_journal_storage_unavailable"
    WRITE_FAILED = "environment_promotion_journal_write_failed"
    APPLY_FAILED = "environment_promotion_journal_apply_failed"
    VERIFY_FAILED = "environment_promotion_journal_verify_failed"


class EnvironmentPromotionJournalError(RuntimeError):
    """Sanitized failure at the durable environment-promotion boundary."""

    _MESSAGES = {
        EnvironmentPromotionJournalErrorCode.INPUT_INVALID: (
            "The environment promotion journal request is invalid."
        ),
        EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID: (
            "The environment promotion journal authority is invalid."
        ),
        EnvironmentPromotionJournalErrorCode.STORAGE_UNAVAILABLE: (
            "Protected environment promotion storage is unavailable."
        ),
        EnvironmentPromotionJournalErrorCode.WRITE_FAILED: (
            "The environment promotion journal could not be advanced durably."
        ),
        EnvironmentPromotionJournalErrorCode.APPLY_FAILED: (
            "The environment candidate could not be promoted safely."
        ),
        EnvironmentPromotionJournalErrorCode.VERIFY_FAILED: (
            "The promoted environment could not be verified durably."
        ),
    }

    def __init__(self, code: EnvironmentPromotionJournalErrorCode) -> None:
        if type(code) is not EnvironmentPromotionJournalErrorCode:
            raise ValueError("Unknown environment promotion journal error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"EnvironmentPromotionJournalError(code={self.code.value!r})"


class EnvironmentPromotionStoragePort(Protocol):
    def promote_environment_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        authority: EnvironmentPromotionAuthority,
    ) -> EnvironmentDestinationObservation: ...


def _fail(code: EnvironmentPromotionJournalErrorCode) -> NoReturn:
    raise EnvironmentPromotionJournalError(code) from None


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
            raise TypeError("Protected journal root is unavailable.")
        return run(operation)
    except EnvironmentPromotionJournalError:
        raise
    except Exception:
        _fail(EnvironmentPromotionJournalErrorCode.STORAGE_UNAVAILABLE)


def _load_chain(
    root_path: str,
    stream: JournalStreamIdentity,
    storage: JournalGenerationStoragePort,
    protection: JournalProtectionPort,
) -> PersistedEnvironmentJournalChain:
    try:
        chain = load_persisted_environment_journal_chain_from_held_root(
            root_path,
            stream,
            storage=storage,
            protection=protection,
        )
    except RecoveryJournalStorageError as exc:
        if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(EnvironmentPromotionJournalErrorCode.STORAGE_UNAVAILABLE)
        _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
    except RecoveryJournalError:
        _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
    if type(chain) is not PersistedEnvironmentJournalChain:
        _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
    return chain


def _authority_from_chain(
    chain: PersistedEnvironmentJournalChain,
) -> tuple[EnvironmentPromotionAuthority, EnvironmentAppliedRecord | None]:
    generations = chain.selection.generations
    if (
        len(generations) not in {3, 4}
        or generations[0].state is not EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED
        or generations[1].state is not EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED
        or generations[2].state is not EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED
        or type(generations[0].record) is not EnvironmentTempPlanRecord
        or type(generations[2].record) is not EnvironmentTempVerifiedRecord
    ):
        _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
    plan = generations[0].record
    verified = generations[2].record
    if plan.original_present:
        try:
            original = EnvironmentDestinationObservation(
                True,
                plan.original_identity,
                plan.original_sha256,
                plan.original_size,
                plan.original_file_attributes,
                plan.original_security_descriptor_sha256,
            )
        except ValueError:
            _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
    else:
        original = EnvironmentDestinationObservation(False)
    try:
        authority = EnvironmentPromotionAuthority(
            1,
            chain.selection.tip.stream.package_root_identity,
            original,
            verified,
        )
    except ValueError:
        _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
    applied: EnvironmentAppliedRecord | None = None
    if len(generations) == 4:
        if (
            generations[3].state is not EnvironmentJournalState.ENVIRONMENT_APPLIED
            or type(generations[3].record) is not EnvironmentAppliedRecord
        ):
            _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
        applied = generations[3].record
    return authority, applied


def _ensure_pointer(
    root_path: str,
    stream: JournalStreamIdentity,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: JournalProtectionPort,
    expected_tip: str,
) -> PersistedEnvironmentJournalChain:
    try:
        selected = ensure_persisted_environment_journal_pointer_from_held_root(
            root_path,
            stream,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
    except RecoveryJournalStorageError as exc:
        if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
            _fail(EnvironmentPromotionJournalErrorCode.STORAGE_UNAVAILABLE)
        if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
            _fail(EnvironmentPromotionJournalErrorCode.WRITE_FAILED)
        _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
    except RecoveryJournalError:
        _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
    if (
        type(selected) is not PersistedEnvironmentJournalChain
        or selected.selection.pointer_disposition
        is not JournalPointerDisposition.CURRENT
        or selected.selection.tip_generation_sha256 != expected_tip
    ):
        _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
    return selected


def _promote(
    package_root: PathHierarchyTrust,
    promotion: EnvironmentPromotionStoragePort,
    authority: EnvironmentPromotionAuthority,
) -> EnvironmentDestinationObservation:
    try:
        observed = promotion.promote_environment_while_package_root_held(
            package_root,
            authority,
        )
    except Exception:
        _fail(EnvironmentPromotionJournalErrorCode.APPLY_FAILED)
    if (
        type(observed) is not EnvironmentDestinationObservation
        or observed != authority.expected_applied
    ):
        _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
    return observed


def persist_environment_applied_generation(
    *,
    stream: JournalStreamIdentity,
    package_root: PathHierarchyTrust,
    root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    journal_protection: JournalProtectionPort,
    promotion: EnvironmentPromotionStoragePort,
) -> PersistedEnvironmentJournalChain:
    """Apply/reconcile one authenticated candidate and select its durable tip."""

    if (
        type(stream) is not JournalStreamIdentity
        or type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.evidence.root_identity != stream.package_root_identity
        or root is None
        or generation_storage is None
        or pointer_storage is None
        or journal_protection is None
        or promotion is None
    ):
        _fail(EnvironmentPromotionJournalErrorCode.INPUT_INVALID)

    def apply_and_record(root_path: str) -> PersistedEnvironmentJournalChain:
        try:
            package_root.assert_unchanged_while_held()
        except WindowsSecurityError:
            _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
        chain = _load_chain(root_path, stream, generation_storage, journal_protection)
        authority, applied = _authority_from_chain(chain)
        if applied is None:
            chain = _ensure_pointer(
                root_path,
                stream,
                generation_storage,
                pointer_storage,
                journal_protection,
                chain.selection.tip_generation_sha256,
            )
            authority, applied = _authority_from_chain(chain)
            if applied is not None:
                _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)
        observed = _promote(package_root, promotion, authority)
        try:
            package_root.assert_unchanged_while_held()
        except WindowsSecurityError:
            _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)

        if applied is None:
            assert observed.identity is not None
            assert observed.file_attributes is not None
            assert observed.security_descriptor_sha256 is not None
            try:
                record = EnvironmentAppliedRecord(
                    1,
                    chain.selection.tip_generation_sha256,
                    stream.package_root_identity,
                    observed.identity,
                    authority.verified.candidate_sha256,
                    authority.verified.candidate_size,
                    observed.file_attributes,
                    observed.security_descriptor_sha256,
                    authority.verified.temp_name,
                )
                generation = EnvironmentJournalGeneration(
                    1,
                    stream,
                    4,
                    chain.selection.tip_generation_sha256,
                    EnvironmentJournalState.ENVIRONMENT_APPLIED,
                    record,
                )
                sealed = protect_environment_journal_generation(
                    generation,
                    protection=journal_protection,
                )
            except (RecoveryJournalError, ValueError):
                _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
            try:
                chain = append_persisted_environment_journal_generation_from_held_root(
                    root_path,
                    sealed,
                    stream=stream,
                    storage=generation_storage,
                    protection=journal_protection,
                )
            except RecoveryJournalStorageError as exc:
                if exc.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE:
                    _fail(EnvironmentPromotionJournalErrorCode.STORAGE_UNAVAILABLE)
                if exc.code is RecoveryJournalStorageErrorCode.WRITE_FAILED:
                    _fail(EnvironmentPromotionJournalErrorCode.WRITE_FAILED)
                _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
            except RecoveryJournalError:
                _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
            if chain.selection.tip != generation:
                _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
        elif (
            applied.candidate_identity != observed.identity
            or applied.candidate_sha256 != observed.sha256
            or applied.candidate_size != observed.size
            or applied.candidate_file_attributes != observed.file_attributes
            or applied.candidate_security_descriptor_sha256
            != observed.security_descriptor_sha256
        ):
            _fail(EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID)

        return _ensure_pointer(
            root_path,
            stream,
            generation_storage,
            pointer_storage,
            journal_protection,
            chain.selection.tip_generation_sha256,
        )

    try:
        return package_root.run_while_held(
            lambda: _run_under_root(root, apply_and_record)
        )
    except EnvironmentPromotionJournalError:
        raise
    except WindowsSecurityError:
        _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)
    except Exception:
        _fail(EnvironmentPromotionJournalErrorCode.VERIFY_FAILED)


__all__ = [
    "EnvironmentPromotionJournalError",
    "EnvironmentPromotionJournalErrorCode",
    "EnvironmentPromotionStoragePort",
    "persist_environment_applied_generation",
]
