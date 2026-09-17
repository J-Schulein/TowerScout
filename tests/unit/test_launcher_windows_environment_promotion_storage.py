from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path
from typing import Callable, TypeVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_environment_promotion_storage as applied  # noqa: E402
import towerscout_launcher.windows_environment_replacement_journal as replacement_journal  # noqa: E402
import towerscout_launcher.windows_environment_replacement_storage as replacement_storage  # noqa: E402
import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal_storage as storage  # noqa: E402
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    plan_ca_environment_replacement,
)
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentAppliedRecord,
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402
from towerscout_launcher.windows_security import NativeFileFacts  # noqa: E402
from towerscout_launcher.target_contracts import ABSENT_FILE_SHA256  # noqa: E402

_Result = TypeVar("_Result")
_ROOT = r"C:\Users\reviewed-user\TowerScout"
_TEMP = ".towerscout-env-0123456789abcdef0123456789abcdef.tmp"


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


class _Protection:
    def __init__(self) -> None:
        self.nonce = 0

    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        self.nonce += 1
        return CurrentUserProtectedBlob(
            purpose,
            self.nonce.to_bytes(4, "big") + plaintext,
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        if blob.purpose is not purpose:
            raise ValueError("private purpose")
        return blob.ciphertext[4:]


class _Root:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.active = False

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        self.active = True
        try:
            return operation(r"C:\Users\private\TowerScout\Recovery\v1")
        finally:
            self.active = False


class _Storage:
    def __init__(self, root: _Root, events: list[str]) -> None:
        self.root = root
        self.events = events
        self.files: dict[str, storage.StoredJournalGenerationFile] = {}
        self.pointer: storage.StoredJournalPointerFile | None = None
        self.next_identity = 30

    def _held(self) -> None:
        assert self.root.active

    def list_names(self, root_path: str) -> tuple[str, ...]:
        self._held()
        del root_path
        names = tuple(self.files)
        if self.pointer is not None:
            names += (f"journal-{'a' * 32}.pointer",)
        return names

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalGenerationFile:
        self._held()
        del root_path
        item = self.files[name]
        assert len(item.contents) <= maximum
        return item

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> storage.StoredJournalGenerationFile:
        self._held()
        del root_path
        if name in self.files:
            raise FileExistsError("private generation")
        sequence = int(name.removesuffix(".generation").rsplit("-", 1)[-1])
        self.events.append(f"journal:{sequence}")
        self.next_identity += 1
        item = storage.StoredJournalGenerationFile(
            _identity(self.next_identity),
            contents,
        )
        self.files[name] = item
        return item

    def read_pointer(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalPointerFile | None:
        self._held()
        del root_path, maximum
        assert name == f"journal-{'a' * 32}.pointer"
        return self.pointer

    def replace_pointer(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> storage.StoredJournalPointerFile:
        self._held()
        del root_path
        assert name == f"journal-{'a' * 32}.pointer"
        pointer = journal.decode_environment_journal_pointer(contents)
        self.events.append(f"pointer:{pointer.sequence}")
        self.next_identity += 1
        self.pointer = storage.StoredJournalPointerFile(
            _identity(self.next_identity),
            contents,
        )
        return self.pointer


class _PathApi:
    supported = True

    def current_user_sid(self) -> str:
        return "S-1-5-21-1000"

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        return path

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, str)
        return NativeDirectoryFacts(
            handle,
            7,
            (
                _identity(7).file_id
                if handle == _ROOT
                else hashlib.sha256(handle.casefold().encode("utf-16-le")).digest()[:16]
            ),
            0x10,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, str)
        return NativeSecurityFacts("S-1-5-21-1000", True, ())

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, str)


class _Promotion:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0
        self.error: BaseException | None = None
        self.drift = False

    def promote_environment_while_package_root_held(
        self,
        package_root: object,
        authority: object,
    ) -> EnvironmentDestinationObservation:
        del package_root
        self.events.append("promote")
        self.calls += 1
        if self.error is not None:
            raise self.error
        expected = authority.expected_applied  # type: ignore[attr-defined]
        if self.drift:
            return replace(expected, sha256="0" * 64)
        return expected


def _stream() -> journal.JournalStreamIdentity:
    return journal.JournalStreamIdentity(1, "a" * 32, "b" * 64, _identity(7))


def _chain(
    protection: _Protection,
    *,
    applied_tip: bool = False,
    original_present: bool = True,
) -> tuple[journal.SealedEnvironmentJournalGeneration, ...]:
    stream = _stream()
    plan = EnvironmentTempPlanRecord(
        1,
        stream.package_root_identity,
        "c" * 64 if original_present else ABSENT_FILE_SHA256,
        "d" * 64,
        23,
        _TEMP,
        original_present,
        _identity(8) if original_present else None,
        11 if original_present else None,
        0x20 if original_present else None,
        "e" * 64 if original_present else None,
    )
    records: list[tuple[journal.EnvironmentJournalState, object]] = [
        (journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED, plan),
    ]
    sealed: list[journal.SealedEnvironmentJournalGeneration] = []
    previous = journal.GENESIS_GENERATION_SHA256

    def add(state: journal.EnvironmentJournalState, record: object) -> str:
        nonlocal previous
        generation = journal.EnvironmentJournalGeneration(
            1,
            stream,
            len(sealed) + 1,
            previous,
            state,
            record,  # type: ignore[arg-type]
        )
        item = journal.protect_environment_journal_generation(
            generation,
            protection=protection,
        )
        sealed.append(item)
        previous = item.generation_sha256
        return previous

    del records
    planned_hash = add(
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        plan,
    )
    created = EnvironmentTempCreatedRecord(
        1,
        planned_hash,
        stream.package_root_identity,
        _identity(9),
        plan.candidate_sha256,
        plan.candidate_size,
        0x80,
        "f" * 64,
        plan.temp_name,
    )
    created_hash = add(
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
        created,
    )
    verified = EnvironmentTempVerifiedRecord(
        1,
        created_hash,
        stream.package_root_identity,
        created.temp_identity,
        created.candidate_sha256,
        created.candidate_size,
        created.candidate_file_attributes,
        created.candidate_security_descriptor_sha256,
        created.temp_name,
    )
    verified_hash = add(
        journal.EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
        verified,
    )
    if applied_tip:
        add(
            journal.EnvironmentJournalState.ENVIRONMENT_APPLIED,
            EnvironmentAppliedRecord(
                1,
                verified_hash,
                stream.package_root_identity,
                verified.temp_identity,
                verified.candidate_sha256,
                verified.candidate_size,
                (
                    plan.original_file_attributes
                    if plan.original_present
                    else verified.candidate_file_attributes
                ),
                (
                    plan.original_security_descriptor_sha256
                    if plan.original_present
                    else verified.candidate_security_descriptor_sha256
                ),
                verified.temp_name,
            ),
        )
    return tuple(sealed)


def _arrange(
    *,
    applied_tip: bool = False,
    original_present: bool = True,
) -> tuple[
    object,
    _Root,
    _Storage,
    _Protection,
    _Promotion,
    list[str],
]:
    events: list[str] = []
    root = _Root(events)
    storage_port = _Storage(root, events)
    protection = _Protection()
    for sequence, sealed in enumerate(
        _chain(
            protection,
            applied_tip=applied_tip,
            original_present=original_present,
        ),
        start=1,
    ):
        name = f"journal-{'a' * 32}-{sequence:020d}.generation"
        storage_port.files[name] = storage.StoredJournalGenerationFile(
            _identity(20 + sequence),
            sealed.protected_blob.ciphertext,
        )
    package_root = capture_path_hierarchy(
        _ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_PathApi(),
    )
    return package_root, root, storage_port, protection, _Promotion(events), events


def _apply(
    package_root: object,
    root: _Root,
    storage_port: _Storage,
    protection: _Protection,
    promotion: _Promotion,
) -> storage.PersistedEnvironmentJournalChain:
    return applied.persist_environment_applied_generation(
        stream=_stream(),
        package_root=package_root,  # type: ignore[arg-type]
        root=root,
        generation_storage=storage_port,
        pointer_storage=storage_port,
        journal_protection=protection,
        promotion=promotion,
    )


def test_verified_candidate_is_current_before_apply_and_applied_before_pointer() -> (
    None
):
    package_root, root, storage_port, protection, promotion, events = _arrange()
    try:
        result = _apply(package_root, root, storage_port, protection, promotion)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert events == ["pointer:3", "promote", "journal:4", "pointer:4"]
    assert (
        result.selection.pointer_disposition
        is journal.JournalPointerDisposition.CURRENT
    )
    assert (
        result.selection.tip.state
        is journal.EnvironmentJournalState.ENVIRONMENT_APPLIED
    )
    assert type(result.selection.tip.record) is EnvironmentAppliedRecord
    assert len(storage_port.files) == 4


def test_applied_restart_reverifies_destination_and_repairs_only_pointer() -> None:
    package_root, root, storage_port, protection, promotion, events = _arrange(
        applied_tip=True
    )
    try:
        result = _apply(package_root, root, storage_port, protection, promotion)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert events == ["promote", "pointer:4"]
    assert promotion.calls == 1
    assert len(storage_port.files) == 4
    assert (
        result.selection.tip.state
        is journal.EnvironmentJournalState.ENVIRONMENT_APPLIED
    )


def test_absent_original_applies_with_verified_candidate_metadata() -> None:
    package_root, root, storage_port, protection, promotion, _events = _arrange(
        original_present=False
    )
    try:
        result = _apply(package_root, root, storage_port, protection, promotion)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    record = result.selection.tip.record
    verified = result.selection.generations[2].record
    assert type(record) is EnvironmentAppliedRecord
    assert type(verified) is EnvironmentTempVerifiedRecord
    assert record.candidate_file_attributes == verified.candidate_file_attributes
    assert (
        record.candidate_security_descriptor_sha256
        == verified.candidate_security_descriptor_sha256
    )


@pytest.mark.parametrize("drift", (False, True))
def test_apply_failure_or_drift_never_appends_applied_generation(drift: bool) -> None:
    package_root, root, storage_port, protection, promotion, events = _arrange()
    if drift:
        promotion.drift = True
        expected = applied.EnvironmentPromotionJournalErrorCode.VERIFY_FAILED
    else:
        promotion.error = OSError("private path")
        expected = applied.EnvironmentPromotionJournalErrorCode.APPLY_FAILED
    try:
        with pytest.raises(applied.EnvironmentPromotionJournalError) as failure:
            _apply(package_root, root, storage_port, protection, promotion)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert failure.value.code is expected
    assert len(storage_port.files) == 3
    assert events == ["pointer:3", "promote"]
    assert "private" not in str(failure.value)


def test_incomplete_chain_never_reaches_promotion() -> None:
    package_root, root, storage_port, protection, promotion, _events = _arrange()
    storage_port.files.pop(f"journal-{'a' * 32}-{3:020d}.generation")
    try:
        with pytest.raises(applied.EnvironmentPromotionJournalError) as failure:
            _apply(package_root, root, storage_port, protection, promotion)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert (
        failure.value.code
        is applied.EnvironmentPromotionJournalErrorCode.AUTHORITY_INVALID
    )
    assert promotion.calls == 0


def _replacement_journal(
    root: _Root,
    storage_port: _Storage,
    protection: _Protection,
) -> replacement_journal.PersistedEnvironmentReplacementJournal:
    return replacement_journal.PersistedEnvironmentReplacementJournal(
        stream=_stream(),
        root=root,
        generation_storage=storage_port,
        pointer_storage=storage_port,
        protection=protection,
    )


def _plan() -> EnvironmentTempPlanRecord:
    return EnvironmentTempPlanRecord(
        1,
        _identity(7),
        "c" * 64,
        "d" * 64,
        23,
        _TEMP,
        True,
        _identity(8),
        11,
        0x20,
        "e" * 64,
    )


def test_staging_journal_makes_each_generation_current_before_receipt() -> None:
    events: list[str] = []
    root = _Root(events)
    storage_port = _Storage(root, events)
    protection = _Protection()
    durable = _replacement_journal(root, storage_port, protection)
    plan = _plan()

    planned = durable.record_environment_temp_planned(plan)
    created_record = EnvironmentTempCreatedRecord(
        1,
        planned.generation_sha256,
        _identity(7),
        _identity(9),
        plan.candidate_sha256,
        plan.candidate_size,
        0x80,
        "f" * 64,
        plan.temp_name,
    )
    created = durable.record_environment_temp_created(created_record)
    verified_record = EnvironmentTempVerifiedRecord(
        1,
        created.generation_sha256,
        _identity(7),
        created_record.temp_identity,
        created_record.candidate_sha256,
        created_record.candidate_size,
        created_record.candidate_file_attributes,
        created_record.candidate_security_descriptor_sha256,
        created_record.temp_name,
    )
    verified = durable.record_environment_temp_verified(verified_record)

    assert events == [
        "journal:1",
        "pointer:1",
        "journal:2",
        "pointer:2",
        "journal:3",
        "pointer:3",
    ]
    assert verified.record == verified_record
    assert len(storage_port.files) == 3

    events.clear()
    retried = durable.record_environment_temp_verified(verified_record)
    assert retried == verified
    assert events == []
    assert len(storage_port.files) == 3


def test_staging_journal_rejects_skipped_or_conflicting_transition() -> None:
    events: list[str] = []
    root = _Root(events)
    storage_port = _Storage(root, events)
    protection = _Protection()
    durable = _replacement_journal(root, storage_port, protection)
    plan = _plan()
    skipped = EnvironmentTempCreatedRecord(
        1,
        "0" * 64,
        _identity(7),
        _identity(9),
        plan.candidate_sha256,
        plan.candidate_size,
        0x80,
        "f" * 64,
        plan.temp_name,
    )

    with pytest.raises(replacement_journal.EnvironmentReplacementJournalError) as gap:
        durable.record_environment_temp_created(skipped)
    assert gap.value.code is (
        replacement_journal.EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID
    )

    durable.record_environment_temp_planned(plan)
    with pytest.raises(
        replacement_journal.EnvironmentReplacementJournalError
    ) as conflict:
        durable.record_environment_temp_planned(
            replace(plan, candidate_sha256="0" * 64)
        )
    assert conflict.value.code is (
        replacement_journal.EnvironmentReplacementJournalErrorCode.AUTHORITY_INVALID
    )
    assert len(storage_port.files) == 1


class _FixedNameSource:
    def new_environment_temp_name(self) -> str:
        return _TEMP


class _CandidateHandle:
    def __init__(self, identity: StableFileIdentity) -> None:
        self.identity = identity
        self.cursor = 0


class _CandidateApi:
    supported = True

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.exists = False
        self.identity = _identity(9)
        self.contents = b""
        self.attributes = 0x80
        self.descriptor = "f" * 64
        self.delete_error: Exception | None = None
        self.delete_error_after_apply = False

    def current_user_sid(self) -> str:
        return "S-1-5-21-1000"

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert path == rf"{_ROOT}\{_TEMP}"
        assert owner_sid == self.current_user_sid()
        self.events.append("temp:create")
        if self.exists:
            raise FileExistsError("private")
        self.exists = True
        self.identity = _identity(9)
        self.contents = b""
        return _CandidateHandle(self.identity)

    def open_existing_file_for_update(self, path: str) -> object:
        assert path == rf"{_ROOT}\{_TEMP}"
        self.events.append("temp:update")
        if not self.exists:
            raise FileNotFoundError("private")
        return _CandidateHandle(self.identity)

    def reopen_file_for_verification(self, path: str) -> object:
        assert path == rf"{_ROOT}\{_TEMP}"
        self.events.append("temp:reopen")
        if not self.exists:
            raise FileNotFoundError("private")
        return _CandidateHandle(self.identity)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        assert path == rf"{_ROOT}\{_TEMP}"
        self.events.append("temp:delete-open")
        return _CandidateHandle(self.identity) if self.exists else None

    def reopen_file_if_exists(self, path: str) -> object | None:
        assert path == rf"{_ROOT}\{_TEMP}"
        self.events.append("temp:presence")
        return _CandidateHandle(self.identity) if self.exists else None

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _CandidateHandle)
        return NativeFileFacts(
            rf"{_ROOT}\{_TEMP}",
            handle.identity.volume_serial,
            handle.identity.file_id,
            self.attributes,
            1,
            len(self.contents),
            100,
            200,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _CandidateHandle)
        return NativeSecurityFacts(
            self.current_user_sid(),
            True,
            (
                AccessAllowedAce(self.current_user_sid(), 0x001F01FF, 0),
                AccessAllowedAce("S-1-5-18", 0x001F01FF, 0),
            ),
            True,
            self.descriptor,
        )

    def write_file(self, handle: object, contents: bytes) -> int:
        assert isinstance(handle, _CandidateHandle)
        self.events.append("temp:write")
        end = handle.cursor + len(contents)
        self.contents = self.contents[: handle.cursor] + contents + self.contents[end:]
        handle.cursor = end
        return len(contents)

    def flush_file(self, handle: object) -> None:
        assert isinstance(handle, _CandidateHandle)
        self.events.append("temp:flush")

    def truncate_file(self, handle: object) -> None:
        assert isinstance(handle, _CandidateHandle)
        self.events.append("temp:truncate")
        self.contents = b""
        handle.cursor = 0

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _CandidateHandle)
        handle.cursor = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _CandidateHandle)
        chunk = self.contents[handle.cursor : handle.cursor + maximum]
        handle.cursor += len(chunk)
        return chunk

    def mark_file_for_deletion(self, handle: object) -> None:
        assert isinstance(handle, _CandidateHandle)
        self.events.append("temp:delete")
        if self.delete_error is not None and not self.delete_error_after_apply:
            raise self.delete_error
        self.exists = False
        if self.delete_error is not None:
            raise self.delete_error

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _CandidateHandle)


def _staging_request() -> tuple[object, EnvironmentDestinationObservation]:
    original = b"OTHER=value\r\n"
    plan = plan_ca_environment_replacement(original, original_present=True)
    observation = EnvironmentDestinationObservation(
        True,
        _identity(8),
        hashlib.sha256(original).hexdigest(),
        len(original),
        0x20,
        "e" * 64,
    )
    return plan, observation


def _stage_persisted(
    package_root: object,
    durable: replacement_journal.PersistedEnvironmentReplacementJournal,
    api: _CandidateApi,
) -> object:
    plan, original = _staging_request()
    return replacement_storage.stage_or_resume_persisted_environment_candidate(
        plan,  # type: ignore[arg-type]
        original,
        package_root,  # type: ignore[arg-type]
        durable,
        api=api,
        name_source=_FixedNameSource(),
    )


def _staging_arrangement() -> tuple[
    object,
    _Root,
    _Storage,
    _Protection,
    replacement_journal.PersistedEnvironmentReplacementJournal,
    _CandidateApi,
    list[str],
]:
    events: list[str] = []
    root = _Root(events)
    storage_port = _Storage(root, events)
    protection = _Protection()
    durable = _replacement_journal(root, storage_port, protection)
    package_root = capture_path_hierarchy(
        _ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_PathApi(),
    )
    return (
        package_root,
        root,
        storage_port,
        protection,
        durable,
        _CandidateApi(events),
        events,
    )


def _planned_record() -> EnvironmentTempPlanRecord:
    plan, original = _staging_request()
    return EnvironmentTempPlanRecord(
        1,
        _identity(7),
        plan.original_sha256,  # type: ignore[attr-defined]
        plan.candidate_sha256,  # type: ignore[attr-defined]
        len(plan.candidate_contents),  # type: ignore[attr-defined]
        _TEMP,
        True,
        original.identity,
        original.size,
        original.file_attributes,
        original.security_descriptor_sha256,
    )


def test_persisted_staging_creates_and_selects_complete_candidate() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    try:
        result = _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert (
        result.verified_receipt.record.candidate_sha256
        == hashlib.sha256(api.contents).hexdigest()
    )
    assert len(storage_port.files) == 3
    assert events == [
        "journal:1",
        "pointer:1",
        "temp:create",
        "journal:2",
        "pointer:2",
        "temp:write",
        "temp:flush",
        "temp:reopen",
        "journal:3",
        "pointer:3",
    ]


def test_planned_restart_removes_only_empty_private_orphan_then_recreates() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    durable.record_environment_temp_planned(_planned_record())
    api.exists = True
    api.identity = _identity(99)
    events.clear()
    try:
        _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert api.exists
    assert api.identity == _identity(9)
    assert len(storage_port.files) == 3
    assert events[:4] == [
        "temp:delete-open",
        "temp:delete",
        "temp:presence",
        "temp:create",
    ]


def test_planned_orphan_delete_error_is_reconciled_from_exact_absence() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    durable.record_environment_temp_planned(_planned_record())
    api.exists = True
    api.identity = _identity(99)
    api.delete_error = OSError("private")
    api.delete_error_after_apply = True
    events.clear()
    try:
        _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert api.exists
    assert api.identity == _identity(9)
    assert len(storage_port.files) == 3
    assert events[:4] == [
        "temp:delete-open",
        "temp:delete",
        "temp:presence",
        "temp:create",
    ]


def test_planned_orphan_failed_delete_preserves_exact_file_and_blocks() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    durable.record_environment_temp_planned(_planned_record())
    api.exists = True
    api.identity = _identity(99)
    api.delete_error = OSError("private")
    events.clear()
    try:
        with pytest.raises(
            replacement_storage.EnvironmentReplacementStorageError
        ) as failure:
            _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert failure.value.code is (
        replacement_storage.EnvironmentReplacementStorageErrorCode.WRITE_FAILED
    )
    assert api.exists
    assert "temp:create" not in events
    assert len(storage_port.files) == 1


def test_planned_nonempty_collision_is_preserved_without_delete_or_create() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    durable.record_environment_temp_planned(_planned_record())
    api.exists = True
    api.identity = _identity(99)
    api.contents = b"untrusted"
    events.clear()
    try:
        with pytest.raises(
            replacement_storage.EnvironmentReplacementStorageError
        ) as failure:
            _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert failure.value.code is (
        replacement_storage.EnvironmentReplacementStorageErrorCode.VERIFY_FAILED
    )
    assert api.exists
    assert api.contents == b"untrusted"
    assert "temp:delete" not in events
    assert "temp:create" not in events
    assert len(storage_port.files) == 1


def test_created_restart_rewrites_partial_exact_identity_without_recreating() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    planned = durable.record_environment_temp_planned(_planned_record())
    plan, _original = _staging_request()
    created_record = EnvironmentTempCreatedRecord(
        1,
        planned.generation_sha256,
        _identity(7),
        api.identity,
        plan.candidate_sha256,  # type: ignore[attr-defined]
        len(plan.candidate_contents),  # type: ignore[attr-defined]
        api.attributes,
        api.descriptor,
        _TEMP,
    )
    durable.record_environment_temp_created(created_record)
    api.exists = True
    api.contents = b"partial"
    events.clear()
    try:
        result = _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert result.verified_receipt.record.temp_identity == api.identity
    assert api.contents == plan.candidate_contents  # type: ignore[attr-defined]
    assert "temp:truncate" in events
    assert "temp:create" not in events
    assert "temp:delete" not in events
    assert len(storage_port.files) == 3


def test_created_restart_preserves_substituted_identity_without_rewrite() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    planned = durable.record_environment_temp_planned(_planned_record())
    plan, _original = _staging_request()
    created_record = EnvironmentTempCreatedRecord(
        1,
        planned.generation_sha256,
        _identity(7),
        api.identity,
        plan.candidate_sha256,  # type: ignore[attr-defined]
        len(plan.candidate_contents),  # type: ignore[attr-defined]
        api.attributes,
        api.descriptor,
        _TEMP,
    )
    durable.record_environment_temp_created(created_record)
    api.exists = True
    api.identity = _identity(99)
    api.contents = b"substituted"
    events.clear()
    try:
        with pytest.raises(
            replacement_storage.EnvironmentReplacementStorageError
        ) as failure:
            _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert failure.value.code is (
        replacement_storage.EnvironmentReplacementStorageErrorCode.VERIFY_FAILED
    )
    assert api.identity == _identity(99)
    assert api.contents == b"substituted"
    assert "temp:truncate" not in events
    assert "temp:write" not in events
    assert len(storage_port.files) == 2


def test_verified_restart_preserves_drift_and_never_rewrites() -> None:
    package_root, _root, storage_port, _protection, durable, api, events = (
        _staging_arrangement()
    )
    try:
        _stage_persisted(package_root, durable, api)
        api.contents = b"drift"
        events.clear()
        with pytest.raises(
            replacement_storage.EnvironmentReplacementStorageError
        ) as failure:
            _stage_persisted(package_root, durable, api)
    finally:
        package_root.close()  # type: ignore[attr-defined]

    assert failure.value.code is (
        replacement_storage.EnvironmentReplacementStorageErrorCode.VERIFY_FAILED
    )
    assert api.contents == b"drift"
    assert "temp:write" not in events
    assert "temp:truncate" not in events
    assert len(storage_port.files) == 3
