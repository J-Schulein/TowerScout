from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_environment_replacement_native as staging  # noqa: E402
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    plan_ca_environment_replacement,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_environment_restore import (  # noqa: E402
    EnvironmentDestinationObservation,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_PACKAGE_ROOT = r"C:\Users\reviewed-user\TowerScout"
_TEMP_NAME = ".towerscout-env-0123456789abcdef0123456789abcdef.tmp"
_TEMP_PATH = rf"{_PACKAGE_ROOT}\{_TEMP_NAME}"
_USER_SID = "S-1-5-21-1000"
_SYSTEM_SID = "S-1-5-18"
_CANDIDATE_SOURCE = b"OTHER=value\r\n"
_SECURITY_DESCRIPTOR_SHA256 = "a" * 64


def _identity(value: str) -> bytes:
    return hashlib.sha256(value.casefold().encode("utf-16-le")).digest()[:16]


@dataclass(frozen=True, slots=True)
class _PathHandle:
    path: str
    sequence: int


class _PathApi:
    supported = True

    def __init__(self) -> None:
        self.opened: list[_PathHandle] = []
        self.closed: list[_PathHandle] = []

    def current_user_sid(self) -> str:
        return _USER_SID

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        handle = _PathHandle(path, len(self.opened))
        self.opened.append(handle)
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, _PathHandle)
        return NativeDirectoryFacts(
            final_path=handle.path,
            volume_serial=7,
            file_id=_identity(handle.path),
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _PathHandle)
        return NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(),
        )

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PathHandle)
        self.closed.append(handle)


@dataclass(slots=True)
class _FileHandle:
    identity: StableFileIdentity
    cursor: int = 0


def _file_facts(
    *,
    identity: StableFileIdentity | None = None,
    contents: bytes = b"",
    final_path: str = _TEMP_PATH,
) -> NativeFileFacts:
    selected = identity or StableFileIdentity(7, bytes.fromhex("22" * 16))
    return NativeFileFacts(
        final_path=final_path,
        volume_serial=selected.volume_serial,
        file_id=selected.file_id,
        attributes=0x80,
        link_count=1,
        size=len(contents),
        creation_time=100,
        last_write_time=200,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


def _protected_file_security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=_USER_SID,
        dacl_present=True,
        allowed_aces=(
            AccessAllowedAce(_USER_SID, 0x001F01FF, 0),
            AccessAllowedAce(_SYSTEM_SID, 0x001F01FF, 0),
        ),
        dacl_protected=True,
        security_descriptor_sha256=_SECURITY_DESCRIPTOR_SHA256,
    )


def _original_observation() -> EnvironmentDestinationObservation:
    return EnvironmentDestinationObservation(
        True,
        StableFileIdentity(7, bytes.fromhex("33" * 16)),
        hashlib.sha256(_CANDIDATE_SOURCE).hexdigest(),
        len(_CANDIDATE_SOURCE),
        0x20,
        "b" * 64,
    )


class _StagingApi:
    supported = True

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.identity = StableFileIdentity(7, bytes.fromhex("22" * 16))
        self.contents = b""
        self.security = _protected_file_security()
        self.reopen_security: NativeSecurityFacts | None = None
        self.reopen_identity = self.identity
        self.written_attributes: int | None = None
        self.reopen_attributes: int | None = None
        self.reopened = False
        self.create_error: Exception | None = None
        self.readback_contents: bytes | None = None
        self.write_limit: int | None = None
        self.zero_progress = False
        self.flush_error: Exception | None = None
        self.closed = 0

    def current_user_sid(self) -> str:
        return _USER_SID

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert path == _TEMP_PATH
        assert owner_sid == _USER_SID
        self.events.append("api:create")
        if self.create_error is not None:
            raise self.create_error
        return _FileHandle(self.identity)

    def reopen_file_for_verification(self, path: str) -> object:
        assert path == _TEMP_PATH
        self.events.append("api:reopen")
        self.reopened = True
        return _FileHandle(self.reopen_identity)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _FileHandle)
        self.events.append("api:query")
        attributes = 0x80
        if self.reopened and self.reopen_attributes is not None:
            attributes = self.reopen_attributes
        elif self.contents and self.written_attributes is not None:
            attributes = self.written_attributes
        return replace(
            _file_facts(identity=handle.identity, contents=self.contents),
            attributes=attributes,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _FileHandle)
        self.events.append("api:security")
        if self.reopened and self.reopen_security is not None:
            return self.reopen_security
        return self.security

    def write_file(self, handle: object, contents: bytes) -> int:
        assert isinstance(handle, _FileHandle)
        self.events.append("api:write")
        if self.zero_progress:
            return 0
        amount = len(contents)
        if self.write_limit is not None:
            amount = min(amount, self.write_limit)
        self.contents += contents[:amount]
        handle.cursor += amount
        return amount

    def flush_file(self, handle: object) -> None:
        assert isinstance(handle, _FileHandle)
        self.events.append("api:flush")
        if self.flush_error is not None:
            raise self.flush_error

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _FileHandle)
        handle.cursor = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _FileHandle)
        self.events.append("api:read")
        contents = self.readback_contents or self.contents
        chunk = contents[handle.cursor : handle.cursor + maximum]
        handle.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _FileHandle)
        self.events.append("api:close")
        self.closed += 1


class _Journal:
    def __init__(self, events: list[str], *, fail_at: str | None = None) -> None:
        self.events = events
        self.fail_at = fail_at
        self.records: list[object] = []

    def record_environment_temp_planned(
        self, record: staging.EnvironmentTempPlanRecord
    ) -> staging.EnvironmentTempPlannedReceipt:
        self.events.append("journal:planned")
        self.records.append(record)
        if self.fail_at == "planned":
            raise OSError(_TEMP_PATH)
        return staging.EnvironmentTempPlannedReceipt(record, "1" * 64)

    def record_environment_temp_created(
        self, record: staging.EnvironmentTempCreatedRecord
    ) -> staging.EnvironmentTempCreatedReceipt:
        self.events.append("journal:created")
        self.records.append(record)
        if self.fail_at == "created":
            raise OSError(_TEMP_PATH)
        return staging.EnvironmentTempCreatedReceipt(record, "2" * 64)

    def record_environment_temp_verified(
        self, record: staging.EnvironmentTempVerifiedRecord
    ) -> staging.EnvironmentTempVerifiedReceipt:
        self.events.append("journal:verified")
        self.records.append(record)
        if self.fail_at == "verified":
            raise OSError(_TEMP_PATH)
        return staging.EnvironmentTempVerifiedReceipt(record, "3" * 64)


class _NameSource:
    def new_environment_temp_name(self) -> str:
        return _TEMP_NAME


def _stage(
    *,
    api: _StagingApi | None = None,
    journal: _Journal | None = None,
    original: EnvironmentDestinationObservation | None = None,
) -> tuple[staging.StagedEnvironmentCandidate, _StagingApi, list[str]]:
    events: list[str] = []
    selected_api = api or _StagingApi(events)
    selected_journal = journal or _Journal(events)
    root = capture_path_hierarchy(
        _PACKAGE_ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_PathApi(),
    )
    plan = plan_ca_environment_replacement(
        _CANDIDATE_SOURCE,
        original_present=True,
    )
    try:
        result = staging._stage_environment_candidate_with_api(
            plan,
            original or _original_observation(),
            root,
            selected_journal,
            api=selected_api,
            name_source=_NameSource(),
        )
    finally:
        root.close()
    return result, selected_api, events


def test_stage_orders_durable_journal_transitions_around_native_io() -> None:
    result, api, events = _stage()

    assert events == [
        "journal:planned",
        "api:create",
        "api:query",
        "api:security",
        "journal:created",
        "api:write",
        "api:flush",
        "api:query",
        "api:read",
        "api:close",
        "api:reopen",
        "api:query",
        "api:security",
        "api:read",
        "api:close",
        "journal:verified",
    ]
    assert (
        result.verified_receipt.record.candidate_sha256
        == hashlib.sha256(api.contents).hexdigest()
    )
    assert result.verified_receipt.record.candidate_file_attributes == 0x80
    assert (
        result.verified_receipt.record.candidate_security_descriptor_sha256
        == _SECURITY_DESCRIPTOR_SHA256
    )
    assert _TEMP_PATH not in repr(result)
    assert _TEMP_NAME not in repr(result)


@pytest.mark.parametrize(
    "original",
    (
        EnvironmentDestinationObservation(False),
        replace(
            _original_observation(),
            identity=StableFileIdentity(7, _identity(_PACKAGE_ROOT)),
        ),
        replace(_original_observation(), sha256="0" * 64),
        replace(_original_observation(), size=len(_CANDIDATE_SOURCE) + 1),
    ),
)
def test_original_authority_mismatch_blocks_before_journal_or_creation(
    original: EnvironmentDestinationObservation,
) -> None:
    events: list[str] = []
    api = _StagingApi(events)

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events), original=original)

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.INPUT_INVALID
    assert events == []


def test_planned_generation_binds_exact_original_observation() -> None:
    events: list[str] = []
    durable = _Journal(events)
    original = _original_observation()

    _stage(journal=durable, original=original)

    plan = durable.records[0]
    assert type(plan) is staging.EnvironmentTempPlanRecord
    assert plan.original_present
    assert plan.original_identity == original.identity
    assert plan.original_sha256 == original.sha256
    assert plan.original_size == original.size
    assert plan.original_file_attributes == original.file_attributes
    assert (
        plan.original_security_descriptor_sha256 == original.security_descriptor_sha256
    )


def test_planned_journal_failure_prevents_temp_creation() -> None:
    events: list[str] = []
    api = _StagingApi(events)

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events, fail_at="planned"))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.JOURNAL_FAILED
    assert events == ["journal:planned"]
    assert _TEMP_PATH not in str(failure.value)
    assert _TEMP_PATH not in repr(failure.value)


def test_created_journal_failure_prevents_first_write() -> None:
    events: list[str] = []
    api = _StagingApi(events)

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events, fail_at="created"))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.JOURNAL_FAILED
    assert "api:create" in events
    assert "api:write" not in events
    assert api.contents == b""
    assert api.closed == 1


def test_create_collision_is_sanitized_and_leaves_existing_name_untouched() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.create_error = FileExistsError(_TEMP_PATH)

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.CREATE_FAILED
    assert events == ["journal:planned", "api:create"]
    assert api.closed == 0
    assert failure.value.__context__ is None
    assert _TEMP_PATH not in str(failure.value)
    assert _TEMP_PATH not in repr(failure.value)


def test_partial_writes_are_completed_before_flush() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.write_limit = 7

    result, _, _ = _stage(api=api, journal=_Journal(events))

    assert api.contents
    assert (
        result.verified_receipt.record.candidate_sha256
        == hashlib.sha256(api.contents).hexdigest()
    )
    assert events.count("api:write") > 1
    assert events.index("api:flush") > max(
        index for index, event in enumerate(events) if event == "api:write"
    )


@pytest.mark.parametrize("failure_kind", ["zero_progress", "flush"])
def test_write_or_flush_failure_never_records_verified(
    failure_kind: str,
) -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.zero_progress = failure_kind == "zero_progress"
    api.flush_error = OSError(_TEMP_PATH) if failure_kind == "flush" else None

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.WRITE_FAILED
    assert "journal:verified" not in events
    assert api.closed == 1
    assert _TEMP_PATH not in str(failure.value)


def test_same_handle_readback_mismatch_blocks_reopen() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    expected_size = len(
        plan_ca_environment_replacement(
            _CANDIDATE_SOURCE,
            original_present=True,
        ).candidate_contents
    )
    api.readback_contents = b"X" * expected_size

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.VERIFY_FAILED
    assert "api:reopen" not in events
    assert "journal:verified" not in events
    assert api.closed == 1


def test_reopen_identity_drift_blocks_verified_record() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.reopen_identity = StableFileIdentity(7, bytes.fromhex("33" * 16))

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.VERIFY_FAILED
    assert "journal:verified" not in events
    assert api.closed == 2


def test_reopen_dacl_drift_blocks_verified_record() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.reopen_security = replace(_protected_file_security(), dacl_protected=False)

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.VERIFY_FAILED
    assert "journal:verified" not in events
    assert api.closed == 2


@pytest.mark.parametrize("phase", ["written", "reopened"])
def test_file_attribute_drift_blocks_verified_record(phase: str) -> None:
    events: list[str] = []
    api = _StagingApi(events)
    if phase == "written":
        api.written_attributes = 0x20
    else:
        api.reopen_attributes = 0x20

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.VERIFY_FAILED
    assert "journal:verified" not in events


def test_reopen_security_descriptor_drift_blocks_verified_record() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.reopen_security = replace(
        _protected_file_security(),
        security_descriptor_sha256="b" * 64,
    )

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.VERIFY_FAILED
    assert "journal:verified" not in events
    assert api.closed == 2


def test_missing_created_security_descriptor_digest_blocks_created_record() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.security = replace(
        _protected_file_security(),
        security_descriptor_sha256=None,
    )

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.SECURITY_FAILED
    assert "journal:created" not in events
    assert "api:write" not in events


@pytest.mark.parametrize(
    "security",
    [
        NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
            dacl_protected=True,
        ),
        NativeSecurityFacts(
            owner_sid="S-1-5-32-545",
            dacl_present=True,
            allowed_aces=(
                AccessAllowedAce(_USER_SID, 0x001F01FF, 0),
                AccessAllowedAce(_SYSTEM_SID, 0x001F01FF, 0),
            ),
            dacl_protected=True,
        ),
        replace(_protected_file_security(), dacl_protected=False),
    ],
)
def test_unsafe_created_security_blocks_created_journal_and_write(
    security: NativeSecurityFacts,
) -> None:
    events: list[str] = []
    api = _StagingApi(events)
    api.security = security

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.SECURITY_FAILED
    assert "journal:created" not in events
    assert "api:write" not in events
    assert api.closed == 1


def test_wrong_parent_or_volume_blocks_created_journal() -> None:
    events: list[str] = []
    api = _StagingApi(events)
    original_query = api.query_file

    def wrong_parent(handle: object) -> NativeFileFacts:
        return replace(original_query(handle), final_path=r"C:\Other\private.tmp")

    api.query_file = wrong_parent  # type: ignore[method-assign]

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.SECURITY_FAILED
    assert "journal:created" not in events


@pytest.mark.parametrize(
    "unsafe_facts",
    [
        replace(
            _file_facts(),
            attributes=0x00000480,
            reparse_tag=0xA000000C,
        ),
        replace(_file_facts(), link_count=2),
        replace(_file_facts(), drive_type=4),
    ],
)
def test_unsafe_leaf_state_blocks_created_journal(
    unsafe_facts: NativeFileFacts,
) -> None:
    events: list[str] = []
    api = _StagingApi(events)

    def query_unsafe(handle: object) -> NativeFileFacts:
        assert isinstance(handle, _FileHandle)
        api.events.append("api:query")
        return unsafe_facts

    api.query_file = query_unsafe  # type: ignore[method-assign]

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.SECURITY_FAILED
    assert "journal:created" not in events
    assert "api:write" not in events


def test_receipts_reject_mismatched_records() -> None:
    events: list[str] = []

    class _MismatchedJournal(_Journal):
        def record_environment_temp_planned(
            self, record: staging.EnvironmentTempPlanRecord
        ) -> staging.EnvironmentTempPlannedReceipt:
            self.events.append("journal:planned")
            different = replace(record, candidate_sha256="f" * 64)
            return staging.EnvironmentTempPlannedReceipt(different, "1" * 64)

    api = _StagingApi(events)
    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_MismatchedJournal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.JOURNAL_FAILED
    assert "api:create" not in events


def test_created_receipt_mismatch_blocks_first_write() -> None:
    events: list[str] = []

    class _MismatchedJournal(_Journal):
        def record_environment_temp_created(
            self, record: staging.EnvironmentTempCreatedRecord
        ) -> staging.EnvironmentTempCreatedReceipt:
            self.events.append("journal:created")
            different = replace(record, candidate_sha256="f" * 64)
            return staging.EnvironmentTempCreatedReceipt(different, "2" * 64)

    api = _StagingApi(events)
    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_MismatchedJournal(events))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.JOURNAL_FAILED
    assert "api:write" not in events
    assert api.contents == b""
    assert api.closed == 1


def test_verified_journal_failure_retains_closed_verified_temp() -> None:
    events: list[str] = []
    api = _StagingApi(events)

    with pytest.raises(staging.EnvironmentTempStageError) as failure:
        _stage(api=api, journal=_Journal(events, fail_at="verified"))

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.JOURNAL_FAILED
    assert events[-1] == "journal:verified"
    assert api.contents
    assert api.closed == 2
    assert _TEMP_NAME not in str(failure.value)
    assert _TEMP_NAME not in repr(failure.value)


def test_invalid_temp_name_blocks_journal_and_native_calls() -> None:
    events: list[str] = []
    root = capture_path_hierarchy(
        _PACKAGE_ROOT,
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_PathApi(),
    )
    plan = plan_ca_environment_replacement(
        _CANDIDATE_SOURCE,
        original_present=True,
    )

    class _BadNameSource:
        def new_environment_temp_name(self) -> str:
            return r"..\private.tmp"

    try:
        with pytest.raises(staging.EnvironmentTempStageError) as failure:
            staging._stage_environment_candidate_with_api(
                plan,
                _original_observation(),
                root,
                _Journal(events),
                api=_StagingApi(events),
                name_source=_BadNameSource(),
            )
    finally:
        root.close()

    assert failure.value.code is staging.EnvironmentTempStageErrorCode.INPUT_INVALID
    assert events == []


def test_native_temp_names_are_unique_and_contract_safe() -> None:
    source = staging.NativeEnvironmentTempNameSource()

    first = source.new_environment_temp_name()
    second = source.new_environment_temp_name()

    assert first != second
    assert first.startswith(".towerscout-env-")
    assert first.endswith(".tmp")
    assert len(first) == len(".towerscout-env-") + 32 + len(".tmp")


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_api_creates_writes_flushes_and_reopens_restrictive_file(
    tmp_path: Path,
) -> None:
    api = staging.NativeWindowsEnvironmentReplacementApi()
    path = (
        tmp_path / staging.NativeEnvironmentTempNameSource().new_environment_temp_name()
    )
    owner_sid = api.current_user_sid()
    contents = b"REQUESTS_CA_BUNDLE=/run/towerscout/ca/ca-bundle.crt\r\n"
    handle: object | None = None
    reopened: object | None = None
    try:
        handle = api.create_new_restricted_file(str(path), owner_sid=owner_sid)
        created = api.query_file(handle)
        security = api.query_security(handle)
        assert created.size == 0
        assert created.link_count == 1
        assert security.owner_sid.upper() == owner_sid.upper()
        assert security.dacl_present
        assert security.dacl_protected
        assert {ace.principal_sid.upper() for ace in security.allowed_aces} == {
            owner_sid.upper(),
            _SYSTEM_SID,
        }
        assert all(ace.access_mask == 0x001F01FF for ace in security.allowed_aces)
        assert all(ace.flags == 0 for ace in security.allowed_aces)
        assert security.security_descriptor_sha256 is not None

        assert api.write_file(handle, contents) == len(contents)
        api.flush_file(handle)
        api.seek_file(handle, 0)
        assert api.read_file(handle, len(contents)) == contents
        api.close_handle(handle)
        handle = None

        reopened = api.reopen_file_for_verification(str(path))
        verified = api.query_file(reopened)
        verified_security = api.query_security(reopened)
        assert StableFileIdentity(verified.volume_serial, verified.file_id) == (
            StableFileIdentity(created.volume_serial, created.file_id)
        )
        assert (
            verified_security.security_descriptor_sha256
            == security.security_descriptor_sha256
        )
        api.seek_file(reopened, 0)
        assert api.read_file(reopened, len(contents)) == contents
    finally:
        if reopened is not None:
            api.close_handle(reopened)
        if handle is not None:
            api.close_handle(handle)
        path.unlink(missing_ok=True)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_api_truncates_and_deletes_only_a_held_exact_temp(
    tmp_path: Path,
) -> None:
    api = staging.NativeWindowsEnvironmentReplacementApi()
    path = (
        tmp_path / staging.NativeEnvironmentTempNameSource().new_environment_temp_name()
    )
    handle: object | None = None
    try:
        handle = api.create_new_restricted_file(
            str(path),
            owner_sid=api.current_user_sid(),
        )
        created = api.query_file(handle)
        assert api.write_file(handle, b"partial") == len(b"partial")
        api.truncate_file(handle)
        truncated = api.query_file(handle)
        assert truncated.size == 0
        assert (truncated.volume_serial, truncated.file_id) == (
            created.volume_serial,
            created.file_id,
        )
        api.close_handle(handle)
        handle = None

        handle = api.open_file_for_delete_if_exists(str(path))
        assert handle is not None
        deleting = api.query_file(handle)
        assert (deleting.volume_serial, deleting.file_id) == (
            created.volume_serial,
            created.file_id,
        )
        api.mark_file_for_deletion(handle)
        api.close_handle(handle)
        handle = None
        assert api.reopen_file_if_exists(str(path)) is None
    finally:
        if handle is not None:
            api.close_handle(handle)
        path.unlink(missing_ok=True)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_stage_runs_under_retained_package_root_trust(tmp_path: Path) -> None:
    events: list[str] = []
    journal = _Journal(events)
    api = staging.NativeWindowsEnvironmentReplacementApi()
    temp_name = staging.NativeEnvironmentTempNameSource().new_environment_temp_name()
    native_path_api = NativeWindowsPathTrustApi()

    class _NativeHandlePathApi:
        supported = True

        def current_user_sid(self) -> str:
            return native_path_api.current_user_sid()

        def open_directory(self, path: str, *, follow_reparse: bool) -> object:
            return native_path_api.open_directory(
                path,
                follow_reparse=follow_reparse,
            )

        def query_directory(self, handle: object) -> NativeDirectoryFacts:
            return native_path_api.query_directory(handle)

        def query_security(self, handle: object) -> NativeSecurityFacts:
            del handle
            return NativeSecurityFacts(
                owner_sid=self.current_user_sid(),
                dacl_present=True,
                allowed_aces=(),
            )

        def close_handle(self, handle: object) -> None:
            native_path_api.close_handle(handle)

    class _SelectedNameSource:
        def new_environment_temp_name(self) -> str:
            return temp_name

    root = capture_path_hierarchy(
        str(tmp_path),
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_NativeHandlePathApi(),
    )
    plan = plan_ca_environment_replacement(
        _CANDIDATE_SOURCE,
        original_present=True,
    )
    path = tmp_path / temp_name
    try:
        result = staging._stage_environment_candidate_with_api(
            plan,
            _original_observation(),
            root,
            journal,
            api=api,
            name_source=_SelectedNameSource(),
        )

        assert events == ["journal:planned", "journal:created", "journal:verified"]
        assert path.read_bytes() == plan.candidate_contents
        assert result.verified_receipt.record.candidate_sha256 == (
            plan.candidate_sha256
        )
    finally:
        root.close()
        path.unlink(missing_ok=True)
