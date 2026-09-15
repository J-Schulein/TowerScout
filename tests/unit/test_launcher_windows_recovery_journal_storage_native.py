from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_journal_storage_native as native  # noqa: E402
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeSecurityFacts,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_ROOT = r"C:\Users\reviewed-user\AppData\Local\TowerScout\Recovery\v1"
_NAME = "journal-0123456789abcdef0123456789abcdef-00000000000000000001.generation"
_PATH = rf"{_ROOT}\{_NAME}"
_USER_SID = "S-1-5-21-1000"
_SYSTEM_SID = "S-1-5-18"
_CONTENTS = b"protected-generation"


def _identity(fill: str) -> StableFileIdentity:
    return StableFileIdentity(7, bytes.fromhex(fill * 16))


def _protected_security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=_USER_SID,
        dacl_present=True,
        allowed_aces=(
            AccessAllowedAce(_USER_SID, 0x001F01FF, 0),
            AccessAllowedAce(_SYSTEM_SID, 0x001F01FF, 0),
        ),
        dacl_protected=True,
    )


@dataclass(slots=True)
class _Handle:
    identity: StableFileIdentity
    reopened: bool
    cursor: int = 0


class _Api:
    def __init__(self) -> None:
        self._supported = True
        self.supported_error: BaseException | None = None
        self.list_error: BaseException | None = None
        self.create_error: BaseException | None = None
        self.listed_names: tuple[str, ...] = (_NAME,)
        self.identity = _identity("11")
        self.reopen_identity = self.identity
        self.contents = _CONTENTS
        self.reopened_contents: bytes | None = None
        self.security = _protected_security()
        self.reopened_security: NativeSecurityFacts | None = None
        self.post_read_security: NativeSecurityFacts | None = None
        self.security_queries = 0
        self.final_path = _PATH
        self.reopened_path: str | None = None
        self.drive_type = 3
        self.file_type = 1
        self.attributes = 0x80
        self.reparse_tag = 0
        self.link_count = 1
        self.write_limit: int | None = None
        self.zero_write = False
        self.created = False
        self.events: list[str] = []

    @property
    def supported(self) -> bool:
        if self.supported_error is not None:
            raise self.supported_error
        return self._supported

    def current_user_sid(self) -> str:
        self.events.append("sid")
        return _USER_SID

    def list_names(self, root_path: str, maximum: int) -> tuple[str, ...]:
        assert root_path == _ROOT
        assert maximum == 257
        self.events.append("list")
        if self.list_error is not None:
            raise self.list_error
        return self.listed_names

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert path == _PATH
        assert owner_sid == _USER_SID
        self.events.append("create")
        if self.create_error is not None:
            raise self.create_error
        self.created = True
        self.contents = b""
        return _Handle(self.identity, False)

    def reopen_file_for_verification(self, path: str) -> object:
        assert path == _PATH
        self.events.append("reopen")
        return _Handle(self.reopen_identity, True)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _Handle)
        self.events.append("query")
        contents = self._readable_contents(handle)
        return NativeFileFacts(
            final_path=(
                (self.reopened_path or self.final_path)
                if handle.reopened
                else self.final_path
            ),
            volume_serial=handle.identity.volume_serial,
            file_id=handle.identity.file_id,
            attributes=self.attributes,
            link_count=self.link_count,
            size=len(contents),
            creation_time=100,
            last_write_time=200,
            drive_type=self.drive_type,
            file_type=self.file_type,
            reparse_tag=self.reparse_tag,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _Handle)
        self.events.append("security")
        self.security_queries += 1
        if self.security_queries > 1 and self.post_read_security is not None:
            return self.post_read_security
        if handle.reopened and self.reopened_security is not None:
            return self.reopened_security
        return self.security

    def write_file(self, handle: object, contents: bytes) -> int:
        assert isinstance(handle, _Handle)
        self.events.append("write")
        if self.zero_write:
            return 0
        amount = len(contents)
        if self.write_limit is not None:
            amount = min(amount, self.write_limit)
        self.contents += contents[:amount]
        handle.cursor += amount
        return amount

    def flush_file(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("flush")

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("seek")
        handle.cursor = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _Handle)
        self.events.append("read")
        contents = self._readable_contents(handle)
        chunk = contents[handle.cursor : handle.cursor + maximum]
        handle.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _Handle)
        self.events.append("close")

    def _readable_contents(self, handle: _Handle) -> bytes:
        if handle.reopened and self.reopened_contents is not None:
            return self.reopened_contents
        return self.contents


def test_list_names_is_bounded_and_requires_a_valid_absolute_root() -> None:
    api = _Api()
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    assert storage.list_names(_ROOT) == (_NAME,)

    api.listed_names = tuple(f"entry-{index}" for index in range(257))
    with pytest.raises(RecoveryJournalStorageError) as excessive:
        storage.list_names(_ROOT)
    assert excessive.value.code is RecoveryJournalStorageErrorCode.STORAGE_INVALID

    with pytest.raises(RecoveryJournalStorageError) as relative:
        storage.list_names("relative")
    assert relative.value.code is RecoveryJournalStorageErrorCode.INPUT_INVALID


def test_read_generation_verifies_identity_security_size_and_contents() -> None:
    api = _Api()
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    stored = storage.read_generation(_ROOT, _NAME, 1024)

    assert stored.identity == api.identity
    assert stored.contents == _CONTENTS
    assert api.events == [
        "sid",
        "reopen",
        "query",
        "security",
        "seek",
        "read",
        "query",
        "security",
        "close",
    ]


@pytest.mark.parametrize(
    ("change", "value"),
    (
        ("reopened_path", rf"{_ROOT}\other.generation"),
        ("drive_type", 4),
        ("file_type", 2),
        ("attributes", 0x400),
        ("reparse_tag", 0xA000000C),
        ("link_count", 2),
        (
            "reopened_security",
            NativeSecurityFacts(
                owner_sid=_USER_SID,
                dacl_present=True,
                allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
                dacl_protected=True,
            ),
        ),
    ),
)
def test_read_generation_rejects_unsafe_native_facts(
    change: str,
    value: object,
) -> None:
    api = _Api()
    setattr(api, change, value)
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    with pytest.raises(RecoveryJournalStorageError) as failure:
        storage.read_generation(_ROOT, _NAME, 1024)

    assert failure.value.code is RecoveryJournalStorageErrorCode.STORAGE_INVALID
    assert api.events[-1] == "close"


def test_read_generation_rejects_security_drift_after_read() -> None:
    api = _Api()
    api.post_read_security = NativeSecurityFacts(
        owner_sid=_USER_SID,
        dacl_present=True,
        allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
        dacl_protected=True,
    )
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    with pytest.raises(RecoveryJournalStorageError) as drifted:
        storage.read_generation(_ROOT, _NAME, 1024)

    assert drifted.value.code is RecoveryJournalStorageErrorCode.STORAGE_INVALID
    assert api.events[-1] == "close"


def test_create_generation_flushes_closes_reopens_and_rereads() -> None:
    api = _Api()
    api.write_limit = 3
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    stored = storage.create_generation(_ROOT, _NAME, _CONTENTS)

    assert stored.identity == api.identity
    assert stored.contents == _CONTENTS
    assert api.contents == _CONTENTS
    assert api.events.index("flush") < api.events.index("reopen")
    assert api.events.count("close") == 2
    assert api.events.count("write") > 1


@pytest.mark.parametrize("failure", ("identity", "contents", "security"))
def test_create_generation_rejects_reopened_drift(failure: str) -> None:
    api = _Api()
    if failure == "identity":
        api.reopen_identity = _identity("22")
    elif failure == "contents":
        api.reopened_contents = b"tampered-generation"
    else:
        api.reopened_security = NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
            dacl_protected=True,
        )
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    with pytest.raises(RecoveryJournalStorageError) as invalid:
        storage.create_generation(_ROOT, _NAME, _CONTENTS)

    assert invalid.value.code is RecoveryJournalStorageErrorCode.VERIFY_FAILED
    assert api.events[-1] == "close"


def test_create_generation_rejects_zero_progress_and_sanitizes_failure() -> None:
    api = _Api()
    api.zero_write = True
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    with pytest.raises(RecoveryJournalStorageError) as stalled:
        storage.create_generation(_ROOT, _NAME, _CONTENTS)

    assert stalled.value.code is RecoveryJournalStorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(stalled.value)
    assert api.events[-1] == "close"

    api = _Api()
    api.create_error = OSError("sensitive native detail")
    storage = native.NativeWindowsJournalGenerationStorage(api=api)
    with pytest.raises(RecoveryJournalStorageError) as failed:
        storage.create_generation(_ROOT, _NAME, _CONTENTS)
    assert failed.value.code is RecoveryJournalStorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(failed.value)


def test_adapter_dependency_failures_and_process_control_are_distinct() -> None:
    api = _Api()
    api.supported_error = RuntimeError("sensitive probe detail")
    storage = native.NativeWindowsJournalGenerationStorage(api=api)
    with pytest.raises(RecoveryJournalStorageError) as unavailable:
        storage.list_names(_ROOT)
    assert unavailable.value.code is RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE
    assert "sensitive" not in str(unavailable.value)

    interruption = KeyboardInterrupt()
    api = _Api()
    api.list_error = interruption
    storage = native.NativeWindowsJournalGenerationStorage(api=api)
    with pytest.raises(KeyboardInterrupt) as raised:
        storage.list_names(_ROOT)
    assert raised.value is interruption


def test_adapter_repr_redacts_native_dependency() -> None:
    adapter = native.NativeWindowsJournalGenerationStorage(api=_Api())

    assert repr(adapter) == "NativeWindowsJournalGenerationStorage(<redacted>)"
    assert _ROOT not in repr(adapter)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_adapter_round_trip_in_isolated_temp_directory(tmp_path: Path) -> None:
    adapter = native.NativeWindowsJournalGenerationStorage()
    root_path = str(tmp_path)

    created = adapter.create_generation(root_path, _NAME, _CONTENTS)
    assert _NAME in adapter.list_names(root_path)
    loaded = adapter.read_generation(root_path, _NAME, len(_CONTENTS))

    assert loaded == created
    assert loaded.contents == _CONTENTS
