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
_TRANSITION_NAME = (
    "pointer-transition-0123456789abcdef0123456789abcdef-"
    "00000000000000000001.generation"
)
_POINTER_NAME = "journal-0123456789abcdef0123456789abcdef.pointer"
_POINTER_PATH = rf"{_ROOT}\{_POINTER_NAME}"
_POINTER_TEMP_NAME = ".journal-pointer-fedcba9876543210fedcba9876543210.tmp"
_POINTER_TEMP_PATH = rf"{_ROOT}\{_POINTER_TEMP_NAME}"
_USER_SID = "S-1-5-21-1000"
_SYSTEM_SID = "S-1-5-18"
_CONTENTS = b"protected-generation"
_POINTER_CONTENTS = b'{"generation_sha256":"pointer"}'


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
        self.expected_path = _PATH
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
        assert path == self.expected_path
        assert owner_sid == _USER_SID
        self.events.append("create")
        if self.create_error is not None:
            raise self.create_error
        self.created = True
        self.contents = b""
        return _Handle(self.identity, False)

    def reopen_file_for_verification(self, path: str) -> object:
        assert path == self.expected_path
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


@dataclass(slots=True)
class _PointerHandle:
    path: str
    identity: StableFileIdentity
    cursor: int = 0


class _PointerApi:
    supported = True

    def __init__(self) -> None:
        self.files: dict[str, tuple[StableFileIdentity, bytes]] = {
            _POINTER_PATH: (_identity("33"), b"old-pointer")
        }
        self.temp_identity = _identity("44")
        self.destination_identity: StableFileIdentity | None = None
        self.destination_contents: bytes | None = None
        self.destination_path: str | None = None
        self.destination_security: NativeSecurityFacts | None = None
        self.post_read_security: NativeSecurityFacts | None = None
        self.security_queries: dict[str, int] = {}
        self.leave_temp_after_move = False
        self.close_error: BaseException | None = None
        self.move_error: BaseException | None = None
        self.move_error_after_move: BaseException | None = None
        self.events: list[str] = []

    def current_user_sid(self) -> str:
        self.events.append("sid")
        return _USER_SID

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert path == _POINTER_TEMP_PATH
        assert owner_sid == _USER_SID
        self.events.append(f"create:{path}")
        if path in self.files:
            raise FileExistsError("collision")
        self.files[path] = (self.temp_identity, b"")
        return _PointerHandle(path, self.temp_identity)

    def reopen_file_for_verification(self, path: str) -> object:
        self.events.append(f"reopen:{path}")
        identity, _contents = self.files[path]
        return _PointerHandle(path, identity)

    def reopen_file_if_exists(self, path: str) -> object | None:
        self.events.append(f"optional:{path}")
        stored = self.files.get(path)
        if stored is None:
            return None
        identity, _contents = stored
        return _PointerHandle(path, identity)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"query:{handle.path}")
        identity, contents = self.files[handle.path]
        return NativeFileFacts(
            final_path=(
                self.destination_path
                if handle.path == _POINTER_PATH and self.destination_path is not None
                else handle.path
            ),
            volume_serial=identity.volume_serial,
            file_id=identity.file_id,
            attributes=0x80,
            link_count=1,
            size=len(contents),
            creation_time=100,
            last_write_time=200,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"security:{handle.path}")
        queries = self.security_queries.get(handle.path, 0) + 1
        self.security_queries[handle.path] = queries
        if queries > 1 and self.post_read_security is not None:
            return self.post_read_security
        if handle.path == _POINTER_PATH and self.destination_security is not None:
            return self.destination_security
        return _protected_security()

    def write_file(self, handle: object, contents: bytes) -> int:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"write:{handle.path}")
        identity, current = self.files[handle.path]
        updated = current[: handle.cursor] + contents
        self.files[handle.path] = (identity, updated)
        handle.cursor += len(contents)
        return len(contents)

    def flush_file(self, handle: object) -> None:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"flush:{handle.path}")

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"seek:{handle.path}")
        handle.cursor = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"read:{handle.path}")
        _identity_value, contents = self.files[handle.path]
        chunk = contents[handle.cursor : handle.cursor + maximum]
        handle.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PointerHandle)
        self.events.append(f"close:{handle.path}")
        if self.close_error is not None:
            raise self.close_error

    def move_file_replace_write_through(
        self,
        source_path: str,
        destination_path: str,
    ) -> None:
        assert source_path == _POINTER_TEMP_PATH
        assert destination_path == _POINTER_PATH
        self.events.append("move")
        if self.move_error is not None:
            raise self.move_error
        source = self.files[source_path]
        if not self.leave_temp_after_move:
            self.files.pop(source_path)
        identity, contents = source
        self.files[destination_path] = (
            self.destination_identity or identity,
            self.destination_contents or contents,
        )
        if self.move_error_after_move is not None:
            raise self.move_error_after_move


class _PointerNameSource:
    def new_pointer_temp_name(self) -> str:
        return _POINTER_TEMP_NAME


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


def test_generation_adapter_accepts_only_supported_generation_names() -> None:
    api = _Api()
    api.expected_path = rf"{_ROOT}\{_TRANSITION_NAME}"
    api.final_path = api.expected_path
    storage = native.NativeWindowsJournalGenerationStorage(api=api)

    stored = storage.create_generation(_ROOT, _TRANSITION_NAME, _CONTENTS)

    assert stored.contents == _CONTENTS
    invalid_code = RecoveryJournalStorageErrorCode.INPUT_INVALID
    for name in (
        "transition-" + "a" * 32 + "-00000000000000000001.generation",
        "pointer-transition-" + "a" * 32 + "-1.generation",
        "pointer-transition-" + "a" * 32 + "-00000000000000000001.tmp",
    ):
        with pytest.raises(RecoveryJournalStorageError) as invalid:
            storage.create_generation(_ROOT, name, _CONTENTS)
        assert invalid.value.code is invalid_code


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


def test_pointer_read_distinguishes_missing_from_verified_present() -> None:
    api = _PointerApi()
    api.files.pop(_POINTER_PATH)
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    assert storage.read_pointer(_ROOT, _POINTER_NAME, 1024) is None

    api.files[_POINTER_PATH] = (_identity("33"), _POINTER_CONTENTS)
    stored = storage.read_pointer(_ROOT, _POINTER_NAME, 1024)

    assert stored is not None
    assert stored.identity == _identity("33")
    assert stored.contents == _POINTER_CONTENTS


def test_pointer_replace_closes_temp_before_move_and_verifies_destination() -> None:
    api = _PointerApi()
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    stored = storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert stored.identity == api.temp_identity
    assert stored.contents == _POINTER_CONTENTS
    assert api.files == {_POINTER_PATH: (api.temp_identity, _POINTER_CONTENTS)}
    move_index = api.events.index("move")
    assert api.events[:move_index].count(f"close:{_POINTER_TEMP_PATH}") == 2
    assert api.events[move_index + 1] == f"optional:{_POINTER_TEMP_PATH}"
    assert f"reopen:{_POINTER_PATH}" in api.events[move_index + 2 :]


def test_pointer_read_rejects_security_drift_after_read() -> None:
    api = _PointerApi()
    api.files[_POINTER_PATH] = (_identity("33"), _POINTER_CONTENTS)
    api.post_read_security = NativeSecurityFacts(
        owner_sid=_USER_SID,
        dacl_present=True,
        allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
        dacl_protected=True,
    )
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    with pytest.raises(RecoveryJournalStorageError) as drifted:
        storage.read_pointer(_ROOT, _POINTER_NAME, 1024)

    assert drifted.value.code is RecoveryJournalStorageErrorCode.STORAGE_INVALID
    assert api.events[-1] == f"close:{_POINTER_PATH}"


def test_pointer_temp_names_are_unique_and_contract_safe() -> None:
    source = native.NativeJournalPointerTempNameSource()

    first = source.new_pointer_temp_name()
    second = source.new_pointer_temp_name()

    assert first != second
    assert first.startswith(".journal-pointer-")
    assert first.endswith(".tmp")
    assert len(first) == len(".journal-pointer-") + 32 + len(".tmp")


@pytest.mark.parametrize(
    "failure_mode",
    ("identity", "contents", "path", "security", "source-remains"),
)
def test_pointer_replace_rejects_post_move_drift(failure_mode: str) -> None:
    api = _PointerApi()
    if failure_mode == "identity":
        api.destination_identity = _identity("55")
    elif failure_mode == "contents":
        api.destination_contents = b"wrong-pointer"
    elif failure_mode == "path":
        api.destination_path = rf"{_ROOT}\other.pointer"
    elif failure_mode == "security":
        api.destination_security = NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
            dacl_protected=True,
        )
    else:
        api.leave_temp_after_move = True
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert failure.value.code is RecoveryJournalStorageErrorCode.VERIFY_FAILED


def test_pointer_move_failure_is_sanitized_and_process_control_propagates() -> None:
    api = _PointerApi()
    api.move_error = OSError("sensitive pointer path")
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert failure.value.code is RecoveryJournalStorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(failure.value)
    assert _POINTER_TEMP_PATH in api.files

    interruption = KeyboardInterrupt()
    api = _PointerApi()
    api.move_error = interruption
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )
    with pytest.raises(KeyboardInterrupt) as raised:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)
    assert raised.value is interruption


def test_pointer_move_error_accepts_only_exact_completed_move() -> None:
    api = _PointerApi()
    api.move_error_after_move = OSError("sensitive pointer path")
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    stored = storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert stored.identity == api.temp_identity
    assert stored.contents == _POINTER_CONTENTS
    assert _POINTER_TEMP_PATH not in api.files
    assert api.files[_POINTER_PATH] == (api.temp_identity, _POINTER_CONTENTS)


@pytest.mark.parametrize(
    "failure_mode",
    ("identity", "contents", "path", "security", "source-remains"),
)
def test_pointer_move_error_reconciliation_rejects_destination_drift(
    failure_mode: str,
) -> None:
    api = _PointerApi()
    api.move_error_after_move = OSError("sensitive pointer path")
    if failure_mode == "identity":
        api.destination_identity = _identity("55")
    elif failure_mode == "contents":
        api.destination_contents = b"wrong-pointer"
    elif failure_mode == "path":
        api.destination_path = rf"{_ROOT}\other.pointer"
    elif failure_mode == "security":
        api.destination_security = NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
            dacl_protected=True,
        )
    else:
        api.leave_temp_after_move = True
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert failure.value.code is RecoveryJournalStorageErrorCode.WRITE_FAILED
    assert "sensitive" not in str(failure.value)


def test_pointer_move_process_control_after_move_is_not_reconciled() -> None:
    interruption = KeyboardInterrupt()
    api = _PointerApi()
    api.move_error_after_move = interruption
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    with pytest.raises(KeyboardInterrupt) as raised:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert raised.value is interruption


def test_pointer_close_failure_prevents_move() -> None:
    api = _PointerApi()
    api.close_error = OSError("sensitive close detail")
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_PointerNameSource(),
    )

    with pytest.raises(RecoveryJournalStorageError) as failure:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)

    assert failure.value.code is RecoveryJournalStorageErrorCode.VERIFY_FAILED
    assert "move" not in api.events
    assert "sensitive" not in str(failure.value)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows ctypes errors")
def test_native_pointer_move_uses_only_replace_and_write_through_flags() -> None:
    class _Kernel:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, int]] = []

        def MoveFileExW(
            self,
            source_path: str,
            destination_path: str,
            flags: int,
        ) -> int:
            self.calls.append((source_path, destination_path, flags))
            return 1

    kernel = _Kernel()
    api = object.__new__(native.NativeWindowsJournalPointerApi)
    object.__setattr__(api, "_kernel32", kernel)
    object.__setattr__(api, "_pointer_file_api", object())

    api.move_file_replace_write_through(_POINTER_TEMP_PATH, _POINTER_PATH)

    assert kernel.calls == [(_POINTER_TEMP_PATH, _POINTER_PATH, 0x00000009)]


def test_pointer_adapter_rejects_untrusted_names_and_oversized_bytes() -> None:
    class _BadNameSource:
        def new_pointer_temp_name(self) -> str:
            return r"..\outside.tmp"

    api = _PointerApi()
    storage = native.NativeWindowsJournalPointerStorage(
        api=api,
        name_source=_BadNameSource(),
    )

    with pytest.raises(RecoveryJournalStorageError) as invalid_name:
        storage.replace_pointer(_ROOT, _POINTER_NAME, _POINTER_CONTENTS)
    assert invalid_name.value.code is RecoveryJournalStorageErrorCode.WRITE_FAILED
    assert api.events == []

    with pytest.raises(RecoveryJournalStorageError) as invalid_pointer:
        storage.read_pointer(_ROOT, r"..\outside.pointer", 1024)
    assert invalid_pointer.value.code is RecoveryJournalStorageErrorCode.INPUT_INVALID

    with pytest.raises(RecoveryJournalStorageError) as oversized:
        storage.replace_pointer(_ROOT, _POINTER_NAME, b"x" * 1025)
    assert oversized.value.code is RecoveryJournalStorageErrorCode.INPUT_INVALID


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_pointer_adapter_replaces_and_rereads_in_isolated_directory(
    tmp_path: Path,
) -> None:
    adapter = native.NativeWindowsJournalPointerStorage()
    root_path = str(tmp_path)
    pointer_name = _POINTER_NAME
    first = b'{"generation_sha256":"first"}'
    second = b'{"generation_sha256":"second"}'

    assert adapter.read_pointer(root_path, pointer_name, 1024) is None
    created = adapter.replace_pointer(root_path, pointer_name, first)
    assert adapter.read_pointer(root_path, pointer_name, 1024) == created

    replaced = adapter.replace_pointer(root_path, pointer_name, second)
    assert replaced.contents == second
    assert replaced.identity != created.identity
    assert adapter.read_pointer(root_path, pointer_name, 1024) == replaced
    assert not tuple(tmp_path.glob(".journal-pointer-*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_adapter_round_trip_in_isolated_temp_directory(tmp_path: Path) -> None:
    adapter = native.NativeWindowsJournalGenerationStorage()
    root_path = str(tmp_path)

    created = adapter.create_generation(root_path, _NAME, _CONTENTS)
    assert _NAME in adapter.list_names(root_path)
    loaded = adapter.read_generation(root_path, _NAME, len(_CONTENTS))

    assert loaded == created
    assert loaded.contents == _CONTENTS
