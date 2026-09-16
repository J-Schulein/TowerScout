from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_backup_storage as storage  # noqa: E402
import towerscout_launcher.windows_recovery_backup_storage_native as native  # noqa: E402
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeSecurityFacts,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    StableFileIdentity,
)

_ROOT = r"C:\Users\reviewed-user\AppData\Local\TowerScout\Recovery\v1"
_NAME = "recovery-backup-" + "1" * 32 + ".blob"
_PATH = rf"{_ROOT}\{_NAME}"
_USER_SID = "S-1-5-21-1000"
_SYSTEM_SID = "S-1-5-18"
_CIPHERTEXT = b"opaque-dpapi-ciphertext"


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
        self.create_error: BaseException | None = None
        self.reopen_error: BaseException | None = None
        self.identity = _identity("11")
        self.reopened_identity = self.identity
        self.contents = b""
        self.reopened_contents: bytes | None = None
        self.security = _protected_security()
        self.reopened_security: NativeSecurityFacts | None = None
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

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        assert path == _PATH
        assert owner_sid == _USER_SID
        self.events.append("create")
        if self.create_error is not None:
            raise self.create_error
        if self.created:
            raise FileExistsError("private collision path")
        self.created = True
        self.contents = b""
        return _Handle(self.identity, False)

    def reopen_file_for_verification(self, path: str) -> object:
        assert path == _PATH
        self.events.append("reopen")
        if self.reopen_error is not None:
            raise self.reopen_error
        return _Handle(self.reopened_identity, True)

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


def _blob(
    purpose: ProtectedDataPurpose = ProtectedDataPurpose.ENVIRONMENT_BACKUP,
) -> CurrentUserProtectedBlob:
    return CurrentUserProtectedBlob(purpose, _CIPHERTEXT)


def test_native_blob_create_flushes_and_verifies_both_handles() -> None:
    api = _Api()
    api.write_limit = 3
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)

    stored = adapter.create_backup_blob(_ROOT, _NAME, _blob())

    assert stored.name == _NAME
    assert stored.identity == api.identity
    assert stored.ciphertext_sha256 == _blob().ciphertext_sha256
    assert stored.ciphertext_size == len(_CIPHERTEXT)
    assert api.contents == _CIPHERTEXT
    assert api.events.index("flush") < api.events.index("reopen")
    assert api.events.count("close") == 2
    assert api.events.count("write") > 1
    assert api.events.count("query") == 5
    assert api.events.count("security") == 5


def test_native_blob_reverifies_exact_receipt_without_create() -> None:
    api = _Api()
    api.contents = _CIPHERTEXT
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)
    expected = storage.StoredRecoveryBackupBlob(
        _NAME,
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        api.identity,
        hashlib.sha256(_CIPHERTEXT).hexdigest(),
        len(_CIPHERTEXT),
    )

    verified = adapter.verify_backup_blob(_ROOT, expected)

    assert verified == expected
    assert "create" not in api.events
    assert api.events.count("reopen") == 1
    assert api.events.count("query") == 2
    assert api.events.count("security") == 2


def test_native_blob_reads_verified_ciphertext_as_purpose_bound_blob() -> None:
    api = _Api()
    api.contents = _CIPHERTEXT
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)
    expected = storage.StoredRecoveryBackupBlob(
        _NAME,
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        api.identity,
        hashlib.sha256(_CIPHERTEXT).hexdigest(),
        len(_CIPHERTEXT),
    )

    protected = adapter.read_backup_blob(_ROOT, expected)

    assert protected == _blob()
    assert "create" not in api.events
    assert api.events.count("reopen") == 1
    assert api.events.count("query") == 2
    assert api.events.count("security") == 2


@pytest.mark.parametrize(
    ("change", "value"),
    (
        ("reopened_identity", _identity("22")),
        ("reopened_path", rf"{_ROOT}\other.blob"),
        ("contents", b"x" * len(_CIPHERTEXT)),
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
def test_native_blob_reverification_rejects_exact_receipt_drift(
    change: str,
    value: object,
) -> None:
    api = _Api()
    api.contents = _CIPHERTEXT
    setattr(api, change, value)
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)
    expected = storage.StoredRecoveryBackupBlob(
        _NAME,
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        api.identity,
        hashlib.sha256(_CIPHERTEXT).hexdigest(),
        len(_CIPHERTEXT),
    )

    with pytest.raises(storage.RecoveryBackupStorageError) as failure:
        adapter.verify_backup_blob(_ROOT, expected)

    assert failure.value.code is storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    assert "create" not in api.events


def test_native_blob_reverification_failure_is_sanitized_and_control_propagates() -> (
    None
):
    expected = storage.StoredRecoveryBackupBlob(
        _NAME,
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        _identity("11"),
        hashlib.sha256(_CIPHERTEXT).hexdigest(),
        len(_CIPHERTEXT),
    )
    api = _Api()
    api.contents = _CIPHERTEXT
    api.reopen_error = OSError("private verification path")
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)

    with pytest.raises(storage.RecoveryBackupStorageError) as failure:
        adapter.verify_backup_blob(_ROOT, expected)
    assert failure.value.code is storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    assert "private" not in str(failure.value)

    interruption = KeyboardInterrupt()
    api = _Api()
    api.contents = _CIPHERTEXT
    api.reopen_error = interruption
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)
    with pytest.raises(KeyboardInterrupt) as raised:
        adapter.verify_backup_blob(_ROOT, expected)
    assert raised.value is interruption


def test_native_blob_rejects_untrusted_inputs_before_create() -> None:
    api = _Api()
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)

    for root_path, name, blob in (
        ("relative", _NAME, _blob()),
        (_ROOT, r"..\outside.blob", _blob()),
        (
            _ROOT,
            _NAME,
            CurrentUserProtectedBlob(
                ProtectedDataPurpose.JOURNAL_GENERATION,
                _CIPHERTEXT,
            ),
        ),
    ):
        with pytest.raises(storage.RecoveryBackupStorageError) as failure:
            adapter.create_backup_blob(root_path, name, blob)
        assert (
            failure.value.code is storage.RecoveryBackupStorageErrorCode.INPUT_INVALID
        )
    assert "create" not in api.events


@pytest.mark.parametrize(
    ("change", "value", "written"),
    (
        ("reopened_identity", _identity("22"), True),
        ("reopened_path", rf"{_ROOT}\other.blob", True),
        ("reopened_contents", b"tampered-ciphertext", True),
        ("drive_type", 4, False),
        ("file_type", 2, False),
        ("attributes", 0x400, False),
        ("reparse_tag", 0xA000000C, False),
        ("link_count", 2, False),
        (
            "reopened_security",
            NativeSecurityFacts(
                owner_sid=_USER_SID,
                dacl_present=True,
                allowed_aces=(AccessAllowedAce(_USER_SID, 0x001F01FF, 0),),
                dacl_protected=True,
            ),
            True,
        ),
    ),
)
def test_native_blob_preserves_and_rejects_unsafe_or_reopened_drift(
    change: str,
    value: object,
    written: bool,
) -> None:
    api = _Api()
    setattr(api, change, value)
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)

    with pytest.raises(storage.RecoveryBackupStorageError) as failure:
        adapter.create_backup_blob(_ROOT, _NAME, _blob())

    assert failure.value.code is storage.RecoveryBackupStorageErrorCode.VERIFY_FAILED
    assert api.created
    assert api.contents == (_CIPHERTEXT if written else b"")
    assert api.events[-1] == "close"


def test_native_blob_zero_progress_and_collision_preserve_artifact() -> None:
    api = _Api()
    api.zero_write = True
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)

    with pytest.raises(storage.RecoveryBackupStorageError) as stalled:
        adapter.create_backup_blob(_ROOT, _NAME, _blob())
    assert stalled.value.code is storage.RecoveryBackupStorageErrorCode.WRITE_FAILED
    assert api.created
    assert api.events[-1] == "close"

    api.zero_write = False
    with pytest.raises(storage.RecoveryBackupStorageError) as collision:
        adapter.create_backup_blob(_ROOT, _NAME, _blob())
    assert collision.value.code is storage.RecoveryBackupStorageErrorCode.WRITE_FAILED
    assert "private" not in str(collision.value)


def test_native_blob_dependency_failure_is_sanitized_and_control_propagates() -> None:
    api = _Api()
    api.supported_error = OSError("private support detail")
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)
    with pytest.raises(storage.RecoveryBackupStorageError) as unavailable:
        adapter.create_backup_blob(_ROOT, _NAME, _blob())
    assert (
        unavailable.value.code
        is storage.RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE
    )
    assert "private" not in str(unavailable.value)

    interruption = KeyboardInterrupt()
    api = _Api()
    api.create_error = interruption
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=api)
    with pytest.raises(KeyboardInterrupt) as raised:
        adapter.create_backup_blob(_ROOT, _NAME, _blob())
    assert raised.value is interruption


def test_native_blob_adapter_has_no_broad_file_capabilities() -> None:
    adapter = native.NativeWindowsRecoveryBackupBlobStorage(api=_Api())

    assert repr(adapter) == "NativeWindowsRecoveryBackupBlobStorage(<redacted>)"
    for method in ("list_names", "delete", "move", "replace", "restore"):
        assert not hasattr(adapter, method)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file APIs")
def test_native_blob_round_trip_and_collision_in_isolated_directory(
    tmp_path: Path,
) -> None:
    adapter = native.NativeWindowsRecoveryBackupBlobStorage()
    root_path = str(tmp_path)
    blob = _blob()

    stored = adapter.create_backup_blob(root_path, _NAME, blob)

    assert stored.ciphertext_sha256 == blob.ciphertext_sha256
    assert (tmp_path / _NAME).read_bytes() == blob.ciphertext
    with pytest.raises(storage.RecoveryBackupStorageError) as collision:
        adapter.create_backup_blob(root_path, _NAME, blob)
    assert collision.value.code is storage.RecoveryBackupStorageErrorCode.WRITE_FAILED
    assert (tmp_path / _NAME).read_bytes() == blob.ciphertext
