"""Native exact-file storage for encrypted Windows recovery backup blobs.

The adapter writes one already-protected blob under its exact planned leaf,
then verifies identity, bytes, locality, file type, and the protected current-
user/SYSTEM DACL on the creation handle and a no-follow reopen. It can later
reverify or read only an exact receipt, or delete only an authenticated planned
blob that exactly matches its recorded metadata.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
from typing import Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement_native import (
    NativeWindowsEnvironmentReplacementApi,
)
from .windows_path_trust import AccessAllowedAce, NativeSecurityFacts
from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_backup_storage import (
    PlannedRecoveryBackupBlob,
    RecoveryBackupStorageError,
    RecoveryBackupStorageErrorCode,
    StoredRecoveryBackupBlob,
)
from .windows_security import NativeFileFacts, StableFileIdentity

_MAX_PATH_CHARACTERS = 32_768
_MAX_PROTECTED_BACKUP_BYTES = 4 * 1024 * 1024
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_BACKUP_NAME = re.compile(r"^recovery-backup-[0-9a-f]{32}\.blob$")
_Result = TypeVar("_Result")


class _WindowsRecoveryBackupBlobApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object: ...

    def reopen_file_for_verification(self, path: str) -> object: ...

    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def write_file(self, handle: object, contents: bytes) -> int: ...

    def flush_file(self, handle: object) -> None: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...


class NativeWindowsRecoveryBackupBlobApi:
    """Restricted-file primitives without enumeration or replacement methods."""

    __slots__ = ("_files",)

    def __init__(self) -> None:
        self._files = NativeWindowsEnvironmentReplacementApi()

    @property
    def supported(self) -> bool:
        return self._files.supported

    def current_user_sid(self) -> str:
        return self._files.current_user_sid()

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        return self._files.create_new_restricted_file(path, owner_sid=owner_sid)

    def reopen_file_for_verification(self, path: str) -> object:
        return self._files.reopen_file_for_verification(path)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._files.open_file_for_delete_if_exists(path)

    def reopen_file_if_exists(self, path: str) -> object | None:
        return self._files.reopen_file_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._files.query_security(handle)

    def write_file(self, handle: object, contents: bytes) -> int:
        return self._files.write_file(handle, contents)

    def flush_file(self, handle: object) -> None:
        self._files.flush_file(handle)

    def seek_file(self, handle: object, offset: int) -> None:
        self._files.seek_file(handle, offset)

    def read_file(self, handle: object, maximum: int) -> bytes:
        return self._files.read_file(handle, maximum)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._files.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)


def _fail(code: RecoveryBackupStorageErrorCode) -> NoReturn:
    raise RecoveryBackupStorageError(code)


def _call(
    operation: Callable[[], _Result], code: RecoveryBackupStorageErrorCode
) -> _Result:
    try:
        return operation()
    except RecoveryBackupStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsRecoveryBackupBlobApi, handle: object) -> None:
    try:
        api.close_handle(handle)
    except BaseException:
        return


def _path_key(path: str) -> str:
    value = path
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _backup_path(root_path: str, name: str) -> str:
    if (
        type(root_path) is not str
        or not root_path
        or "\x00" in root_path
        or len(root_path) > _MAX_PATH_CHARACTERS
        or not ntpath.isabs(root_path)
        or type(name) is not str
        or _BACKUP_NAME.fullmatch(name) is None
    ):
        _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
    path = ntpath.join(root_path, name)
    if len(path) > _MAX_PATH_CHARACTERS or _path_key(ntpath.dirname(path)) != _path_key(
        root_path
    ):
        _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
    return path


def _current_user_sid(api: _WindowsRecoveryBackupBlobApi) -> str:
    sid = _call(
        api.current_user_sid,
        RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE,
    )
    if type(sid) is not str or _SID.fullmatch(sid) is None:
        _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
    return sid


def _validate_security(
    security: object,
    current_user_sid: str,
) -> None:
    if type(security) is not NativeSecurityFacts:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    allowed_aces = security.allowed_aces
    if any(type(ace) is not AccessAllowedAce for ace in allowed_aces):
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    accepted = {current_user_sid.upper(), _SYSTEM_SID}
    if (
        security.owner_sid.upper() != current_user_sid.upper()
        or not security.dacl_present
        or not security.dacl_protected
        or len(allowed_aces) != 2
        or {ace.principal_sid.upper() for ace in allowed_aces} != accepted
        or any(
            ace.access_mask != _FILE_ALL_ACCESS or ace.flags != 0
            for ace in allowed_aces
        )
    ):
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)


def _validate_file(
    facts: object,
    *,
    expected_path: str,
    expected_size: int,
    expected_identity: StableFileIdentity | None,
) -> StableFileIdentity:
    if type(facts) is not NativeFileFacts:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    try:
        identity = StableFileIdentity(facts.volume_serial, facts.file_id)
    except ValueError:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    if (
        _path_key(facts.final_path) != _path_key(expected_path)
        or _path_key(ntpath.dirname(facts.final_path))
        != _path_key(ntpath.dirname(expected_path))
        or facts.drive_type != 3
        or facts.file_type != 1
        or facts.attributes
        & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        or facts.reparse_tag != 0
        or facts.link_count != 1
        or facts.size != expected_size
        or (expected_identity is not None and identity != expected_identity)
    ):
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    return identity


def _write_all(
    api: _WindowsRecoveryBackupBlobApi,
    handle: object,
    contents: bytes,
) -> None:
    offset = 0
    while offset < len(contents):
        written = _call(
            lambda: api.write_file(handle, contents[offset:]),
            RecoveryBackupStorageErrorCode.WRITE_FAILED,
        )
        if type(written) is not int or not 0 < written <= len(contents) - offset:
            _fail(RecoveryBackupStorageErrorCode.WRITE_FAILED)
        offset += written


def _read_exact(
    api: _WindowsRecoveryBackupBlobApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        RecoveryBackupStorageErrorCode.VERIFY_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_verified(
    api: _WindowsRecoveryBackupBlobApi,
    handle: object,
    *,
    path: str,
    current_user_sid: str,
    expected_identity: StableFileIdentity,
    expected_size: int,
    expected_sha256: str,
    expected_contents: bytes | None = None,
) -> bytes:
    observed_identity = _validate_file(
        _call(
            lambda: api.query_file(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        expected_path=path,
        expected_size=expected_size,
        expected_identity=expected_identity,
    )
    _validate_security(
        _call(
            lambda: api.query_security(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        current_user_sid,
    )
    contents = _read_exact(api, handle, expected_size)
    if (
        expected_contents is not None
        and contents != expected_contents
        or hashlib.sha256(contents).hexdigest() != expected_sha256
    ):
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    _validate_file(
        _call(
            lambda: api.query_file(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        expected_path=path,
        expected_size=expected_size,
        expected_identity=observed_identity,
    )
    _validate_security(
        _call(
            lambda: api.query_security(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        current_user_sid,
    )
    return contents


class NativeWindowsRecoveryBackupBlobStorage:
    """Create, reverify, read, or narrowly delete one exact backup blob."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _WindowsRecoveryBackupBlobApi | None = None) -> None:
        self._api = NativeWindowsRecoveryBackupBlobApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsRecoveryBackupBlobStorage(<redacted>)"

    def create_backup_blob(
        self,
        root_path: str,
        name: str,
        blob: CurrentUserProtectedBlob,
    ) -> StoredRecoveryBackupBlob:
        supported = _call(
            lambda: self._api.supported,
            RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
        if (
            type(blob) is not CurrentUserProtectedBlob
            or blob.purpose
            not in {
                ProtectedDataPurpose.ENVIRONMENT_BACKUP,
                ProtectedDataPurpose.CERTIFICATE_BACKUP,
            }
            or not 1 <= len(blob.ciphertext) <= _MAX_PROTECTED_BACKUP_BYTES
        ):
            _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
        path = _backup_path(root_path, name)
        current_user_sid = _current_user_sid(self._api)
        handle = _call(
            lambda: self._api.create_new_restricted_file(
                path,
                owner_sid=current_user_sid,
            ),
            RecoveryBackupStorageErrorCode.WRITE_FAILED,
        )
        if handle is None:
            _fail(RecoveryBackupStorageErrorCode.WRITE_FAILED)
        created_handle: object | None = handle
        try:
            identity = _validate_file(
                _call(
                    lambda: self._api.query_file(handle),
                    RecoveryBackupStorageErrorCode.VERIFY_FAILED,
                ),
                expected_path=path,
                expected_size=0,
                expected_identity=None,
            )
            _validate_security(
                _call(
                    lambda: self._api.query_security(handle),
                    RecoveryBackupStorageErrorCode.VERIFY_FAILED,
                ),
                current_user_sid,
            )
            _write_all(self._api, handle, blob.ciphertext)
            _call(
                lambda: self._api.flush_file(handle),
                RecoveryBackupStorageErrorCode.WRITE_FAILED,
            )
            _read_verified(
                self._api,
                handle,
                path=path,
                current_user_sid=current_user_sid,
                expected_identity=identity,
                expected_size=len(blob.ciphertext),
                expected_sha256=blob.ciphertext_sha256,
                expected_contents=blob.ciphertext,
            )
            _call(
                lambda: self._api.close_handle(handle),
                RecoveryBackupStorageErrorCode.VERIFY_FAILED,
            )
            created_handle = None
        finally:
            if created_handle is not None:
                _safe_close(self._api, created_handle)

        reopened = _call(
            lambda: self._api.reopen_file_for_verification(path),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        )
        if reopened is None:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        reopened_handle: object | None = reopened
        try:
            _read_verified(
                self._api,
                reopened,
                path=path,
                current_user_sid=current_user_sid,
                expected_identity=identity,
                expected_size=len(blob.ciphertext),
                expected_sha256=blob.ciphertext_sha256,
                expected_contents=blob.ciphertext,
            )
            _call(
                lambda: self._api.close_handle(reopened),
                RecoveryBackupStorageErrorCode.VERIFY_FAILED,
            )
            reopened_handle = None
        finally:
            if reopened_handle is not None:
                _safe_close(self._api, reopened_handle)
        try:
            return StoredRecoveryBackupBlob(
                name,
                blob.purpose,
                identity,
                blob.ciphertext_sha256,
                len(blob.ciphertext),
            )
        except ValueError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)

    def verify_backup_blob(
        self,
        root_path: str,
        expected: StoredRecoveryBackupBlob,
    ) -> StoredRecoveryBackupBlob:
        self.read_backup_blob(root_path, expected)
        try:
            return StoredRecoveryBackupBlob(
                expected.name,
                expected.purpose,
                expected.identity,
                expected.ciphertext_sha256,
                expected.ciphertext_size,
            )
        except ValueError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)

    def read_backup_blob(
        self,
        root_path: str,
        expected: StoredRecoveryBackupBlob,
    ) -> CurrentUserProtectedBlob:
        supported = _call(
            lambda: self._api.supported,
            RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
        if type(expected) is not StoredRecoveryBackupBlob:
            _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
        path = _backup_path(root_path, expected.name)
        current_user_sid = _current_user_sid(self._api)
        reopened = _call(
            lambda: self._api.reopen_file_for_verification(path),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        )
        if reopened is None:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        reopened_handle: object | None = reopened
        try:
            contents = _read_verified(
                self._api,
                reopened,
                path=path,
                current_user_sid=current_user_sid,
                expected_identity=expected.identity,
                expected_size=expected.ciphertext_size,
                expected_sha256=expected.ciphertext_sha256,
            )
            _call(
                lambda: self._api.close_handle(reopened),
                RecoveryBackupStorageErrorCode.VERIFY_FAILED,
            )
            reopened_handle = None
        finally:
            if reopened_handle is not None:
                _safe_close(self._api, reopened_handle)
        try:
            blob = CurrentUserProtectedBlob(expected.purpose, contents)
        except ValueError:
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        if (
            blob.ciphertext_sha256 != expected.ciphertext_sha256
            or len(blob.ciphertext) != expected.ciphertext_size
        ):
            _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
        return blob

    def delete_backup_blob_if_exact_or_absent(
        self,
        root_path: str,
        expected: PlannedRecoveryBackupBlob,
    ) -> None:
        supported = _call(
            lambda: self._api.supported,
            RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
        if type(expected) is not PlannedRecoveryBackupBlob:
            _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
        path = _backup_path(root_path, expected.name)
        current_user_sid = _current_user_sid(self._api)
        handle = _call(
            lambda: self._api.open_file_for_delete_if_exists(path),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        )
        if handle is None:
            self.verify_backup_blob_absent(root_path, expected)
            return
        held: object | None = handle
        operation_failed = False
        try:
            _read_verified(
                self._api,
                handle,
                path=path,
                current_user_sid=current_user_sid,
                expected_identity=expected.identity,
                expected_size=expected.ciphertext_size,
                expected_sha256=expected.ciphertext_sha256,
            )
            try:
                self._api.mark_file_for_deletion(handle)
            except RecoveryBackupStorageError:
                raise
            except Exception:
                operation_failed = True
            try:
                self._api.close_handle(handle)
            except RecoveryBackupStorageError:
                raise
            except Exception:
                operation_failed = True
            else:
                held = None
        finally:
            if held is not None:
                _safe_close(self._api, held)
        remaining = _call(
            lambda: self._api.reopen_file_if_exists(path),
            RecoveryBackupStorageErrorCode.DELETE_FAILED,
        )
        if remaining is not None:
            _safe_close(self._api, remaining)
            _fail(
                RecoveryBackupStorageErrorCode.DELETE_FAILED
                if operation_failed
                else RecoveryBackupStorageErrorCode.VERIFY_FAILED
            )

    def verify_backup_blob_absent(
        self,
        root_path: str,
        expected: PlannedRecoveryBackupBlob,
    ) -> None:
        supported = _call(
            lambda: self._api.supported,
            RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryBackupStorageErrorCode.STORAGE_UNAVAILABLE)
        if type(expected) is not PlannedRecoveryBackupBlob:
            _fail(RecoveryBackupStorageErrorCode.INPUT_INVALID)
        path = _backup_path(root_path, expected.name)
        handle = _call(
            lambda: self._api.reopen_file_if_exists(path),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        )
        if handle is None:
            return
        _safe_close(self._api, handle)
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)


__all__ = [
    "NativeWindowsRecoveryBackupBlobApi",
    "NativeWindowsRecoveryBackupBlobStorage",
]
