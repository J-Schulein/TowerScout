"""Native create-only storage for encrypted Windows recovery backup blobs.

The adapter writes one already-protected blob under its exact planned leaf,
then verifies identity, bytes, locality, file type, and the protected current-
user/SYSTEM DACL on the creation handle and a no-follow reopen. It has no list,
delete, move, replace, restore, or mutation-adjacent operation.
"""

from __future__ import annotations

import ntpath
import re
from typing import Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement_native import (
    NativeWindowsEnvironmentReplacementApi,
)
from .windows_path_trust import AccessAllowedAce, NativeSecurityFacts
from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_backup_storage import (
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

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def write_file(self, handle: object, contents: bytes) -> int: ...

    def flush_file(self, handle: object) -> None: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def close_handle(self, handle: object) -> None: ...


class NativeWindowsRecoveryBackupBlobApi:
    """Restricted-file primitives without enumeration or mutation methods."""

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
    contents: bytes,
) -> None:
    _validate_file(
        _call(
            lambda: api.query_file(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        expected_path=path,
        expected_size=len(contents),
        expected_identity=expected_identity,
    )
    _validate_security(
        _call(
            lambda: api.query_security(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        current_user_sid,
    )
    if _read_exact(api, handle, len(contents)) != contents:
        _fail(RecoveryBackupStorageErrorCode.VERIFY_FAILED)
    _validate_file(
        _call(
            lambda: api.query_file(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        expected_path=path,
        expected_size=len(contents),
        expected_identity=expected_identity,
    )
    _validate_security(
        _call(
            lambda: api.query_security(handle),
            RecoveryBackupStorageErrorCode.VERIFY_FAILED,
        ),
        current_user_sid,
    )


class NativeWindowsRecoveryBackupBlobStorage:
    """Create and fully verify one exact encrypted backup blob."""

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
                contents=blob.ciphertext,
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
                contents=blob.ciphertext,
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


__all__ = [
    "NativeWindowsRecoveryBackupBlobApi",
    "NativeWindowsRecoveryBackupBlobStorage",
]
