"""Native Windows persistence for immutable recovery-journal generations.

This adapter implements only bounded enumeration and protected generation-file
create/read operations. Pointer replacement, cleanup, recovery, package-file
promotion, and runtime mutation remain outside this module.
"""

from __future__ import annotations

import ntpath
import os
import re
from typing import Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement_native import (
    NativeWindowsEnvironmentReplacementApi,
)
from .windows_path_trust import AccessAllowedAce, NativeSecurityFacts
from .windows_recovery_journal_storage import (
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    StoredJournalGenerationFile,
)
from .windows_security import NativeFileFacts, StableFileIdentity

_MAX_PATH_CHARACTERS = 32_768
_MAX_PROTECTED_GENERATION_BYTES = 4 * 1024 * 1024
_MAX_ROOT_ENTRIES = 256
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_GENERATION_NAME = re.compile(r"^journal-[0-9a-f]{32}-[0-9]{20}\.generation$")
_Result = TypeVar("_Result")


class _WindowsJournalGenerationApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def list_names(self, root_path: str, maximum: int) -> tuple[str, ...]: ...

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object: ...

    def reopen_file_for_verification(self, path: str) -> object: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def write_file(self, handle: object, contents: bytes) -> int: ...

    def flush_file(self, handle: object) -> None: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def close_handle(self, handle: object) -> None: ...


class NativeWindowsJournalGenerationApi:
    """Windows directory enumeration plus the reviewed restricted-file API."""

    __slots__ = ("_files",)

    def __init__(self) -> None:
        self._files = NativeWindowsEnvironmentReplacementApi()

    @property
    def supported(self) -> bool:
        return self._files.supported

    def current_user_sid(self) -> str:
        return self._files.current_user_sid()

    def list_names(self, root_path: str, maximum: int) -> tuple[str, ...]:
        if (
            not self.supported
            or type(root_path) is not str
            or not root_path
            or "\x00" in root_path
            or len(root_path) > _MAX_PATH_CHARACTERS
            or type(maximum) is not int
            or not 1 <= maximum <= _MAX_ROOT_ENTRIES + 1
        ):
            raise OSError("Native Windows recovery enumeration is unavailable.")
        names: list[str] = []
        with os.scandir(root_path) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) == maximum:
                    break
        return tuple(names)

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


def _fail(code: RecoveryJournalStorageErrorCode) -> NoReturn:
    raise RecoveryJournalStorageError(code)


def _call(
    operation: Callable[[], _Result],
    code: RecoveryJournalStorageErrorCode,
) -> _Result:
    try:
        return operation()
    except RecoveryJournalStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsJournalGenerationApi, handle: object) -> None:
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


def _validate_root_path(root_path: str) -> None:
    if (
        type(root_path) is not str
        or not root_path
        or "\x00" in root_path
        or len(root_path) > _MAX_PATH_CHARACTERS
        or not ntpath.isabs(root_path)
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)


def _generation_path(root_path: str, name: str) -> str:
    _validate_root_path(root_path)
    if type(name) is not str or _GENERATION_NAME.fullmatch(name) is None:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    path = ntpath.join(root_path, name)
    if len(path) > _MAX_PATH_CHARACTERS or _path_key(ntpath.dirname(path)) != _path_key(
        root_path
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return path


def _current_user_sid(
    api: _WindowsJournalGenerationApi,
    code: RecoveryJournalStorageErrorCode,
) -> str:
    sid = _call(api.current_user_sid, code)
    if type(sid) is not str or _SID.fullmatch(sid) is None:
        _fail(code)
    return sid


def _validate_security(
    security: object,
    current_user_sid: str,
    code: RecoveryJournalStorageErrorCode,
) -> None:
    if type(security) is not NativeSecurityFacts:
        _fail(code)
    allowed_aces = security.allowed_aces
    if any(type(ace) is not AccessAllowedAce for ace in allowed_aces):
        _fail(code)
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
        _fail(code)


def _validate_file(
    facts: object,
    *,
    expected_path: str,
    maximum_size: int,
    expected_size: int | None,
    expected_identity: StableFileIdentity | None,
    code: RecoveryJournalStorageErrorCode,
) -> tuple[StableFileIdentity, int]:
    if type(facts) is not NativeFileFacts:
        _fail(code)
    identity = StableFileIdentity(facts.volume_serial, facts.file_id)
    size_valid = (
        1 <= facts.size <= maximum_size
        if expected_size is None
        else facts.size == expected_size
    )
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
        or not size_valid
        or (expected_identity is not None and identity != expected_identity)
    ):
        _fail(code)
    return identity, facts.size


def _write_all(
    api: _WindowsJournalGenerationApi,
    handle: object,
    contents: bytes,
) -> None:
    offset = 0
    while offset < len(contents):
        written = _call(
            lambda: api.write_file(handle, contents[offset:]),
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        if type(written) is not int or not 0 < written <= len(contents) - offset:
            _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
        offset += written


def _read_exact(
    api: _WindowsJournalGenerationApi,
    handle: object,
    expected_size: int,
    code: RecoveryJournalStorageErrorCode,
) -> bytes:
    _call(lambda: api.seek_file(handle, 0), code)
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)), code
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(code)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class NativeWindowsJournalGenerationStorage:
    """Native protected-file implementation of the generation storage port."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _WindowsJournalGenerationApi | None = None) -> None:
        self._api = NativeWindowsJournalGenerationApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsJournalGenerationStorage(<redacted>)"

    def _require_supported(self) -> None:
        supported = _call(
            lambda: self._api.supported,
            RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)

    def list_names(self, root_path: str) -> tuple[str, ...]:
        self._require_supported()
        _validate_root_path(root_path)
        names = _call(
            lambda: self._api.list_names(root_path, _MAX_ROOT_ENTRIES + 1),
            RecoveryJournalStorageErrorCode.STORAGE_INVALID,
        )
        if (
            type(names) is not tuple
            or len(names) > _MAX_ROOT_ENTRIES
            or any(
                type(name) is not str or not name or "\x00" in name for name in names
            )
        ):
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        return names

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalGenerationFile:
        self._require_supported()
        if (
            type(maximum) is not int
            or not 1 <= maximum <= _MAX_PROTECTED_GENERATION_BYTES
        ):
            _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
        path = _generation_path(root_path, name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.STORAGE_INVALID,
        )
        handle = _call(
            lambda: self._api.reopen_file_for_verification(path),
            RecoveryJournalStorageErrorCode.STORAGE_INVALID,
        )
        if handle is None:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_INVALID)
        held: object | None = handle
        try:
            identity, size = _validate_file(
                _call(
                    lambda: self._api.query_file(handle),
                    RecoveryJournalStorageErrorCode.STORAGE_INVALID,
                ),
                expected_path=path,
                maximum_size=maximum,
                expected_size=None,
                expected_identity=None,
                code=RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            _validate_security(
                _call(
                    lambda: self._api.query_security(handle),
                    RecoveryJournalStorageErrorCode.STORAGE_INVALID,
                ),
                current_user_sid,
                RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            contents = _read_exact(
                self._api,
                handle,
                size,
                RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            _validate_file(
                _call(
                    lambda: self._api.query_file(handle),
                    RecoveryJournalStorageErrorCode.STORAGE_INVALID,
                ),
                expected_path=path,
                maximum_size=maximum,
                expected_size=size,
                expected_identity=identity,
                code=RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            _validate_security(
                _call(
                    lambda: self._api.query_security(handle),
                    RecoveryJournalStorageErrorCode.STORAGE_INVALID,
                ),
                current_user_sid,
                RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            _call(
                lambda: self._api.close_handle(handle),
                RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            held = None
        finally:
            if held is not None:
                _safe_close(self._api, held)
        return StoredJournalGenerationFile(identity, contents)

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalGenerationFile:
        self._require_supported()
        if (
            type(contents) is not bytes
            or not 1 <= len(contents) <= _MAX_PROTECTED_GENERATION_BYTES
        ):
            _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
        path = _generation_path(root_path, name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        handle = _call(
            lambda: self._api.create_new_restricted_file(
                path,
                owner_sid=current_user_sid,
            ),
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        if handle is None:
            _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
        created_handle: object | None = handle
        identity: StableFileIdentity
        try:
            identity, _size = _validate_file(
                _call(
                    lambda: self._api.query_file(handle),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                ),
                expected_path=path,
                maximum_size=_MAX_PROTECTED_GENERATION_BYTES,
                expected_size=0,
                expected_identity=None,
                code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            _validate_security(
                _call(
                    lambda: self._api.query_security(handle),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                ),
                current_user_sid,
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            _write_all(self._api, handle, contents)
            _call(
                lambda: self._api.flush_file(handle),
                RecoveryJournalStorageErrorCode.WRITE_FAILED,
            )
            _validate_file(
                _call(
                    lambda: self._api.query_file(handle),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                ),
                expected_path=path,
                maximum_size=_MAX_PROTECTED_GENERATION_BYTES,
                expected_size=len(contents),
                expected_identity=identity,
                code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            _validate_security(
                _call(
                    lambda: self._api.query_security(handle),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                ),
                current_user_sid,
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            if (
                _read_exact(
                    self._api,
                    handle,
                    len(contents),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                )
                != contents
            ):
                _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
            _call(
                lambda: self._api.close_handle(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            created_handle = None
        finally:
            if created_handle is not None:
                _safe_close(self._api, created_handle)

        reopened = _call(
            lambda: self._api.reopen_file_for_verification(path),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if reopened is None:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        reopened_handle: object | None = reopened
        try:
            _validate_file(
                _call(
                    lambda: self._api.query_file(reopened),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                ),
                expected_path=path,
                maximum_size=_MAX_PROTECTED_GENERATION_BYTES,
                expected_size=len(contents),
                expected_identity=identity,
                code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            _validate_security(
                _call(
                    lambda: self._api.query_security(reopened),
                    RecoveryJournalStorageErrorCode.VERIFY_FAILED,
                ),
                current_user_sid,
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            reopened_contents = _read_exact(
                self._api,
                reopened,
                len(contents),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            if reopened_contents != contents:
                _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
            _call(
                lambda: self._api.close_handle(reopened),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            reopened_handle = None
        finally:
            if reopened_handle is not None:
                _safe_close(self._api, reopened_handle)
        return StoredJournalGenerationFile(identity, reopened_contents)


__all__ = [
    "NativeWindowsJournalGenerationApi",
    "NativeWindowsJournalGenerationStorage",
]
