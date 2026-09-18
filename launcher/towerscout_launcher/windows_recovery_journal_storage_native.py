"""Native Windows persistence for recovery-journal generations and pointers.

This adapter implements bounded protected generation-file persistence,
same-volume metadata-pointer replacement, journal-bound pointer-temp
promotion, and exact empty planned-temp cleanup. Backup/recovery action,
package-file promotion, and runtime mutation remain outside this module.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import re
import secrets
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement_native import (
    NativeWindowsEnvironmentReplacementApi,
)
from .windows_path_trust import (
    AccessAllowedAce,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
)
from .windows_recovery_journal_storage import (
    RecoveryJournalStorageError,
    RecoveryJournalStorageErrorCode,
    StoredJournalGenerationFile,
    StoredJournalPointerFile,
)
from .windows_security import NativeFileFacts, NativeWindowsFileApi, StableFileIdentity

_MAX_PATH_CHARACTERS = 32_768
_MAX_PROTECTED_GENERATION_BYTES = 4 * 1024 * 1024
_MAX_POINTER_BYTES = 1_024
_MAX_ROOT_ENTRIES = 256
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_GENERATION_NAME = re.compile(
    r"^(?:journal|pointer-transition|repair)-[0-9a-f]{32}-[0-9]{20}\.generation$"
)
_POINTER_NAME = re.compile(r"^(?:journal|repair)-[0-9a-f]{32}\.pointer$")
_POINTER_TEMP_NAME = re.compile(r"^\.journal-pointer-[0-9a-f]{32}\.tmp$")
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_Result = TypeVar("_Result")


class _WindowsJournalInspectionApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def close_handle(self, handle: object) -> None: ...


class _WindowsJournalFileApi(_WindowsJournalInspectionApi, Protocol):

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object: ...

    def reopen_file_for_verification(self, path: str) -> object: ...

    def write_file(self, handle: object, contents: bytes) -> int: ...

    def flush_file(self, handle: object) -> None: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...


class _WindowsJournalGenerationApi(_WindowsJournalFileApi, Protocol):
    def list_names(self, root_path: str, maximum: int) -> tuple[str, ...]: ...


class _WindowsJournalPointerApi(_WindowsJournalFileApi, Protocol):
    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def move_file_replace_write_through(
        self,
        source_path: str,
        destination_path: str,
    ) -> None: ...


class _WindowsJournalPointerCleanupApi(_WindowsJournalInspectionApi, Protocol):
    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...


class JournalPointerTempNameSource(Protocol):
    def new_pointer_temp_name(self) -> str: ...


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


class NativeWindowsJournalPointerApi(NativeWindowsJournalGenerationApi):
    """Protected-file operations plus exact write-through pointer replacement."""

    __slots__ = ("_kernel32", "_pointer_file_api")

    def __init__(self) -> None:
        super().__init__()
        self._kernel32: Any | None = None
        self._pointer_file_api: NativeWindowsFileApi | None = None
        loader = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or loader is None:
            return
        try:
            self._pointer_file_api = NativeWindowsFileApi()
            self._kernel32 = loader("kernel32", use_last_error=True)
            self._bind_pointer_move()
        except (AttributeError, OSError, TypeError, ValueError):
            self._kernel32 = None
            self._pointer_file_api = None

    @property
    def supported(self) -> bool:
        return (
            super().supported
            and self._kernel32 is not None
            and self._pointer_file_api is not None
            and self._pointer_file_api.supported
        )

    def _require_pointer_api(self) -> tuple[Any, NativeWindowsFileApi]:
        if self._kernel32 is None or self._pointer_file_api is None:
            raise OSError("Native Windows journal pointer storage is unavailable.")
        return self._kernel32, self._pointer_file_api

    def _bind_pointer_move(self) -> None:
        kernel32, _file_api = self._require_pointer_api()
        kernel32.MoveFileExW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.MoveFileExW.restype = ctypes.c_int

    def reopen_file_if_exists(self, path: str) -> object | None:
        _kernel32, file_api = self._require_pointer_api()
        return file_api.open_file_if_exists(path)

    def move_file_replace_write_through(
        self,
        source_path: str,
        destination_path: str,
    ) -> None:
        if (
            type(source_path) is not str
            or not source_path
            or "\x00" in source_path
            or len(source_path) > _MAX_PATH_CHARACTERS
            or type(destination_path) is not str
            or not destination_path
            or "\x00" in destination_path
            or len(destination_path) > _MAX_PATH_CHARACTERS
        ):
            raise ValueError("Native Windows journal pointer move is invalid.")
        kernel32, _file_api = self._require_pointer_api()
        ctypes.set_last_error(0)
        if not kernel32.MoveFileExW(
            source_path,
            destination_path,
            _MOVEFILE_REPLACE_EXISTING | _MOVEFILE_WRITE_THROUGH,
        ):
            raise OSError(
                ctypes.get_last_error(),
                "Native Windows journal pointer move failed.",
            )


class NativeWindowsJournalPointerCleanupApi:
    """Native exact-leaf inspection and deletion without create/move methods."""

    __slots__ = ("_files", "_paths")

    def __init__(self) -> None:
        self._files = NativeWindowsFileApi()
        self._paths = NativeWindowsPathTrustApi()

    @property
    def supported(self) -> bool:
        return self._files.supported and self._paths.supported

    def current_user_sid(self) -> str:
        return self._paths.current_user_sid()

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._files.open_file_for_delete_if_exists(path)

    def reopen_file_if_exists(self, path: str) -> object | None:
        return self._files.open_file_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._paths.query_security(handle)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._files.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)


class NativeJournalPointerTempNameSource:
    def new_pointer_temp_name(self) -> str:
        return f".journal-pointer-{secrets.token_hex(16)}.tmp"


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


def _safe_close(api: _WindowsJournalInspectionApi, handle: object) -> None:
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


def _pointer_path(root_path: str, name: str) -> str:
    _validate_root_path(root_path)
    if type(name) is not str or _POINTER_NAME.fullmatch(name) is None:
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    path = ntpath.join(root_path, name)
    if len(path) > _MAX_PATH_CHARACTERS or _path_key(ntpath.dirname(path)) != _path_key(
        root_path
    ):
        _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
    return path


def _pointer_temp_path(root_path: str, name: object) -> str:
    _validate_root_path(root_path)
    if type(name) is not str or _POINTER_TEMP_NAME.fullmatch(name) is None:
        _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
    path = ntpath.join(root_path, name)
    if len(path) > _MAX_PATH_CHARACTERS or _path_key(ntpath.dirname(path)) != _path_key(
        root_path
    ):
        _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
    return path


def _current_user_sid(
    api: _WindowsJournalInspectionApi,
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
    api: _WindowsJournalFileApi,
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
    api: _WindowsJournalFileApi,
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


def _read_verified_pointer(
    api: _WindowsJournalFileApi,
    handle: object,
    *,
    path: str,
    current_user_sid: str,
    expected_size: int | None,
    expected_identity: StableFileIdentity | None,
    code: RecoveryJournalStorageErrorCode,
) -> StoredJournalPointerFile:
    identity, size = _validate_file(
        _call(lambda: api.query_file(handle), code),
        expected_path=path,
        maximum_size=_MAX_POINTER_BYTES,
        expected_size=expected_size,
        expected_identity=expected_identity,
        code=code,
    )
    _validate_security(
        _call(lambda: api.query_security(handle), code),
        current_user_sid,
        code,
    )
    contents = _read_exact(api, handle, size, code)
    _validate_file(
        _call(lambda: api.query_file(handle), code),
        expected_path=path,
        maximum_size=_MAX_POINTER_BYTES,
        expected_size=size,
        expected_identity=identity,
        code=code,
    )
    _validate_security(
        _call(lambda: api.query_security(handle), code),
        current_user_sid,
        code,
    )
    return StoredJournalPointerFile(identity, contents)


def _create_verified_pointer_temp(
    api: _WindowsJournalFileApi,
    *,
    temp_path: str,
    current_user_sid: str,
    contents: bytes,
) -> StoredJournalPointerFile:
    handle = _call(
        lambda: api.create_new_restricted_file(
            temp_path,
            owner_sid=current_user_sid,
        ),
        RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if handle is None:
        _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
    created_handle: object | None = handle
    temp_identity: StableFileIdentity
    try:
        temp_identity, _size = _validate_file(
            _call(
                lambda: api.query_file(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            ),
            expected_path=temp_path,
            maximum_size=_MAX_POINTER_BYTES,
            expected_size=0,
            expected_identity=None,
            code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            _call(
                lambda: api.query_security(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            ),
            current_user_sid,
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _write_all(api, handle, contents)
        _call(
            lambda: api.flush_file(handle),
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        same_handle = _read_verified_pointer(
            api,
            handle,
            path=temp_path,
            current_user_sid=current_user_sid,
            expected_size=len(contents),
            expected_identity=temp_identity,
            code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if same_handle.contents != contents:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(handle),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        created_handle = None
    finally:
        if created_handle is not None:
            _safe_close(api, created_handle)

    reopened = _call(
        lambda: api.reopen_file_for_verification(temp_path),
        RecoveryJournalStorageErrorCode.VERIFY_FAILED,
    )
    if reopened is None:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    reopened_handle: object | None = reopened
    try:
        stored = _read_verified_pointer(
            api,
            reopened,
            path=temp_path,
            current_user_sid=current_user_sid,
            expected_size=len(contents),
            expected_identity=temp_identity,
            code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if stored.contents != contents:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(reopened),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        reopened_handle = None
    finally:
        if reopened_handle is not None:
            _safe_close(api, reopened_handle)
    return stored


def _reconcile_completed_pointer_move(
    api: _WindowsJournalPointerApi,
    *,
    temp_path: str,
    destination_path: str,
    current_user_sid: str,
    temp_identity: StableFileIdentity,
    contents: bytes,
) -> StoredJournalPointerFile:
    source = _call(
        lambda: api.reopen_file_if_exists(temp_path),
        RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if source is not None:
        _call(
            lambda: api.close_handle(source),
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)

    destination = _call(
        lambda: api.reopen_file_if_exists(destination_path),
        RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if destination is None:
        _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
    held: object | None = destination
    try:
        stored = _read_verified_pointer(
            api,
            destination,
            path=destination_path,
            current_user_sid=current_user_sid,
            expected_size=len(contents),
            expected_identity=temp_identity,
            code=RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        if stored.contents != contents:
            _fail(RecoveryJournalStorageErrorCode.WRITE_FAILED)
        _call(
            lambda: api.close_handle(destination),
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return stored


def _verify_pointer_before_move(
    api: _WindowsJournalPointerApi,
    *,
    path: str,
    current_user_sid: str,
    expected: StoredJournalPointerFile | None,
) -> None:
    handle = _call(
        lambda: api.reopen_file_if_exists(path),
        RecoveryJournalStorageErrorCode.VERIFY_FAILED,
    )
    if expected is None:
        if handle is None:
            return
        _call(
            lambda: api.close_handle(handle),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    if handle is None:
        _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
    held: object | None = handle
    try:
        stored = _read_verified_pointer(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_size=len(expected.contents),
            expected_identity=expected.identity,
            code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if stored.contents != expected.contents:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        _call(
            lambda: api.close_handle(handle),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)


def _remove_verified_empty_pointer_temp(
    api: _WindowsJournalPointerCleanupApi,
    *,
    temp_path: str,
    current_user_sid: str,
) -> None:
    handle = _call(
        lambda: api.open_file_for_delete_if_exists(temp_path),
        RecoveryJournalStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return
    held: object | None = handle
    operation_failed = False
    try:
        identity, _size = _validate_file(
            _call(
                lambda: api.query_file(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            ),
            expected_path=temp_path,
            maximum_size=_MAX_POINTER_BYTES,
            expected_size=0,
            expected_identity=None,
            code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            _call(
                lambda: api.query_security(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            ),
            current_user_sid,
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _validate_file(
            _call(
                lambda: api.query_file(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            ),
            expected_path=temp_path,
            maximum_size=_MAX_POINTER_BYTES,
            expected_size=0,
            expected_identity=identity,
            code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _validate_security(
            _call(
                lambda: api.query_security(handle),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            ),
            current_user_sid,
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        try:
            api.mark_file_for_deletion(handle)
        except RecoveryJournalStorageError:
            raise
        except Exception:
            operation_failed = True
        try:
            api.close_handle(handle)
        except RecoveryJournalStorageError:
            raise
        except Exception:
            operation_failed = True
        else:
            held = None
    finally:
        if held is not None:
            _safe_close(api, held)

    remaining = _call(
        lambda: api.reopen_file_if_exists(temp_path),
        RecoveryJournalStorageErrorCode.WRITE_FAILED,
    )
    if remaining is not None:
        _safe_close(api, remaining)
        _fail(
            RecoveryJournalStorageErrorCode.WRITE_FAILED
            if operation_failed
            else RecoveryJournalStorageErrorCode.VERIFY_FAILED
        )


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


class NativeWindowsJournalPointerStorage:
    """Native protected-file implementation of the pointer storage port."""

    __slots__ = ("_api", "_name_source")

    def __init__(
        self,
        *,
        api: _WindowsJournalPointerApi | None = None,
        name_source: JournalPointerTempNameSource | None = None,
    ) -> None:
        self._api = NativeWindowsJournalPointerApi() if api is None else api
        self._name_source = (
            NativeJournalPointerTempNameSource() if name_source is None else name_source
        )

    def __repr__(self) -> str:
        return "NativeWindowsJournalPointerStorage(<redacted>)"

    def _require_supported(self) -> None:
        supported = _call(
            lambda: self._api.supported,
            RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)

    def read_pointer(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> StoredJournalPointerFile | None:
        self._require_supported()
        if type(maximum) is not int or not 1 <= maximum <= _MAX_POINTER_BYTES:
            _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
        path = _pointer_path(root_path, name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.STORAGE_INVALID,
        )
        handle = _call(
            lambda: self._api.reopen_file_if_exists(path),
            RecoveryJournalStorageErrorCode.STORAGE_INVALID,
        )
        if handle is None:
            return None
        held: object | None = handle
        try:
            stored = _read_verified_pointer(
                self._api,
                handle,
                path=path,
                current_user_sid=current_user_sid,
                expected_size=None,
                expected_identity=None,
                code=RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            _call(
                lambda: self._api.close_handle(handle),
                RecoveryJournalStorageErrorCode.STORAGE_INVALID,
            )
            held = None
        finally:
            if held is not None:
                _safe_close(self._api, held)
        return stored

    def replace_pointer(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalPointerFile:
        self._require_supported()
        if type(contents) is not bytes or not 1 <= len(contents) <= _MAX_POINTER_BYTES:
            _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
        destination_path = _pointer_path(root_path, name)
        temp_name = _call(
            self._name_source.new_pointer_temp_name,
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        temp_path = _pointer_temp_path(root_path, temp_name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        temp = _create_verified_pointer_temp(
            self._api,
            temp_path=temp_path,
            current_user_sid=current_user_sid,
            contents=contents,
        )
        temp_identity = temp.identity

        move_failed = False
        try:
            self._api.move_file_replace_write_through(
                temp_path,
                destination_path,
            )
        except RecoveryJournalStorageError:
            raise
        except Exception:
            move_failed = True
        if move_failed:
            return _reconcile_completed_pointer_move(
                self._api,
                temp_path=temp_path,
                destination_path=destination_path,
                current_user_sid=current_user_sid,
                temp_identity=temp_identity,
                contents=contents,
            )
        unexpected_temp = _call(
            lambda: self._api.reopen_file_if_exists(temp_path),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if unexpected_temp is not None:
            _safe_close(self._api, unexpected_temp)
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)

        destination = _call(
            lambda: self._api.reopen_file_for_verification(destination_path),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if destination is None:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        destination_handle: object | None = destination
        try:
            stored = _read_verified_pointer(
                self._api,
                destination,
                path=destination_path,
                current_user_sid=current_user_sid,
                expected_size=len(contents),
                expected_identity=temp_identity,
                code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            if stored.contents != contents:
                _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
            _call(
                lambda: self._api.close_handle(destination),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            destination_handle = None
        finally:
            if destination_handle is not None:
                _safe_close(self._api, destination_handle)
        return stored


class NativeWindowsJournalPointerTempStorage:
    """Create and verify exact pointer temps without promotion authority."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _WindowsJournalFileApi | None = None) -> None:
        self._api = NativeWindowsJournalGenerationApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsJournalPointerTempStorage(<redacted>)"

    def create_pointer_temp(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> StoredJournalPointerFile:
        supported = _call(
            lambda: self._api.supported,
            RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)
        if type(contents) is not bytes or not 1 <= len(contents) <= _MAX_POINTER_BYTES:
            _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
        temp_path = _pointer_temp_path(root_path, name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.WRITE_FAILED,
        )
        return _create_verified_pointer_temp(
            self._api,
            temp_path=temp_path,
            current_user_sid=current_user_sid,
            contents=contents,
        )


class NativeWindowsJournalPointerCleanupStorage:
    """Remove only an exact empty planned pointer temp by its held handle."""

    __slots__ = ("_api",)

    def __init__(
        self,
        *,
        api: _WindowsJournalPointerCleanupApi | None = None,
    ) -> None:
        self._api = NativeWindowsJournalPointerCleanupApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsJournalPointerCleanupStorage(<redacted>)"

    def remove_empty_pointer_temp_if_exists(
        self,
        root_path: str,
        name: str,
    ) -> None:
        supported = _call(
            lambda: self._api.supported,
            RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)
        temp_path = _pointer_temp_path(root_path, name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _remove_verified_empty_pointer_temp(
            self._api,
            temp_path=temp_path,
            current_user_sid=current_user_sid,
        )


class NativeWindowsJournalPointerPromotionStorage:
    """Promote one exact existing pointer temp without create/delete authority."""

    __slots__ = ("_api",)

    def __init__(self, *, api: _WindowsJournalPointerApi | None = None) -> None:
        self._api = NativeWindowsJournalPointerApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsJournalPointerPromotionStorage(<redacted>)"

    def promote_pointer_temp(
        self,
        root_path: str,
        source_name: str,
        destination_name: str,
        source_identity: StableFileIdentity,
        contents: bytes,
        expected_destination: StoredJournalPointerFile | None,
    ) -> StoredJournalPointerFile:
        supported = _call(
            lambda: self._api.supported,
            RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryJournalStorageErrorCode.STORAGE_UNAVAILABLE)
        if (
            type(source_identity) is not StableFileIdentity
            or type(contents) is not bytes
            or not 1 <= len(contents) <= _MAX_POINTER_BYTES
            or (
                expected_destination is not None
                and type(expected_destination) is not StoredJournalPointerFile
            )
        ):
            _fail(RecoveryJournalStorageErrorCode.INPUT_INVALID)
        source_path = _pointer_temp_path(root_path, source_name)
        destination_path = _pointer_path(root_path, destination_name)
        current_user_sid = _current_user_sid(
            self._api,
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        _verify_pointer_before_move(
            self._api,
            path=source_path,
            current_user_sid=current_user_sid,
            expected=StoredJournalPointerFile(source_identity, contents),
        )
        _verify_pointer_before_move(
            self._api,
            path=destination_path,
            current_user_sid=current_user_sid,
            expected=expected_destination,
        )

        move_failed = False
        try:
            self._api.move_file_replace_write_through(
                source_path,
                destination_path,
            )
        except RecoveryJournalStorageError:
            raise
        except Exception:
            move_failed = True
        if move_failed:
            return _reconcile_completed_pointer_move(
                self._api,
                temp_path=source_path,
                destination_path=destination_path,
                current_user_sid=current_user_sid,
                temp_identity=source_identity,
                contents=contents,
            )

        unexpected_source = _call(
            lambda: self._api.reopen_file_if_exists(source_path),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if unexpected_source is not None:
            _safe_close(self._api, unexpected_source)
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        destination = _call(
            lambda: self._api.reopen_file_for_verification(destination_path),
            RecoveryJournalStorageErrorCode.VERIFY_FAILED,
        )
        if destination is None:
            _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
        held: object | None = destination
        try:
            stored = _read_verified_pointer(
                self._api,
                destination,
                path=destination_path,
                current_user_sid=current_user_sid,
                expected_size=len(contents),
                expected_identity=source_identity,
                code=RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            if stored.contents != contents:
                _fail(RecoveryJournalStorageErrorCode.VERIFY_FAILED)
            _call(
                lambda: self._api.close_handle(destination),
                RecoveryJournalStorageErrorCode.VERIFY_FAILED,
            )
            held = None
        finally:
            if held is not None:
                _safe_close(self._api, held)
        return stored


__all__ = [
    "JournalPointerTempNameSource",
    "NativeJournalPointerTempNameSource",
    "NativeWindowsJournalGenerationApi",
    "NativeWindowsJournalGenerationStorage",
    "NativeWindowsJournalPointerApi",
    "NativeWindowsJournalPointerCleanupApi",
    "NativeWindowsJournalPointerCleanupStorage",
    "NativeWindowsJournalPointerPromotionStorage",
    "NativeWindowsJournalPointerStorage",
    "NativeWindowsJournalPointerTempStorage",
]
