"""Native protected storage for journal-bound certificate restore temps."""

from __future__ import annotations

import hashlib
import ntpath
import re
import threading
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Callable, NoReturn, Protocol, TypeVar

from .windows_environment_replacement_native import (
    NativeWindowsEnvironmentReplacementApi,
)
from .windows_path_trust import (
    AccessAllowedAce,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
)
from .windows_recovery_certificate_storage import (
    CertificateRestoreTempIdentities,
    RecoveryCertificateStorageError,
    RecoveryCertificateStorageErrorCode,
)
from .windows_recovery_certificate_restore import (
    CertificateDestinationRestoreAuthority,
    CertificateRestorationAuthority,
)
from .windows_recovery_journal import (
    CertificateRestoreTempCreatedRecord,
    CertificateRestoreTempPlanRecord,
    CertificateRestoreTempVerifiedRecord,
)
from .windows_security import NativeFileFacts, NativeWindowsFileApi, StableFileIdentity

_MAX_PATH_CHARACTERS = 32_768
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_TEMP_NAME = re.compile(r"^recovery-certificate-[0-9a-f]{32}\.tmp$")
_Result = TypeVar("_Result")


class _WindowsRecoveryCertificateTempApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object: ...

    def open_existing_file_for_update(self, path: str) -> object: ...

    def reopen_file_for_verification(self, path: str) -> object: ...

    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def flush_file(self, handle: object) -> None: ...

    def write_file(self, handle: object, contents: bytes) -> int: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...


class NativeWindowsRecoveryCertificateTempApi:
    """Restricted Windows primitives for certificate staging only."""

    __slots__ = ("_creation", "_files", "_paths")

    def __init__(self) -> None:
        self._creation = NativeWindowsEnvironmentReplacementApi()
        self._files = NativeWindowsFileApi()
        self._paths = NativeWindowsPathTrustApi()

    @property
    def supported(self) -> bool:
        return (
            self._creation.supported and self._files.supported and self._paths.supported
        )

    def current_user_sid(self) -> str:
        return self._paths.current_user_sid()

    def create_new_restricted_file(self, path: str, *, owner_sid: str) -> object:
        return self._creation.create_new_restricted_file(path, owner_sid=owner_sid)

    def open_existing_file_for_update(self, path: str) -> object:
        return self._creation.open_existing_file_for_update(path)

    def reopen_file_for_verification(self, path: str) -> object:
        return self._files.open_file_for_identity(path)

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._files.open_file_for_delete_if_exists(path)

    def reopen_file_if_exists(self, path: str) -> object | None:
        return self._files.open_file_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._paths.query_security(handle)

    def flush_file(self, handle: object) -> None:
        self._creation.flush_file(handle)

    def write_file(self, handle: object, contents: bytes) -> int:
        return self._creation.write_file(handle, contents)

    def seek_file(self, handle: object, offset: int) -> None:
        self._creation.seek_file(handle, offset)

    def read_file(self, handle: object, maximum: int) -> bytes:
        return self._creation.read_file(handle, maximum)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._files.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)


def _fail(code: RecoveryCertificateStorageErrorCode) -> NoReturn:
    raise RecoveryCertificateStorageError(code)


def _call(
    operation: Callable[[], _Result],
    code: RecoveryCertificateStorageErrorCode,
) -> _Result:
    try:
        return operation()
    except RecoveryCertificateStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsRecoveryCertificateTempApi, handle: object) -> None:
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


def _temp_path(root_path: str, name: object) -> str:
    if (
        type(root_path) is not str
        or not root_path
        or "\x00" in root_path
        or len(root_path) > _MAX_PATH_CHARACTERS
        or not ntpath.isabs(root_path)
        or type(name) is not str
        or _TEMP_NAME.fullmatch(name) is None
    ):
        _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
    path = ntpath.join(root_path, name)
    if len(path) > _MAX_PATH_CHARACTERS or _path_key(ntpath.dirname(path)) != _path_key(
        root_path
    ):
        _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
    return path


def _current_user_sid(api: _WindowsRecoveryCertificateTempApi) -> str:
    sid = _call(
        api.current_user_sid,
        RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE,
    )
    if type(sid) is not str or _SID.fullmatch(sid) is None:
        _fail(RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE)
    return sid


def _validate_security(security: object, current_user_sid: str) -> None:
    if type(security) is not NativeSecurityFacts:
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    accepted = {current_user_sid.upper(), _SYSTEM_SID}
    if (
        security.owner_sid.upper() != current_user_sid.upper()
        or not security.dacl_present
        or not security.dacl_protected
        or len(security.allowed_aces) != 2
        or {ace.principal_sid.upper() for ace in security.allowed_aces} != accepted
        or any(
            type(ace) is not AccessAllowedAce
            or ace.access_mask != _FILE_ALL_ACCESS
            or ace.flags != 0
            for ace in security.allowed_aces
        )
    ):
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)


def _inspect(
    api: _WindowsRecoveryCertificateTempApi,
    handle: object,
    *,
    path: str,
    current_user_sid: str,
    expected_identity: StableFileIdentity | None,
    expected_size: int,
) -> StableFileIdentity:
    facts = _call(
        lambda: api.query_file(handle),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )
    if type(facts) is not NativeFileFacts:
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    try:
        identity = StableFileIdentity(facts.volume_serial, facts.file_id)
    except ValueError:
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    if (
        _path_key(facts.final_path) != _path_key(path)
        or _path_key(ntpath.dirname(facts.final_path))
        != _path_key(ntpath.dirname(path))
        or facts.drive_type != 3
        or facts.file_type != 1
        or facts.attributes
        & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        or facts.reparse_tag != 0
        or facts.link_count != 1
        or facts.size != expected_size
        or (expected_identity is not None and identity != expected_identity)
    ):
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    _validate_security(
        _call(
            lambda: api.query_security(handle),
            RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
        ),
        current_user_sid,
    )
    return identity


def _close_verified(
    api: _WindowsRecoveryCertificateTempApi,
    handle: object,
) -> None:
    _call(
        lambda: api.close_handle(handle),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )


def _create_one(
    api: _WindowsRecoveryCertificateTempApi,
    *,
    path: str,
    current_user_sid: str,
) -> StableFileIdentity:
    handle = _call(
        lambda: api.create_new_restricted_file(path, owner_sid=current_user_sid),
        RecoveryCertificateStorageErrorCode.CREATE_FAILED,
    )
    if handle is None:
        _fail(RecoveryCertificateStorageErrorCode.CREATE_FAILED)
    held: object | None = handle
    try:
        identity = _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=None,
            expected_size=0,
        )
        _call(
            lambda: api.flush_file(handle),
            RecoveryCertificateStorageErrorCode.CREATE_FAILED,
        )
        _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            expected_size=0,
        )
        _close_verified(api, handle)
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return _verify_one(
        api,
        path=path,
        current_user_sid=current_user_sid,
        expected_identity=identity,
        expected_size=0,
        expected_sha256=hashlib.sha256(b"").hexdigest(),
    )


def _remove_zero_orphan(
    api: _WindowsRecoveryCertificateTempApi,
    *,
    path: str,
    current_user_sid: str,
) -> bool:
    handle = _call(
        lambda: api.open_file_for_delete_if_exists(path),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return False
    held: object | None = handle
    try:
        identity = _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=None,
            expected_size=0,
        )
        _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            expected_size=0,
        )
        _call(
            lambda: api.mark_file_for_deletion(handle),
            RecoveryCertificateStorageErrorCode.CLEANUP_FAILED,
        )
        _call(
            lambda: api.close_handle(handle),
            RecoveryCertificateStorageErrorCode.CLEANUP_FAILED,
        )
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    remaining = _call(
        lambda: api.reopen_file_if_exists(path),
        RecoveryCertificateStorageErrorCode.CLEANUP_FAILED,
    )
    if remaining is not None:
        _safe_close(api, remaining)
        _fail(RecoveryCertificateStorageErrorCode.CLEANUP_FAILED)
    return True


def _create_with_reconciliation(
    api: _WindowsRecoveryCertificateTempApi,
    *,
    path: str,
    current_user_sid: str,
) -> StableFileIdentity:
    try:
        return _create_one(
            api,
            path=path,
            current_user_sid=current_user_sid,
        )
    except RecoveryCertificateStorageError as error:
        if error.code is not RecoveryCertificateStorageErrorCode.CREATE_FAILED:
            raise
    if not _remove_zero_orphan(
        api,
        path=path,
        current_user_sid=current_user_sid,
    ):
        _fail(RecoveryCertificateStorageErrorCode.CREATE_FAILED)
    return _create_one(api, path=path, current_user_sid=current_user_sid)


def _read_exact(
    api: _WindowsRecoveryCertificateTempApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _verify_one(
    api: _WindowsRecoveryCertificateTempApi,
    *,
    path: str,
    current_user_sid: str,
    expected_identity: StableFileIdentity,
    expected_size: int,
    expected_sha256: str,
) -> StableFileIdentity:
    handle = _call(
        lambda: api.reopen_file_for_verification(path),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    held: object | None = handle
    try:
        identity = _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=expected_identity,
            expected_size=expected_size,
        )
        if hashlib.sha256(_read_exact(api, handle, expected_size)).hexdigest() != (
            expected_sha256
        ):
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            expected_size=expected_size,
        )
        _close_verified(api, handle)
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return identity


def _write_all(
    api: _WindowsRecoveryCertificateTempApi,
    handle: object,
    contents: bytes,
) -> None:
    offset = 0
    while offset < len(contents):
        written = _call(
            lambda: api.write_file(handle, contents[offset:]),
            RecoveryCertificateStorageErrorCode.WRITE_FAILED,
        )
        if type(written) is not int or not 0 < written <= len(contents) - offset:
            _fail(RecoveryCertificateStorageErrorCode.WRITE_FAILED)
        offset += written


def _write_one(
    api: _WindowsRecoveryCertificateTempApi,
    *,
    path: str,
    current_user_sid: str,
    expected_identity: StableFileIdentity,
    contents: bytes,
    expected_sha256: str,
) -> StableFileIdentity:
    handle = _call(
        lambda: api.open_existing_file_for_update(path),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    held: object | None = handle
    try:
        facts = _call(
            lambda: api.query_file(handle),
            RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
        )
        if type(facts) is not NativeFileFacts or facts.size not in {0, len(contents)}:
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        existing_size = facts.size
        identity = _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=expected_identity,
            expected_size=existing_size,
        )
        if existing_size == len(contents):
            if _read_exact(api, handle, len(contents)) != contents:
                _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        else:
            _call(
                lambda: api.seek_file(handle, 0),
                RecoveryCertificateStorageErrorCode.WRITE_FAILED,
            )
            _write_all(api, handle, contents)
        _call(
            lambda: api.flush_file(handle),
            RecoveryCertificateStorageErrorCode.WRITE_FAILED,
        )
        _inspect(
            api,
            handle,
            path=path,
            current_user_sid=current_user_sid,
            expected_identity=identity,
            expected_size=len(contents),
        )
        if _read_exact(api, handle, len(contents)) != contents:
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        _close_verified(api, handle)
        held = None
    finally:
        if held is not None:
            _safe_close(api, held)
    return _verify_one(
        api,
        path=path,
        current_user_sid=current_user_sid,
        expected_identity=identity,
        expected_size=len(contents),
        expected_sha256=expected_sha256,
    )


class NativeWindowsCertificateRestoreTempStorage:
    """Create, write, and verify only journal-bound certificate temps."""

    __slots__ = ("_api",)

    def __init__(
        self,
        *,
        api: _WindowsRecoveryCertificateTempApi | None = None,
    ) -> None:
        self._api = NativeWindowsRecoveryCertificateTempApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsCertificateRestoreTempStorage(<redacted>)"

    def _context(self) -> str:
        supported = _call(
            lambda: self._api.supported,
            RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE)
        return _current_user_sid(self._api)

    def create_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
    ) -> CertificateRestoreTempIdentities:
        if type(plan) is not CertificateRestoreTempPlanRecord:
            _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
        local_path = (
            _temp_path(root_path, plan.local_ca_temp_name)
            if plan.local_ca_present
            else None
        )
        bundle_path = (
            _temp_path(root_path, plan.ca_bundle_temp_name)
            if plan.ca_bundle_present
            else None
        )
        current_user_sid = self._context()
        local_identity = (
            _create_with_reconciliation(
                self._api,
                path=local_path,
                current_user_sid=current_user_sid,
            )
            if local_path is not None
            else None
        )
        bundle_identity = (
            _create_with_reconciliation(
                self._api,
                path=bundle_path,
                current_user_sid=current_user_sid,
            )
            if bundle_path is not None
            else None
        )
        try:
            return CertificateRestoreTempIdentities(local_identity, bundle_identity)
        except ValueError:
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)

    def verify_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
        created: CertificateRestoreTempCreatedRecord,
    ) -> CertificateRestoreTempIdentities:
        if (
            type(plan) is not CertificateRestoreTempPlanRecord
            or type(created) is not CertificateRestoreTempCreatedRecord
            or (created.local_ca_temp_identity is not None) is not plan.local_ca_present
            or (created.ca_bundle_temp_identity is not None)
            is not plan.ca_bundle_present
        ):
            _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
        current_user_sid = self._context()
        local_identity = (
            _verify_one(
                self._api,
                path=_temp_path(root_path, plan.local_ca_temp_name),
                current_user_sid=current_user_sid,
                expected_identity=created.local_ca_temp_identity,
                expected_size=0,
                expected_sha256=hashlib.sha256(b"").hexdigest(),
            )
            if created.local_ca_temp_identity is not None
            else None
        )
        bundle_identity = (
            _verify_one(
                self._api,
                path=_temp_path(root_path, plan.ca_bundle_temp_name),
                current_user_sid=current_user_sid,
                expected_identity=created.ca_bundle_temp_identity,
                expected_size=0,
                expected_sha256=hashlib.sha256(b"").hexdigest(),
            )
            if created.ca_bundle_temp_identity is not None
            else None
        )
        return CertificateRestoreTempIdentities(local_identity, bundle_identity)

    def write_and_verify_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
        created: CertificateRestoreTempCreatedRecord,
        *,
        local_ca_contents: bytes | None,
        ca_bundle_contents: bytes | None,
    ) -> CertificateRestoreTempIdentities:
        if (
            type(plan) is not CertificateRestoreTempPlanRecord
            or type(created) is not CertificateRestoreTempCreatedRecord
            or (local_ca_contents is not None) is not plan.local_ca_present
            or (ca_bundle_contents is not None) is not plan.ca_bundle_present
            or (created.local_ca_temp_identity is not None) is not plan.local_ca_present
            or (created.ca_bundle_temp_identity is not None)
            is not plan.ca_bundle_present
            or (
                local_ca_contents is not None
                and (
                    len(local_ca_contents) != plan.local_ca_size
                    or hashlib.sha256(local_ca_contents).hexdigest()
                    != plan.local_ca_sha256
                )
            )
            or (
                ca_bundle_contents is not None
                and (
                    len(ca_bundle_contents) != plan.ca_bundle_size
                    or hashlib.sha256(ca_bundle_contents).hexdigest()
                    != plan.ca_bundle_sha256
                )
            )
        ):
            _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
        current_user_sid = self._context()
        local_identity = (
            _write_one(
                self._api,
                path=_temp_path(root_path, plan.local_ca_temp_name),
                current_user_sid=current_user_sid,
                expected_identity=created.local_ca_temp_identity,
                contents=local_ca_contents,
                expected_sha256=plan.local_ca_sha256,
            )
            if local_ca_contents is not None
            and created.local_ca_temp_identity is not None
            and plan.local_ca_sha256 is not None
            else None
        )
        bundle_identity = (
            _write_one(
                self._api,
                path=_temp_path(root_path, plan.ca_bundle_temp_name),
                current_user_sid=current_user_sid,
                expected_identity=created.ca_bundle_temp_identity,
                contents=ca_bundle_contents,
                expected_sha256=plan.ca_bundle_sha256,
            )
            if ca_bundle_contents is not None
            and created.ca_bundle_temp_identity is not None
            and plan.ca_bundle_sha256 is not None
            else None
        )
        return CertificateRestoreTempIdentities(local_identity, bundle_identity)

    def verify_written_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
        verified: CertificateRestoreTempVerifiedRecord,
    ) -> CertificateRestoreTempIdentities:
        if (
            type(plan) is not CertificateRestoreTempPlanRecord
            or type(verified) is not CertificateRestoreTempVerifiedRecord
            or (verified.local_ca_temp_identity is not None)
            is not plan.local_ca_present
            or (verified.ca_bundle_temp_identity is not None)
            is not plan.ca_bundle_present
        ):
            _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
        current_user_sid = self._context()
        local_identity = (
            _verify_one(
                self._api,
                path=_temp_path(root_path, plan.local_ca_temp_name),
                current_user_sid=current_user_sid,
                expected_identity=verified.local_ca_temp_identity,
                expected_size=plan.local_ca_size,
                expected_sha256=plan.local_ca_sha256,
            )
            if verified.local_ca_temp_identity is not None
            and plan.local_ca_size is not None
            and plan.local_ca_sha256 is not None
            else None
        )
        bundle_identity = (
            _verify_one(
                self._api,
                path=_temp_path(root_path, plan.ca_bundle_temp_name),
                current_user_sid=current_user_sid,
                expected_identity=verified.ca_bundle_temp_identity,
                expected_size=plan.ca_bundle_size,
                expected_sha256=plan.ca_bundle_sha256,
            )
            if verified.ca_bundle_temp_identity is not None
            and plan.ca_bundle_size is not None
            and plan.ca_bundle_sha256 is not None
            else None
        )
        return CertificateRestoreTempIdentities(local_identity, bundle_identity)


@dataclass(frozen=True, slots=True, repr=False)
class HeldCertificateRestoreTempPaths:
    local_ca: PureWindowsPath | None = field(default=None, repr=False)
    ca_bundle: PureWindowsPath | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return (
            "HeldCertificateRestoreTempPaths("
            f"local_ca_present={self.local_ca is not None!r}, "
            f"ca_bundle_present={self.ca_bundle is not None!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _HeldCertificateTemp:
    path: str = field(repr=False)
    identity: StableFileIdentity = field(repr=False)
    size: int
    sha256: str = field(repr=False)
    handle: object = field(repr=False)


class HeldCertificateRestoreTemps:
    """Retain exact journal-staged originals against replacement while copied."""

    __slots__ = ("_active", "_api", "_entries", "_lock", "_paths", "_user_sid")

    def __init__(
        self,
        *,
        api: _WindowsRecoveryCertificateTempApi,
        user_sid: str,
        entries: tuple[_HeldCertificateTemp, ...],
        paths: HeldCertificateRestoreTempPaths,
    ) -> None:
        if (
            not callable(getattr(api, "close_handle", None))
            or type(user_sid) is not str
            or _SID.fullmatch(user_sid) is None
            or type(entries) is not tuple
            or type(paths) is not HeldCertificateRestoreTempPaths
            or len(entries)
            != int(paths.local_ca is not None) + int(paths.ca_bundle is not None)
            or len({id(entry.handle) for entry in entries}) != len(entries)
        ):
            _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
        self._lock = threading.RLock()
        self._active = False
        self._api = api
        self._user_sid = user_sid
        self._entries: tuple[_HeldCertificateTemp, ...] | None = entries
        self._paths = paths
        self._assert_unchanged()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._entries is None

    def _assert_unchanged(self) -> None:
        entries = self._entries
        if entries is None:
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        for entry in entries:
            _inspect(
                self._api,
                entry.handle,
                path=entry.path,
                current_user_sid=self._user_sid,
                expected_identity=entry.identity,
                expected_size=entry.size,
            )
            if (
                hashlib.sha256(
                    _read_exact(self._api, entry.handle, entry.size)
                ).hexdigest()
                != entry.sha256
            ):
                _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
            _inspect(
                self._api,
                entry.handle,
                path=entry.path,
                current_user_sid=self._user_sid,
                expected_identity=entry.identity,
                expected_size=entry.size,
            )

    def run_while_held(
        self,
        operation: Callable[[HeldCertificateRestoreTempPaths], _Result],
    ) -> _Result:
        if not callable(operation):
            _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
        self._lock.acquire()
        if self._active or self._entries is None:
            self._lock.release()
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        self._active = True
        try:
            self._assert_unchanged()
            try:
                result = operation(self._paths)
            except BaseException:
                self._assert_unchanged()
                raise
            self._assert_unchanged()
            return result
        finally:
            self._active = False
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            if self._active:
                _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
            entries = self._entries
            self._entries = None
            if entries is None:
                return
            failed = False
            interruption: BaseException | None = None
            for entry in reversed(entries):
                try:
                    self._api.close_handle(entry.handle)
                except BaseException as error:
                    if isinstance(error, Exception):
                        failed = True
                    elif interruption is None:
                        interruption = error
            if interruption is not None:
                raise interruption
            if failed:
                _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)

    def __repr__(self) -> str:
        return f"HeldCertificateRestoreTemps(state={'closed' if self.closed else 'open'!r})"


def _capture_held_certificate_temp(
    api: _WindowsRecoveryCertificateTempApi,
    *,
    root_path: str,
    user_sid: str,
    authority: CertificateDestinationRestoreAuthority,
) -> _HeldCertificateTemp | None:
    if not authority.original_present:
        return None
    if (
        authority.restore_temp_name is None
        or authority.restore_temp_identity is None
        or authority.original_size is None
        or authority.original_sha256 is None
    ):
        _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
    path = _temp_path(root_path, authority.restore_temp_name)
    handle = _call(
        lambda: api.reopen_file_for_verification(path),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
    held: object | None = handle
    try:
        entry = _HeldCertificateTemp(
            path,
            authority.restore_temp_identity,
            authority.original_size,
            authority.original_sha256,
            handle,
        )
        _inspect(
            api,
            handle,
            path=path,
            current_user_sid=user_sid,
            expected_identity=entry.identity,
            expected_size=entry.size,
        )
        if hashlib.sha256(_read_exact(api, handle, entry.size)).hexdigest() != (
            entry.sha256
        ):
            _fail(RecoveryCertificateStorageErrorCode.VERIFY_FAILED)
        held = None
        return entry
    finally:
        if held is not None:
            _safe_close(api, held)


def capture_held_certificate_restore_temps(
    root_path: str,
    authority: CertificateRestorationAuthority,
    *,
    api: _WindowsRecoveryCertificateTempApi | None = None,
) -> HeldCertificateRestoreTemps:
    """Open and retain every original certificate temp named by authority."""

    if type(authority) is not CertificateRestorationAuthority:
        _fail(RecoveryCertificateStorageErrorCode.INPUT_INVALID)
    selected_api = NativeWindowsRecoveryCertificateTempApi() if api is None else api
    supported = _call(
        lambda: selected_api.supported,
        RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE,
    )
    if supported is not True:
        _fail(RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE)
    user_sid = _current_user_sid(selected_api)
    entries: list[_HeldCertificateTemp] = []
    try:
        for destination in (authority.local_ca, authority.ca_bundle):
            entry = _capture_held_certificate_temp(
                selected_api,
                root_path=root_path,
                user_sid=user_sid,
                authority=destination,
            )
            if entry is not None:
                entries.append(entry)
        paths = HeldCertificateRestoreTempPaths(
            (
                PureWindowsPath(entries[0].path)
                if authority.local_ca.original_present
                else None
            ),
            (
                PureWindowsPath(entries[-1].path)
                if authority.ca_bundle.original_present
                else None
            ),
        )
        return HeldCertificateRestoreTemps(
            api=selected_api,
            user_sid=user_sid,
            entries=tuple(entries),
            paths=paths,
        )
    except BaseException:
        for entry in reversed(entries):
            _safe_close(selected_api, entry.handle)
        raise


__all__ = [
    "HeldCertificateRestoreTempPaths",
    "HeldCertificateRestoreTemps",
    "NativeWindowsCertificateRestoreTempStorage",
    "NativeWindowsRecoveryCertificateTempApi",
    "capture_held_certificate_restore_temps",
]
