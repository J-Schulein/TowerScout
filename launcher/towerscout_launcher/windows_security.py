"""Fail-closed Windows identity primitives for the Gate-A repair path.

This module deliberately contains no mutation, ACL, trust-store, recovery, or
runtime behavior.  It establishes the read-only handle and canonical-name
building blocks that those later layers must consume.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import struct
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Sequence, TypeVar

_SCHEMA_VERSION = 1
_ENV_MUTEX_DOMAIN = b"TowerScout.EnvironmentMutex"
_REPAIR_MUTEX_DOMAIN = b"TowerScout.RepairMutex"
_IDENTITY_DOMAIN_PREFIX = b"TowerScout.CanonicalIdentity."
_COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_IDENTITY_DOMAIN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_IDENTITY_FIELDS = 64
_MAX_IDENTITY_FIELD_BYTES = 65_536
_MAX_FINAL_PATH_CHARACTERS = 32_768
_HASH_CHUNK_BYTES = 65_536

_InspectionResult = TypeVar("_InspectionResult")

_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_OFFLINE = 0x00001000
_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
_IO_REPARSE_TAG_NAME_SURROGATE = 0x20000000

# Explicit Windows SDK cloud-placeholder tags.  This is intentionally an
# allowlist, not a bit mask or numeric range.
KNOWN_CLOUD_REPARSE_TAGS = frozenset(
    {
        0x9000001A,
        0x9000101A,
        0x9000201A,
        0x9000301A,
        0x9000401A,
        0x9000501A,
        0x9000601A,
        0x9000701A,
        0x9000801A,
        0x9000901A,
        0x9000A01A,
        0x9000B01A,
        0x9000C01A,
        0x9000D01A,
        0x9000E01A,
        0x9000F01A,
    }
)


class WindowsSecurityError(RuntimeError):
    """A sanitized, fail-closed error at the native security boundary."""

    def __init__(self, category: str, public_message: str) -> None:
        super().__init__(public_message)
        self.category = category
        self.public_message = public_message

    def __repr__(self) -> str:
        return f"WindowsSecurityError(category={self.category!r})"


class PathLocality(str, Enum):
    FIXED_LOCAL = "fixed_local"
    REMOTE = "remote"
    REMOVABLE = "removable"
    OPTICAL = "optical"
    RAM_DISK = "ram_disk"
    UNKNOWN = "unknown"


class ReparseKind(str, Enum):
    NONE = "none"
    KNOWN_CLOUD_PLACEHOLDER = "known_cloud_placeholder"
    NAME_SURROGATE = "name_surrogate"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True, repr=False)
class StableFileIdentity:
    """Canonical Windows volume/file identity with a redacted representation."""

    volume_serial: int
    file_id: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.volume_serial, int)
            or isinstance(self.volume_serial, bool)
            or not 0 <= self.volume_serial < 2**64
            or not isinstance(self.file_id, bytes)
            or len(self.file_id) != 16
        ):
            raise ValueError("Windows file identity is invalid.")

    def __repr__(self) -> str:
        return "StableFileIdentity(<redacted>)"


@dataclass(frozen=True, slots=True)
class PathClassification:
    locality: PathLocality
    reparse_kind: ReparseKind
    hydrated: bool
    regular_file: bool
    single_link: bool


@dataclass(frozen=True, slots=True, repr=False)
class FileSnapshot:
    """A handle-derived file snapshot; its identity and hash stay out of repr."""

    identity: StableFileIdentity
    sha256: str
    size: int
    attributes: int
    creation_time: int
    last_write_time: int
    reparse_tag: int
    final_path: str
    classification: PathClassification

    def __post_init__(self) -> None:
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ValueError("File snapshot digest is invalid.")
        if (
            not isinstance(self.identity, StableFileIdentity)
            or not isinstance(self.size, int)
            or isinstance(self.size, bool)
            or self.size < 0
            or not isinstance(self.final_path, str)
            or not self.final_path
            or "\x00" in self.final_path
            or len(self.final_path) > _MAX_FINAL_PATH_CHARACTERS
            or not isinstance(self.classification, PathClassification)
        ):
            raise ValueError("File snapshot metadata is invalid.")

    def __repr__(self) -> str:
        return (
            "FileSnapshot("
            f"size={self.size}, locality={self.classification.locality.value!r}, "
            f"reparse={self.classification.reparse_kind.value!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CanonicalIdentityDigest:
    """Opaque digest of an already canonical, domain-separated identity."""

    domain: str
    digest_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.domain, str) or not _IDENTITY_DOMAIN.fullmatch(
            self.domain
        ):
            raise ValueError("Canonical identity domain is invalid.")
        if not isinstance(self.digest_sha256, str) or not _SHA256.fullmatch(
            self.digest_sha256
        ):
            raise ValueError("Canonical identity digest is invalid.")

    def __repr__(self) -> str:
        return f"CanonicalIdentityDigest(domain={self.domain!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class NativeFileFacts:
    """Raw facts returned by an injected or native handle API."""

    final_path: str
    volume_serial: int
    file_id: bytes
    attributes: int
    link_count: int
    size: int
    creation_time: int
    last_write_time: int
    drive_type: int
    file_type: int
    reparse_tag: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.final_path, str)
            or not self.final_path
            or "\x00" in self.final_path
            or len(self.final_path) > _MAX_FINAL_PATH_CHARACTERS
            or not isinstance(self.volume_serial, int)
            or isinstance(self.volume_serial, bool)
            or not 0 <= self.volume_serial < 2**64
            or not isinstance(self.file_id, bytes)
            or len(self.file_id) != 16
            or not isinstance(self.attributes, int)
            or isinstance(self.attributes, bool)
            or not 0 <= self.attributes < 2**32
            or not isinstance(self.link_count, int)
            or isinstance(self.link_count, bool)
            or self.link_count < 0
            or not isinstance(self.size, int)
            or isinstance(self.size, bool)
            or self.size < 0
            or not isinstance(self.creation_time, int)
            or not isinstance(self.last_write_time, int)
            or not isinstance(self.drive_type, int)
            or not isinstance(self.file_type, int)
            or not isinstance(self.reparse_tag, int)
            or isinstance(self.reparse_tag, bool)
            or not 0 <= self.reparse_tag < 2**32
            or bool(self.attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
            != bool(self.reparse_tag)
        ):
            raise ValueError("Native Windows file facts are invalid.")

    def __repr__(self) -> str:
        return "NativeFileFacts(<redacted>)"


@dataclass(frozen=True, slots=True)
class FileCapturePolicy:
    """Conservative policy for a critical regular-file leaf.

    Mutable configuration leaves require one link.  A separately trusted
    executable may opt out because the held no-write/no-delete-share handle and
    repeated hash bind the shared file object across its hardlink names.
    """

    max_bytes: int = 16 * 1024 * 1024
    require_single_link: bool = True

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_bytes, int)
            or isinstance(self.max_bytes, bool)
            or not 0 < self.max_bytes <= 1024 * 1024 * 1024
            or not isinstance(self.require_single_link, bool)
        ):
            raise ValueError("File capture size policy is invalid.")


class WindowsFileApi(Protocol):
    """Small injectable seam around native read-only handle operations."""

    @property
    def supported(self) -> bool: ...

    def open_file_for_identity(self, path: str) -> object: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def rewind_file(self, handle: object) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def close_handle(self, handle: object) -> None: ...


def _length_prefixed_digest(domain: bytes, fields: Sequence[bytes]) -> str:
    if not domain or len(fields) > _MAX_IDENTITY_FIELDS:
        raise ValueError("Canonical identity encoding is invalid.")
    values = (domain, str(_SCHEMA_VERSION).encode("ascii"), *fields)
    digest = hashlib.sha256()
    for value in values:
        if not isinstance(value, bytes) or len(value) > _MAX_IDENTITY_FIELD_BYTES:
            raise ValueError("Canonical identity field is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def canonical_identity_digest(
    domain: str, fields: Sequence[bytes]
) -> CanonicalIdentityDigest:
    """Digest canonical bytes without retaining or displaying their contents."""

    if not isinstance(domain, str) or not _IDENTITY_DOMAIN.fullmatch(domain):
        raise ValueError("Canonical identity domain is invalid.")
    digest = _length_prefixed_digest(
        _IDENTITY_DOMAIN_PREFIX + domain.encode("ascii"), tuple(fields)
    )
    return CanonicalIdentityDigest(domain=domain, digest_sha256=digest)


def derive_environment_mutex_name(parent: StableFileIdentity) -> str:
    """Derive the package-parent/.env cross-session mutex name."""

    if type(parent) is not StableFileIdentity:
        raise ValueError("Environment mutex identity is invalid.")
    digest = _length_prefixed_digest(
        _ENV_MUTEX_DOMAIN,
        (
            b"parent-volume",
            parent.volume_serial.to_bytes(8, "big"),
            b"parent-file-id",
            parent.file_id,
            b"leaf",
            b".env",
        ),
    )
    return f"Global\\TowerScoutEnv-v1-{digest}"


def derive_repair_mutex_name(
    *,
    endpoint: CanonicalIdentityDigest,
    compose_project: str,
    config_volume: CanonicalIdentityDigest,
) -> str:
    """Derive the endpoint/project/config-volume cross-session mutex name."""

    if (
        type(endpoint) is not CanonicalIdentityDigest
        or type(config_volume) is not CanonicalIdentityDigest
        or endpoint.domain != "Endpoint"
        or config_volume.domain != "ConfigVolume"
    ):
        raise ValueError("Repair mutex identity domains are invalid.")
    if not isinstance(compose_project, str) or not _COMPOSE_PROJECT.fullmatch(
        compose_project
    ):
        raise ValueError("Compose project identity is invalid.")
    digest = _length_prefixed_digest(
        _REPAIR_MUTEX_DOMAIN,
        (
            b"endpoint-domain",
            endpoint.domain.encode("ascii"),
            b"endpoint-digest",
            bytes.fromhex(endpoint.digest_sha256),
            b"compose-project",
            compose_project.encode("utf-8", errors="strict"),
            b"config-volume-domain",
            config_volume.domain.encode("ascii"),
            b"config-volume-digest",
            bytes.fromhex(config_volume.digest_sha256),
        ),
    )
    return f"Global\\TowerScoutRepair-v1-{digest}"


def classify_path(facts: NativeFileFacts) -> PathClassification:
    """Classify locality and leaf reparse state without exposing the path."""

    locality = {
        2: PathLocality.REMOVABLE,
        3: PathLocality.FIXED_LOCAL,
        4: PathLocality.REMOTE,
        5: PathLocality.OPTICAL,
        6: PathLocality.RAM_DISK,
    }.get(facts.drive_type, PathLocality.UNKNOWN)
    if not facts.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        reparse_kind = ReparseKind.NONE
    elif facts.reparse_tag in KNOWN_CLOUD_REPARSE_TAGS:
        reparse_kind = ReparseKind.KNOWN_CLOUD_PLACEHOLDER
    elif facts.reparse_tag & _IO_REPARSE_TAG_NAME_SURROGATE:
        reparse_kind = ReparseKind.NAME_SURROGATE
    else:
        reparse_kind = ReparseKind.UNSUPPORTED
    hydration_markers = (
        _FILE_ATTRIBUTE_OFFLINE
        | _FILE_ATTRIBUTE_RECALL_ON_OPEN
        | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    )
    return PathClassification(
        locality=locality,
        reparse_kind=reparse_kind,
        hydrated=not bool(facts.attributes & hydration_markers),
        regular_file=(
            facts.file_type == 1
            and not bool(facts.attributes & _FILE_ATTRIBUTE_DIRECTORY)
        ),
        single_link=facts.link_count == 1,
    )


def _validate_capture_policy(
    facts: NativeFileFacts, policy: FileCapturePolicy
) -> PathClassification:
    classification = classify_path(facts)
    if classification.locality is not PathLocality.FIXED_LOCAL:
        raise WindowsSecurityError(
            "file_location_unsafe",
            "The Windows file location could not be classified as local and fixed.",
        )
    if not classification.regular_file:
        raise WindowsSecurityError(
            "file_identity_unsafe",
            "The Windows file identity is not an eligible regular file.",
        )
    if policy.require_single_link and not classification.single_link:
        raise WindowsSecurityError(
            "file_link_count_unsafe",
            "The Windows file link count is not eligible for this operation.",
        )
    # Recognition is not authorization.  Cloud-placeholder hydration, ancestor
    # containment, and ACL policy need their later Gate-A proof before any
    # reparse leaf can become eligible for mutation.
    if classification.reparse_kind is not ReparseKind.NONE:
        raise WindowsSecurityError(
            "file_reparse_unsafe",
            "The Windows file has an unsupported or unavailable reparse state.",
        )
    if facts.size > policy.max_bytes:
        raise WindowsSecurityError(
            "file_size_invalid",
            "The Windows file exceeds the fixed safe size limit.",
        )
    return classification


def _safe_query(api: WindowsFileApi, handle: object) -> NativeFileFacts:
    failed = False
    facts: NativeFileFacts | None = None
    try:
        facts = api.query_file(handle)
    except (OSError, RuntimeError, TypeError, ValueError):
        failed = True
    if failed or not isinstance(facts, NativeFileFacts):
        raise WindowsSecurityError(
            "file_identity_unavailable",
            "The Windows file identity could not be inspected safely.",
        )
    return facts


def _safe_close(api: WindowsFileApi, handle: object) -> None:
    try:
        api.close_handle(handle)
    except BaseException:
        # A close failure must not replace the sanitized primary error.  With no
        # bound object returned, the handle cannot authorize a later operation.
        return


def _safe_hash(
    api: WindowsFileApi, handle: object, expected_size: int, maximum: int
) -> str:
    failed = False
    try:
        api.rewind_file(handle)
    except (OSError, RuntimeError, TypeError, ValueError):
        failed = True
    if failed:
        raise WindowsSecurityError(
            "file_read_unavailable",
            "The Windows file could not be read safely.",
        )
    digest = hashlib.sha256()
    total = 0
    while True:
        read_failed = False
        chunk: bytes | None = None
        try:
            chunk = api.read_file(handle, min(_HASH_CHUNK_BYTES, maximum - total + 1))
        except (OSError, RuntimeError, TypeError, ValueError):
            read_failed = True
        if read_failed or not isinstance(chunk, bytes):
            raise WindowsSecurityError(
                "file_read_unavailable",
                "The Windows file could not be read safely.",
            )
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise WindowsSecurityError(
                "file_size_invalid",
                "The Windows file exceeds the fixed safe size limit.",
            )
        digest.update(chunk)
    if total != expected_size:
        raise WindowsSecurityError(
            "file_identity_changed",
            "The Windows file changed while it was being inspected.",
        )
    return digest.hexdigest()


def _capture_snapshot(
    api: WindowsFileApi, handle: object, policy: FileCapturePolicy
) -> FileSnapshot:
    before = _safe_query(api, handle)
    classification = _validate_capture_policy(before, policy)
    digest = _safe_hash(api, handle, before.size, policy.max_bytes)
    after = _safe_query(api, handle)
    if after != before:
        raise WindowsSecurityError(
            "file_identity_changed",
            "The Windows file changed while it was being inspected.",
        )
    return FileSnapshot(
        identity=StableFileIdentity(before.volume_serial, before.file_id),
        sha256=digest,
        size=before.size,
        attributes=before.attributes,
        creation_time=before.creation_time,
        last_write_time=before.last_write_time,
        reparse_tag=before.reparse_tag,
        final_path=before.final_path,
        classification=classification,
    )


class HandleBoundFile:
    """Own and serialize all use of one read-only Windows file handle.

    The handle remains open until :meth:`close` or context-manager exit.  Every
    hash/revalidation and same-handle inspector owns the cursor-bearing handle
    exclusively through its final post-inspection revalidation.  A close from
    another thread waits for that final use; same-thread reentry fails closed
    instead of deadlocking or moving the shared file cursor recursively.
    """

    __slots__ = (
        "_active_owner",
        "_api",
        "_handle",
        "_lifetime_lock",
        "_policy",
        "_snapshot",
    )

    def __init__(
        self,
        api: WindowsFileApi,
        handle: object,
        policy: FileCapturePolicy,
        snapshot: FileSnapshot,
    ) -> None:
        self._api = api
        self._handle: object | None = handle
        self._policy = policy
        self._snapshot = snapshot
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None

    @property
    def snapshot(self) -> FileSnapshot:
        return self._snapshot

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return self._handle is None

    def _begin_use(self) -> object:
        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            raise WindowsSecurityError(
                "file_handle_in_use",
                "The Windows file handle is already in active use.",
            )
        handle = self._handle
        if handle is None:
            self._lifetime_lock.release()
            raise WindowsSecurityError(
                "file_handle_closed",
                "The Windows file handle is no longer available.",
            )
        self._active_owner = threading.get_ident()
        return handle

    def _end_use(self) -> None:
        self._active_owner = None
        self._lifetime_lock.release()

    def _assert_unchanged_owned(self, handle: object) -> FileSnapshot:
        if self._handle is not handle:
            raise WindowsSecurityError(
                "file_handle_closed",
                "The Windows file handle is no longer available.",
            )
        current = _capture_snapshot(self._api, handle, self._policy)
        if current != self._snapshot:
            raise WindowsSecurityError(
                "file_identity_changed",
                "The Windows file changed after it was inspected.",
            )
        return current

    def assert_unchanged(self) -> FileSnapshot:
        """Rehash and compare the same held handle against the original snapshot."""

        handle = self._begin_use()
        try:
            return self._assert_unchanged_owned(handle)
        finally:
            self._end_use()

    def inspect_same_handle(
        self,
        inspector: Callable[[object, FileSnapshot], _InspectionResult],
    ) -> _InspectionResult:
        """Inspect through the held handle and revalidate it on both sides."""

        if not callable(inspector):
            raise ValueError("The held-file inspector is invalid.")
        handle = self._begin_use()
        try:
            self._assert_unchanged_owned(handle)
            try:
                result = inspector(handle, self._snapshot)
            except BaseException as error:
                self._assert_unchanged_owned(handle)
                if isinstance(error, WindowsSecurityError):
                    raise
                if not isinstance(error, Exception):
                    raise
                raise WindowsSecurityError(
                    "file_inspection_failed",
                    "The Windows file could not be inspected safely.",
                ) from None
            self._assert_unchanged_owned(handle)
            return result
        finally:
            self._end_use()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                raise WindowsSecurityError(
                    "file_handle_in_use",
                    "The Windows file handle is already in active use.",
                )
            handle = self._handle
            self._handle = None
            if handle is None:
                return
            _safe_close(self._api, handle)

    def __enter__(self) -> "HandleBoundFile":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"HandleBoundFile(state={state!r}, identity=<redacted>)"


def capture_handle_bound_file(
    path: Path,
    *,
    api: WindowsFileApi | None = None,
    policy: FileCapturePolicy | None = None,
) -> HandleBoundFile:
    """Open and capture a critical leaf, failing closed outside Windows."""

    selected_api = api if api is not None else NativeWindowsFileApi()
    selected_policy = policy if policy is not None else FileCapturePolicy()
    support_check_failed = False
    supported = False
    try:
        supported = selected_api.supported is True
    except (OSError, RuntimeError, TypeError, ValueError):
        support_check_failed = True
    if support_check_failed or not supported:
        raise WindowsSecurityError(
            "windows_security_unavailable",
            "Secure Windows file inspection is unavailable on this platform.",
        )
    opened = False
    handle: object | None = None
    try:
        handle = selected_api.open_file_for_identity(os.fspath(path))
        opened = True
    except (OSError, RuntimeError, TypeError, ValueError):
        opened = False
    if not opened or handle is None:
        raise WindowsSecurityError(
            "file_open_failed",
            "The Windows file could not be opened safely.",
        )
    try:
        snapshot = _capture_snapshot(selected_api, handle, selected_policy)
    except WindowsSecurityError:
        _safe_close(selected_api, handle)
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _safe_close(selected_api, handle)
        raise WindowsSecurityError(
            "file_identity_unavailable",
            "The Windows file identity could not be inspected safely.",
        ) from None
    except BaseException:
        _safe_close(selected_api, handle)
        raise
    return HandleBoundFile(selected_api, handle, selected_policy, snapshot)


class _FileTime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("last_access_time", _FileTime),
        ("last_write_time", _FileTime),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    )


class _FileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FileIdInformation(ctypes.Structure):
    _fields_ = (("volume_serial", ctypes.c_uint64), ("file_id", _FileId128))


class _FileAttributeTagInformation(ctypes.Structure):
    _fields_ = (("attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32))


def _filetime_value(value: _FileTime) -> int:
    return (int(value.high) << 32) | int(value.low)


class NativeWindowsFileApi:
    """ctypes implementation that holds a no-write/no-delete-share handle."""

    def __init__(self) -> None:
        self._kernel32 = None
        if os.name == "nt":
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._configure_signatures()

    @property
    def supported(self) -> bool:
        return self._kernel32 is not None

    def _configure_signatures(self) -> None:
        kernel32 = self._require_kernel32()
        kernel32.CreateFileW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.GetFileInformationByHandle.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_ByHandleFileInformation),
        )
        kernel32.GetFileInformationByHandle.restype = ctypes.c_int
        kernel32.GetFileInformationByHandleEx.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        kernel32.GetFileInformationByHandleEx.restype = ctypes.c_int
        kernel32.GetFinalPathNameByHandleW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )
        kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
        kernel32.GetVolumePathNameW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        kernel32.GetVolumePathNameW.restype = ctypes.c_int
        kernel32.GetDriveTypeW.argtypes = (ctypes.c_wchar_p,)
        kernel32.GetDriveTypeW.restype = ctypes.c_uint32
        kernel32.GetFileType.argtypes = (ctypes.c_void_p,)
        kernel32.GetFileType.restype = ctypes.c_uint32
        kernel32.SetFilePointerEx.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        kernel32.SetFilePointerEx.restype = ctypes.c_int
        kernel32.ReadFile.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        )
        kernel32.ReadFile.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_int

    def _require_kernel32(self):  # noqa: ANN202
        if self._kernel32 is None:
            raise OSError("Native Windows file inspection is unavailable.")
        return self._kernel32

    @staticmethod
    def _handle(value: object) -> ctypes.c_void_p:
        if not isinstance(value, int) or value <= 0:
            raise OSError("Native Windows file handle is invalid.")
        return ctypes.c_void_p(value)

    @staticmethod
    def _raise_last_error() -> None:
        code = ctypes.get_last_error()
        raise OSError(code, "Native Windows file operation failed.")

    def open_file_for_identity(self, path: str) -> object:
        kernel32 = self._require_kernel32()
        handle = kernel32.CreateFileW(
            path,
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ; deny write and delete sharing
            None,
            3,  # OPEN_EXISTING
            0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle is None or handle == invalid:
            self._raise_last_error()
        return int(handle)

    def query_file(self, handle: object) -> NativeFileFacts:
        kernel32 = self._require_kernel32()
        native_handle = self._handle(handle)
        basic = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(native_handle, ctypes.byref(basic)):
            self._raise_last_error()
        file_id = _FileIdInformation()
        if not kernel32.GetFileInformationByHandleEx(
            native_handle, 18, ctypes.byref(file_id), ctypes.sizeof(file_id)
        ):
            self._raise_last_error()
        tag_info = _FileAttributeTagInformation()
        if not kernel32.GetFileInformationByHandleEx(
            native_handle, 9, ctypes.byref(tag_info), ctypes.sizeof(tag_info)
        ):
            self._raise_last_error()
        final_path = self._final_path(native_handle)
        return NativeFileFacts(
            final_path=final_path,
            volume_serial=int(file_id.volume_serial),
            file_id=bytes(file_id.file_id.identifier),
            attributes=int(tag_info.attributes),
            link_count=int(basic.link_count),
            size=(int(basic.size_high) << 32) | int(basic.size_low),
            creation_time=_filetime_value(basic.creation_time),
            last_write_time=_filetime_value(basic.last_write_time),
            drive_type=self._drive_type(final_path),
            file_type=int(kernel32.GetFileType(native_handle)),
            reparse_tag=int(tag_info.reparse_tag),
        )

    def _final_path(self, handle: ctypes.c_void_p) -> str:
        kernel32 = self._require_kernel32()
        required = kernel32.GetFinalPathNameByHandleW(handle, None, 0, 0)
        if not required or required > _MAX_FINAL_PATH_CHARACTERS:
            self._raise_last_error()
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = kernel32.GetFinalPathNameByHandleW(
            handle, buffer, ctypes.sizeof(buffer) // ctypes.sizeof(ctypes.c_wchar), 0
        )
        if not written or written > required:
            self._raise_last_error()
        return buffer.value

    def _drive_type(self, final_path: str) -> int:
        kernel32 = self._require_kernel32()
        query_path = final_path
        if query_path.startswith("\\\\?\\UNC\\"):
            query_path = "\\\\" + query_path[8:]
        elif query_path.startswith("\\\\?\\"):
            query_path = query_path[4:]
        volume = ctypes.create_unicode_buffer(_MAX_FINAL_PATH_CHARACTERS + 1)
        if not kernel32.GetVolumePathNameW(
            query_path,
            volume,
            ctypes.sizeof(volume) // ctypes.sizeof(ctypes.c_wchar),
        ):
            return 0
        return int(kernel32.GetDriveTypeW(volume.value))

    def rewind_file(self, handle: object) -> None:
        kernel32 = self._require_kernel32()
        if not kernel32.SetFilePointerEx(self._handle(handle), 0, None, 0):
            self._raise_last_error()

    def read_file(self, handle: object, maximum: int) -> bytes:
        if maximum <= 0:
            return b""
        kernel32 = self._require_kernel32()
        amount = min(maximum, _HASH_CHUNK_BYTES)
        buffer = ctypes.create_string_buffer(amount)
        read = ctypes.c_uint32()
        if not kernel32.ReadFile(
            self._handle(handle), buffer, amount, ctypes.byref(read), None
        ):
            self._raise_last_error()
        return buffer.raw[: read.value]

    def close_handle(self, handle: object) -> None:
        kernel32 = self._require_kernel32()
        if not kernel32.CloseHandle(self._handle(handle)):
            self._raise_last_error()
