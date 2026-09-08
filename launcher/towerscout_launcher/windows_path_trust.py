"""Handle-bound Windows ancestor, owner, DACL, and reparse validation.

The module is deliberately inert: it opens read-only handles, captures trust
facts, and retains those handles for later revalidation.  It performs no
launcher discovery, child execution, or filesystem mutation.
"""

from __future__ import annotations

import ctypes
import os
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Protocol

from .windows_security import (
    KNOWN_CLOUD_REPARSE_TAGS,
    StableFileIdentity,
    WindowsSecurityError,
)

_MAX_PATH_CHARACTERS = 32_768
_MAX_ACES = 4_096
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_OFFLINE = 0x00001000
_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
_IO_REPARSE_TAG_NAME_SURROGATE = 0x20000000
_INHERIT_ONLY_ACE = 0x08

_ACCESS_ALLOWED_ACE_TYPES = frozenset({0, 5, 9, 11})
_NON_GRANTING_ACE_TYPES = frozenset(
    {
        1,  # ACCESS_DENIED_ACE_TYPE
        2,  # SYSTEM_AUDIT_ACE_TYPE
        3,  # SYSTEM_ALARM_ACE_TYPE
        6,  # ACCESS_DENIED_OBJECT_ACE_TYPE
        7,  # SYSTEM_AUDIT_OBJECT_ACE_TYPE
        8,  # SYSTEM_ALARM_OBJECT_ACE_TYPE
        10,  # ACCESS_DENIED_CALLBACK_ACE_TYPE
        12,  # ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        13,  # SYSTEM_AUDIT_CALLBACK_ACE_TYPE
        14,  # SYSTEM_ALARM_CALLBACK_ACE_TYPE
        15,  # SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
        16,  # SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
        17,  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
        18,  # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
        19,  # SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
        20,  # SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
        21,  # SYSTEM_ACCESS_FILTER_ACE_TYPE
    }
)

_FILE_ADD_FILE = 0x00000002
_FILE_ADD_SUBDIRECTORY = 0x00000004
_FILE_WRITE_EA = 0x00000010
_FILE_DELETE_CHILD = 0x00000040
_FILE_WRITE_ATTRIBUTES = 0x00000100
_DELETE = 0x00010000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000

_ANCESTOR_RETARGET_MASK = (
    _FILE_DELETE_CHILD
    | _FILE_WRITE_ATTRIBUTES
    | _DELETE
    | _WRITE_DAC
    | _WRITE_OWNER
    | _GENERIC_ALL
    | _GENERIC_WRITE
)
_ROOT_MUTATION_MASK = (
    _ANCESTOR_RETARGET_MASK | _FILE_ADD_FILE | _FILE_ADD_SUBDIRECTORY | _FILE_WRITE_EA
)

BROAD_WRITE_PRINCIPAL_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-7",  # Anonymous
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # Users
        "S-1-5-32-546",  # Guests
    }
)
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_TRUSTED_INSTALLER_SID = (
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)


class PathTrustPurpose(str, Enum):
    PACKAGE_ROOT = "package_root"
    RUNTIME_INSTALL = "runtime_install"


@dataclass(frozen=True, slots=True, repr=False)
class AccessAllowedAce:
    principal_sid: str = field(repr=False)
    access_mask: int
    flags: int

    def __post_init__(self) -> None:
        if (
            not _valid_sid_text(self.principal_sid)
            or type(self.access_mask) is not int
            or not 0 <= self.access_mask < 2**32
            or type(self.flags) is not int
            or not 0 <= self.flags < 2**8
        ):
            raise ValueError("Windows access-allowed ACE facts are invalid.")

    def __repr__(self) -> str:
        return (
            "AccessAllowedAce("
            f"access_mask={self.access_mask:#x}, flags={self.flags:#x}, "
            "principal=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NativeSecurityFacts:
    owner_sid: str = field(repr=False)
    dacl_present: bool
    allowed_aces: tuple[AccessAllowedAce, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _valid_sid_text(self.owner_sid)
            or type(self.dacl_present) is not bool
            or type(self.allowed_aces) is not tuple
            or len(self.allowed_aces) > _MAX_ACES
            or any(type(ace) is not AccessAllowedAce for ace in self.allowed_aces)
        ):
            raise ValueError("Windows security descriptor facts are invalid.")

    def __repr__(self) -> str:
        return (
            "NativeSecurityFacts("
            f"dacl_present={self.dacl_present}, "
            f"allowed_ace_count={len(self.allowed_aces)}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NativeDirectoryFacts:
    final_path: str = field(repr=False)
    volume_serial: int
    file_id: bytes = field(repr=False)
    attributes: int
    drive_type: int
    file_type: int
    reparse_tag: int

    def __post_init__(self) -> None:
        if (
            not _valid_path(self.final_path)
            or type(self.volume_serial) is not int
            or not 0 <= self.volume_serial < 2**64
            or type(self.file_id) is not bytes
            or len(self.file_id) != 16
            or type(self.attributes) is not int
            or not 0 <= self.attributes < 2**32
            or type(self.drive_type) is not int
            or type(self.file_type) is not int
            or type(self.reparse_tag) is not int
            or not 0 <= self.reparse_tag < 2**32
            or bool(self.attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
            != bool(self.reparse_tag)
        ):
            raise ValueError("Native Windows directory facts are invalid.")

    def __repr__(self) -> str:
        return "NativeDirectoryFacts(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryTrustSnapshot:
    identity: StableFileIdentity = field(repr=False)
    final_path: str = field(repr=False)
    attributes: int
    reparse_tag: int
    security: NativeSecurityFacts = field(repr=False)
    is_trusted_root: bool

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not StableFileIdentity
            or not _valid_path(self.final_path)
            or type(self.attributes) is not int
            or type(self.reparse_tag) is not int
            or type(self.security) is not NativeSecurityFacts
            or type(self.is_trusted_root) is not bool
        ):
            raise ValueError("Windows directory trust snapshot is invalid.")

    def __repr__(self) -> str:
        return (
            "DirectoryTrustSnapshot("
            f"trusted_root={self.is_trusted_root}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PathHierarchyEvidence:
    purpose: PathTrustPurpose
    lexical_depth: int
    resolved_depth: int
    root_identity: StableFileIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.purpose) is not PathTrustPurpose
            or type(self.lexical_depth) is not int
            or self.lexical_depth <= 0
            or type(self.resolved_depth) is not int
            or self.resolved_depth <= 0
            or type(self.root_identity) is not StableFileIdentity
        ):
            raise ValueError("Windows path trust evidence is invalid.")

    def __repr__(self) -> str:
        return (
            "PathHierarchyEvidence("
            f"purpose={self.purpose.value!r}, lexical_depth={self.lexical_depth}, "
            f"resolved_depth={self.resolved_depth}, <redacted>)"
        )


class WindowsPathTrustApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def open_directory(self, path: str, *, follow_reparse: bool) -> object: ...

    def query_directory(self, handle: object) -> NativeDirectoryFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def close_handle(self, handle: object) -> None: ...


def _valid_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "\x00" not in value
        and len(value) <= _MAX_PATH_CHARACTERS
    )


def _valid_sid_text(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("S-") or len(value) > 184:
        return False
    pieces = value.split("-")
    return len(pieces) >= 3 and all(piece.isdecimal() for piece in pieces[1:])


def _strip_extended_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _directory_chain(path: str) -> tuple[str, ...]:
    if not _valid_path(path):
        raise WindowsSecurityError(
            "path_invalid", "The Windows directory path is invalid."
        )
    canonical_input = _strip_extended_prefix(path)
    parsed = PureWindowsPath(canonical_input)
    if not parsed.is_absolute() or not parsed.anchor or not parsed.drive:
        raise WindowsSecurityError(
            "path_invalid", "The Windows directory path is invalid."
        )
    if str(parsed) != canonical_input:
        raise WindowsSecurityError(
            "path_invalid", "The Windows directory path is invalid."
        )
    current = PureWindowsPath(parsed.anchor)
    result = [str(current)]
    for component in parsed.parts[1:]:
        if (
            component in ("", ".", "..")
            or component.endswith((".", " "))
            or ":" in component
        ):
            raise WindowsSecurityError(
                "path_invalid", "The Windows directory path is invalid."
            )
        current /= component
        result.append(str(current))
    return tuple(result)


def _accepted_owner_sids(current_user_sid: str) -> frozenset[str]:
    if not _valid_sid_text(current_user_sid):
        raise WindowsSecurityError(
            "path_owner_unavailable",
            "The Windows path owner policy could not be established.",
        )
    return frozenset(
        {
            current_user_sid.upper(),
            _SYSTEM_SID,
            _ADMINISTRATORS_SID,
            _TRUSTED_INSTALLER_SID,
        }
    )


def validate_security_facts(
    security: NativeSecurityFacts,
    *,
    current_user_sid: str,
    trusted_root: bool,
) -> None:
    """Apply TowerScout's explicit owner and authorized-writer policy."""

    if type(security) is not NativeSecurityFacts:
        raise WindowsSecurityError(
            "path_security_unavailable",
            "The Windows path security descriptor could not be inspected.",
        )
    if security.owner_sid.upper() not in _accepted_owner_sids(current_user_sid):
        raise WindowsSecurityError(
            "path_owner_unsafe", "The Windows path owner is not trusted."
        )
    if not security.dacl_present:
        raise WindowsSecurityError(
            "path_acl_unsafe", "The Windows path access policy is not trusted."
        )
    forbidden = _ROOT_MUTATION_MASK if trusted_root else _ANCESTOR_RETARGET_MASK
    accepted_writers = _accepted_owner_sids(current_user_sid)
    for ace in security.allowed_aces:
        if ace.flags & _INHERIT_ONLY_ACE:
            continue
        if (
            ace.principal_sid.upper() not in accepted_writers
            and ace.access_mask & forbidden
        ):
            raise WindowsSecurityError(
                "path_acl_unsafe",
                "The Windows path access policy is not trusted.",
            )


def _validate_directory_facts(facts: NativeDirectoryFacts) -> None:
    if (
        type(facts) is not NativeDirectoryFacts
        or facts.drive_type != 3
        or facts.file_type != 1
        or not facts.attributes & _FILE_ATTRIBUTE_DIRECTORY
    ):
        raise WindowsSecurityError(
            "path_location_unsafe",
            "The Windows directory is not on an eligible local fixed volume.",
        )
    if not facts.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        return
    hydration_markers = (
        _FILE_ATTRIBUTE_OFFLINE
        | _FILE_ATTRIBUTE_RECALL_ON_OPEN
        | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    )
    hydrated_cloud = (
        facts.reparse_tag in KNOWN_CLOUD_REPARSE_TAGS
        and not facts.attributes & hydration_markers
    )
    name_surrogate = bool(facts.reparse_tag & _IO_REPARSE_TAG_NAME_SURROGATE)
    if not hydrated_cloud and not name_surrogate:
        raise WindowsSecurityError(
            "path_reparse_unsafe",
            "The Windows directory has an unsupported reparse state.",
        )
    if facts.attributes & hydration_markers:
        raise WindowsSecurityError(
            "path_reparse_unsafe",
            "The Windows directory has an unsupported reparse state.",
        )


def _safe_close(api: WindowsPathTrustApi, handle: object) -> None:
    try:
        api.close_handle(handle)
    except BaseException:
        return


def _ace_type_grants_access(ace_type: int) -> bool:
    if ace_type in _ACCESS_ALLOWED_ACE_TYPES:
        return True
    if ace_type in _NON_GRANTING_ACE_TYPES:
        return False
    raise OSError("Native Windows DACL contains an unsupported ACE.")


def _open_tracked_directory(
    api: WindowsPathTrustApi,
    handles: list[object],
    path: str,
    *,
    follow_reparse: bool,
) -> object:
    """Open one directory and either track or close it before propagating."""

    handle: object | None = None
    try:
        handle = api.open_directory(path, follow_reparse=follow_reparse)
        if handle is None:
            raise OSError("Windows directory open returned no handle.")
        handles.append(handle)
        return handle
    except BaseException:
        if handle is not None and not any(item is handle for item in handles):
            _safe_close(api, handle)
        raise


def _capture_one(
    api: WindowsPathTrustApi,
    handle: object,
    *,
    current_user_sid: str,
    trusted_root: bool,
) -> DirectoryTrustSnapshot:
    try:
        facts = api.query_directory(handle)
        security = api.query_security(handle)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise WindowsSecurityError(
            "path_security_unavailable",
            "The Windows directory trust facts could not be inspected.",
        ) from None
    _validate_directory_facts(facts)
    validate_security_facts(
        security,
        current_user_sid=current_user_sid,
        trusted_root=trusted_root,
    )
    return DirectoryTrustSnapshot(
        identity=StableFileIdentity(facts.volume_serial, facts.file_id),
        final_path=facts.final_path,
        attributes=facts.attributes,
        reparse_tag=facts.reparse_tag,
        security=security,
        is_trusted_root=trusted_root,
    )


class PathHierarchyTrust:
    """Own every handle needed to keep a validated path hierarchy bound."""

    __slots__ = (
        "_active_owner",
        "_api",
        "_current_user_sid",
        "_evidence",
        "_handles",
        "_lock",
        "_snapshots",
    )

    def __init__(
        self,
        api: WindowsPathTrustApi,
        current_user_sid: str,
        handles: tuple[object, ...],
        snapshots: tuple[DirectoryTrustSnapshot, ...],
        evidence: PathHierarchyEvidence,
    ) -> None:
        self._api = api
        self._active_owner: int | None = None
        self._current_user_sid = current_user_sid
        self._handles: tuple[object, ...] | None = handles
        self._snapshots = snapshots
        self._evidence = evidence
        self._lock = threading.RLock()

    @property
    def evidence(self) -> PathHierarchyEvidence:
        return self._evidence

    @property
    def root_snapshot(self) -> DirectoryTrustSnapshot:
        return self._snapshots[self._evidence.lexical_depth]

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._handles is None

    def assert_unchanged(self) -> PathHierarchyEvidence:
        self._lock.acquire()
        if self._active_owner is not None:
            self._lock.release()
            raise WindowsSecurityError(
                "path_handle_in_use",
                "The Windows path trust handles are already in active use.",
            )
        handles = self._handles
        if handles is None:
            self._lock.release()
            raise WindowsSecurityError(
                "path_handle_closed",
                "The Windows path trust handles are no longer available.",
            )
        self._active_owner = threading.get_ident()
        try:
            try:
                for handle, expected in zip(handles, self._snapshots, strict=True):
                    current = _capture_one(
                        self._api,
                        handle,
                        current_user_sid=self._current_user_sid,
                        trusted_root=expected.is_trusted_root,
                    )
                    if current != expected:
                        raise WindowsSecurityError(
                            "path_changed",
                            "The Windows path changed after it was inspected.",
                        )
            except WindowsSecurityError as error:
                if error.category == "path_handle_closed":
                    raise
                raise WindowsSecurityError(
                    "path_changed",
                    "The Windows path changed after it was inspected.",
                ) from None
            return self._evidence
        finally:
            self._active_owner = None
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            if self._active_owner is not None:
                raise WindowsSecurityError(
                    "path_handle_in_use",
                    "The Windows path trust handles are already in active use.",
                )
            handles = self._handles
            self._handles = None
            if handles is None:
                return
            for handle in reversed(handles):
                _safe_close(self._api, handle)

    def __enter__(self) -> "PathHierarchyTrust":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"PathHierarchyTrust(state={state!r}, <redacted>)"


def capture_path_hierarchy(
    path: str,
    *,
    purpose: PathTrustPurpose,
    api: WindowsPathTrustApi | None = None,
) -> PathHierarchyTrust:
    """Bind lexical and resolved directory chains under strict trust policy."""

    if type(purpose) is not PathTrustPurpose:
        raise ValueError("Windows path trust purpose is invalid.")
    selected = api if api is not None else NativeWindowsPathTrustApi()
    try:
        supported = selected.supported is True
    except (OSError, RuntimeError, TypeError, ValueError):
        supported = False
    if not supported:
        raise WindowsSecurityError(
            "windows_security_unavailable",
            "Secure Windows path inspection is unavailable on this platform.",
        )
    try:
        current_user_sid = selected.current_user_sid()
        _accepted_owner_sids(current_user_sid)
        lexical = _directory_chain(path)
    except WindowsSecurityError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        raise WindowsSecurityError(
            "path_security_unavailable",
            "The Windows path trust policy could not be established.",
        ) from None

    handles: list[object] = []
    snapshots: list[DirectoryTrustSnapshot] = []
    try:
        for index, component in enumerate(lexical):
            handle = _open_tracked_directory(
                selected, handles, component, follow_reparse=False
            )
            snapshots.append(
                _capture_one(
                    selected,
                    handle,
                    current_user_sid=current_user_sid,
                    trusted_root=index == len(lexical) - 1,
                )
            )

        followed = _open_tracked_directory(selected, handles, path, follow_reparse=True)
        followed_snapshot = _capture_one(
            selected,
            followed,
            current_user_sid=current_user_sid,
            trusted_root=True,
        )
        snapshots.append(followed_snapshot)
        resolved = _directory_chain(followed_snapshot.final_path)
        for index, component in enumerate(resolved):
            handle = _open_tracked_directory(
                selected, handles, component, follow_reparse=False
            )
            snapshots.append(
                _capture_one(
                    selected,
                    handle,
                    current_user_sid=current_user_sid,
                    trusted_root=index == len(resolved) - 1,
                )
            )
        if snapshots[-1].identity != followed_snapshot.identity:
            raise WindowsSecurityError(
                "path_changed", "The Windows path changed while it was inspected."
            )
        evidence = PathHierarchyEvidence(
            purpose=purpose,
            lexical_depth=len(lexical),
            resolved_depth=len(resolved),
            root_identity=followed_snapshot.identity,
        )
        result = PathHierarchyTrust(
            selected,
            current_user_sid,
            tuple(handles),
            tuple(snapshots),
            evidence,
        )
        result.assert_unchanged()
        return result
    except WindowsSecurityError:
        for handle in reversed(handles):
            _safe_close(selected, handle)
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        for handle in reversed(handles):
            _safe_close(selected, handle)
        raise WindowsSecurityError(
            "path_open_failed", "The Windows directory could not be opened safely."
        ) from None
    except BaseException:
        for handle in reversed(handles):
            _safe_close(selected, handle)
        raise


class _FileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FileIdInformation(ctypes.Structure):
    _fields_ = (("volume_serial", ctypes.c_uint64), ("file_id", _FileId128))


class _FileAttributeTagInformation(ctypes.Structure):
    _fields_ = (("attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32))


class _AclSizeInformation(ctypes.Structure):
    _fields_ = (
        ("ace_count", ctypes.c_uint32),
        ("bytes_in_use", ctypes.c_uint32),
        ("bytes_free", ctypes.c_uint32),
    )


class _AceHeader(ctypes.Structure):
    _fields_ = (
        ("ace_type", ctypes.c_ubyte),
        ("ace_flags", ctypes.c_ubyte),
        ("ace_size", ctypes.c_ushort),
    )


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (("sid", ctypes.c_void_p), ("attributes", ctypes.c_uint32))


class NativeWindowsPathTrustApi:
    """ctypes implementation of directory and security-descriptor capture."""

    __slots__ = ("_advapi32", "_kernel32")

    def __init__(self) -> None:
        self._advapi32: Any | None = None
        self._kernel32: Any | None = None
        win_dll = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or win_dll is None:
            return
        self._kernel32 = win_dll("kernel32", use_last_error=True)
        self._advapi32 = win_dll("advapi32", use_last_error=True)
        self._bind()

    @property
    def supported(self) -> bool:
        return self._kernel32 is not None and self._advapi32 is not None

    def _bind(self) -> None:
        kernel32, advapi32 = self._require()
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
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_int

        advapi32.GetSecurityInfo.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.GetSecurityInfo.restype = ctypes.c_uint32
        advapi32.GetAclInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
        )
        advapi32.GetAclInformation.restype = ctypes.c_int
        advapi32.GetAce.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.GetAce.restype = ctypes.c_int
        advapi32.IsValidSid.argtypes = (ctypes.c_void_p,)
        advapi32.IsValidSid.restype = ctypes.c_int
        advapi32.GetLengthSid.argtypes = (ctypes.c_void_p,)
        advapi32.GetLengthSid.restype = ctypes.c_uint32
        advapi32.ConvertSidToStringSidW.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
        advapi32.OpenProcessToken.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.OpenProcessToken.restype = ctypes.c_int
        advapi32.GetTokenInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        )
        advapi32.GetTokenInformation.restype = ctypes.c_int

    def _require(self) -> tuple[Any, Any]:
        if self._kernel32 is None or self._advapi32 is None:
            raise OSError("Native Windows path inspection is unavailable.")
        return self._kernel32, self._advapi32

    @staticmethod
    def _handle(value: object) -> ctypes.c_void_p:
        if type(value) is not int or value <= 0:
            raise OSError("Native Windows directory handle is invalid.")
        return ctypes.c_void_p(value)

    @staticmethod
    def _last_error(message: str) -> None:
        raise OSError(ctypes.get_last_error(), message)

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        if not _valid_path(path) or type(follow_reparse) is not bool:
            raise ValueError("Native Windows directory request is invalid.")
        kernel32, _advapi32 = self._require()
        flags = 0x02000000  # FILE_FLAG_BACKUP_SEMANTICS
        if not follow_reparse:
            flags |= 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
        invalid = ctypes.c_void_p(-1).value
        native: int | None = None
        handle: int | None = None
        try:
            native = kernel32.CreateFileW(
                path,
                0x00020080,  # READ_CONTROL | FILE_READ_ATTRIBUTES
                0x00000001,  # FILE_SHARE_READ; deny write and delete sharing
                None,
                3,
                flags,
                None,
            )
            if native is None or native == invalid:
                self._last_error("Native Windows directory open failed.")
            handle = int(native)
            return handle
        except BaseException:
            to_close = handle
            if to_close is None and type(native) is int and native > 0:
                to_close = native
            if to_close is not None and to_close != invalid:
                try:
                    kernel32.CloseHandle(ctypes.c_void_p(to_close))
                except BaseException:
                    pass
            raise

    def _final_path(self, handle: ctypes.c_void_p) -> str:
        kernel32, _advapi32 = self._require()
        required = int(kernel32.GetFinalPathNameByHandleW(handle, None, 0, 0))
        if required <= 0 or required > _MAX_PATH_CHARACTERS:
            self._last_error("Native Windows directory path query failed.")
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = int(
            kernel32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        )
        if written <= 0 or written > required:
            self._last_error("Native Windows directory path query failed.")
        return buffer.value

    def _drive_type(self, final_path: str) -> int:
        kernel32, _advapi32 = self._require()
        query = _strip_extended_prefix(final_path)
        volume = ctypes.create_unicode_buffer(_MAX_PATH_CHARACTERS + 1)
        if not kernel32.GetVolumePathNameW(query, volume, len(volume)):
            return 0
        return int(kernel32.GetDriveTypeW(volume.value))

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        kernel32, _advapi32 = self._require()
        native = self._handle(handle)
        file_id = _FileIdInformation()
        if not kernel32.GetFileInformationByHandleEx(
            native, 18, ctypes.byref(file_id), ctypes.sizeof(file_id)
        ):
            self._last_error("Native Windows directory identity query failed.")
        tag = _FileAttributeTagInformation()
        if not kernel32.GetFileInformationByHandleEx(
            native, 9, ctypes.byref(tag), ctypes.sizeof(tag)
        ):
            self._last_error("Native Windows directory attribute query failed.")
        final_path = self._final_path(native)
        return NativeDirectoryFacts(
            final_path=final_path,
            volume_serial=int(file_id.volume_serial),
            file_id=bytes(file_id.file_id.identifier),
            attributes=int(tag.attributes),
            drive_type=self._drive_type(final_path),
            file_type=int(kernel32.GetFileType(native)),
            reparse_tag=int(tag.reparse_tag),
        )

    def _sid_text(self, sid: ctypes.c_void_p) -> str:
        kernel32, advapi32 = self._require()
        if not sid or not advapi32.IsValidSid(sid):
            raise OSError("Native Windows SID is invalid.")
        rendered = ctypes.c_void_p()
        try:
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
                self._last_error("Native Windows SID conversion failed.")
            value = ctypes.wstring_at(rendered)
        finally:
            if rendered:
                try:
                    kernel32.LocalFree(rendered)
                except BaseException:
                    pass
        if not _valid_sid_text(value):
            raise OSError("Native Windows SID is invalid.")
        return value.upper()

    def _allowed_aces(self, dacl: ctypes.c_void_p) -> tuple[AccessAllowedAce, ...]:
        _kernel32, advapi32 = self._require()
        size = _AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl, ctypes.byref(size), ctypes.sizeof(size), 2
        ):
            self._last_error("Native Windows DACL query failed.")
        if size.ace_count > _MAX_ACES:
            raise OSError("Native Windows DACL is too large.")
        allowed: list[AccessAllowedAce] = []
        for index in range(size.ace_count):
            pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(pointer)) or not pointer:
                self._last_error("Native Windows ACE query failed.")
            header = ctypes.cast(pointer, ctypes.POINTER(_AceHeader)).contents
            if not _ace_type_grants_access(int(header.ace_type)):
                continue
            if pointer.value is None:
                raise OSError("Native Windows ACE is invalid.")
            address = int(pointer.value)
            if header.ace_size < 8:
                raise OSError("Native Windows ACE is invalid.")
            mask = ctypes.c_uint32.from_address(address + 4).value
            sid_offset = 8
            if header.ace_type in (5, 11):
                if header.ace_size < 12:
                    raise OSError("Native Windows ACE is invalid.")
                object_flags = ctypes.c_uint32.from_address(address + 8).value
                sid_offset = 12
                if object_flags & 0x1:
                    sid_offset += 16
                if object_flags & 0x2:
                    sid_offset += 16
            if sid_offset >= header.ace_size:
                raise OSError("Native Windows ACE is invalid.")
            sid_pointer = ctypes.c_void_p(address + sid_offset)
            if not advapi32.IsValidSid(sid_pointer):
                raise OSError("Native Windows ACE is invalid.")
            sid_length = int(advapi32.GetLengthSid(sid_pointer))
            if sid_length <= 0 or sid_offset + sid_length > header.ace_size:
                raise OSError("Native Windows ACE is invalid.")
            sid = self._sid_text(sid_pointer)
            allowed.append(AccessAllowedAce(sid, int(mask), int(header.ace_flags)))
        return tuple(allowed)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        kernel32, advapi32 = self._require()
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = -1
        try:
            result = int(
                advapi32.GetSecurityInfo(
                    self._handle(handle),
                    1,  # SE_FILE_OBJECT
                    0x00000001 | 0x00000004,  # OWNER | DACL
                    ctypes.byref(owner),
                    None,
                    ctypes.byref(dacl),
                    None,
                    ctypes.byref(descriptor),
                )
            )
            if result != 0 or not descriptor or not owner:
                raise OSError(
                    result, "Native Windows security descriptor query failed."
                )
            owner_sid = self._sid_text(owner)
            allowed = self._allowed_aces(dacl) if dacl else ()
            return NativeSecurityFacts(owner_sid, bool(dacl), allowed)
        finally:
            if descriptor:
                try:
                    kernel32.LocalFree(descriptor)
                except BaseException:
                    pass

    def current_user_sid(self) -> str:
        kernel32, advapi32 = self._require()
        token = ctypes.c_void_p()
        try:
            if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
            ):
                self._last_error("Native Windows process token query failed.")
            required = ctypes.c_uint32()
            ctypes.set_last_error(0)
            first = advapi32.GetTokenInformation(
                token, 1, None, 0, ctypes.byref(required)
            )
            if first or required.value == 0 or ctypes.get_last_error() != 122:
                raise OSError("Native Windows token sizing failed.")
            buffer = ctypes.create_string_buffer(required.value)
            if not advapi32.GetTokenInformation(
                token, 1, buffer, required.value, ctypes.byref(required)
            ):
                self._last_error("Native Windows token query failed.")
            user = ctypes.cast(buffer, ctypes.POINTER(_SidAndAttributes)).contents
            return self._sid_text(user.sid)
        finally:
            if token:
                try:
                    kernel32.CloseHandle(token)
                except BaseException:
                    pass

    def close_handle(self, handle: object) -> None:
        kernel32, _advapi32 = self._require()
        if not kernel32.CloseHandle(self._handle(handle)):
            self._last_error("Native Windows directory close failed.")


__all__ = [
    "BROAD_WRITE_PRINCIPAL_SIDS",
    "AccessAllowedAce",
    "DirectoryTrustSnapshot",
    "NativeDirectoryFacts",
    "NativeSecurityFacts",
    "NativeWindowsPathTrustApi",
    "PathHierarchyEvidence",
    "PathHierarchyTrust",
    "PathTrustPurpose",
    "WindowsPathTrustApi",
    "capture_path_hierarchy",
    "validate_security_facts",
]
