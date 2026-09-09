"""Secured cross-session Windows mutex ownership for Gate-A transactions.

The module creates no worker, listener, file, or durable state.  It only owns a
named Windows mutex whose current-user/SYSTEM security descriptor is verified
before the mutex can authorize later recovery or mutation work.
"""

from __future__ import annotations

import ctypes
import os
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn, Protocol

SYSTEM_SID = "S-1-5-18"
MUTEX_ACCESS_MASK = 0x00120001  # READ_CONTROL | SYNCHRONIZE | MUTEX_MODIFY_STATE

_MUTEX_NAME = re.compile(r"^Global\\TowerScout(?:Env|Repair)-v1-[0-9a-f]{64}$")
_MAX_SID_CHARACTERS = 184
_MAX_ACES = 64
_ERROR_ALREADY_EXISTS = 183
_CREATE_MUTEX_INITIAL_OWNER = 0x00000001
_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED = 0x00000080
_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_SE_KERNEL_OBJECT = 6
_SE_DACL_PROTECTED = 0x1000
_SDDL_REVISION_1 = 1
_MAX_TIMEOUT_MS = 60_000

_active_names: set[str] = set()
_active_names_lock = threading.Lock()


class WindowsMutexError(RuntimeError):
    """A sanitized, fail-closed cross-session mutex error."""

    def __init__(self, category: str, public_message: str) -> None:
        super().__init__(public_message)
        self.category = category
        self.public_message = public_message

    def __repr__(self) -> str:
        return f"WindowsMutexError(category={self.category!r})"


class MutexWaitOutcome(str, Enum):
    ACQUIRED = "acquired"
    ABANDONED = "abandoned"
    TIMEOUT = "timeout"
    FAILED = "failed"


def _valid_sid(value: object) -> bool:
    if (
        type(value) is not str
        or not value.startswith("S-")
        or len(value) > _MAX_SID_CHARACTERS
    ):
        return False
    pieces = value.split("-")
    return len(pieces) >= 3 and all(piece.isdecimal() for piece in pieces[1:])


@dataclass(frozen=True, slots=True, repr=False)
class MutexAccessAllowedAce:
    principal_sid: str = field(repr=False)
    access_mask: int
    flags: int

    def __post_init__(self) -> None:
        if (
            not _valid_sid(self.principal_sid)
            or type(self.access_mask) is not int
            or not 0 <= self.access_mask < 2**32
            or type(self.flags) is not int
            or not 0 <= self.flags < 2**8
        ):
            raise ValueError("Windows mutex ACE facts are invalid.")

    def __repr__(self) -> str:
        return (
            "MutexAccessAllowedAce("
            f"access_mask={self.access_mask:#x}, flags={self.flags:#x}, "
            "principal=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class MutexSecurityFacts:
    owner_sid: str = field(repr=False)
    dacl_present: bool
    dacl_protected: bool
    ace_count: int
    allowed_aces: tuple[MutexAccessAllowedAce, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _valid_sid(self.owner_sid)
            or type(self.dacl_present) is not bool
            or type(self.dacl_protected) is not bool
            or type(self.ace_count) is not int
            or not 0 <= self.ace_count <= _MAX_ACES
            or type(self.allowed_aces) is not tuple
            or len(self.allowed_aces) > self.ace_count
            or any(type(ace) is not MutexAccessAllowedAce for ace in self.allowed_aces)
        ):
            raise ValueError("Windows mutex security facts are invalid.")

    def __repr__(self) -> str:
        return (
            "MutexSecurityFacts("
            f"dacl_present={self.dacl_present}, "
            f"dacl_protected={self.dacl_protected}, "
            f"ace_count={self.ace_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CreatedMutex:
    handle: object = field(repr=False)
    created: bool

    def __post_init__(self) -> None:
        if self.handle is None or type(self.created) is not bool:
            raise ValueError("Windows mutex creation result is invalid.")

    def __repr__(self) -> str:
        return f"CreatedMutex(created={self.created}, handle=<redacted>)"


class WindowsMutexApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def create_mutex(
        self, name: str, *, owner_sid: str, access_mask: int
    ) -> CreatedMutex: ...

    def query_security(self, handle: object) -> MutexSecurityFacts: ...

    def wait(self, handle: object, timeout_ms: int) -> MutexWaitOutcome: ...

    def release_mutex(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...


def _fail(category: str) -> NoReturn:
    messages = {
        "mutex_invalid": "The Windows repair lock request is invalid.",
        "mutex_unavailable": "The Windows repair lock is unavailable.",
        "mutex_busy": "Another repair operation currently owns this target.",
        "mutex_security_mismatch": (
            "The Windows repair lock access policy is not trusted."
        ),
        "mutex_wrong_thread": (
            "The Windows repair lock must be released by its owning operation."
        ),
        "mutex_release_failed": (
            "The Windows repair lock could not be released safely."
        ),
    }
    raise WindowsMutexError(category, messages[category]) from None


def _reserve_name(name: str) -> None:
    with _active_names_lock:
        if name in _active_names:
            _fail("mutex_busy")
        _active_names.add(name)


def _unreserve_name(name: str) -> None:
    with _active_names_lock:
        _active_names.discard(name)


def _security_matches(facts: object, current_user_sid: str) -> bool:
    if type(facts) is not MutexSecurityFacts:
        return False
    expected = {
        (SYSTEM_SID, MUTEX_ACCESS_MASK, 0),
        (current_user_sid.upper(), MUTEX_ACCESS_MASK, 0),
    }
    actual = {
        (ace.principal_sid.upper(), ace.access_mask, ace.flags)
        for ace in facts.allowed_aces
    }
    return (
        facts.owner_sid.upper() == current_user_sid.upper()
        and facts.dacl_present is True
        and facts.dacl_protected is True
        and facts.ace_count == 2
        and len(facts.allowed_aces) == 2
        and actual == expected
    )


def _best_effort_cleanup(
    api: WindowsMutexApi,
    handle: object | None,
    *,
    owned: bool,
    name: str,
) -> None:
    if handle is not None and owned:
        try:
            api.release_mutex(handle)
        except BaseException:
            pass
    if handle is not None:
        try:
            api.close_handle(handle)
        except BaseException:
            pass
    _unreserve_name(name)


class HeldCrossSessionMutex:
    """Own one verified mutex until same-thread release and handle close."""

    __slots__ = (
        "_abandoned",
        "_api",
        "_closed",
        "_handle",
        "_name",
        "_owner_thread",
    )

    def __init__(
        self,
        *,
        api: WindowsMutexApi,
        handle: object,
        name: str,
        abandoned: bool,
    ) -> None:
        self._api = api
        self._handle: object | None = handle
        self._name = name
        self._abandoned = abandoned
        self._owner_thread = threading.get_ident()
        self._closed = False

    @property
    def abandoned(self) -> bool:
        return self._abandoned

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        if threading.get_ident() != self._owner_thread:
            _fail("mutex_wrong_thread")
        handle = self._handle
        self._handle = None
        self._closed = True
        failed = False
        try:
            if handle is not None:
                try:
                    self._api.release_mutex(handle)
                except BaseException:
                    failed = True
                try:
                    self._api.close_handle(handle)
                except BaseException:
                    failed = True
        finally:
            _unreserve_name(self._name)
        if failed:
            _fail("mutex_release_failed")

    def __enter__(self) -> "HeldCrossSessionMutex":
        if self._closed:
            _fail("mutex_unavailable")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else "owned"
        return (
            "HeldCrossSessionMutex("
            f"state={state!r}, abandoned={self._abandoned}, name=<redacted>)"
        )


def acquire_secured_cross_session_mutex(
    name: str,
    *,
    api: WindowsMutexApi | None = None,
    timeout_ms: int = 0,
) -> HeldCrossSessionMutex:
    """Create/open, verify, and own an exact TowerScout global mutex."""

    if (
        type(name) is not str
        or _MUTEX_NAME.fullmatch(name) is None
        or type(timeout_ms) is not int
        or not 0 <= timeout_ms <= _MAX_TIMEOUT_MS
    ):
        _fail("mutex_invalid")
    selected: WindowsMutexApi = api if api is not None else NativeWindowsMutexApi()
    try:
        supported = selected.supported
        current_user_sid = selected.current_user_sid()
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail("mutex_unavailable")
    if supported is not True or not _valid_sid(current_user_sid):
        _fail("mutex_unavailable")

    _reserve_name(name)
    handle: object | None = None
    owned = False
    try:
        created = selected.create_mutex(
            name,
            owner_sid=current_user_sid,
            access_mask=MUTEX_ACCESS_MASK,
        )
        if type(created) is not CreatedMutex:
            _fail("mutex_unavailable")
        handle = created.handle
        owned = created.created
        try:
            security = selected.query_security(handle)
        except (OSError, RuntimeError, TypeError, ValueError):
            _fail("mutex_unavailable")
        if not _security_matches(security, current_user_sid):
            _fail("mutex_security_mismatch")

        abandoned = False
        if not created.created:
            try:
                outcome = selected.wait(handle, timeout_ms)
            except (OSError, RuntimeError, TypeError, ValueError):
                _fail("mutex_unavailable")
            if outcome is MutexWaitOutcome.ACQUIRED:
                owned = True
            elif outcome is MutexWaitOutcome.ABANDONED:
                owned = True
                abandoned = True
            elif outcome is MutexWaitOutcome.TIMEOUT:
                _fail("mutex_busy")
            else:
                _fail("mutex_unavailable")
        return HeldCrossSessionMutex(
            api=selected,
            handle=handle,
            name=name,
            abandoned=abandoned,
        )
    except WindowsMutexError:
        _best_effort_cleanup(selected, handle, owned=owned, name=name)
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _best_effort_cleanup(selected, handle, owned=owned, name=name)
        _fail("mutex_unavailable")
    except BaseException:
        _best_effort_cleanup(selected, handle, owned=owned, name=name)
        raise


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", ctypes.c_int),
    )


class _AclSizeInformation(ctypes.Structure):
    _fields_ = (
        ("ace_count", ctypes.c_uint32),
        ("acl_bytes_in_use", ctypes.c_uint32),
        ("acl_bytes_free", ctypes.c_uint32),
    )


class _AceHeader(ctypes.Structure):
    _fields_ = (
        ("ace_type", ctypes.c_ubyte),
        ("ace_flags", ctypes.c_ubyte),
        ("ace_size", ctypes.c_ushort),
    )


class NativeWindowsMutexApi:
    """ctypes adapter for secured named Windows mutex operations."""

    @property
    def supported(self) -> bool:
        return os.name == "nt" and getattr(ctypes, "WinDLL", None) is not None

    def _require(self) -> tuple[Any, Any]:
        loader = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or loader is None:
            raise OSError("Native Windows mutex APIs are unavailable.")
        return (
            loader("kernel32", use_last_error=True),
            loader("advapi32", use_last_error=True),
        )

    @staticmethod
    def _handle(handle: object) -> ctypes.c_void_p:
        if type(handle) is not int or handle <= 0:
            raise OSError("Native Windows mutex handle is invalid.")
        return ctypes.c_void_p(handle)

    def current_user_sid(self) -> str:
        from .windows_path_trust import NativeWindowsPathTrustApi

        return NativeWindowsPathTrustApi().current_user_sid()

    def create_mutex(
        self, name: str, *, owner_sid: str, access_mask: int
    ) -> CreatedMutex:
        kernel32, advapi32 = self._require()
        descriptor = ctypes.c_void_p()
        descriptor_size = ctypes.c_uint32()
        sddl = (
            f"O:{owner_sid}D:P"
            f"(A;;0x{access_mask:08x};;;SY)"
            f"(A;;0x{access_mask:08x};;;{owner_sid})"
        )
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            ctypes.c_int
        )
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            raise OSError("Native Windows mutex descriptor creation failed.")
        try:
            attributes = _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes),
                descriptor,
                False,
            )
            kernel32.CreateMutexExW.restype = ctypes.c_void_p
            ctypes.set_last_error(0)
            raw_handle = kernel32.CreateMutexExW(
                ctypes.byref(attributes),
                name,
                _CREATE_MUTEX_INITIAL_OWNER,
                access_mask,
            )
            last_error = ctypes.get_last_error()
            if not raw_handle:
                raise OSError("Native Windows mutex creation failed.")
            native_handle = int(raw_handle)
            if native_handle <= 0:
                raise OSError("Native Windows mutex creation failed.")
            return CreatedMutex(
                native_handle,
                last_error != _ERROR_ALREADY_EXISTS,
            )
        finally:
            if descriptor:
                kernel32.LocalFree(descriptor)

    def _sid_text(self, sid: ctypes.c_void_p) -> str:
        kernel32, advapi32 = self._require()
        if not sid or not advapi32.IsValidSid(sid):
            raise OSError("Native Windows mutex SID is invalid.")
        rendered = ctypes.c_void_p()
        try:
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
                raise OSError("Native Windows mutex SID conversion failed.")
            value = ctypes.wstring_at(rendered)
        finally:
            if rendered:
                kernel32.LocalFree(rendered)
        if not _valid_sid(value):
            raise OSError("Native Windows mutex SID is invalid.")
        return value.upper()

    def _allowed_aces(
        self, dacl: ctypes.c_void_p, ace_count: int
    ) -> tuple[MutexAccessAllowedAce, ...]:
        _kernel32, advapi32 = self._require()
        allowed: list[MutexAccessAllowedAce] = []
        for index in range(ace_count):
            pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(pointer)) or not pointer:
                raise OSError("Native Windows mutex ACE query failed.")
            header = ctypes.cast(pointer, ctypes.POINTER(_AceHeader)).contents
            if int(header.ace_type) != 0:
                continue
            if pointer.value is None or header.ace_size < 8:
                raise OSError("Native Windows mutex ACE is invalid.")
            address = int(pointer.value)
            mask = int(ctypes.c_uint32.from_address(address + 4).value)
            sid_pointer = ctypes.c_void_p(address + 8)
            if not advapi32.IsValidSid(sid_pointer):
                raise OSError("Native Windows mutex ACE is invalid.")
            sid_length = int(advapi32.GetLengthSid(sid_pointer))
            if sid_length <= 0 or 8 + sid_length > header.ace_size:
                raise OSError("Native Windows mutex ACE is invalid.")
            allowed.append(
                MutexAccessAllowedAce(
                    self._sid_text(sid_pointer),
                    mask,
                    int(header.ace_flags),
                )
            )
        return tuple(allowed)

    def query_security(self, handle: object) -> MutexSecurityFacts:
        kernel32, advapi32 = self._require()
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        try:
            result = int(
                advapi32.GetSecurityInfo(
                    self._handle(handle),
                    _SE_KERNEL_OBJECT,
                    _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                    ctypes.byref(owner),
                    None,
                    ctypes.byref(dacl),
                    None,
                    ctypes.byref(descriptor),
                )
            )
            if result != 0 or not descriptor or not owner:
                raise OSError("Native Windows mutex security query failed.")
            dacl_present = ctypes.c_int()
            dacl_defaulted = ctypes.c_int()
            actual_dacl = ctypes.c_void_p()
            if not advapi32.GetSecurityDescriptorDacl(
                descriptor,
                ctypes.byref(dacl_present),
                ctypes.byref(actual_dacl),
                ctypes.byref(dacl_defaulted),
            ):
                raise OSError("Native Windows mutex DACL query failed.")
            control = ctypes.c_ushort()
            revision = ctypes.c_uint32()
            if not advapi32.GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                raise OSError("Native Windows mutex DACL query failed.")
            ace_count = 0
            allowed: tuple[MutexAccessAllowedAce, ...] = ()
            if dacl_present.value and actual_dacl:
                size = _AclSizeInformation()
                if not advapi32.GetAclInformation(
                    actual_dacl,
                    ctypes.byref(size),
                    ctypes.sizeof(size),
                    2,
                ):
                    raise OSError("Native Windows mutex DACL query failed.")
                ace_count = int(size.ace_count)
                if ace_count > _MAX_ACES:
                    raise OSError("Native Windows mutex DACL is too large.")
                allowed = self._allowed_aces(actual_dacl, ace_count)
            return MutexSecurityFacts(
                owner_sid=self._sid_text(owner),
                dacl_present=bool(dacl_present.value),
                dacl_protected=bool(control.value & _SE_DACL_PROTECTED),
                ace_count=ace_count,
                allowed_aces=allowed,
            )
        finally:
            if descriptor:
                kernel32.LocalFree(descriptor)

    def wait(self, handle: object, timeout_ms: int) -> MutexWaitOutcome:
        kernel32, _advapi32 = self._require()
        result = int(kernel32.WaitForSingleObject(self._handle(handle), timeout_ms))
        return {
            _WAIT_OBJECT_0: MutexWaitOutcome.ACQUIRED,
            _WAIT_ABANDONED: MutexWaitOutcome.ABANDONED,
            _WAIT_TIMEOUT: MutexWaitOutcome.TIMEOUT,
            _WAIT_FAILED: MutexWaitOutcome.FAILED,
        }.get(result, MutexWaitOutcome.FAILED)

    def release_mutex(self, handle: object) -> None:
        kernel32, _advapi32 = self._require()
        if not kernel32.ReleaseMutex(self._handle(handle)):
            raise OSError("Native Windows mutex release failed.")

    def close_handle(self, handle: object) -> None:
        kernel32, _advapi32 = self._require()
        if not kernel32.CloseHandle(self._handle(handle)):
            raise OSError("Native Windows mutex close failed.")


__all__ = [
    "MUTEX_ACCESS_MASK",
    "SYSTEM_SID",
    "CreatedMutex",
    "HeldCrossSessionMutex",
    "MutexAccessAllowedAce",
    "MutexSecurityFacts",
    "MutexWaitOutcome",
    "NativeWindowsMutexApi",
    "WindowsMutexApi",
    "WindowsMutexError",
    "acquire_secured_cross_session_mutex",
]
