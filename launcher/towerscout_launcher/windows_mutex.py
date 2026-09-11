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
from typing import Any, Callable, NoReturn, Protocol

from .target_contracts import ResolvedRepairTarget
from .windows_security import (
    StableFileIdentity,
    canonical_identity_digest,
    derive_environment_mutex_name,
    derive_repair_mutex_name,
)

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


class RuntimeTransactionLockErrorCode(str, Enum):
    INVALID_BINDING = "invalid_binding"
    LOCK_UNAVAILABLE = "repair_lock_unavailable"
    BUSY = "repair_busy"
    BINDING_CHANGED = "target_changed"
    WRONG_THREAD = "repair_lock_wrong_thread"
    RELEASE_FAILED = "repair_lock_release_failed"


class RuntimeTransactionLockError(RuntimeError):
    """A sanitized failure while owning the ordered Gate-A lock pair."""

    _MESSAGES = {
        RuntimeTransactionLockErrorCode.INVALID_BINDING: (
            "The runtime transaction lock binding is invalid."
        ),
        RuntimeTransactionLockErrorCode.LOCK_UNAVAILABLE: (
            "The Windows repair locks are unavailable."
        ),
        RuntimeTransactionLockErrorCode.BUSY: (
            "Another repair operation currently owns this environment or target."
        ),
        RuntimeTransactionLockErrorCode.BINDING_CHANGED: (
            "The runtime repair target changed while its locks were acquired."
        ),
        RuntimeTransactionLockErrorCode.WRONG_THREAD: (
            "The runtime repair locks must be released by their owning operation."
        ),
        RuntimeTransactionLockErrorCode.RELEASE_FAILED: (
            "The runtime repair locks could not be released safely."
        ),
    }

    def __init__(self, code: RuntimeTransactionLockErrorCode) -> None:
        if type(code) is not RuntimeTransactionLockErrorCode:
            raise ValueError("Unknown runtime transaction lock error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeTransactionLockError(code={self.code.value!r})"


def _fail_runtime_locks(code: RuntimeTransactionLockErrorCode) -> NoReturn:
    raise RuntimeTransactionLockError(code) from None


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeTransactionLockBinding:
    """Opaque lock keys plus the exact immutable state they serialize."""

    environment_mutex_name: str = field(repr=False)
    target_mutex_name: str = field(repr=False)
    target_token_sha256: str = field(repr=False)
    environment_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.environment_mutex_name) is not str
            or not self.environment_mutex_name.startswith("Global\\TowerScoutEnv-v1-")
            or _MUTEX_NAME.fullmatch(self.environment_mutex_name) is None
            or type(self.target_mutex_name) is not str
            or not self.target_mutex_name.startswith("Global\\TowerScoutRepair-v1-")
            or _MUTEX_NAME.fullmatch(self.target_mutex_name) is None
            or not _is_sha256(self.target_token_sha256)
            or not _is_sha256(self.environment_sha256)
        ):
            raise ValueError("Runtime transaction lock binding is invalid.")

    def __repr__(self) -> str:
        return "RuntimeTransactionLockBinding(<redacted>)"


def runtime_transaction_lock_binding(
    target: ResolvedRepairTarget,
    package_parent: StableFileIdentity,
) -> RuntimeTransactionLockBinding:
    """Bind stable serialization keys to one exact immutable repair target.

    ``package_parent`` is the held identity of the directory containing
    ``.env`` (the package root). Mutable endpoint and volume inspection hashes
    deliberately remain in the target token, not the mutex names, so identity
    drift cannot create a second lock for the same canonical target.
    """

    if (
        type(target) is not ResolvedRepairTarget
        or type(package_parent) is not StableFileIdentity
        or target.package_root.volume_serial != package_parent.volume_serial
        or target.package_root.file_id != package_parent.file_id
        or target.compose.environment_source.final_path.parent
        != target.package_root.final_path
        or target.volumes[0].logical_name != "towerscout_config"
    ):
        _fail_runtime_locks(RuntimeTransactionLockErrorCode.INVALID_BINDING)
    try:
        endpoint = canonical_identity_digest(
            "Endpoint",
            (
                b"runtime-product",
                target.endpoint.product.value.encode("ascii"),
                b"endpoint-kind",
                target.endpoint.kind.value.encode("ascii"),
                b"canonical-endpoint",
                target.endpoint.canonical_endpoint.encode("utf-8", errors="strict"),
                b"rootless",
                b"1" if target.endpoint.rootless else b"0",
            ),
        )
        config_volume = target.volumes[0]
        volume = canonical_identity_digest(
            "ConfigVolume",
            (
                b"logical-name",
                config_volume.logical_name.encode("utf-8", errors="strict"),
                b"runtime-name",
                config_volume.runtime_name.encode("utf-8", errors="strict"),
                b"destination",
                config_volume.destination.encode("utf-8", errors="strict"),
            ),
        )
        return RuntimeTransactionLockBinding(
            environment_mutex_name=derive_environment_mutex_name(package_parent),
            target_mutex_name=derive_repair_mutex_name(
                endpoint=endpoint,
                compose_project=target.compose_project,
                config_volume=volume,
            ),
            target_token_sha256=target.target_token.digest_sha256,
            environment_sha256=target.compose.environment_sha256,
        )
    except Exception:
        _fail_runtime_locks(RuntimeTransactionLockErrorCode.INVALID_BINDING)


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


def _mapped_runtime_lock_error(
    error: WindowsMutexError,
) -> RuntimeTransactionLockErrorCode:
    return {
        "mutex_busy": RuntimeTransactionLockErrorCode.BUSY,
        "mutex_wrong_thread": RuntimeTransactionLockErrorCode.WRONG_THREAD,
        "mutex_release_failed": RuntimeTransactionLockErrorCode.RELEASE_FAILED,
    }.get(error.category, RuntimeTransactionLockErrorCode.LOCK_UNAVAILABLE)


def _close_runtime_mutexes(
    mutexes: tuple[HeldCrossSessionMutex | None, ...],
) -> bool:
    failed = False
    for mutex in mutexes:
        if mutex is None:
            continue
        try:
            mutex.close()
        except WindowsMutexError:
            failed = True
    return failed


class HeldRuntimeTransactionLocks:
    """Own the environment mutex first and target mutex second."""

    __slots__ = (
        "_binding",
        "_environment_abandoned",
        "_environment_mutex",
        "_target_abandoned",
        "_target_mutex",
    )

    def __init__(
        self,
        *,
        binding: RuntimeTransactionLockBinding,
        environment_mutex: HeldCrossSessionMutex,
        target_mutex: HeldCrossSessionMutex,
    ) -> None:
        if (
            type(binding) is not RuntimeTransactionLockBinding
            or type(environment_mutex) is not HeldCrossSessionMutex
            or environment_mutex.closed
            or type(target_mutex) is not HeldCrossSessionMutex
            or target_mutex.closed
        ):
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.INVALID_BINDING)
        self._binding = binding
        self._environment_abandoned = environment_mutex.abandoned
        self._target_abandoned = target_mutex.abandoned
        self._environment_mutex: HeldCrossSessionMutex | None = environment_mutex
        self._target_mutex: HeldCrossSessionMutex | None = target_mutex

    @property
    def environment_abandoned(self) -> bool:
        return self._environment_abandoned

    @property
    def target_abandoned(self) -> bool:
        return self._target_abandoned

    @property
    def closed(self) -> bool:
        return self._environment_mutex is None and self._target_mutex is None

    def close(self) -> None:
        if self.closed:
            return
        wrong_thread = False
        failed = False
        target_mutex = self._target_mutex
        environment_mutex = self._environment_mutex
        for mutex in (target_mutex, environment_mutex):
            if mutex is None:
                continue
            try:
                mutex.close()
            except WindowsMutexError as error:
                wrong_thread = wrong_thread or error.category == "mutex_wrong_thread"
                failed = True
            finally:
                if mutex.closed:
                    if mutex is target_mutex:
                        self._target_mutex = None
                    else:
                        self._environment_mutex = None
        if wrong_thread:
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.WRONG_THREAD)
        if failed:
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.RELEASE_FAILED)

    def __enter__(self) -> "HeldRuntimeTransactionLocks":
        if self.closed:
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.LOCK_UNAVAILABLE)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "owned"
        return (
            "HeldRuntimeTransactionLocks("
            f"state={state!r}, "
            f"environment_abandoned={self._environment_abandoned}, "
            f"target_abandoned={self._target_abandoned}, <redacted>)"
        )


def acquire_ordered_runtime_transaction_locks(
    binding: RuntimeTransactionLockBinding,
    revalidate: Callable[[], RuntimeTransactionLockBinding],
    *,
    api: WindowsMutexApi | None = None,
    timeout_ms: int = 0,
) -> HeldRuntimeTransactionLocks:
    """Acquire environment then target mutex and revalidate under both.

    The callback must reconstruct the binding from currently held, freshly
    validated target and environment state. It runs once under the environment
    mutex before target acquisition and again while both mutexes are owned.
    """

    if type(binding) is not RuntimeTransactionLockBinding or not callable(revalidate):
        _fail_runtime_locks(RuntimeTransactionLockErrorCode.INVALID_BINDING)
    environment_mutex: HeldCrossSessionMutex | None = None
    target_mutex: HeldCrossSessionMutex | None = None
    try:
        environment_mutex = acquire_secured_cross_session_mutex(
            binding.environment_mutex_name,
            api=api,
            timeout_ms=timeout_ms,
        )
        after_environment = revalidate()
        if (
            type(after_environment) is not RuntimeTransactionLockBinding
            or after_environment != binding
        ):
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.BINDING_CHANGED)
        target_mutex = acquire_secured_cross_session_mutex(
            after_environment.target_mutex_name,
            api=api,
            timeout_ms=timeout_ms,
        )
        after_target = revalidate()
        if (
            type(after_target) is not RuntimeTransactionLockBinding
            or after_target != binding
        ):
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.BINDING_CHANGED)
        return HeldRuntimeTransactionLocks(
            binding=binding,
            environment_mutex=environment_mutex,
            target_mutex=target_mutex,
        )
    except RuntimeTransactionLockError:
        if _close_runtime_mutexes((target_mutex, environment_mutex)):
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.RELEASE_FAILED)
        raise
    except WindowsMutexError as error:
        code = _mapped_runtime_lock_error(error)
        if _close_runtime_mutexes((target_mutex, environment_mutex)):
            code = RuntimeTransactionLockErrorCode.RELEASE_FAILED
        _fail_runtime_locks(code)
    except Exception:
        if _close_runtime_mutexes((target_mutex, environment_mutex)):
            _fail_runtime_locks(RuntimeTransactionLockErrorCode.RELEASE_FAILED)
        _fail_runtime_locks(RuntimeTransactionLockErrorCode.BINDING_CHANGED)
    except BaseException:
        _close_runtime_mutexes((target_mutex, environment_mutex))
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
    "HeldRuntimeTransactionLocks",
    "MutexAccessAllowedAce",
    "MutexSecurityFacts",
    "MutexWaitOutcome",
    "NativeWindowsMutexApi",
    "RuntimeTransactionLockBinding",
    "RuntimeTransactionLockError",
    "RuntimeTransactionLockErrorCode",
    "WindowsMutexApi",
    "WindowsMutexError",
    "acquire_ordered_runtime_transaction_locks",
    "acquire_secured_cross_session_mutex",
    "runtime_transaction_lock_binding",
]
