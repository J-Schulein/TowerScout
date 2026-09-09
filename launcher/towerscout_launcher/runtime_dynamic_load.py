"""Fail-closed Windows process-image and DLL-load destination enforcement.

The backends start an already planned command as a contained ``DEBUG_PROCESS``
tree.  Windows freezes the reporting process for each debug event, so the
debugger can hash the exact file handle supplied for the process image or DLL
before allowing that event to continue.  The CPython backend admits only its
held AMD64 inventory and denies descendants.  The provider-child backend uses
separate exact provider and runtime-child policies and permits only one active
child alongside the provider.

This source slice remains intentionally unwired from launcher discovery,
runtime planning, and repair.
"""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import struct
import threading
from contextlib import ExitStack
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Callable, Protocol

from .runtime_command_native import (
    _BoundedReader,
    _Clock,
    _NativeProcess,
    _NativeWindowsProcessApi,
    _ProcessApi,
    _SystemClock,
)
from .runtime_command_version import (
    CommandExecutionError,
    CommandExecutionErrorCode,
    CommandProcessRequest,
    CommandProcessResult,
)
from .runtime_dependency_capture import (
    CpythonDependencyCaptureError,
    CpythonDynamicLoadPolicy,
    HeldCpythonDependencyInventory,
)
from .runtime_execution import CommandKind, ProcessCommandPlan
from .runtime_provider_child import (
    ProcessImagePolicy,
    ProcessImageRole,
    ProviderChildProcessRequest,
)
from .windows_path_trust import (
    PathTrustPurpose,
    WindowsPathTrustApi,
    capture_path_hierarchy,
)
from .windows_security import (
    FileCapturePolicy,
    FileSnapshot,
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsFileApi,
    WindowsSecurityError,
    inspect_open_file_handle,
)

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

_EXCEPTION_DEBUG_EVENT = 1
_CREATE_THREAD_DEBUG_EVENT = 2
_CREATE_PROCESS_DEBUG_EVENT = 3
_EXIT_THREAD_DEBUG_EVENT = 4
_EXIT_PROCESS_DEBUG_EVENT = 5
_LOAD_DLL_DEBUG_EVENT = 6
_UNLOAD_DLL_DEBUG_EVENT = 7
_OUTPUT_DEBUG_STRING_EVENT = 8
_RIP_EVENT = 9
_EXCEPTION_BREAKPOINT = 0x80000003
_ERROR_SEM_TIMEOUT = 121
_POLL_MILLISECONDS = 25
_TERMINATION_TIMEOUT_SECONDS = 5.0
_MAX_DEBUG_EVENTS = 4096
_MAX_IMAGE_BYTES = 1024 * 1024 * 1024
_EVIDENCE_DOMAIN = b"TowerScout.CpythonDynamicLoadEnforcement.v1"
_SYSTEM_IMAGE_POLICY_DOMAIN = b"TowerScout.CpythonSystemImagePolicy.v1"

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int
_ULONG_PTR = ctypes.c_size_t


class _EXCEPTION_RECORD(ctypes.Structure):
    pass


_EXCEPTION_RECORD._fields_ = (
    ("ExceptionCode", _DWORD),
    ("ExceptionFlags", _DWORD),
    ("ExceptionRecord", ctypes.POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", _DWORD),
    ("ExceptionInformation", _ULONG_PTR * 15),
)


class _EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = (("ExceptionRecord", _EXCEPTION_RECORD), ("dwFirstChance", _DWORD))


class _CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = (
        ("hThread", _HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    )


class _CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = (
        ("hFile", _HANDLE),
        ("hProcess", _HANDLE),
        ("hThread", _HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", _DWORD),
        ("nDebugInfoSize", _DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", ctypes.c_ushort),
    )


class _EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = (("dwExitCode", _DWORD),)


class _EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = (("dwExitCode", _DWORD),)


class _LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = (
        ("hFile", _HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", _DWORD),
        ("nDebugInfoSize", _DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", ctypes.c_ushort),
    )


class _UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = (("lpBaseOfDll", ctypes.c_void_p),)


class _OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = (
        ("lpDebugStringData", ctypes.c_void_p),
        ("fUnicode", ctypes.c_ushort),
        ("nDebugStringLength", ctypes.c_ushort),
    )


class _RIP_INFO(ctypes.Structure):
    _fields_ = (("dwError", _DWORD), ("dwType", _DWORD))


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = (
        ("Exception", _EXCEPTION_DEBUG_INFO),
        ("CreateThread", _CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", _CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", _EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", _EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", _LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", _UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", _OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", _RIP_INFO),
    )


class _DEBUG_EVENT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = (
        ("dwDebugEventCode", _DWORD),
        ("dwProcessId", _DWORD),
        ("dwThreadId", _DWORD),
        ("u", _DEBUG_EVENT_UNION),
    )


class DynamicLoadEnforcementErrorCode(str, Enum):
    UNAVAILABLE = "unavailable"
    START_FAILED = "start_failed"
    EVENT_INVALID = "event_invalid"
    IMAGE_UNAPPROVED = "image_unapproved"
    CHILD_PROCESS_DENIED = "child_process_denied"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    CONTAINMENT_FAILED = "containment_failed"
    PLAN_REJECTED = "plan_rejected"


class DynamicLoadEnforcementError(RuntimeError):
    _MESSAGES = {
        DynamicLoadEnforcementErrorCode.UNAVAILABLE: (
            "Secure Windows dynamic-load enforcement is unavailable."
        ),
        DynamicLoadEnforcementErrorCode.START_FAILED: (
            "The authenticated Windows command could not be monitored safely."
        ),
        DynamicLoadEnforcementErrorCode.EVENT_INVALID: (
            "The Windows image-load event stream was incomplete or invalid."
        ),
        DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED: (
            "The Windows command requested an unapproved executable image."
        ),
        DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED: (
            "The Windows command attempted to start an unapproved child process."
        ),
        DynamicLoadEnforcementErrorCode.TIMEOUT: (
            "The monitored Windows command exceeded its time limit."
        ),
        DynamicLoadEnforcementErrorCode.OUTPUT_LIMIT: (
            "The monitored Windows command exceeded its output limit."
        ),
        DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED: (
            "The monitored Windows process tree could not be contained safely."
        ),
        DynamicLoadEnforcementErrorCode.PLAN_REJECTED: (
            "The authenticated provider-child command plan is invalid."
        ),
    }

    def __init__(self, code: DynamicLoadEnforcementErrorCode) -> None:
        if type(code) is not DynamicLoadEnforcementErrorCode:
            raise ValueError("Unknown dynamic-load enforcement error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"DynamicLoadEnforcementError(code={self.code.value!r})"


class DebugEventKind(str, Enum):
    EXCEPTION = "exception"
    CREATE_THREAD = "create_thread"
    CREATE_PROCESS = "create_process"
    EXIT_THREAD = "exit_thread"
    EXIT_PROCESS = "exit_process"
    LOAD_DLL = "load_dll"
    UNLOAD_DLL = "unload_dll"
    OUTPUT_DEBUG_STRING = "output_debug_string"
    RIP = "rip"


_KIND_BY_CODE = {
    _EXCEPTION_DEBUG_EVENT: DebugEventKind.EXCEPTION,
    _CREATE_THREAD_DEBUG_EVENT: DebugEventKind.CREATE_THREAD,
    _CREATE_PROCESS_DEBUG_EVENT: DebugEventKind.CREATE_PROCESS,
    _EXIT_THREAD_DEBUG_EVENT: DebugEventKind.EXIT_THREAD,
    _EXIT_PROCESS_DEBUG_EVENT: DebugEventKind.EXIT_PROCESS,
    _LOAD_DLL_DEBUG_EVENT: DebugEventKind.LOAD_DLL,
    _UNLOAD_DLL_DEBUG_EVENT: DebugEventKind.UNLOAD_DLL,
    _OUTPUT_DEBUG_STRING_EVENT: DebugEventKind.OUTPUT_DEBUG_STRING,
    _RIP_EVENT: DebugEventKind.RIP,
}


@dataclass(frozen=True, slots=True, repr=False)
class DebugEvent:
    kind: DebugEventKind
    process_id: int
    thread_id: int
    image_handle: object | None = field(default=None, repr=False)
    exception_code: int | None = None
    first_chance: bool | None = None
    exit_code: int | None = None

    def __post_init__(self) -> None:
        is_image = self.kind in {
            DebugEventKind.CREATE_PROCESS,
            DebugEventKind.LOAD_DLL,
        }
        is_exception = self.kind is DebugEventKind.EXCEPTION
        is_exit = self.kind in {
            DebugEventKind.EXIT_PROCESS,
            DebugEventKind.EXIT_THREAD,
        }
        if (
            type(self.kind) is not DebugEventKind
            or type(self.process_id) is not int
            or not 0 < self.process_id < 2**32
            or type(self.thread_id) is not int
            or not 0 < self.thread_id < 2**32
            or (not is_image and self.image_handle is not None)
            or (
                is_exception
                and (
                    type(self.exception_code) is not int
                    or not 0 <= self.exception_code < 2**32
                    or type(self.first_chance) is not bool
                )
            )
            or (
                not is_exception
                and (self.exception_code is not None or self.first_chance is not None)
            )
            or (
                is_exit
                and (type(self.exit_code) is not int or not 0 <= self.exit_code < 2**32)
            )
            or (not is_exit and self.exit_code is not None)
        ):
            raise ValueError("Windows debug event is invalid.")

    def __repr__(self) -> str:
        return f"DebugEvent(kind={self.kind.value!r}, <redacted>)"


class DebugEventApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def prepare_kill_on_exit(self) -> None: ...

    def wait_event(self, milliseconds: int) -> DebugEvent | None: ...

    def inspect_image(self, handle: object) -> FileSnapshot: ...

    def close_image_handle(self, handle: object) -> None: ...

    def continue_event(self, event: DebugEvent, status: int) -> None: ...


class _WorkerThread(Protocol):
    def start(self) -> None: ...

    def is_alive(self) -> bool: ...

    def join(self, timeout: float) -> None: ...


def _default_worker_factory(target: Callable[[], None]) -> _WorkerThread:
    return threading.Thread(target=target, daemon=True)


def _native_handle(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


class NativeWindowsDebugEventApi:
    """Narrow same-thread adapter for Windows debugger image events."""

    __slots__ = ("_file_api", "_kernel32")

    def __init__(self, *, file_api: WindowsFileApi | None = None) -> None:
        self._file_api = file_api if file_api is not None else NativeWindowsFileApi()
        self._kernel32: Any | None = None
        win_dll = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or win_dll is None:
            return
        kernel32 = win_dll("kernel32", use_last_error=True)
        if getattr(kernel32, "WaitForDebugEventEx", None) is None:
            return
        self._kernel32 = kernel32
        self._bind(kernel32)

    @staticmethod
    def _bind(kernel32: Any) -> None:
        kernel32.WaitForDebugEventEx.argtypes = (
            ctypes.POINTER(_DEBUG_EVENT),
            _DWORD,
        )
        kernel32.WaitForDebugEventEx.restype = _BOOL
        kernel32.ContinueDebugEvent.argtypes = (_DWORD, _DWORD, _DWORD)
        kernel32.ContinueDebugEvent.restype = _BOOL
        kernel32.DebugSetProcessKillOnExit.argtypes = (_BOOL,)
        kernel32.DebugSetProcessKillOnExit.restype = _BOOL
        kernel32.CloseHandle.argtypes = (_HANDLE,)
        kernel32.CloseHandle.restype = _BOOL

    @property
    def supported(self) -> bool:
        try:
            return self._kernel32 is not None and self._file_api.supported is True
        except Exception:
            return False

    def _require(self) -> Any:
        if self._kernel32 is None:
            raise OSError("Windows debug-event APIs are unavailable.")
        return self._kernel32

    def prepare_kill_on_exit(self) -> None:
        if not self._require().DebugSetProcessKillOnExit(True):
            raise OSError("Windows debugger termination policy failed.")

    def wait_event(self, milliseconds: int) -> DebugEvent | None:
        if type(milliseconds) is not int or not 0 <= milliseconds <= 1000:
            raise ValueError("Windows debug-event wait is invalid.")
        kernel32 = self._require()
        native = _DEBUG_EVENT()
        image_handle: int | None = None
        received = False
        kind: DebugEventKind | None = None
        try:
            ctypes.set_last_error(0)
            if not kernel32.WaitForDebugEventEx(ctypes.byref(native), milliseconds):
                if ctypes.get_last_error() == _ERROR_SEM_TIMEOUT:
                    return None
                raise OSError("Windows debug-event wait failed.")
            received = True
            kind = _KIND_BY_CODE.get(int(native.dwDebugEventCode))
            if kind is None:
                raise OSError("Windows debug-event kind is unsupported.")
            if kind is DebugEventKind.CREATE_PROCESS:
                image_handle = _native_handle(native.CreateProcessInfo.hFile)
                # Windows owns the debugger's hProcess/hThread handles until
                # EXIT_PROCESS_DEBUG_EVENT is continued.  Only hFile is closed
                # explicitly by this debugger.
            elif kind is DebugEventKind.LOAD_DLL:
                image_handle = _native_handle(native.LoadDll.hFile)
            exception_code = None
            first_chance = None
            exit_code = None
            if kind is DebugEventKind.EXCEPTION:
                exception_code = int(native.Exception.ExceptionRecord.ExceptionCode)
                first_chance = bool(native.Exception.dwFirstChance)
            elif kind is DebugEventKind.EXIT_PROCESS:
                exit_code = int(native.ExitProcess.dwExitCode)
            elif kind is DebugEventKind.EXIT_THREAD:
                exit_code = int(native.ExitThread.dwExitCode)
            result = DebugEvent(
                kind,
                int(native.dwProcessId),
                int(native.dwThreadId),
                image_handle=image_handle,
                exception_code=exception_code,
                first_chance=first_chance,
                exit_code=exit_code,
            )
            return result
        except BaseException as original:
            cleanup_proven = kind is not None
            if image_handle is not None:
                try:
                    if not kernel32.CloseHandle(_HANDLE(image_handle)):
                        cleanup_proven = False
                except BaseException:
                    cleanup_proven = False
            if received:
                try:
                    if not kernel32.ContinueDebugEvent(
                        native.dwProcessId,
                        native.dwThreadId,
                        DBG_CONTINUE,
                    ):
                        cleanup_proven = False
                except BaseException:
                    cleanup_proven = False
            if not cleanup_proven:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                ) from None
            raise original

    def inspect_image(self, handle: object) -> FileSnapshot:
        return inspect_open_file_handle(
            handle,
            api=self._file_api,
            policy=FileCapturePolicy(
                max_bytes=_MAX_IMAGE_BYTES,
                require_single_link=False,
            ),
        )

    def close_image_handle(self, handle: object) -> None:
        native = _native_handle(handle)
        if native is None or not self._require().CloseHandle(_HANDLE(native)):
            raise OSError("Windows debug image handle close failed.")

    def continue_event(self, event: DebugEvent, status: int) -> None:
        if (
            type(event) is not DebugEvent
            or status not in {DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED}
            or not self._require().ContinueDebugEvent(
                event.process_id,
                event.thread_id,
                status,
            )
        ):
            raise OSError("Windows debug-event continuation failed.")

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeWindowsDebugEventApi(state={state!r})"


@dataclass(frozen=True, slots=True, repr=False)
class DynamicLoadEnforcementEvidence:
    policy_sha256: str = field(repr=False)
    system_directory_identity: StableFileIdentity = field(repr=False)
    system_image_policy_sha256: str = field(repr=False)
    approved_system_image_name_count: int
    loaded_image_count: int
    exact_inventory_image_count: int
    system32_image_count: int
    debug_process_tree: bool
    dynamic_code_prohibited: bool
    child_process_creation_restricted: bool
    unexpected_child_events_denied: bool
    event_file_handles_closed: bool
    arbitrary_dynamic_destinations_denied: bool
    image_sequence_sha256: str = field(repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not _is_sha256(self.policy_sha256)
            or type(self.system_directory_identity) is not StableFileIdentity
            or not _is_sha256(self.system_image_policy_sha256)
            or type(self.approved_system_image_name_count) is not int
            or not 1 <= self.approved_system_image_name_count <= 256
            or type(self.loaded_image_count) is not int
            or not 1 <= self.loaded_image_count <= _MAX_DEBUG_EVENTS
            or type(self.exact_inventory_image_count) is not int
            or not 1 <= self.exact_inventory_image_count <= self.loaded_image_count
            or type(self.system32_image_count) is not int
            or not 0 <= self.system32_image_count <= self.loaded_image_count
            or self.exact_inventory_image_count + self.system32_image_count
            != self.loaded_image_count
            or self.debug_process_tree is not True
            or self.dynamic_code_prohibited is not True
            or self.child_process_creation_restricted is not True
            or self.unexpected_child_events_denied is not True
            or self.event_file_handles_closed is not True
            or self.arbitrary_dynamic_destinations_denied is not True
            or not _is_sha256(self.image_sequence_sha256)
        ):
            raise ValueError("Dynamic-load enforcement evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _digest(
                _EVIDENCE_DOMAIN,
                self.policy_sha256.encode("ascii"),
                self.system_directory_identity.volume_serial.to_bytes(8, "big"),
                self.system_directory_identity.file_id,
                self.system_image_policy_sha256.encode("ascii"),
                self.approved_system_image_name_count.to_bytes(4, "big"),
                self.loaded_image_count.to_bytes(4, "big"),
                self.exact_inventory_image_count.to_bytes(4, "big"),
                self.system32_image_count.to_bytes(4, "big"),
                bytes(
                    (
                        self.debug_process_tree,
                        self.dynamic_code_prohibited,
                        self.child_process_creation_restricted,
                        self.unexpected_child_events_denied,
                        self.event_file_handles_closed,
                        self.arbitrary_dynamic_destinations_denied,
                    )
                ),
                self.image_sequence_sha256.encode("ascii"),
            ),
        )

    def __repr__(self) -> str:
        return (
            "DynamicLoadEnforcementEvidence("
            f"loaded_image_count={self.loaded_image_count}, "
            "destination_policy='enforced', <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class DynamicLoadCommandResult:
    command: CommandProcessResult = field(repr=False)
    enforcement: DynamicLoadEnforcementEvidence

    def __post_init__(self) -> None:
        if (
            type(self.command) is not CommandProcessResult
            or type(self.enforcement) is not DynamicLoadEnforcementEvidence
        ):
            raise ValueError("Dynamic-load command result is invalid.")

    def __repr__(self) -> str:
        return (
            "DynamicLoadCommandResult("
            f"exit_code={self.command.exit_code}, "
            f"loaded_image_count={self.enforcement.loaded_image_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProviderChildEnforcementEvidence:
    """Sanitized proof for one provider and its serialized runtime children."""

    request_binding_sha256: str = field(repr=False)
    provider_policy_sha256: str = field(repr=False)
    child_policy_sha256: str = field(repr=False)
    system_directory_identity: StableFileIdentity = field(repr=False)
    provider_image_count: int
    child_image_count: int
    child_process_count: int
    exact_inventory_image_count: int
    system32_image_count: int
    active_process_limit: int
    debug_process_tree: bool
    provider_dynamic_code_prohibited: bool
    root_alive_during_child: bool
    unexpected_processes_denied: bool
    event_file_handles_closed: bool
    arbitrary_dynamic_destinations_denied: bool
    image_sequence_sha256: str = field(repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        loaded = self.provider_image_count + self.child_image_count
        if (
            not _is_sha256(self.request_binding_sha256)
            or not _is_sha256(self.provider_policy_sha256)
            or not _is_sha256(self.child_policy_sha256)
            or type(self.system_directory_identity) is not StableFileIdentity
            or type(self.provider_image_count) is not int
            or self.provider_image_count < 1
            or type(self.child_image_count) is not int
            or self.child_image_count < 1
            or type(self.child_process_count) is not int
            or not 1 <= self.child_process_count <= _MAX_DEBUG_EVENTS
            or type(self.exact_inventory_image_count) is not int
            or self.exact_inventory_image_count < 2
            or type(self.system32_image_count) is not int
            or self.system32_image_count < 0
            or self.exact_inventory_image_count + self.system32_image_count != loaded
            or loaded > _MAX_DEBUG_EVENTS
            or self.active_process_limit != 2
            or self.debug_process_tree is not True
            or self.provider_dynamic_code_prohibited is not True
            or self.root_alive_during_child is not True
            or self.unexpected_processes_denied is not True
            or self.event_file_handles_closed is not True
            or self.arbitrary_dynamic_destinations_denied is not True
            or not _is_sha256(self.image_sequence_sha256)
        ):
            raise ValueError("Provider-child enforcement evidence is invalid.")
        object.__setattr__(
            self,
            "evidence_sha256",
            _digest(
                b"TowerScout.ProviderChildEnforcementEvidence.v1",
                self.request_binding_sha256.encode("ascii"),
                self.provider_policy_sha256.encode("ascii"),
                self.child_policy_sha256.encode("ascii"),
                self.system_directory_identity.volume_serial.to_bytes(8, "big"),
                self.system_directory_identity.file_id,
                self.provider_image_count.to_bytes(4, "big"),
                self.child_image_count.to_bytes(4, "big"),
                self.child_process_count.to_bytes(4, "big"),
                self.exact_inventory_image_count.to_bytes(4, "big"),
                self.system32_image_count.to_bytes(4, "big"),
                self.active_process_limit.to_bytes(4, "big"),
                bytes(
                    (
                        self.debug_process_tree,
                        self.provider_dynamic_code_prohibited,
                        self.root_alive_during_child,
                        self.unexpected_processes_denied,
                        self.event_file_handles_closed,
                        self.arbitrary_dynamic_destinations_denied,
                    )
                ),
                self.image_sequence_sha256.encode("ascii"),
            ),
        )

    def __repr__(self) -> str:
        return (
            "ProviderChildEnforcementEvidence("
            f"provider_images={self.provider_image_count}, "
            f"child_images={self.child_image_count}, "
            f"child_processes={self.child_process_count}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProviderChildCommandResult:
    command: CommandProcessResult = field(repr=False)
    enforcement: ProviderChildEnforcementEvidence

    def __post_init__(self) -> None:
        if (
            type(self.command) is not CommandProcessResult
            or type(self.enforcement) is not ProviderChildEnforcementEvidence
        ):
            raise ValueError("Provider-child command result is invalid.")

    def __repr__(self) -> str:
        return (
            "ProviderChildCommandResult("
            f"exit_code={self.command.exit_code}, "
            f"child_processes={self.enforcement.child_process_count}, <redacted>)"
        )


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _digest(*values: bytes) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _canonical_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("Windows image path is invalid.")
    path = value.replace("/", "\\")
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    normalized = ntpath.normpath(path)
    if not PureWindowsPath(normalized).is_absolute():
        raise ValueError("Windows image path is invalid.")
    return ntpath.normcase(normalized)


class _ImagePolicy:
    __slots__ = (
        "_bindings",
        "_sequence",
        "_system_directory",
        "_system_image_names",
        "_system_policy_sha256",
    )

    def __init__(
        self,
        policy: CpythonDynamicLoadPolicy | ProcessImagePolicy,
        system_directory: PureWindowsPath,
    ) -> None:
        if (
            type(policy) not in {CpythonDynamicLoadPolicy, ProcessImagePolicy}
            or type(system_directory) is not PureWindowsPath
        ):
            raise ValueError("Windows image-load policy is invalid.")
        self._bindings = policy.exact_files
        self._system_directory = _canonical_path(str(system_directory))
        self._system_image_names = frozenset(policy.system_image_names)
        self._system_policy_sha256 = _digest(
            _SYSTEM_IMAGE_POLICY_DOMAIN,
            *(
                name.encode("ascii", errors="strict")
                for name in policy.system_image_names
            ),
        )
        self._sequence = hashlib.sha256()

    def authorize(self, event: DebugEvent, snapshot: FileSnapshot) -> str:
        if type(event) is not DebugEvent or type(snapshot) is not FileSnapshot:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        exact = tuple(
            binding for binding in self._bindings if binding.matches(snapshot)
        )
        if event.kind is DebugEventKind.CREATE_PROCESS:
            if len(exact) != 1 or exact[0].entrypoint is not True:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED
                )
            decision = "exact"
        elif event.kind is DebugEventKind.LOAD_DLL:
            if len(exact) == 1:
                decision = "exact"
            else:
                try:
                    parent = _canonical_path(
                        str(PureWindowsPath(snapshot.final_path).parent)
                    )
                except ValueError:
                    parent = ""
                leaf = PureWindowsPath(snapshot.final_path).name.casefold()
                if (
                    parent != self._system_directory
                    or leaf not in self._system_image_names
                ):
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED
                    )
                decision = "system32"
        else:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        for value in (
            event.kind.value.encode("ascii"),
            decision.encode("ascii"),
            snapshot.identity.volume_serial.to_bytes(8, "big"),
            snapshot.identity.file_id,
            snapshot.sha256.encode("ascii"),
            _canonical_path(snapshot.final_path).encode("utf-16-le", errors="strict"),
        ):
            self._sequence.update(struct.pack(">Q", len(value)))
            self._sequence.update(value)
        return decision

    @property
    def sequence_sha256(self) -> str:
        return self._sequence.hexdigest()

    @property
    def system_policy_sha256(self) -> str:
        return self._system_policy_sha256

    @property
    def system_image_name_count(self) -> int:
        return len(self._system_image_names)


class _EventMonitor:
    __slots__ = (
        "_event_count",
        "_exact_count",
        "_initial_breakpoint",
        "_policy",
        "_root_created",
        "_root_process_id",
        "_system_count",
    )

    def __init__(self, root_process_id: int, policy: _ImagePolicy) -> None:
        self._root_process_id = root_process_id
        self._policy = policy
        self._root_created = False
        self._initial_breakpoint = False
        self._event_count = 0
        self._exact_count = 0
        self._system_count = 0

    def accept(
        self, event: DebugEvent, snapshot: FileSnapshot | None
    ) -> tuple[int, bool]:
        self._event_count += 1
        if self._event_count > _MAX_DEBUG_EVENTS:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        if event.process_id != self._root_process_id:
            code = (
                DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED
                if event.kind is DebugEventKind.CREATE_PROCESS
                else DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
            raise DynamicLoadEnforcementError(code)
        if event.kind in {DebugEventKind.CREATE_PROCESS, DebugEventKind.LOAD_DLL}:
            if snapshot is None:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.EVENT_INVALID
                )
            if event.kind is DebugEventKind.CREATE_PROCESS:
                if self._root_created:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.EVENT_INVALID
                    )
                self._root_created = True
            elif not self._root_created:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.EVENT_INVALID
                )
            decision = self._policy.authorize(event, snapshot)
            if decision == "exact":
                self._exact_count += 1
            else:
                self._system_count += 1
            return (DBG_CONTINUE, False)
        if not self._root_created:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        if event.kind is DebugEventKind.EXCEPTION:
            if not self._initial_breakpoint:
                if (
                    event.exception_code != _EXCEPTION_BREAKPOINT
                    or event.first_chance is not True
                ):
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.EVENT_INVALID
                    )
                self._initial_breakpoint = True
                return (DBG_CONTINUE, False)
            return (DBG_EXCEPTION_NOT_HANDLED, False)
        if event.kind is DebugEventKind.EXIT_PROCESS:
            if not self._initial_breakpoint:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.EVENT_INVALID
                )
            return (DBG_CONTINUE, True)
        if event.kind is DebugEventKind.RIP:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        return (DBG_CONTINUE, False)

    def evidence(
        self,
        policy_sha256: str,
        system_directory_identity: StableFileIdentity,
    ) -> DynamicLoadEnforcementEvidence:
        return DynamicLoadEnforcementEvidence(
            policy_sha256=policy_sha256,
            system_directory_identity=system_directory_identity,
            system_image_policy_sha256=self._policy.system_policy_sha256,
            approved_system_image_name_count=self._policy.system_image_name_count,
            loaded_image_count=self._exact_count + self._system_count,
            exact_inventory_image_count=self._exact_count,
            system32_image_count=self._system_count,
            debug_process_tree=True,
            dynamic_code_prohibited=True,
            child_process_creation_restricted=True,
            unexpected_child_events_denied=True,
            event_file_handles_closed=True,
            arbitrary_dynamic_destinations_denied=True,
            image_sequence_sha256=self._policy.sequence_sha256,
        )


class _ProviderChildEventMonitor:
    """Authorize one root provider and at most one active runtime child."""

    __slots__ = (
        "_breakpoints",
        "_child_exact_count",
        "_child_policy",
        "_child_process_count",
        "_child_processes",
        "_child_system_count",
        "_event_count",
        "_provider_exact_count",
        "_provider_policy",
        "_provider_system_count",
        "_root_created",
        "_root_process_id",
    )

    def __init__(
        self,
        root_process_id: int,
        provider_policy: _ImagePolicy,
        child_policy: _ImagePolicy,
    ) -> None:
        self._root_process_id = root_process_id
        self._provider_policy = provider_policy
        self._child_policy = child_policy
        self._root_created = False
        self._child_processes: set[int] = set()
        self._breakpoints: set[int] = set()
        self._event_count = 0
        self._child_process_count = 0
        self._provider_exact_count = 0
        self._provider_system_count = 0
        self._child_exact_count = 0
        self._child_system_count = 0

    def _known_process(self, process_id: int) -> bool:
        return (
            process_id == self._root_process_id or process_id in self._child_processes
        )

    def _policy_for(self, process_id: int) -> _ImagePolicy:
        if process_id == self._root_process_id:
            return self._provider_policy
        if process_id in self._child_processes:
            return self._child_policy
        raise DynamicLoadEnforcementError(DynamicLoadEnforcementErrorCode.EVENT_INVALID)

    def _record_decision(self, process_id: int, decision: str) -> None:
        if process_id == self._root_process_id:
            if decision == "exact":
                self._provider_exact_count += 1
            else:
                self._provider_system_count += 1
        elif decision == "exact":
            self._child_exact_count += 1
        else:
            self._child_system_count += 1

    def accept(
        self, event: DebugEvent, snapshot: FileSnapshot | None
    ) -> tuple[int, bool]:
        self._event_count += 1
        if self._event_count > _MAX_DEBUG_EVENTS:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )

        if event.kind is DebugEventKind.CREATE_PROCESS:
            if snapshot is None:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.EVENT_INVALID
                )
            if event.process_id == self._root_process_id:
                if self._root_created:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.EVENT_INVALID
                    )
                self._root_created = True
            else:
                if (
                    not self._root_created
                    or self._root_process_id not in self._breakpoints
                    or self._child_processes
                    or event.process_id in self._breakpoints
                ):
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED
                    )
                self._child_processes.add(event.process_id)
                self._child_process_count += 1
            decision = self._policy_for(event.process_id).authorize(event, snapshot)
            self._record_decision(event.process_id, decision)
            return (DBG_CONTINUE, False)

        if not self._root_created or not self._known_process(event.process_id):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        if event.kind is DebugEventKind.LOAD_DLL:
            if snapshot is None:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.EVENT_INVALID
                )
            decision = self._policy_for(event.process_id).authorize(event, snapshot)
            self._record_decision(event.process_id, decision)
            return (DBG_CONTINUE, False)
        if event.kind is DebugEventKind.EXCEPTION:
            if event.process_id not in self._breakpoints:
                if (
                    event.exception_code != _EXCEPTION_BREAKPOINT
                    or event.first_chance is not True
                ):
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.EVENT_INVALID
                    )
                self._breakpoints.add(event.process_id)
                return (DBG_CONTINUE, False)
            return (DBG_EXCEPTION_NOT_HANDLED, False)
        if event.kind is DebugEventKind.EXIT_PROCESS:
            if event.process_id not in self._breakpoints:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.EVENT_INVALID
                )
            if event.process_id == self._root_process_id:
                if self._child_processes or self._child_process_count < 1:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED
                    )
                return (DBG_CONTINUE, True)
            self._child_processes.remove(event.process_id)
            self._breakpoints.remove(event.process_id)
            return (DBG_CONTINUE, False)
        if event.kind is DebugEventKind.RIP:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        return (DBG_CONTINUE, False)

    def evidence(
        self,
        request_binding_sha256: str,
        provider_policy_sha256: str,
        child_policy_sha256: str,
        system_directory_identity: StableFileIdentity,
    ) -> ProviderChildEnforcementEvidence:
        return ProviderChildEnforcementEvidence(
            request_binding_sha256=request_binding_sha256,
            provider_policy_sha256=provider_policy_sha256,
            child_policy_sha256=child_policy_sha256,
            system_directory_identity=system_directory_identity,
            provider_image_count=(
                self._provider_exact_count + self._provider_system_count
            ),
            child_image_count=self._child_exact_count + self._child_system_count,
            child_process_count=self._child_process_count,
            exact_inventory_image_count=(
                self._provider_exact_count + self._child_exact_count
            ),
            system32_image_count=(
                self._provider_system_count + self._child_system_count
            ),
            active_process_limit=2,
            debug_process_tree=True,
            provider_dynamic_code_prohibited=True,
            root_alive_during_child=True,
            unexpected_processes_denied=True,
            event_file_handles_closed=True,
            arbitrary_dynamic_destinations_denied=True,
            image_sequence_sha256=_digest(
                self._provider_policy.sequence_sha256.encode("ascii"),
                self._child_policy.sequence_sha256.encode("ascii"),
            ),
        )


class _WorkerCancelled(BaseException):
    pass


class NativeWindowsCpythonDynamicLoadBackend:
    """Execute one fixed request while policing every Windows image event."""

    __slots__ = (
        "_clock",
        "_debug_api",
        "_path_api",
        "_process_api",
        "_worker_factory",
    )

    def __init__(
        self,
        *,
        process_api: _ProcessApi | None = None,
        debug_api: DebugEventApi | None = None,
        clock: _Clock | None = None,
        path_api: WindowsPathTrustApi | None = None,
        worker_factory: Callable[[Callable[[], None]], _WorkerThread] | None = None,
    ) -> None:
        self._process_api = (
            process_api if process_api is not None else _NativeWindowsProcessApi()
        )
        self._debug_api = (
            debug_api if debug_api is not None else NativeWindowsDebugEventApi()
        )
        self._clock = clock if clock is not None else _SystemClock()
        self._path_api = path_api
        self._worker_factory = (
            worker_factory if worker_factory is not None else _default_worker_factory
        )

    @property
    def supported(self) -> bool:
        try:
            return (
                self._process_api.supported is True
                and self._debug_api.supported is True
            )
        except Exception:
            return False

    def execute(
        self,
        request: CommandProcessRequest,
        inventory: HeldCpythonDependencyInventory,
    ) -> DynamicLoadCommandResult:
        if (
            type(request) is not CommandProcessRequest
            or type(inventory) is not HeldCpythonDependencyInventory
            or self.supported is not True
        ):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.UNAVAILABLE
            )
        try:
            system_directory = PureWindowsPath(self._process_api.system_directory())
            if request.working_directory != system_directory:
                raise ValueError("System directory mismatch.")
            system_trust = capture_path_hierarchy(
                str(system_directory),
                purpose=PathTrustPurpose.RUNTIME_INSTALL,
                api=self._path_api,
            )
        except Exception:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.UNAVAILABLE
            ) from None
        try:
            with system_trust:
                system_trust.assert_unchanged()

                def run() -> DynamicLoadCommandResult:
                    dynamic_load_policy = inventory.active_dynamic_load_policy()
                    return self._execute_under_policy(
                        request,
                        dynamic_load_policy,
                        system_directory=system_directory,
                        system_directory_identity=(system_trust.evidence.root_identity),
                        policy_sha256=inventory.evidence.dependency.policy_sha256,
                    )

                result = inventory.run_while_held(run)
                system_trust.assert_unchanged()
                return result
        except DynamicLoadEnforcementError:
            raise
        except (CpythonDependencyCaptureError, WindowsSecurityError):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED
            ) from None
        except Exception:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.START_FAILED
            ) from None

    def _inspect_event_image(self, event: DebugEvent) -> FileSnapshot | None:
        handle = event.image_handle
        if event.kind not in {
            DebugEventKind.CREATE_PROCESS,
            DebugEventKind.LOAD_DLL,
        }:
            return None
        if handle is None:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            )
        try:
            snapshot = self._debug_api.inspect_image(handle)
            if type(snapshot) is not FileSnapshot:
                raise TypeError("Invalid image snapshot.")
            return snapshot
        except DynamicLoadEnforcementError:
            raise
        except Exception:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.EVENT_INVALID
            ) from None

    def _terminate_and_drain(
        self,
        process: _NativeProcess,
        pending: DebugEvent | None,
        pending_image_closed: bool = False,
    ) -> bool:
        contained = True
        can_wait = True
        root_exit_continued = False

        def close_image(handle: object) -> bool:
            try:
                self._debug_api.close_image_handle(handle)
                return True
            except BaseException:
                # Cleanup may follow an interruption at the native-call
                # boundary, where the first close could have completed.  An
                # immediate retry occurs before any new handle can be dequeued.
                try:
                    self._debug_api.close_image_handle(handle)
                    return True
                except BaseException:
                    return False

        def continue_debug_event(event: DebugEvent) -> bool:
            try:
                self._debug_api.continue_event(event, DBG_CONTINUE)
                return True
            except BaseException:
                # No later event is dequeued before this retry, so the event
                # identity cannot be confused with another pending event.
                try:
                    self._debug_api.continue_event(event, DBG_CONTINUE)
                    return True
                except BaseException:
                    return False

        try:
            self._process_api.terminate_job(process.job)
        except BaseException:
            # Even when job termination fails, release the event currently
            # freezing the debuggee and drain anything Windows already queued.
            # The false result still prevents callers from treating cleanup as
            # successful containment.
            contained = False
        if pending is not None:
            if (
                pending.image_handle is not None
                and not pending_image_closed
                and not close_image(pending.image_handle)
            ):
                contained = False
            pending_continued = continue_debug_event(pending)
            if not pending_continued:
                contained = False
                can_wait = False
            elif (
                pending.kind is DebugEventKind.EXIT_PROCESS
                and pending.process_id == process.process_id
            ):
                root_exit_continued = True
        deadline = self._clock.monotonic() + _TERMINATION_TIMEOUT_SECONDS
        while self._clock.monotonic() < deadline:
            event = None
            if can_wait:
                try:
                    event = self._debug_api.wait_event(0)
                except BaseException:
                    contained = False
                    can_wait = False
            if event is not None:
                if event.image_handle is not None and not close_image(
                    event.image_handle
                ):
                    contained = False
                event_continued = continue_debug_event(event)
                if not event_continued:
                    contained = False
                    can_wait = False
                elif (
                    event.kind is DebugEventKind.EXIT_PROCESS
                    and event.process_id == process.process_id
                ):
                    root_exit_continued = True
                continue
            try:
                if (
                    self._process_api.active_processes(process.job) == 0
                    and root_exit_continued
                ):
                    return contained
            except BaseException:
                return False
            self._clock.wait(0.025)
        return False

    def _execute_under_policy(
        self,
        request: CommandProcessRequest,
        dynamic_load_policy: CpythonDynamicLoadPolicy,
        *,
        system_directory: PureWindowsPath,
        system_directory_identity: StableFileIdentity,
        policy_sha256: str,
    ) -> DynamicLoadCommandResult:
        if (
            type(request) is not CommandProcessRequest
            or not _is_sha256(policy_sha256)
            or type(system_directory_identity) is not StableFileIdentity
            or self.supported is not True
        ):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.UNAVAILABLE
            )
        policy = _ImagePolicy(dynamic_load_policy, system_directory)
        cancellation = threading.Event()
        results: list[DynamicLoadCommandResult] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                result = self._execute_worker(
                    request,
                    policy,
                    policy_sha256,
                    system_directory_identity,
                    cancellation,
                )
                if type(result) is not DynamicLoadCommandResult:
                    raise TypeError("CPython dynamic-load result is invalid.")
                results.append(result)
            except BaseException as error:
                failures.append(error)

        worker = self._worker_factory(run)
        primary: BaseException | None = None
        try:
            worker.start()
        except BaseException as error:
            primary = error
            cancellation.set()
        while worker.is_alive():
            try:
                worker.join(0.05)
            except BaseException as error:
                if primary is None:
                    primary = error
                cancellation.set()
        if primary is not None:
            if failures and isinstance(failures[0], DynamicLoadEnforcementError):
                if (
                    failures[0].code
                    is DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                ):
                    raise failures[0]
            if isinstance(primary, Exception):
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.START_FAILED
                ) from None
            raise primary
        if len(results) == 1 and not failures:
            return results[0]
        if len(failures) == 1 and not results:
            if isinstance(failures[0], Exception) and not isinstance(
                failures[0], DynamicLoadEnforcementError
            ):
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.START_FAILED
                ) from None
            raise failures[0]
        raise DynamicLoadEnforcementError(
            DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
        )

    def _execute_worker(
        self,
        request: CommandProcessRequest | ProviderChildProcessRequest,
        policy: _ImagePolicy,
        policy_sha256: str,
        system_directory_identity: StableFileIdentity,
        cancellation: threading.Event,
        *,
        child_policy: _ImagePolicy | None = None,
        child_policy_sha256: str = "",
        request_binding_sha256: str = "",
    ) -> DynamicLoadCommandResult | ProviderChildCommandResult:
        process: _NativeProcess | None = None
        try:
            if child_policy is None:
                process = self._process_api.start(request, debug_process_tree=True)
            else:
                process = self._process_api.start(
                    request,
                    debug_process_tree=True,
                    active_process_limit=2,
                )
            if (
                type(process) is not _NativeProcess
                or process.process_id <= 0
                or process.debug_process_tree is not True
                or process.dynamic_code_prohibited is not True
                or process.child_processes_restricted is not (child_policy is None)
                or process.active_process_limit != (1 if child_policy is None else 2)
            ):
                raise TypeError("Debug process state is invalid.")
            self._debug_api.prepare_kill_on_exit()
        except CommandExecutionError as error:
            if process is not None:
                cleaned = self._terminate_and_drain(process, None)
                self._process_api.close_process(process)
                if not cleaned:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                    ) from None
            code = (
                DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                if error.code is CommandExecutionErrorCode.CONTAINMENT_FAILED
                else DynamicLoadEnforcementErrorCode.START_FAILED
            )
            raise DynamicLoadEnforcementError(code) from None
        except BaseException as error:
            if process is not None:
                cleaned = self._terminate_and_drain(process, None)
                self._process_api.close_process(process)
                if not cleaned:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                    ) from None
            if not isinstance(error, Exception):
                raise
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.START_FAILED
            ) from None

        stdout: _BoundedReader | None = None
        stderr: _BoundedReader | None = None
        pending: DebugEvent | None = None
        pending_image_closed = False
        tree_empty = False
        monitor: _EventMonitor | _ProviderChildEventMonitor
        if child_policy is None:
            monitor = _EventMonitor(process.process_id, policy)
        else:
            monitor = _ProviderChildEventMonitor(
                process.process_id,
                policy,
                child_policy,
            )
        try:
            stdout = _BoundedReader(
                self._process_api, process.stdout_read, request.stdout_limit_bytes
            )
            stderr = _BoundedReader(
                self._process_api, process.stderr_read, request.stderr_limit_bytes
            )
            stdout.start()
            stderr.start()
            deadline = self._clock.monotonic() + request.timeout_ms / 1000.0
            exited = False
            while not exited:
                if cancellation.is_set():
                    raise _WorkerCancelled
                if stdout.overflowed or stderr.overflowed:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.OUTPUT_LIMIT
                    )
                if stdout.failed or stderr.failed:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.START_FAILED
                    )
                remaining = deadline - self._clock.monotonic()
                if remaining <= 0:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.TIMEOUT
                    )
                wait_ms = min(_POLL_MILLISECONDS, max(0, int(remaining * 1000)))
                try:
                    event = self._debug_api.wait_event(wait_ms)
                except DynamicLoadEnforcementError:
                    raise
                except Exception:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.EVENT_INVALID
                    ) from None
                if event is None:
                    self._clock.wait(min(0.001, remaining))
                    continue
                if type(event) is not DebugEvent:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.EVENT_INVALID
                    )
                pending = event
                pending_image_closed = False
                if (
                    child_policy is None
                    and event.process_id != process.process_id
                    and event.image_handle is not None
                ):
                    try:
                        self._debug_api.close_image_handle(event.image_handle)
                    except Exception:
                        raise DynamicLoadEnforcementError(
                            DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                        ) from None
                    pending_image_closed = True
                    snapshot = None
                else:
                    try:
                        snapshot = self._inspect_event_image(event)
                    finally:
                        if event.image_handle is not None:
                            try:
                                self._debug_api.close_image_handle(event.image_handle)
                            except Exception:
                                raise DynamicLoadEnforcementError(
                                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                                ) from None
                            pending_image_closed = True
                status, exited = monitor.accept(event, snapshot)
                try:
                    self._debug_api.continue_event(event, status)
                except Exception:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                    ) from None
                pending = None
                pending_image_closed = False

            while True:
                if cancellation.is_set():
                    raise _WorkerCancelled
                try:
                    active = self._process_api.active_processes(process.job)
                except Exception:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                    ) from None
                if active == 0:
                    tree_empty = True
                    break
                remaining = deadline - self._clock.monotonic()
                if remaining <= 0:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.TIMEOUT
                    )
                self._clock.wait(min(0.025, remaining))

            stdout.join(1.0)
            stderr.join(1.0)
            if stdout.alive or stderr.alive or stdout.failed or stderr.failed:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                )
            if stdout.overflowed or stderr.overflowed:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.OUTPUT_LIMIT
                )
            try:
                exit_code = self._process_api.exit_code(process.process)
            except Exception:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                ) from None
            command = CommandProcessResult(
                stdout=stdout.data,
                stderr=stderr.data,
                exit_code=exit_code,
                stdin_closed=True,
                stdout_streamed=True,
                stderr_streamed=True,
                process_tree_contained=True,
                process_tree_empty=True,
            )
            if child_policy is None:
                if type(monitor) is not _EventMonitor:
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                    )
                return DynamicLoadCommandResult(
                    command,
                    monitor.evidence(policy_sha256, system_directory_identity),
                )
            if (
                type(monitor) is not _ProviderChildEventMonitor
                or not _is_sha256(child_policy_sha256)
                or not _is_sha256(request_binding_sha256)
            ):
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                )
            return ProviderChildCommandResult(
                command,
                monitor.evidence(
                    request_binding_sha256,
                    policy_sha256,
                    child_policy_sha256,
                    system_directory_identity,
                ),
            )
        except DynamicLoadEnforcementError:
            cleaned = self._terminate_and_drain(process, pending, pending_image_closed)
            pending = None
            pending_image_closed = True
            try:
                tree_empty = self._process_api.active_processes(process.job) == 0
            except BaseException:
                tree_empty = False
            if not cleaned:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                ) from None
            tree_empty = True
            raise
        except BaseException:
            cleaned = self._terminate_and_drain(process, pending, pending_image_closed)
            pending = None
            pending_image_closed = True
            try:
                tree_empty = self._process_api.active_processes(process.job) == 0
            except BaseException:
                tree_empty = False
            if not cleaned:
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                ) from None
            tree_empty = True
            raise
        finally:
            if not tree_empty:
                self._terminate_and_drain(process, pending, pending_image_closed)
            if stdout is not None:
                stdout.join(0.25)
            if stderr is not None:
                stderr.join(0.25)
            self._process_api.close_process(process)

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeWindowsCpythonDynamicLoadBackend(state={state!r})"


class NativeWindowsProviderChildDynamicLoadBackend:
    """Execute one exact Podman provider plan with one serialized child role."""

    __slots__ = ("_delegate",)

    def __init__(
        self,
        *,
        process_api: _ProcessApi | None = None,
        debug_api: DebugEventApi | None = None,
        clock: _Clock | None = None,
        path_api: WindowsPathTrustApi | None = None,
        worker_factory: Callable[[Callable[[], None]], _WorkerThread] | None = None,
    ) -> None:
        self._delegate = NativeWindowsCpythonDynamicLoadBackend(
            process_api=process_api,
            debug_api=debug_api,
            clock=clock,
            path_api=path_api,
            worker_factory=worker_factory,
        )

    @property
    def supported(self) -> bool:
        return self._delegate.supported

    @staticmethod
    def _validate_policies(
        plan: ProcessCommandPlan,
        provider_policy: ProcessImagePolicy,
        child_policy: ProcessImagePolicy,
    ) -> None:
        provider_images = {
            (item.identity, item.sha256, item.final_path_sha256)
            for item in provider_policy.exact_files
        }
        child_images = {
            (item.identity, item.sha256, item.final_path_sha256)
            for item in child_policy.exact_files
        }
        if (
            type(plan) is not ProcessCommandPlan
            or plan.kind is not CommandKind.PODMAN_COMPOSE
            or type(provider_policy) is not ProcessImagePolicy
            or provider_policy.role is not ProcessImageRole.PROVIDER
            or type(child_policy) is not ProcessImagePolicy
            or child_policy.role is not ProcessImageRole.RUNTIME_CHILD
            or provider_policy.content_sha256 == child_policy.content_sha256
            or not provider_policy.entrypoint.matches_file_identity(plan.executable)
            or not child_policy.entrypoint.matches_file_identity(
                plan.target.runtime.executable
            )
            or provider_images.intersection(child_images)
        ):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.PLAN_REJECTED
            )

    def execute(
        self,
        plan: ProcessCommandPlan,
        provider_policy: ProcessImagePolicy,
        child_policy: ProcessImagePolicy,
    ) -> ProviderChildCommandResult:
        if self.supported is not True:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.UNAVAILABLE
            )
        try:
            self._validate_policies(plan, provider_policy, child_policy)
            request = ProviderChildProcessRequest.from_plan(plan)
            system_directory = PureWindowsPath(
                self._delegate._process_api.system_directory()
            )
            expected_system = plan.target.process_environment.system_root.final_path / (
                "System32"
            )
            if _canonical_path(str(system_directory)) != _canonical_path(
                str(expected_system)
            ):
                raise ValueError("System directory mismatch.")
            if plan.working_directory != plan.target.package_root.final_path:
                raise ValueError("Package working directory mismatch.")
            with ExitStack() as stack:
                system_trust = stack.enter_context(
                    capture_path_hierarchy(
                        str(system_directory),
                        purpose=PathTrustPurpose.RUNTIME_INSTALL,
                        api=self._delegate._path_api,
                    )
                )
                package_trust = stack.enter_context(
                    capture_path_hierarchy(
                        str(plan.working_directory),
                        purpose=PathTrustPurpose.PACKAGE_ROOT,
                        api=self._delegate._path_api,
                    )
                )
                system_trust.assert_unchanged()
                package_trust.assert_unchanged()
                expected_package_identity = StableFileIdentity(
                    plan.target.package_root.volume_serial,
                    plan.target.package_root.file_id,
                )
                if (
                    package_trust.evidence.root_identity != expected_package_identity
                    or _canonical_path(package_trust.root_snapshot.final_path)
                    != _canonical_path(str(plan.target.package_root.final_path))
                ):
                    raise DynamicLoadEnforcementError(
                        DynamicLoadEnforcementErrorCode.PLAN_REJECTED
                    )
                result = self._execute_provider_request(
                    request,
                    provider_policy,
                    child_policy,
                    system_directory=system_directory,
                    system_directory_identity=system_trust.evidence.root_identity,
                )
                system_trust.assert_unchanged()
                package_trust.assert_unchanged()
                return result
        except DynamicLoadEnforcementError:
            raise
        except (TypeError, ValueError, WindowsSecurityError):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.PLAN_REJECTED
            ) from None
        except Exception:
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.START_FAILED
            ) from None

    def _execute_provider_request(
        self,
        request: ProviderChildProcessRequest,
        provider_policy: ProcessImagePolicy,
        child_policy: ProcessImagePolicy,
        *,
        system_directory: PureWindowsPath,
        system_directory_identity: StableFileIdentity,
    ) -> ProviderChildCommandResult:
        if (
            type(request) is not ProviderChildProcessRequest
            or type(provider_policy) is not ProcessImagePolicy
            or type(child_policy) is not ProcessImagePolicy
            or type(system_directory) is not PureWindowsPath
            or type(system_directory_identity) is not StableFileIdentity
            or self.supported is not True
        ):
            raise DynamicLoadEnforcementError(
                DynamicLoadEnforcementErrorCode.UNAVAILABLE
            )
        provider = _ImagePolicy(provider_policy, system_directory)
        child = _ImagePolicy(child_policy, system_directory)
        cancellation = threading.Event()
        results: list[ProviderChildCommandResult] = []
        failures: list[BaseException] = []

        def run() -> None:
            try:
                result = self._delegate._execute_worker(
                    request,
                    provider,
                    provider_policy.content_sha256,
                    system_directory_identity,
                    cancellation,
                    child_policy=child,
                    child_policy_sha256=child_policy.content_sha256,
                    request_binding_sha256=request.binding_sha256,
                )
                if type(result) is not ProviderChildCommandResult:
                    raise TypeError("Provider-child execution result is invalid.")
                results.append(result)
            except BaseException as error:
                failures.append(error)

        worker = self._delegate._worker_factory(run)
        primary: BaseException | None = None
        try:
            worker.start()
        except BaseException as error:
            primary = error
            cancellation.set()
        while worker.is_alive():
            try:
                worker.join(0.05)
            except BaseException as error:
                if primary is None:
                    primary = error
                cancellation.set()
        if primary is not None:
            if failures and isinstance(failures[0], DynamicLoadEnforcementError):
                if (
                    failures[0].code
                    is DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
                ):
                    raise failures[0]
            if isinstance(primary, Exception):
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.START_FAILED
                ) from None
            raise primary
        if len(results) == 1 and not failures:
            return results[0]
        if len(failures) == 1 and not results:
            if isinstance(failures[0], Exception) and not isinstance(
                failures[0], DynamicLoadEnforcementError
            ):
                raise DynamicLoadEnforcementError(
                    DynamicLoadEnforcementErrorCode.START_FAILED
                ) from None
            raise failures[0]
        raise DynamicLoadEnforcementError(
            DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
        )

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return (
            "NativeWindowsProviderChildDynamicLoadBackend("
            f"state={state!r}, active_process_limit=2)"
        )


__all__ = [
    "DBG_CONTINUE",
    "DBG_EXCEPTION_NOT_HANDLED",
    "DebugEvent",
    "DebugEventKind",
    "DynamicLoadCommandResult",
    "DynamicLoadEnforcementError",
    "DynamicLoadEnforcementErrorCode",
    "DynamicLoadEnforcementEvidence",
    "NativeWindowsCpythonDynamicLoadBackend",
    "NativeWindowsDebugEventApi",
    "NativeWindowsProviderChildDynamicLoadBackend",
    "ProviderChildCommandResult",
    "ProviderChildEnforcementEvidence",
]
