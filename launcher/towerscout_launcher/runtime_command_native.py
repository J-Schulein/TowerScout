"""Native Windows process containment for authenticated version commands.

The adapter launches one exact absolute application path suspended, assigns it
to a kill-on-close Job Object before its first instruction, restricts inherited
handles to three anonymous-pipe ends, closes stdin, and streams stdout/stderr
into fixed in-memory budgets.  Timeout or overflow terminates the complete Job
Object and verifies that its active-process count reached zero.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, NoReturn, Protocol

from .runtime_command_version import (
    CommandExecutionError,
    CommandExecutionErrorCode,
    CommandProcessRequest,
    CommandProcessResult,
)

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_STILL_ACTIVE = 259
_ERROR_BROKEN_PIPE = 109
_ERROR_INSUFFICIENT_BUFFER = 122
_READ_CHUNK_BYTES = 4096
_POLL_MILLISECONDS = 25
_TERMINATION_TIMEOUT_SECONDS = 5.0
_MAX_DIRECTORY_CHARACTERS = 32_767
_REQUIRED_ENVIRONMENT_NAMES = ("SystemRoot", "WINDIR")

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int
_SIZE_T = ctypes.c_size_t
_ULONG_PTR = ctypes.c_size_t
_LPBYTE = ctypes.POINTER(ctypes.c_ubyte)


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("nLength", _DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", _BOOL),
    )


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = (
        ("cb", _DWORD),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", _DWORD),
        ("dwY", _DWORD),
        ("dwXSize", _DWORD),
        ("dwYSize", _DWORD),
        ("dwXCountChars", _DWORD),
        ("dwYCountChars", _DWORD),
        ("dwFillAttribute", _DWORD),
        ("dwFlags", _DWORD),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", _LPBYTE),
        ("hStdInput", _HANDLE),
        ("hStdOutput", _HANDLE),
        ("hStdError", _HANDLE),
    )


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = (
        ("StartupInfo", _STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    )


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("hProcess", _HANDLE),
        ("hThread", _HANDLE),
        ("dwProcessId", _DWORD),
        ("dwThreadId", _DWORD),
    )


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", _DWORD),
        ("MinimumWorkingSetSize", _SIZE_T),
        ("MaximumWorkingSetSize", _SIZE_T),
        ("ActiveProcessLimit", _DWORD),
        ("Affinity", _ULONG_PTR),
        ("PriorityClass", _DWORD),
        ("SchedulingClass", _DWORD),
    )


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = tuple(
        (name, ctypes.c_uint64)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    )


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", _SIZE_T),
        ("JobMemoryLimit", _SIZE_T),
        ("PeakProcessMemoryUsed", _SIZE_T),
        ("PeakJobMemoryUsed", _SIZE_T),
    )


class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("TotalUserTime", ctypes.c_int64),
        ("TotalKernelTime", ctypes.c_int64),
        ("ThisPeriodTotalUserTime", ctypes.c_int64),
        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
        ("TotalPageFaultCount", _DWORD),
        ("TotalProcesses", _DWORD),
        ("ActiveProcesses", _DWORD),
        ("TotalTerminatedProcesses", _DWORD),
    )


def _handle_value(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise OSError("Native process handle is invalid.")
    return value


def _optional_handle_value(value: object) -> int | None:
    if type(value) is int and value > 0:
        return value
    return None


@dataclass(frozen=True, slots=True, repr=False)
class _NativeProcess:
    job: int = field(repr=False)
    process: int = field(repr=False)
    stdout_read: int = field(repr=False)
    stderr_read: int = field(repr=False)

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value <= 0
            for value in (
                self.job,
                self.process,
                self.stdout_read,
                self.stderr_read,
            )
        ):
            raise ValueError("Native process state is invalid.")

    def __repr__(self) -> str:
        return "_NativeProcess(<redacted>)"


class _ProcessApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def windows_directory(self) -> str: ...

    def system_directory(self) -> str: ...

    def start(self, request: CommandProcessRequest) -> _NativeProcess: ...

    def read_file(self, handle: int, maximum: int) -> bytes: ...

    def wait_process(self, process: int, milliseconds: int) -> bool: ...

    def exit_code(self, process: int) -> int: ...

    def active_processes(self, job: int) -> int: ...

    def terminate_job(self, job: int) -> None: ...

    def close_process(self, process: _NativeProcess) -> None: ...


class _Clock(Protocol):
    def monotonic(self) -> float: ...

    def wait(self, seconds: float) -> None: ...


class _SystemClock:
    __slots__ = ()

    def monotonic(self) -> float:
        import time

        return time.monotonic()

    def wait(self, seconds: float) -> None:
        threading.Event().wait(seconds)


class _NativeWindowsProcessApi:
    """Narrow ctypes wrapper around the fixed Windows process policy."""

    __slots__ = ("_kernel32",)

    _kernel32: Any | None

    def __init__(self) -> None:
        win_dll = getattr(ctypes, "WinDLL", None)
        if os.name != "nt" or win_dll is None:
            self._kernel32 = None
            return
        kernel32 = win_dll("kernel32", use_last_error=True)
        self._kernel32 = kernel32
        self._bind(kernel32)

    @staticmethod
    def _bind(kernel32: Any) -> None:
        kernel32.CreatePipe.argtypes = (
            ctypes.POINTER(_HANDLE),
            ctypes.POINTER(_HANDLE),
            ctypes.POINTER(_SECURITY_ATTRIBUTES),
            _DWORD,
        )
        kernel32.CreatePipe.restype = _BOOL
        kernel32.SetHandleInformation.argtypes = (_HANDLE, _DWORD, _DWORD)
        kernel32.SetHandleInformation.restype = _BOOL
        kernel32.InitializeProcThreadAttributeList.argtypes = (
            ctypes.c_void_p,
            _DWORD,
            _DWORD,
            ctypes.POINTER(_SIZE_T),
        )
        kernel32.InitializeProcThreadAttributeList.restype = _BOOL
        kernel32.UpdateProcThreadAttribute.argtypes = (
            ctypes.c_void_p,
            _DWORD,
            _SIZE_T,
            ctypes.c_void_p,
            _SIZE_T,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        kernel32.UpdateProcThreadAttribute.restype = _BOOL
        kernel32.DeleteProcThreadAttributeList.argtypes = (ctypes.c_void_p,)
        kernel32.DeleteProcThreadAttributeList.restype = None
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
        kernel32.CreateJobObjectW.restype = _HANDLE
        kernel32.SetInformationJobObject.argtypes = (
            _HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            _DWORD,
        )
        kernel32.SetInformationJobObject.restype = _BOOL
        kernel32.CreateProcessW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            _BOOL,
            _DWORD,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(_STARTUPINFOW),
            ctypes.POINTER(_PROCESS_INFORMATION),
        )
        kernel32.CreateProcessW.restype = _BOOL
        kernel32.AssignProcessToJobObject.argtypes = (_HANDLE, _HANDLE)
        kernel32.AssignProcessToJobObject.restype = _BOOL
        kernel32.ResumeThread.argtypes = (_HANDLE,)
        kernel32.ResumeThread.restype = _DWORD
        kernel32.TerminateProcess.argtypes = (_HANDLE, _DWORD)
        kernel32.TerminateProcess.restype = _BOOL
        kernel32.TerminateJobObject.argtypes = (_HANDLE, _DWORD)
        kernel32.TerminateJobObject.restype = _BOOL
        kernel32.QueryInformationJobObject.argtypes = (
            _HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
        )
        kernel32.QueryInformationJobObject.restype = _BOOL
        kernel32.WaitForSingleObject.argtypes = (_HANDLE, _DWORD)
        kernel32.WaitForSingleObject.restype = _DWORD
        kernel32.GetExitCodeProcess.argtypes = (_HANDLE, ctypes.POINTER(_DWORD))
        kernel32.GetExitCodeProcess.restype = _BOOL
        kernel32.ReadFile.argtypes = (
            _HANDLE,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
            ctypes.c_void_p,
        )
        kernel32.ReadFile.restype = _BOOL
        kernel32.CloseHandle.argtypes = (_HANDLE,)
        kernel32.CloseHandle.restype = _BOOL
        kernel32.GetWindowsDirectoryW.argtypes = (ctypes.c_wchar_p, _DWORD)
        kernel32.GetWindowsDirectoryW.restype = _DWORD
        kernel32.GetSystemDirectoryW.argtypes = (ctypes.c_wchar_p, _DWORD)
        kernel32.GetSystemDirectoryW.restype = _DWORD

    @property
    def supported(self) -> bool:
        return self._kernel32 is not None

    def _require_kernel32(self) -> Any:
        if self._kernel32 is None:
            raise OSError("Native Windows process APIs are unavailable.")
        return self._kernel32

    def _directory(self, function_name: str) -> str:
        kernel32 = self._require_kernel32()
        buffer = ctypes.create_unicode_buffer(_MAX_DIRECTORY_CHARACTERS + 1)
        function = getattr(kernel32, function_name)
        length = int(function(buffer, len(buffer)))
        if length <= 0 or length >= len(buffer):
            raise OSError("Native Windows directory resolution failed.")
        value = buffer.value
        if len(value) != length:
            raise OSError("Native Windows directory resolution was inconsistent.")
        return value

    def windows_directory(self) -> str:
        return self._directory("GetWindowsDirectoryW")

    def system_directory(self) -> str:
        return self._directory("GetSystemDirectoryW")

    @staticmethod
    def _environment_block(environment: tuple[tuple[str, str], ...]) -> str:
        if (
            type(environment) is not tuple
            or tuple(item[0] for item in environment) != _REQUIRED_ENVIRONMENT_NAMES
        ):
            raise ValueError("The contained environment is invalid.")
        rendered: list[str] = []
        previous = ""
        for key, value in environment:
            folded = key.casefold()
            if (
                not key
                or "=" in key
                or "\x00" in key
                or "\x00" in value
                or (previous and folded <= previous)
            ):
                raise ValueError("The contained environment is invalid.")
            previous = folded
            rendered.append(f"{key}={value}")
        # create_unicode_buffer supplies the second terminal NUL.
        return "\x00".join(rendered) + "\x00"

    def _close(self, value: int | None) -> None:
        if value is None or value <= 0 or self._kernel32 is None:
            return
        try:
            self._kernel32.CloseHandle(_HANDLE(value))
        except BaseException:
            pass

    def _pipe(self) -> tuple[int, int]:
        kernel32 = self._require_kernel32()
        read = _HANDLE()
        write = _HANDLE()
        attributes = _SECURITY_ATTRIBUTES(
            nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
            lpSecurityDescriptor=None,
            bInheritHandle=True,
        )
        if not kernel32.CreatePipe(
            ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0
        ):
            raise OSError("Native process pipe creation failed.")
        return _handle_value(read.value), _handle_value(write.value)

    def _remove_inheritance(self, handle: int) -> None:
        kernel32 = self._require_kernel32()
        if not kernel32.SetHandleInformation(_HANDLE(handle), HANDLE_FLAG_INHERIT, 0):
            raise OSError("Native process pipe protection failed.")

    def _terminate_failed_start(
        self,
        *,
        process: int,
        job: int | None,
        assigned: bool,
    ) -> bool:
        """Terminate and prove cleanup after CreateProcessW succeeded."""

        kernel32 = self._require_kernel32()
        try:
            if not assigned:
                if not kernel32.TerminateProcess(_HANDLE(process), 1):
                    return False
                return (
                    int(kernel32.WaitForSingleObject(_HANDLE(process), 5000))
                    == _WAIT_OBJECT_0
                )
            if job is None or not kernel32.TerminateJobObject(_HANDLE(job), 1):
                return False

            import time

            deadline = time.monotonic() + _TERMINATION_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if self.active_processes(job) == 0:
                    return True
                threading.Event().wait(0.025)
        except BaseException:
            return False
        return False

    def start(self, request: CommandProcessRequest) -> _NativeProcess:
        if type(request) is not CommandProcessRequest:
            raise ValueError("Contained command request is invalid.")
        kernel32 = self._require_kernel32()
        stdout_read = stdout_write = None
        stderr_read = stderr_write = None
        stdin_read = stdin_write = None
        job = None
        process = thread = None
        assigned = False
        attribute_list = None
        attribute_initialized = False
        process_info = _PROCESS_INFORMATION()
        try:
            stdout_read, stdout_write = self._pipe()
            stderr_read, stderr_write = self._pipe()
            stdin_read, stdin_write = self._pipe()
            for handle in (stdout_read, stderr_read, stdin_write):
                self._remove_inheritance(handle)

            job = _handle_value(kernel32.CreateJobObjectW(None, None))
            job_limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            job_limits.BasicLimitInformation.LimitFlags = (
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            if not kernel32.SetInformationJobObject(
                _HANDLE(job),
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(job_limits),
                ctypes.sizeof(job_limits),
            ):
                raise OSError("Native process Job Object policy failed.")

            attribute_bytes = _SIZE_T()
            ctypes.set_last_error(0)
            first = kernel32.InitializeProcThreadAttributeList(
                None, 1, 0, ctypes.byref(attribute_bytes)
            )
            if (
                first
                or attribute_bytes.value == 0
                or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER
            ):
                raise OSError("Native process handle-list sizing failed.")
            attribute_buffer = ctypes.create_string_buffer(attribute_bytes.value)
            attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
            if not kernel32.InitializeProcThreadAttributeList(
                attribute_list, 1, 0, ctypes.byref(attribute_bytes)
            ):
                raise OSError("Native process handle-list initialization failed.")
            attribute_initialized = True
            inherited_handles = (_HANDLE * 3)(
                _HANDLE(stdin_read), _HANDLE(stdout_write), _HANDLE(stderr_write)
            )
            if not kernel32.UpdateProcThreadAttribute(
                attribute_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                ctypes.cast(inherited_handles, ctypes.c_void_p),
                ctypes.sizeof(inherited_handles),
                None,
                None,
            ):
                raise OSError("Native process inherited-handle policy failed.")

            startup = _STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEXW)
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput = _HANDLE(stdin_read)
            startup.StartupInfo.hStdOutput = _HANDLE(stdout_write)
            startup.StartupInfo.hStdError = _HANDLE(stderr_write)
            startup.lpAttributeList = attribute_list
            command_line = subprocess.list2cmdline(
                (str(request.executable_path), *request.arguments)
            )
            command_buffer = ctypes.create_unicode_buffer(command_line)
            environment_buffer = ctypes.create_unicode_buffer(
                self._environment_block(request.environment)
            )
            flags = (
                CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
            )
            if not kernel32.CreateProcessW(
                str(request.executable_path),
                command_buffer,
                None,
                None,
                True,
                flags,
                environment_buffer,
                str(request.working_directory),
                ctypes.byref(startup.StartupInfo),
                ctypes.byref(process_info),
            ):
                raise OSError("Native contained process creation failed.")
            process = _handle_value(process_info.hProcess)
            thread = _handle_value(process_info.hThread)

            # Parent copies of all child-only pipe ends are closed immediately.
            self._close(stdin_read)
            stdin_read = None
            self._close(stdout_write)
            stdout_write = None
            self._close(stderr_write)
            stderr_write = None
            self._close(stdin_write)
            stdin_write = None

            if not kernel32.AssignProcessToJobObject(_HANDLE(job), _HANDLE(process)):
                raise OSError("Native contained process assignment failed.")
            assigned = True
            if kernel32.ResumeThread(_HANDLE(thread)) == 0xFFFFFFFF:
                raise OSError("Native contained process resume failed.")
            self._close(thread)
            thread = None
            result = _NativeProcess(job, process, stdout_read, stderr_read)
            job = process = stdout_read = stderr_read = None
            return result
        except BaseException:
            if process is None:
                process = _optional_handle_value(process_info.hProcess)
            if thread is None:
                thread = _optional_handle_value(process_info.hThread)
            cleanup_verified = True
            if process is not None:
                cleanup_verified = self._terminate_failed_start(
                    process=process,
                    job=job,
                    assigned=assigned,
                )
            elif thread is not None:
                cleanup_verified = False
            if not cleanup_verified:
                raise CommandExecutionError(
                    CommandExecutionErrorCode.CONTAINMENT_FAILED
                ) from None
            raise
        finally:
            if attribute_initialized and attribute_list is not None:
                try:
                    kernel32.DeleteProcThreadAttributeList(attribute_list)
                except BaseException:
                    pass
            for cleanup_handle in (
                thread,
                process,
                stdin_read,
                stdin_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
                job,
            ):
                self._close(cleanup_handle)

    def read_file(self, handle: int, maximum: int) -> bytes:
        if type(maximum) is not int or not 1 <= maximum <= _READ_CHUNK_BYTES:
            raise ValueError("Native stream read size is invalid.")
        kernel32 = self._require_kernel32()
        buffer = ctypes.create_string_buffer(maximum)
        read = _DWORD()
        ctypes.set_last_error(0)
        if not kernel32.ReadFile(
            _HANDLE(handle), buffer, maximum, ctypes.byref(read), None
        ):
            if ctypes.get_last_error() == _ERROR_BROKEN_PIPE:
                return b""
            raise OSError("Native process stream reading failed.")
        if read.value > maximum:
            raise OSError("Native process stream reading was inconsistent.")
        return bytes(buffer.raw[: read.value])

    def wait_process(self, process: int, milliseconds: int) -> bool:
        if type(milliseconds) is not int or not 0 <= milliseconds <= 1000:
            raise ValueError("Native process wait interval is invalid.")
        result = int(
            self._require_kernel32().WaitForSingleObject(_HANDLE(process), milliseconds)
        )
        if result == _WAIT_OBJECT_0:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        raise OSError("Native process wait failed.")

    def exit_code(self, process: int) -> int:
        code = _DWORD()
        if not self._require_kernel32().GetExitCodeProcess(
            _HANDLE(process), ctypes.byref(code)
        ):
            raise OSError("Native process exit-code query failed.")
        if code.value == _STILL_ACTIVE:
            raise OSError("Native process remained active unexpectedly.")
        return int(code.value)

    def active_processes(self, job: int) -> int:
        accounting = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        returned = _DWORD()
        if not self._require_kernel32().QueryInformationJobObject(
            _HANDLE(job),
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            ctypes.byref(returned),
        ):
            raise OSError("Native process-tree query failed.")
        if returned.value != ctypes.sizeof(accounting):
            raise OSError("Native process-tree query was inconsistent.")
        return int(accounting.ActiveProcesses)

    def terminate_job(self, job: int) -> None:
        if not self._require_kernel32().TerminateJobObject(_HANDLE(job), 1):
            raise OSError("Native process-tree termination failed.")

    def close_process(self, process: _NativeProcess) -> None:
        if type(process) is not _NativeProcess:
            return
        for handle in (
            process.stdout_read,
            process.stderr_read,
            process.process,
            process.job,
        ):
            self._close(handle)

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"_NativeWindowsProcessApi(state={state!r})"


class _BoundedReader:
    __slots__ = (
        "_api",
        "_buffer",
        "_error",
        "_handle",
        "_limit",
        "_overflow",
        "_started",
        "_thread",
    )

    def __init__(self, api: _ProcessApi, handle: int, limit: int) -> None:
        self._api = api
        self._handle = handle
        self._limit = limit
        self._buffer = bytearray()
        self._overflow = threading.Event()
        self._error = threading.Event()
        self._started = False
        self._thread = threading.Thread(target=self._read, daemon=True)

    @property
    def overflowed(self) -> bool:
        return self._overflow.is_set()

    @property
    def failed(self) -> bool:
        return self._error.is_set()

    @property
    def alive(self) -> bool:
        return self._started and self._thread.is_alive()

    @property
    def data(self) -> bytes:
        return bytes(self._buffer)

    def start(self) -> None:
        try:
            self._thread.start()
        finally:
            # Thread.start() waits for native startup before returning.  The
            # identifier also covers an injected failure raised immediately
            # after that startup, so cleanup will still join a live reader.
            self._started = self._thread.ident is not None

    def join(self, timeout: float) -> None:
        if self._started:
            self._thread.join(timeout)

    def _read(self) -> None:
        try:
            while True:
                remaining = self._limit - len(self._buffer)
                maximum = min(_READ_CHUNK_BYTES, remaining + 1)
                chunk = self._api.read_file(self._handle, maximum)
                if not chunk:
                    return
                if len(chunk) > remaining:
                    self._buffer.extend(chunk[:remaining])
                    self._overflow.set()
                    return
                self._buffer.extend(chunk)
        except Exception:
            self._error.set()


class NativeWindowsCommandVersionBackend:
    """Run a fixed version command inside a verified Windows process tree."""

    __slots__ = ("_api", "_clock")

    def __init__(
        self,
        *,
        api: _ProcessApi | None = None,
        clock: _Clock | None = None,
    ) -> None:
        self._api = api if api is not None else _NativeWindowsProcessApi()
        self._clock = clock if clock is not None else _SystemClock()

    @property
    def supported(self) -> bool:
        try:
            return self._api.supported is True
        except Exception:
            return False

    def windows_directory(self) -> str:
        try:
            return self._api.windows_directory()
        except Exception:
            raise CommandExecutionError(CommandExecutionErrorCode.UNAVAILABLE) from None

    def system_directory(self) -> str:
        try:
            return self._api.system_directory()
        except Exception:
            raise CommandExecutionError(CommandExecutionErrorCode.UNAVAILABLE) from None

    def _terminate_and_verify(self, process: _NativeProcess) -> bool:
        try:
            self._api.terminate_job(process.job)
            deadline = self._clock.monotonic() + _TERMINATION_TIMEOUT_SECONDS
            while self._clock.monotonic() < deadline:
                if self._api.active_processes(process.job) == 0:
                    return True
                remaining = max(0.0, deadline - self._clock.monotonic())
                self._clock.wait(min(0.025, remaining))
        except Exception:
            return False
        return False

    def _abort(
        self,
        process: _NativeProcess,
        code: CommandExecutionErrorCode,
    ) -> NoReturn:
        if not self._terminate_and_verify(process):
            raise CommandExecutionError(CommandExecutionErrorCode.CONTAINMENT_FAILED)
        raise CommandExecutionError(code)

    def execute(self, request: CommandProcessRequest) -> CommandProcessResult:
        if type(request) is not CommandProcessRequest or self.supported is not True:
            raise CommandExecutionError(CommandExecutionErrorCode.UNAVAILABLE)
        try:
            process = self._api.start(request)
        except CommandExecutionError:
            raise
        except Exception:
            raise CommandExecutionError(
                CommandExecutionErrorCode.START_FAILED
            ) from None

        stdout: _BoundedReader | None = None
        stderr: _BoundedReader | None = None
        tree_empty = False
        try:
            stdout = _BoundedReader(
                self._api, process.stdout_read, request.stdout_limit_bytes
            )
            stderr = _BoundedReader(
                self._api, process.stderr_read, request.stderr_limit_bytes
            )
            stdout.start()
            stderr.start()
            deadline = self._clock.monotonic() + (request.timeout_ms / 1000.0)
            direct_exited = False
            while True:
                if stdout.overflowed or stderr.overflowed:
                    self._abort(process, CommandExecutionErrorCode.OUTPUT_LIMIT)
                if stdout.failed or stderr.failed:
                    self._abort(process, CommandExecutionErrorCode.START_FAILED)
                try:
                    active = self._api.active_processes(process.job)
                except Exception:
                    self._abort(process, CommandExecutionErrorCode.CONTAINMENT_FAILED)
                if active == 0:
                    tree_empty = True
                    break
                remaining = deadline - self._clock.monotonic()
                if remaining <= 0:
                    self._abort(process, CommandExecutionErrorCode.TIMEOUT)
                if not direct_exited:
                    try:
                        direct_exited = self._api.wait_process(
                            process.process,
                            min(_POLL_MILLISECONDS, max(0, int(remaining * 1000))),
                        )
                    except Exception:
                        self._abort(
                            process, CommandExecutionErrorCode.CONTAINMENT_FAILED
                        )
                else:
                    self._clock.wait(min(0.025, remaining))

            stdout.join(1.0)
            stderr.join(1.0)
            if stdout.alive or stderr.alive or stdout.failed or stderr.failed:
                self._abort(process, CommandExecutionErrorCode.CONTAINMENT_FAILED)
            if stdout.overflowed or stderr.overflowed:
                self._abort(process, CommandExecutionErrorCode.OUTPUT_LIMIT)
            try:
                exit_code = self._api.exit_code(process.process)
            except Exception:
                raise CommandExecutionError(
                    CommandExecutionErrorCode.CONTAINMENT_FAILED
                ) from None
            return CommandProcessResult(
                stdout=stdout.data,
                stderr=stderr.data,
                exit_code=exit_code,
                stdin_closed=True,
                stdout_streamed=True,
                stderr_streamed=True,
                process_tree_contained=True,
                process_tree_empty=tree_empty,
            )
        except CommandExecutionError:
            raise
        except Exception:
            self._abort(process, CommandExecutionErrorCode.START_FAILED)
        except BaseException:
            if not self._terminate_and_verify(process):
                raise CommandExecutionError(
                    CommandExecutionErrorCode.CONTAINMENT_FAILED
                ) from None
            tree_empty = True
            raise
        finally:
            if not tree_empty:
                try:
                    self._terminate_and_verify(process)
                except Exception:
                    pass
            if stdout is not None:
                stdout.join(0.25)
            if stderr is not None:
                stderr.join(0.25)
            self._api.close_process(process)

    def __repr__(self) -> str:
        state = "supported" if self.supported else "unavailable"
        return f"NativeWindowsCommandVersionBackend(state={state!r})"


__all__ = ["NativeWindowsCommandVersionBackend"]
