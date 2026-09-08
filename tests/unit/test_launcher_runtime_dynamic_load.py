from __future__ import annotations

import hashlib
import sys
import threading
import ctypes
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_dynamic_load as dynamic_module  # noqa: E402
from towerscout_launcher.runtime_command_native import _NativeProcess  # noqa: E402
from towerscout_launcher.runtime_command_version import (  # noqa: E402
    COMMAND_STDERR_LIMIT_BYTES,
    COMMAND_STDOUT_LIMIT_BYTES,
    COMMAND_TIMEOUT_MS,
    CommandProcessRequest,
)
from towerscout_launcher.runtime_dependency_capture import (  # noqa: E402
    CpythonDynamicLoadBinding,
    CpythonDynamicLoadPolicy,
    HeldCpythonDependencyInventory,
)
from towerscout_launcher.runtime_dynamic_load import (  # noqa: E402
    DBG_CONTINUE,
    DBG_EXCEPTION_NOT_HANDLED,
    DebugEvent,
    DebugEventKind,
    DynamicLoadEnforcementError,
    DynamicLoadEnforcementErrorCode,
    NativeWindowsCpythonDynamicLoadBackend,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    FileSnapshot,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
)

_PYTHON = PureWindowsPath(r"C:\Python312\python.exe")
_DEPENDENCY = PureWindowsPath(r"C:\Python312\DLLs\_ssl.pyd")
_SYSTEM32 = PureWindowsPath(r"C:\Windows\System32")
_KERNEL32 = _SYSTEM32 / "kernel32.dll"
_UNAPPROVED = PureWindowsPath(r"C:\Users\Public\attacker.dll")


def _identity(marker: int) -> StableFileIdentity:
    return StableFileIdentity(7, marker.to_bytes(16, "big"))


def _snapshot(path: PureWindowsPath, marker: int) -> FileSnapshot:
    content = str(path).encode("utf-8")
    return FileSnapshot(
        identity=_identity(marker),
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        attributes=0x80,
        creation_time=1,
        last_write_time=2,
        reparse_tag=0,
        final_path=rf"\\?\{path}",
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=True,
            regular_file=True,
            single_link=False,
        ),
    )


def _binding(path: PureWindowsPath, marker: int, *, entrypoint: bool = False):
    return CpythonDynamicLoadBinding.from_snapshot(
        _snapshot(path, marker),
        entrypoint=entrypoint,
    )


def _load_policy(
    *bindings: CpythonDynamicLoadBinding,
    system_image_names: tuple[str, ...] = ("kernel32.dll", "ntdll.dll"),
) -> CpythonDynamicLoadPolicy:
    return CpythonDynamicLoadPolicy(tuple(bindings), system_image_names)


def _request() -> CommandProcessRequest:
    return CommandProcessRequest(
        executable_path=_PYTHON,
        arguments=("--version",),
        environment=(("SystemRoot", r"C:\Windows"), ("WINDIR", r"C:\Windows")),
        working_directory=_SYSTEM32,
        timeout_ms=COMMAND_TIMEOUT_MS,
        stdout_limit_bytes=COMMAND_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=COMMAND_STDERR_LIMIT_BYTES,
    )


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def wait(self, seconds: float) -> None:
        self.value += seconds


class _TimeoutClock(_Clock):
    def __init__(self) -> None:
        super().__init__()
        self.first_wait = True

    def wait(self, seconds: float) -> None:
        if self.first_wait:
            self.first_wait = False
            self.value += COMMAND_TIMEOUT_MS / 1000.0 + 1.0
            return
        super().wait(seconds)


class _ProcessApi:
    supported = True

    def __init__(self, *, fail_terminate: bool = False) -> None:
        self.active = 1
        self.terminated = 0
        self.closed = 0
        self.fail_terminate = fail_terminate
        self.starts: list[tuple[object, bool]] = []
        self.start_threads: list[int] = []
        self.streams = {31: bytearray(b"Python 3.12.10\r\n"), 32: bytearray()}

    def windows_directory(self) -> str:
        return r"C:\Windows"

    def system_directory(self) -> str:
        return str(_SYSTEM32)

    def start(
        self, request: CommandProcessRequest, *, debug_process_tree: bool = False
    ) -> _NativeProcess:
        self.starts.append((request, debug_process_tree))
        self.start_threads.append(threading.get_ident())
        return _NativeProcess(
            11,
            12,
            31,
            32,
            process_id=101,
            debug_process_tree=debug_process_tree,
            dynamic_code_prohibited=debug_process_tree,
            child_processes_restricted=debug_process_tree,
        )

    def read_file(self, handle: int, maximum: int) -> bytes:
        result = bytes(self.streams[handle][:maximum])
        del self.streams[handle][:maximum]
        return result

    def wait_process(self, process: int, milliseconds: int) -> bool:
        del process, milliseconds
        return self.active == 0

    def exit_code(self, process: int) -> int:
        del process
        return 0

    def active_processes(self, job: int) -> int:
        del job
        return self.active

    def terminate_job(self, job: int) -> None:
        del job
        self.terminated += 1
        self.active = 0
        if self.fail_terminate:
            raise OSError("injected termination failure")

    def close_process(self, process: _NativeProcess) -> None:
        del process
        self.closed += 1


class _DebugApi:
    supported = True

    def __init__(
        self,
        events: tuple[DebugEvent | None, ...],
        images: dict[object, FileSnapshot],
        process_api: _ProcessApi,
        *,
        fail_prepare: bool = False,
        interrupt_wait: bool = False,
        fail_close_once: bool = False,
    ) -> None:
        self.events = list(events)
        self.images = images
        self.process_api = process_api
        self.fail_prepare = fail_prepare
        self.interrupt_wait = interrupt_wait
        self.fail_close_once = fail_close_once
        self.prepared = 0
        self.closed: list[object] = []
        self.continued: list[tuple[DebugEventKind, int]] = []
        self.debug_threads: list[int] = []

    def prepare_kill_on_exit(self) -> None:
        self.debug_threads.append(threading.get_ident())
        self.prepared += 1
        if self.fail_prepare:
            raise OSError("injected prepare failure")

    def wait_event(self, milliseconds: int) -> DebugEvent | None:
        self.debug_threads.append(threading.get_ident())
        assert 0 <= milliseconds <= 25
        if self.interrupt_wait:
            self.interrupt_wait = False
            raise KeyboardInterrupt
        return self.events.pop(0) if self.events else None

    def inspect_image(self, handle: object) -> FileSnapshot:
        return self.images[handle]

    def close_image_handle(self, handle: object) -> None:
        if self.fail_close_once:
            self.fail_close_once = False
            raise OSError("injected close failure")
        self.closed.append(handle)

    def continue_event(self, event: DebugEvent, status: int) -> None:
        self.debug_threads.append(threading.get_ident())
        assert event.image_handle is None or event.image_handle in self.closed
        self.continued.append((event.kind, status))
        if event.kind is DebugEventKind.EXIT_PROCESS:
            self.process_api.active = 0


class _SlowFirstWaitDebugApi(_DebugApi):
    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        super().__init__(*args, **kwargs)
        self.first_wait = True

    def wait_event(self, milliseconds: int) -> DebugEvent | None:
        if self.first_wait:
            self.first_wait = False
            threading.Event().wait(0.05)
            return None
        return super().wait_event(milliseconds)


def _events(*loads: tuple[object, PureWindowsPath, int]) -> tuple[DebugEvent, ...]:
    del loads
    return (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="dependency"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="system"),
        DebugEvent(
            DebugEventKind.EXCEPTION,
            101,
            201,
            exception_code=0x80000003,
            first_chance=True,
        ),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=0),
    )


def _backend(events: tuple[DebugEvent, ...] | None = None):
    process_api = _ProcessApi()
    selected = events if events is not None else _events()
    debug_api = _DebugApi(
        selected,
        {
            "python": _snapshot(_PYTHON, 1),
            "dependency": _snapshot(_DEPENDENCY, 2),
            "system": _snapshot(_KERNEL32, 3),
            "attacker": _snapshot(_UNAPPROVED, 4),
        },
        process_api,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )
    bindings = (
        _binding(_PYTHON, 1, entrypoint=True),
        _binding(_DEPENDENCY, 2),
    )
    return backend, process_api, debug_api, bindings


def test_debug_event_backend_allows_only_exact_inventory_or_system32_images() -> None:
    backend, process_api, debug_api, bindings = _backend()

    result = backend._execute_under_policy(  # noqa: SLF001
        _request(),
        _load_policy(*bindings),
        system_directory=_SYSTEM32,
        system_directory_identity=_identity(99),
        policy_sha256="a" * 64,
    )

    assert result.command.stdout == b"Python 3.12.10\r\n"
    assert result.enforcement.loaded_image_count == 3
    assert result.enforcement.exact_inventory_image_count == 2
    assert result.enforcement.system32_image_count == 1
    assert result.enforcement.debug_process_tree
    assert result.enforcement.dynamic_code_prohibited
    assert result.enforcement.child_process_creation_restricted
    assert result.enforcement.unexpected_child_events_denied
    assert result.enforcement.approved_system_image_name_count == 2
    assert result.enforcement.event_file_handles_closed
    assert result.enforcement.arbitrary_dynamic_destinations_denied
    assert process_api.starts == [(_request(), True)]
    assert process_api.terminated == 0
    assert process_api.closed == 1
    assert debug_api.prepared == 1
    assert debug_api.closed == ["python", "dependency", "system"]
    assert debug_api.continued == [
        (DebugEventKind.CREATE_PROCESS, DBG_CONTINUE),
        (DebugEventKind.LOAD_DLL, DBG_CONTINUE),
        (DebugEventKind.LOAD_DLL, DBG_CONTINUE),
        (DebugEventKind.EXCEPTION, DBG_CONTINUE),
        (DebugEventKind.EXIT_PROCESS, DBG_CONTINUE),
    ]
    assert len(set((*process_api.start_threads, *debug_api.debug_threads))) == 1
    assert process_api.start_threads[0] != threading.get_ident()


class _SystemTrust:
    def __init__(self) -> None:
        self.evidence = SimpleNamespace(root_identity=_identity(99))
        self.assertions = 0

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        del exc_type, exc, traceback

    def assert_unchanged(self) -> None:
        self.assertions += 1


def test_public_execute_binds_system_trust_and_held_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, _process_api, _debug_api, bindings = _backend(_events())
    trust = _SystemTrust()
    inventory = object.__new__(HeldCpythonDependencyInventory)
    inventory._evidence = SimpleNamespace(  # type: ignore[assignment]  # noqa: SLF001
        dependency=SimpleNamespace(policy_sha256="a" * 64)
    )
    dynamic_policy = _load_policy(*bindings)
    monkeypatch.setattr(
        dynamic_module,
        "capture_path_hierarchy",
        lambda *args, **kwargs: trust,
    )
    monkeypatch.setattr(
        HeldCpythonDependencyInventory,
        "run_while_held",
        lambda self, operation: operation(),
    )
    monkeypatch.setattr(
        HeldCpythonDependencyInventory,
        "active_dynamic_load_policy",
        lambda self: dynamic_policy,
    )

    result = backend.execute(_request(), inventory)

    assert result.command.exit_code == 0
    assert trust.assertions == 2


@pytest.mark.parametrize(
    "snapshot",
    (
        _snapshot(_UNAPPROVED, 4),
        _snapshot(_DEPENDENCY, 9),
        _snapshot(PureWindowsPath(r"C:\Other\_ssl.pyd"), 2),
        _snapshot(PureWindowsPath(r"C:\Windows\SysWOW64\kernel32.dll"), 3),
        _snapshot(PureWindowsPath(r"C:\Windows\System32\nested\helper.dll"), 3),
        _snapshot(PureWindowsPath(r"C:\Windows\System32\unlisted.dll"), 3),
    ),
)
def test_unapproved_identity_hash_or_destination_terminates_before_continue(
    snapshot: FileSnapshot,
) -> None:
    events = (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="attacker"),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
    )
    backend, process_api, debug_api, bindings = _backend(events)
    debug_api.images["attacker"] = snapshot

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(*bindings),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED
    assert process_api.terminated == 1
    assert process_api.active == 0
    assert debug_api.closed == ["python", "attacker"]
    assert debug_api.continued[0] == (DebugEventKind.CREATE_PROCESS, DBG_CONTINUE)
    assert (DebugEventKind.LOAD_DLL, DBG_CONTINUE) in debug_api.continued


def test_cleanup_waits_for_and_continues_root_exit_after_job_becomes_empty() -> None:
    process_api = _ProcessApi()
    events = (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="attacker"),
        None,
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
    )
    debug_api = _DebugApi(
        events,
        {
            "python": _snapshot(_PYTHON, 1),
            "attacker": _snapshot(_UNAPPROVED, 4),
        },
        process_api,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(_binding(_PYTHON, 1, entrypoint=True)),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.IMAGE_UNAPPROVED
    assert debug_api.continued[-1] == (DebugEventKind.EXIT_PROCESS, DBG_CONTINUE)
    assert debug_api.events == []
    assert process_api.closed == 1


def test_cleanup_without_root_exit_event_reports_failed_containment() -> None:
    events = (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201, image_handle="attacker"),
    )
    backend, process_api, debug_api, bindings = _backend(events)

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(*bindings),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
    assert process_api.active == 0
    assert debug_api.events == []
    assert process_api.closed == 1


def test_timeout_preserves_reason_after_root_exit_is_drained() -> None:
    process_api = _ProcessApi()
    debug_api = _DebugApi(
        (None, *_events()),
        {
            "python": _snapshot(_PYTHON, 1),
            "dependency": _snapshot(_DEPENDENCY, 2),
            "system": _snapshot(_KERNEL32, 3),
        },
        process_api,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_TimeoutClock(),
    )

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(
                _binding(_PYTHON, 1, entrypoint=True),
                _binding(_DEPENDENCY, 2),
            ),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.TIMEOUT
    assert process_api.terminated == 1
    assert debug_api.continued[-1] == (DebugEventKind.EXIT_PROCESS, DBG_CONTINUE)
    assert process_api.closed == 1


def test_stdout_limit_preserves_reason_after_root_exit_is_drained() -> None:
    process_api = _ProcessApi()
    process_api.streams[31] = bytearray(b"x" * (COMMAND_STDOUT_LIMIT_BYTES + 1))
    debug_api = _SlowFirstWaitDebugApi(
        _events(),
        {
            "python": _snapshot(_PYTHON, 1),
            "dependency": _snapshot(_DEPENDENCY, 2),
            "system": _snapshot(_KERNEL32, 3),
        },
        process_api,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(
                _binding(_PYTHON, 1, entrypoint=True),
                _binding(_DEPENDENCY, 2),
            ),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.OUTPUT_LIMIT
    assert process_api.terminated == 1
    assert debug_api.continued[-1] == (DebugEventKind.EXIT_PROCESS, DBG_CONTINUE)
    assert process_api.closed == 1


def test_descendant_process_is_denied_and_its_image_handle_is_closed() -> None:
    events = (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(DebugEventKind.CREATE_PROCESS, 102, 202, image_handle="attacker"),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
    )
    backend, process_api, debug_api, bindings = _backend(events)

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(*bindings),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.CHILD_PROCESS_DENIED
    assert process_api.terminated == 1
    assert debug_api.closed == ["python", "attacker"]


def test_missing_image_handle_fails_closed() -> None:
    events = (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(DebugEventKind.LOAD_DLL, 101, 201),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
    )
    backend, process_api, _debug_api, bindings = _backend(events)

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(*bindings),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.EVENT_INVALID
    assert process_api.terminated == 1


def test_non_initial_exception_is_returned_to_windows_exception_dispatch() -> None:
    events = (
        DebugEvent(DebugEventKind.CREATE_PROCESS, 101, 201, image_handle="python"),
        DebugEvent(
            DebugEventKind.EXCEPTION,
            101,
            201,
            exception_code=0x80000003,
            first_chance=True,
        ),
        DebugEvent(
            DebugEventKind.EXCEPTION,
            101,
            201,
            exception_code=0xC0000005,
            first_chance=True,
        ),
        DebugEvent(DebugEventKind.EXIT_PROCESS, 101, 201, exit_code=1),
    )
    backend, _process_api, debug_api, bindings = _backend(events)

    backend._execute_under_policy(  # noqa: SLF001
        _request(),
        _load_policy(*bindings),
        system_directory=_SYSTEM32,
        system_directory_identity=_identity(99),
        policy_sha256="a" * 64,
    )

    assert debug_api.continued[1:] == [
        (DebugEventKind.EXCEPTION, DBG_CONTINUE),
        (DebugEventKind.EXCEPTION, DBG_EXCEPTION_NOT_HANDLED),
        (DebugEventKind.EXIT_PROCESS, DBG_CONTINUE),
    ]


def test_prepare_failure_terminates_drains_and_closes_started_process() -> None:
    process_api = _ProcessApi()
    debug_api = _DebugApi(
        _events(),
        {
            "python": _snapshot(_PYTHON, 1),
            "dependency": _snapshot(_DEPENDENCY, 2),
            "system": _snapshot(_KERNEL32, 3),
        },
        process_api,
        fail_prepare=True,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(
                _binding(_PYTHON, 1, entrypoint=True),
                _binding(_DEPENDENCY, 2),
            ),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.START_FAILED
    assert process_api.terminated == 1
    assert process_api.active == 0
    assert process_api.closed == 1
    assert debug_api.closed == ["python", "dependency", "system"]


def test_worker_interruption_propagates_only_after_process_tree_cleanup() -> None:
    process_api = _ProcessApi()
    debug_api = _DebugApi(
        _events(),
        {},
        process_api,
        interrupt_wait=True,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )

    with pytest.raises(KeyboardInterrupt):
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(_binding(_PYTHON, 1, entrypoint=True)),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert process_api.terminated == 1
    assert process_api.active == 0
    assert process_api.closed == 1


class _TwiceInterruptedThread:
    last: "_TwiceInterruptedThread | None" = None

    def __init__(self, *, target, daemon: bool) -> None:  # noqa: ANN001
        assert daemon is True
        self.target = target
        self.alive = False
        self.interruptions = 2
        _TwiceInterruptedThread.last = self

    def start(self) -> None:
        self.alive = True

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float) -> None:
        assert timeout == 0.05
        if self.interruptions:
            self.interruptions -= 1
            raise KeyboardInterrupt
        self.target()
        self.alive = False


def test_repeated_main_interruptions_wait_for_worker_cleanup() -> None:
    process_api = _ProcessApi()
    debug_api = _DebugApi(_events(), {}, process_api)
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
        worker_factory=lambda target: _TwiceInterruptedThread(
            target=target, daemon=True
        ),
    )

    with pytest.raises(KeyboardInterrupt):
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(_binding(_PYTHON, 1, entrypoint=True)),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert _TwiceInterruptedThread.last is not None
    assert not _TwiceInterruptedThread.last.alive
    assert process_api.terminated == 1
    assert process_api.active == 0
    assert process_api.closed == 1


def test_image_handle_close_failure_is_retried_before_containment_completes() -> None:
    process_api = _ProcessApi()
    debug_api = _DebugApi(
        _events(),
        {
            "python": _snapshot(_PYTHON, 1),
            "dependency": _snapshot(_DEPENDENCY, 2),
            "system": _snapshot(_KERNEL32, 3),
        },
        process_api,
        fail_close_once=True,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(
                _binding(_PYTHON, 1, entrypoint=True),
                _binding(_DEPENDENCY, 2),
            ),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
    assert process_api.terminated == 1
    assert process_api.active == 0
    assert debug_api.closed[0] == "python"
    assert process_api.closed == 1


def test_job_termination_failure_still_releases_pending_debug_event() -> None:
    process_api = _ProcessApi(fail_terminate=True)
    debug_api = _DebugApi(
        _events(),
        {
            "python": _snapshot(_PYTHON, 1),
            "dependency": _snapshot(_DEPENDENCY, 2),
            "system": _snapshot(_KERNEL32, 3),
        },
        process_api,
    )
    backend = NativeWindowsCpythonDynamicLoadBackend(
        process_api=process_api,
        debug_api=debug_api,
        clock=_Clock(),
    )

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        backend._execute_under_policy(  # noqa: SLF001
            _request(),
            _load_policy(_binding(_PYTHON, 1, entrypoint=True)),
            system_directory=_SYSTEM32,
            system_directory_identity=_identity(99),
            policy_sha256="a" * 64,
        )

    assert failure.value.code is DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
    assert process_api.terminated >= 1
    assert "python" in debug_api.closed
    assert (DebugEventKind.CREATE_PROCESS, DBG_CONTINUE) in debug_api.continued
    assert process_api.closed == 1


def test_models_are_strict_immutable_and_redacted() -> None:
    binding = _binding(_PYTHON, 1, entrypoint=True)
    policy = _load_policy(binding)
    assert "Python312" not in repr(binding)
    assert "kernel32.dll" not in repr(policy)
    with pytest.raises((AttributeError, TypeError)):
        binding.entrypoint = False  # type: ignore[misc]
    with pytest.raises(ValueError):
        CpythonDynamicLoadPolicy((binding,), ("ntdll.dll", "kernel32.dll"))
    with pytest.raises(ValueError):
        CpythonDynamicLoadPolicy((binding,), (r"nested\kernel32.dll",))
    with pytest.raises(ValueError):
        DebugEvent(DebugEventKind.EXIT_PROCESS, 0, 1, exit_code=0)
    with pytest.raises(ValueError):
        DebugEvent(
            DebugEventKind.LOAD_DLL,
            1,
            1,
            exception_code=1,
            first_chance=True,
        )


def test_native_debug_api_degrades_closed_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(dynamic_module.os, "name", "posix")
        api = dynamic_module.NativeWindowsDebugEventApi()

    assert not api.supported
    with pytest.raises(OSError):
        api.wait_event(0)


class _NativeDebugShim:
    def __init__(
        self,
        *,
        malformed_process_id: bool = False,
        close_succeeds: bool = True,
        continue_succeeds: bool = True,
    ) -> None:
        self.closed: list[int] = []
        self.continued: list[tuple[int, int, int]] = []
        self.kill_on_exit: list[bool] = []
        self.malformed_process_id = malformed_process_id
        self.close_succeeds = close_succeeds
        self.continue_succeeds = continue_succeeds

    def WaitForDebugEventEx(self, event_pointer: object, milliseconds: int) -> bool:
        assert milliseconds == 25
        event = ctypes.cast(
            event_pointer, ctypes.POINTER(dynamic_module._DEBUG_EVENT)
        ).contents
        event.dwDebugEventCode = dynamic_module._LOAD_DLL_DEBUG_EVENT
        event.dwProcessId = 0 if self.malformed_process_id else 101
        event.dwThreadId = 201
        event.LoadDll.hFile = 501
        return True

    def ContinueDebugEvent(self, process_id: int, thread_id: int, status: int) -> bool:
        self.continued.append((process_id, thread_id, status))
        return self.continue_succeeds

    def DebugSetProcessKillOnExit(self, enabled: bool) -> bool:
        self.kill_on_exit.append(bool(enabled))
        return True

    def CloseHandle(self, handle: object) -> bool:
        self.closed.append(int(handle.value))
        return self.close_succeeds


class _SupportedFileApi:
    supported = True


def test_native_debug_api_owns_exact_event_handle_and_continuation() -> None:
    shim = _NativeDebugShim()
    api = object.__new__(dynamic_module.NativeWindowsDebugEventApi)
    api._kernel32 = shim  # noqa: SLF001
    api._file_api = _SupportedFileApi()  # type: ignore[assignment]  # noqa: SLF001

    api.prepare_kill_on_exit()
    event = api.wait_event(25)

    assert event == DebugEvent(
        DebugEventKind.LOAD_DLL,
        101,
        201,
        image_handle=501,
    )
    api.close_image_handle(event.image_handle)
    api.continue_event(event, DBG_CONTINUE)
    assert shim.kill_on_exit == [True]
    assert shim.closed == [501]
    assert shim.continued == [(101, 201, DBG_CONTINUE)]


@pytest.mark.parametrize(
    ("close_succeeds", "continue_succeeds"),
    ((False, True), (True, False), (False, False)),
)
def test_native_debug_api_reports_failed_malformed_event_cleanup_as_containment(
    close_succeeds: bool,
    continue_succeeds: bool,
) -> None:
    shim = _NativeDebugShim(
        malformed_process_id=True,
        close_succeeds=close_succeeds,
        continue_succeeds=continue_succeeds,
    )
    api = object.__new__(dynamic_module.NativeWindowsDebugEventApi)
    api._kernel32 = shim  # noqa: SLF001
    api._file_api = _SupportedFileApi()  # type: ignore[assignment]  # noqa: SLF001

    with pytest.raises(DynamicLoadEnforcementError) as failure:
        api.wait_event(25)

    assert failure.value.code is DynamicLoadEnforcementErrorCode.CONTAINMENT_FAILED
    assert shim.closed == [501]
    assert shim.continued == [(0, 201, DBG_CONTINUE)]


def test_dynamic_load_slice_remains_unwired_from_launcher_and_repair() -> None:
    for relative in (
        "towerscout_launcher/app.py",
        "towerscout_launcher/discovery.py",
        "towerscout_launcher/repair.py",
        "towerscout_launcher/runtime_execution.py",
        "towerscout_launcher/runtime_verification.py",
    ):
        source = (LAUNCHER_ROOT / relative).read_text(encoding="utf-8")
        assert "runtime_dynamic_load" not in source
