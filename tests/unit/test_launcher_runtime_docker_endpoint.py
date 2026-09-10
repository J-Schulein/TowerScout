from __future__ import annotations

import ast
import ctypes
import dataclasses
import hashlib
import json
import sys
import threading
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_command_native as native_module  # noqa: E402
import towerscout_launcher.runtime_command_version as command_module  # noqa: E402
import towerscout_launcher.runtime_docker_endpoint as endpoint_module  # noqa: E402
from towerscout_launcher.runtime_command_version import (  # noqa: E402
    BoundCommandRuntimeEvidence,
    CommandExecutionError,
    CommandProcessResult,
)
from towerscout_launcher.runtime_docker_endpoint import (  # noqa: E402
    BoundDockerEndpointEvidence,
    DockerEndpointCommandKind,
    DockerEndpointCommandRequest,
    DockerEndpointError,
    DockerEndpointErrorCode,
    capture_bound_docker_endpoint,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.target_contracts import (  # noqa: E402
    EndpointKind,
    RuntimeProduct,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    FileSnapshot,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
)

_WINDOWS = r"C:\Windows"
_SYSTEM = r"C:\Windows\System32"
_PROFILE = r"C:\Users\reviewed-user"
_CONFIGURATION = rf"{_PROFILE}\.docker"
_DOCKER_FINAL = r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker.exe"
_ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine"
_OTHER_ENDPOINT = "npipe:////./pipe/towerscoutOtherEngine"
_CONTEXT_NAME = "desktop-linux"
_VERSION = "28.3.2"


def _json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _result(
    value: Any,
    *,
    stderr: bytes = b"",
    exit_code: int = 0,
) -> CommandProcessResult:
    return CommandProcessResult(
        stdout=value if type(value) is bytes else _json(value),
        stderr=stderr,
        exit_code=exit_code,
        stdin_closed=True,
        stdout_streamed=True,
        stderr_streamed=True,
        process_tree_contained=True,
        process_tree_empty=True,
    )


def _uncontained_result() -> CommandProcessResult:
    result = object.__new__(CommandProcessResult)
    values: dict[str, object] = {
        "stdout": _json(_context()),
        "stderr": b"",
        "exit_code": 0,
        "stdin_closed": True,
        "stdout_streamed": True,
        "stderr_streamed": True,
        "process_tree_contained": False,
        "process_tree_empty": True,
    }
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _context(
    *,
    name: str = _CONTEXT_NAME,
    endpoint: str = _ENDPOINT,
    skip_tls: bool = False,
    tls_material: Any | None = None,
) -> list[dict[str, Any]]:
    return [
        {
            "Name": name,
            "Metadata": {"Description": "Docker Desktop"},
            "Endpoints": {"docker": {"Host": endpoint, "SkipTLSVerify": skip_tls}},
            "TLSMaterial": {} if tls_material is None else tls_material,
            "Storage": {"MetadataPath": "<IN MEMORY>"},
        }
    ]


def _info(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "ID": "4cee6e1a-8a35-4d13-b40e-67cc3111fbbb",
        "ServerVersion": _VERSION,
        "OperatingSystem": "Docker Desktop",
        "OSType": "linux",
        "Architecture": "x86_64",
        "Name": "docker-desktop",
        "DockerRootDir": "/var/lib/docker",
        "Driver": "overlay2",
        "Containers": 3,
        "Images": 7,
    }
    value.update(overrides)
    return value


def _cycle(
    *,
    context: Any | None = None,
    info: Any | None = None,
) -> list[CommandProcessResult]:
    return [
        _result(_context() if context is None else context),
        _result(_info() if info is None else info),
    ]


def _runtime_snapshot() -> FileSnapshot:
    content = b"authenticated-docker-runtime"
    return FileSnapshot(
        identity=StableFileIdentity(0x1020304050607080, bytes.fromhex("11" * 16)),
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        attributes=0x80,
        creation_time=10,
        last_write_time=20,
        reparse_tag=0,
        final_path=_DOCKER_FINAL,
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=True,
            regular_file=True,
            single_link=True,
        ),
    )


class _RuntimeCandidate:
    def __init__(self, snapshot: FileSnapshot) -> None:
        self.snapshot = snapshot
        self.closed = False
        self.assert_count = 0

    def assert_unchanged(self) -> FileSnapshot:
        if self.closed:
            raise RuntimeError("closed")
        self.assert_count += 1
        return self.snapshot

    def close(self) -> None:
        self.closed = True


def _runtime(
    *, product: RuntimeProductId = RuntimeProductId.DOCKER_CLI
) -> tuple[BoundCommandRuntimeEvidence, _RuntimeCandidate]:
    snapshot = _runtime_snapshot()
    candidate = _RuntimeCandidate(snapshot)
    owner = object.__new__(BoundCommandRuntimeEvidence)
    owner._active_owner = None  # noqa: SLF001
    owner._candidate = candidate  # type: ignore[assignment]  # noqa: SLF001
    owner._evidence = SimpleNamespace(  # type: ignore[assignment]  # noqa: SLF001
        product_id=product,
        exact_version=_VERSION,
        evidence_sha256="a" * 64,
        file_identity=snapshot.identity,
        file_sha256=snapshot.sha256,
        executable_path_sha256=command_module._path_sha256(  # noqa: SLF001
            PureWindowsPath(snapshot.final_path)
        ),
    )
    owner._lifetime_lock = threading.RLock()  # noqa: SLF001
    return owner, candidate


class _Backend:
    supported = True

    def __init__(
        self,
        responses: list[object],
        *,
        windows: str = _WINDOWS,
        system: str = _SYSTEM,
        profile: str = _PROFILE,
    ) -> None:
        self.responses = list(responses)
        self.windows = windows
        self.system = system
        self.profile = profile
        self.requests: list[DockerEndpointCommandRequest] = []
        self.on_execute: Any | None = None

    def windows_directory(self) -> str:
        return self.windows

    def system_directory(self) -> str:
        return self.system

    def user_profile_directory(self) -> str:
        return self.profile

    def execute(self, request: DockerEndpointCommandRequest) -> CommandProcessResult:
        self.requests.append(request)
        if self.on_execute is not None:
            self.on_execute(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, CommandProcessResult)
        return response


def _capture(
    responses: list[object] | None = None,
) -> tuple[
    BoundDockerEndpointEvidence,
    BoundCommandRuntimeEvidence,
    _RuntimeCandidate,
    _Backend,
]:
    runtime, candidate = _runtime()
    backend = _Backend(responses or [*_cycle(), *_cycle()])
    owner = capture_bound_docker_endpoint(runtime, backend=backend)
    return owner, runtime, candidate, backend


def test_capture_binds_explicit_named_pipe_with_minimal_environment() -> None:
    owner, runtime, candidate, backend = _capture()

    assert owner.endpoint.product is RuntimeProduct.DOCKER
    assert owner.endpoint.kind is EndpointKind.DOCKER_NAMED_PIPE
    assert owner.endpoint.canonical_endpoint == _ENDPOINT
    assert owner.endpoint.rootless is False
    assert owner.endpoint.identity_key is None
    assert owner.endpoint.discovery_artifacts == ()
    assert owner.evidence.runtime_evidence_sha256 == "a" * 64
    assert owner.evidence.binding_sha256 == owner.endpoint.private_metadata_sha256
    assert candidate.assert_count == 4
    assert runtime.closed is False

    assert [request.kind for request in backend.requests] == [
        DockerEndpointCommandKind.CONTEXT_INSPECT,
        DockerEndpointCommandKind.ENDPOINT_INFO,
    ] * 2
    for index, request in enumerate(backend.requests):
        assert request.executable_path == PureWindowsPath(_DOCKER_FINAL)
        assert request.environment == (
            ("SystemRoot", _WINDOWS),
            ("WINDIR", _WINDOWS),
        )
        assert request.working_directory == PureWindowsPath(_SYSTEM)
        assert request.arguments[:2] == ("--config", _CONFIGURATION)
        assert request.stdin_closed is True
        assert request.shell is False
        if index % 2:
            assert request.arguments == (
                "--config",
                _CONFIGURATION,
                "--host",
                _ENDPOINT,
                "info",
                "--format",
                "{{json .}}",
            )
        else:
            assert request.arguments == (
                "--config",
                _CONFIGURATION,
                "context",
                "inspect",
            )

    rendered = "\n".join(
        (repr(owner), repr(owner.evidence), *(repr(item) for item in backend.requests))
    )
    assert _ENDPOINT not in rendered
    assert _PROFILE not in rendered
    assert _CONTEXT_NAME not in rendered

    owner.close()
    owner.close()
    assert owner.closed
    assert runtime.closed is False


def test_context_labels_and_volatile_counts_are_not_security_identity() -> None:
    first = _cycle(
        context=_context(name="first-label"),
        info=_info(Containers=1, Images=2),
    )
    second = _cycle(
        context=_context(name="second-label"),
        info=_info(Containers=22, Images=33),
    )
    third = _cycle(
        context=_context(name="third-label"),
        info=_info(Containers=44, Images=55),
    )
    owner, runtime, _candidate, backend = _capture([*first, *second, *third])

    assert owner.assert_unchanged(runtime, backend) is owner.evidence
    owner.close()


@pytest.mark.parametrize(
    "context",
    (
        [],
        [*_context(), *_context(name="other")],
        _context(endpoint="tcp://127.0.0.1:2375"),
        _context(endpoint="ssh://user@127.0.0.1/run/docker.sock"),
        _context(endpoint="unix:///var/run/docker.sock"),
        _context(endpoint="npipe://./pipe/docker_engine"),
        _context(endpoint="npipe:////./pipe/../docker_engine"),
        _context(endpoint="npipe:////./pipe/docker%5Fengine"),
        _context(skip_tls=True),
        _context(tls_material={"docker": ["ca.pem"]}),
        _context(name="unsafe context"),
    ),
)
def test_capture_rejects_remote_ambiguous_or_tls_contexts(context: Any) -> None:
    runtime, _candidate = _runtime()
    backend = _Backend(_cycle(context=context))

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 1
    assert _ENDPOINT not in str(captured.value)


@pytest.mark.parametrize(
    "overrides",
    (
        {"ID": ""},
        {"ServerVersion": "28"},
        {"OperatingSystem": "Docker\nDesktop"},
        {"OSType": "windows"},
        {"Architecture": "arm64"},
        {"Name": ""},
        {"DockerRootDir": "var/lib/docker"},
        {"DockerRootDir": "/var//lib/docker"},
        {"DockerRootDir": "/var/lib/../docker"},
        {"Driver": ""},
    ),
)
def test_capture_rejects_unapproved_daemon_facts(overrides: dict[str, Any]) -> None:
    runtime, _candidate = _runtime()
    backend = _Backend(_cycle(info=_info(**overrides)))

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 2


def test_duplicate_json_members_fail_closed_without_raw_output() -> None:
    duplicate = (
        b'[{"Name":"desktop-linux","Name":"attacker",'
        b'"Endpoints":{"docker":{"Host":"npipe:////./pipe/docker_engine",'
        b'"SkipTLSVerify":false}},"TLSMaterial":{}}]'
    )
    runtime, _candidate = _runtime()
    backend = _Backend([_result(duplicate)])

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_INVALID
    assert "attacker" not in str(captured.value)


def _nested_json(depth: int) -> bytes:
    value = "null"
    for _index in range(depth):
        value = f"[{value}]"
    return value.encode("ascii")


@pytest.mark.parametrize(
    "output",
    (
        pytest.param(b"\xef\xbb\xbf[]", id="bom"),
        pytest.param(b"[NaN]", id="non-finite"),
        pytest.param(b'["\xff"]', id="invalid-utf8"),
        pytest.param(_nested_json(18), id="depth"),
        pytest.param(_json(list(range(257))), id="items"),
        pytest.param(
            _json([[0] * 256 for _index in range(33)]),
            id="nodes",
        ),
        pytest.param(_json(["x" * 32_768]), id="string-size"),
    ),
)
def test_capture_enforces_json_encoding_and_structure_bounds(output: bytes) -> None:
    runtime, _candidate = _runtime()
    backend = _Backend([_result(output)])

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 1


@pytest.mark.parametrize(
    "field",
    ("OperatingSystem", "Name", "DockerRootDir", "Driver"),
)
def test_capture_rejects_non_utf8_daemon_text_with_sanitized_error(
    field: str,
) -> None:
    private_value = "private-\ud800-value"
    runtime, _candidate = _runtime()
    backend = _Backend(_cycle(info=_info(**{field: private_value})))

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_INVALID
    assert private_value not in str(captured.value)


def test_revalidation_maps_non_utf8_daemon_text_to_endpoint_change() -> None:
    private_value = "private-\ud800-value"
    owner, runtime, _candidate, backend = _capture(
        [
            *_cycle(),
            *_cycle(),
            *_cycle(info=_info(OperatingSystem=private_value)),
        ]
    )

    with pytest.raises(DockerEndpointError) as captured:
        owner.assert_unchanged(runtime, backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_CHANGED
    assert private_value not in str(captured.value)
    assert owner.closed is False
    owner.close()


@pytest.mark.parametrize(
    "result",
    (
        _result(_context(), exit_code=1),
        _result(_context(), stderr=b"warning"),
        _uncontained_result(),
    ),
)
def test_capture_requires_clean_contained_command_result(result: object) -> None:
    runtime, _candidate = _runtime()
    backend = _Backend([result])

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_INVALID


def test_endpoint_repoint_between_observations_fails_closed() -> None:
    responses = [
        *_cycle(),
        *_cycle(context=_context(endpoint=_OTHER_ENDPOINT)),
    ]
    runtime, _candidate = _runtime()
    backend = _Backend(responses)

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_CHANGED


def test_daemon_identity_change_between_observations_fails_closed() -> None:
    responses = [*_cycle(), *_cycle(info=_info(ID="changed-daemon-id"))]
    runtime, _candidate = _runtime()
    backend = _Backend(responses)

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_CHANGED


def test_revalidation_detects_context_repoint_and_owner_remains_closeable() -> None:
    owner, runtime, _candidate, backend = _capture(
        [
            *_cycle(),
            *_cycle(),
            *_cycle(context=_context(endpoint=_OTHER_ENDPOINT)),
        ]
    )

    with pytest.raises(DockerEndpointError) as captured:
        owner.assert_unchanged(runtime, backend)

    assert captured.value.code is DockerEndpointErrorCode.ENDPOINT_CHANGED
    assert owner.closed is False
    owner.close()


def test_capture_and_revalidation_reject_wrong_or_closed_runtime() -> None:
    wrong, _candidate = _runtime(product=RuntimeProductId.PODMAN_CLI)
    backend = _Backend([*_cycle(), *_cycle()])
    with pytest.raises(DockerEndpointError) as wrong_error:
        capture_bound_docker_endpoint(wrong, backend=backend)
    assert wrong_error.value.code is DockerEndpointErrorCode.RUNTIME_INVALID
    assert not backend.requests

    owner, runtime, _candidate, backend = _capture([*_cycle(), *_cycle()])
    runtime.close()
    with pytest.raises(DockerEndpointError) as closed_error:
        owner.assert_unchanged(runtime, backend)
    assert closed_error.value.code is DockerEndpointErrorCode.RUNTIME_INVALID
    assert len(backend.requests) == 4
    owner.close()


@pytest.mark.parametrize(
    ("attribute", "value"),
    (
        ("supported", False),
        ("windows", r"C:\NotWindows"),
        ("system", r"C:\Windows\SysWOW64"),
        ("profile", r"relative\profile"),
        ("profile", r"C:\Users\CON"),
    ),
)
def test_capture_rejects_unavailable_or_invalid_native_directories(
    attribute: str, value: object
) -> None:
    runtime, _candidate = _runtime()
    backend = _Backend([*_cycle(), *_cycle()])
    setattr(backend, attribute, value)

    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)

    assert captured.value.code is DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE
    assert not backend.requests
    assert _PROFILE not in str(captured.value)


def test_backend_exception_is_sanitized_but_interruption_is_preserved() -> None:
    runtime, _candidate = _runtime()
    backend = _Backend([OSError(_PROFILE)])
    with pytest.raises(DockerEndpointError) as captured:
        capture_bound_docker_endpoint(runtime, backend=backend)
    assert captured.value.code is DockerEndpointErrorCode.VERIFICATION_UNAVAILABLE
    assert _PROFILE not in str(captured.value)

    runtime, _candidate = _runtime()
    backend = _Backend([KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        capture_bound_docker_endpoint(runtime, backend=backend)


def test_close_waits_for_active_revalidation() -> None:
    owner, runtime, _candidate, backend = _capture([*_cycle(), *_cycle(), *_cycle()])
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()

    def block(_request: DockerEndpointCommandRequest) -> None:
        if len(backend.requests) == 5:
            entered.set()
            assert release.wait(timeout=5)

    backend.on_execute = block
    worker = threading.Thread(target=lambda: owner.assert_unchanged(runtime, backend))
    closer = threading.Thread(target=lambda: (owner.close(), closed.set()))
    worker.start()
    assert entered.wait(timeout=5)
    closer.start()
    assert not closed.wait(timeout=0.1)
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    assert not worker.is_alive()
    assert not closer.is_alive()
    assert closed.is_set()


def test_runtime_close_waits_for_active_endpoint_query() -> None:
    owner, runtime, candidate, backend = _capture([*_cycle(), *_cycle(), *_cycle()])
    entered = threading.Event()
    release = threading.Event()
    runtime_closed = threading.Event()

    def block(_request: DockerEndpointCommandRequest) -> None:
        if len(backend.requests) == 5:
            entered.set()
            assert release.wait(timeout=5)

    backend.on_execute = block
    worker = threading.Thread(target=lambda: owner.assert_unchanged(runtime, backend))
    closer = threading.Thread(target=lambda: (runtime.close(), runtime_closed.set()))
    worker.start()
    assert entered.wait(timeout=5)
    closer.start()
    assert not runtime_closed.wait(timeout=0.1)
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    assert runtime_closed.is_set()
    assert candidate.closed
    owner.close()


def test_command_request_is_frozen_fixed_and_redacted() -> None:
    request = DockerEndpointCommandRequest(
        kind=DockerEndpointCommandKind.ENDPOINT_INFO,
        executable_path=PureWindowsPath(_DOCKER_FINAL),
        arguments=(
            "--config",
            _CONFIGURATION,
            "--host",
            _ENDPOINT,
            "info",
            "--format",
            "{{json .}}",
        ),
        environment=(("SystemRoot", _WINDOWS), ("WINDIR", _WINDOWS)),
        working_directory=PureWindowsPath(_SYSTEM),
    )

    assert dataclasses.is_dataclass(request)
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.kind = DockerEndpointCommandKind.CONTEXT_INSPECT  # type: ignore[misc]
    assert _ENDPOINT not in repr(request)
    assert _PROFILE not in repr(request)
    with pytest.raises(ValueError):
        replace(request, arguments=("info", "--format", "{{json .}}"))
    with pytest.raises(ValueError):
        replace(
            request,
            environment=(
                ("DOCKER_HOST", "tcp://attacker:2375"),
                ("SystemRoot", _WINDOWS),
            ),
        )
    with pytest.raises(ValueError):
        replace(request, shell=True)


def test_native_backend_accepts_only_docker_endpoint_request_type() -> None:
    request = DockerEndpointCommandRequest(
        kind=DockerEndpointCommandKind.CONTEXT_INSPECT,
        executable_path=PureWindowsPath(_DOCKER_FINAL),
        arguments=("--config", _CONFIGURATION, "context", "inspect"),
        environment=(("SystemRoot", _WINDOWS), ("WINDIR", _WINDOWS)),
        working_directory=PureWindowsPath(_SYSTEM),
    )
    expected = _result(_context())

    class _Contained:
        supported = True

        def __init__(self) -> None:
            self.requests: list[DockerEndpointCommandRequest] = []

        def windows_directory(self) -> str:
            return _WINDOWS

        def system_directory(self) -> str:
            return _SYSTEM

        def user_profile_directory(self) -> str:
            return _PROFILE

        def _execute_contained(
            self, selected: DockerEndpointCommandRequest
        ) -> CommandProcessResult:
            self.requests.append(selected)
            return expected

    contained = _Contained()
    backend = object.__new__(native_module.NativeWindowsDockerEndpointCommandBackend)
    backend._contained = contained  # type: ignore[assignment]  # noqa: SLF001

    assert backend.user_profile_directory() == _PROFILE
    assert backend.execute(request) is expected
    assert contained.requests == [request]
    assert _PROFILE not in repr(backend)
    with pytest.raises(CommandExecutionError):
        backend.execute(object())  # type: ignore[arg-type]


def test_native_profile_directory_uses_current_process_token_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = SimpleNamespace(last_error=0)

    class _Kernel:
        def __init__(self) -> None:
            self.closed: list[int] = []

        def GetCurrentProcess(self) -> int:
            return -1

        def CloseHandle(self, handle: object) -> bool:
            self.closed.append(int(getattr(handle, "value")))
            return True

    class _Advapi:
        def OpenProcessToken(
            self, process: object, access: int, token_pointer: object
        ) -> bool:
            assert process == -1
            assert access == native_module._TOKEN_QUERY
            ctypes.cast(
                token_pointer, ctypes.POINTER(native_module._HANDLE)
            ).contents.value = 901
            return True

    class _Userenv:
        def GetUserProfileDirectoryW(
            self, token: object, buffer: object, size_pointer: object
        ) -> bool:
            assert int(getattr(token, "value")) == 901
            size = ctypes.cast(
                size_pointer, ctypes.POINTER(native_module._DWORD)
            ).contents
            if buffer is None:
                size.value = len(_PROFILE) + 1
                state.last_error = native_module._ERROR_INSUFFICIENT_BUFFER
                return False
            buffer.value = _PROFILE
            size.value = len(_PROFILE) + 1
            return True

    monkeypatch.setattr(
        native_module.ctypes,
        "set_last_error",
        lambda value: setattr(state, "last_error", value),
        raising=False,
    )
    monkeypatch.setattr(
        native_module.ctypes,
        "get_last_error",
        lambda: state.last_error,
        raising=False,
    )
    kernel = _Kernel()
    api = object.__new__(native_module._NativeWindowsProcessApi)
    api._kernel32 = kernel
    api._advapi32 = _Advapi()
    api._userenv = _Userenv()

    assert api.user_profile_directory() == _PROFILE
    assert kernel.closed == [901]


def test_default_backend_is_lazy_and_resolver_remains_unwired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _candidate = _runtime()
    backend = _Backend([*_cycle(), *_cycle()])
    monkeypatch.setattr(
        native_module,
        "NativeWindowsDockerEndpointCommandBackend",
        lambda: backend,
    )

    owner = capture_bound_docker_endpoint(runtime)
    assert len(backend.requests) == 4
    owner.close()

    forbidden = (
        LAUNCHER_ROOT / "towerscout_launcher" / "app.py",
        LAUNCHER_ROOT / "towerscout_launcher" / "discovery.py",
        LAUNCHER_ROOT / "towerscout_launcher" / "repair.py",
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_execution.py",
    )
    for path in forbidden:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert not any("runtime_docker_endpoint" in item for item in imports)

    source = Path(endpoint_module.__file__).read_text(encoding="utf-8")
    assert "os.environ" not in source
    assert "subprocess.run" not in source
    assert "subprocess.Popen" not in source
