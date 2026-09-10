from __future__ import annotations

import ast
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

import towerscout_launcher.runtime_command_version as command_module  # noqa: E402
import towerscout_launcher.runtime_command_native as native_module  # noqa: E402
import towerscout_launcher.runtime_podman_endpoint as endpoint_module  # noqa: E402
from towerscout_launcher.runtime_command_version import (  # noqa: E402
    BoundCommandRuntimeEvidence,
    CommandExecutionError,
    CommandProcessResult,
)
from towerscout_launcher.runtime_podman_endpoint import (  # noqa: E402
    BoundPodmanEndpointEvidence,
    PodmanEndpointCommandKind,
    PodmanEndpointCommandRequest,
    PodmanEndpointError,
    PodmanEndpointErrorCode,
    capture_bound_podman_endpoint,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.target_contracts import (  # noqa: E402
    EndpointKind,
    RuntimeProduct,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    KNOWN_CLOUD_REPARSE_TAGS,
    FileSnapshot,
    NativeFileFacts,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
)

_MACHINE = "podman-machine-default"
_USERNAME = "core"
_PORT = 52123
_UID = 1000
_KEY_PATH = r"C:\Users\reviewed-user\AppData\Local\containers\podman\machine\machine"
_KEY_FINAL = (
    r"\\?\C:\Users\reviewed-user\AppData\Local\containers\podman\machine\machine"
)
_PODMAN_FINAL = r"\\?\C:\Users\reviewed-user\AppData\Local\Programs\Podman\podman.exe"
_ENDPOINT = (
    f"ssh://{_USERNAME}@127.0.0.1:{_PORT}" f"/run/user/{_UID}/podman/podman.sock"
)
_WINDOWS = r"C:\Windows"
_SYSTEM = r"C:\Windows\System32"
_VERSION = "6.0.2"


def _json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _result(value: Any) -> CommandProcessResult:
    return CommandProcessResult(
        stdout=_json(value),
        stderr=b"",
        exit_code=0,
        stdin_closed=True,
        stdout_streamed=True,
        stderr_streamed=True,
        process_tree_contained=True,
        process_tree_empty=True,
    )


def _machine(
    *,
    name: str = _MACHINE,
    vm_type: str | None = "wsl",
    rootful: bool = False,
    state: str = "running",
    username: str = _USERNAME,
    port: int = _PORT,
    identity: str = _KEY_PATH,
) -> list[dict[str, Any]]:
    machine: dict[str, Any] = {
        "Name": name,
        "State": state,
        "Rootful": rootful,
        "UserModeNetworking": True,
        "SSHConfig": {
            "IdentityPath": identity,
            "Port": port,
            "RemoteUsername": username,
        },
    }
    if vm_type is not None:
        machine["VMType"] = vm_type
    return [machine]


def _connections(
    *,
    endpoint: str = _ENDPOINT,
    identity: str = _KEY_PATH,
    name: str = _MACHINE,
    duplicate: bool = False,
    user_only: bool = False,
) -> list[dict[str, Any]]:
    user = {
        "Name": name,
        "URI": endpoint,
        "Identity": identity,
        "IsMachine": True,
        "Default": True,
        "ReadWrite": True,
    }
    output = [user]
    if duplicate:
        output.append({**user, "Name": f"{name}-duplicate", "Default": False})
    if not user_only:
        output.append(
            {
                "Name": f"{name}-root",
                "URI": f"ssh://root@127.0.0.1:{_PORT}/run/podman/podman.sock",
                "Identity": identity,
                "IsMachine": True,
                "Default": False,
                "ReadWrite": True,
            }
        )
    return output


def _info(
    *,
    rootless: bool = True,
    socket: str = f"/run/user/{_UID}/podman/podman.sock",
    graph_root: str = f"/home/{_USERNAME}/.local/share/containers/storage",
    run_root: str = f"/run/user/{_UID}/containers",
    version: str = _VERSION,
) -> dict[str, Any]:
    return {
        "host": {
            "hostname": "podman-machine-default",
            "remoteSocket": {"path": socket},
            "security": {"rootless": rootless},
            "serviceIsRemote": False,
        },
        "store": {"graphRoot": graph_root, "runRoot": run_root},
        "version": {"Version": version},
    }


def _cycle(
    *,
    machine: Any | None = None,
    connections: Any | None = None,
    info: Any | None = None,
) -> list[CommandProcessResult]:
    return [
        _result(_machine() if machine is None else machine),
        _result(_connections() if connections is None else connections),
        _result(_info() if info is None else info),
    ]


def _runtime_snapshot() -> FileSnapshot:
    content = b"authenticated-podman-runtime"
    return FileSnapshot(
        identity=StableFileIdentity(0x1020304050607080, bytes.fromhex("11" * 16)),
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        attributes=0x80,
        creation_time=10,
        last_write_time=20,
        reparse_tag=0,
        final_path=_PODMAN_FINAL,
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


def _runtime() -> tuple[BoundCommandRuntimeEvidence, _RuntimeCandidate]:
    snapshot = _runtime_snapshot()
    candidate = _RuntimeCandidate(snapshot)
    owner = object.__new__(BoundCommandRuntimeEvidence)
    owner._active_owner = None  # noqa: SLF001
    owner._candidate = candidate  # type: ignore[assignment]  # noqa: SLF001
    owner._evidence = SimpleNamespace(  # type: ignore[assignment]  # noqa: SLF001
        product_id=RuntimeProductId.PODMAN_CLI,
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


class _FileApi:
    supported = True

    def __init__(self, *, final_path: str = _KEY_FINAL) -> None:
        self.content = b"private-key-material"
        self.facts = NativeFileFacts(
            final_path=final_path,
            volume_serial=0x8877665544332211,
            file_id=bytes.fromhex("22" * 16),
            attributes=0x80,
            link_count=1,
            size=len(self.content),
            creation_time=30,
            last_write_time=40,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )
        self.handle = object()
        self.cursor = 0
        self.opened: list[str] = []
        self.close_count = 0

    def open_file_for_identity(self, path: str) -> object:
        self.opened.append(path)
        return self.handle

    def open_file_for_hydrated_identity(self, path: str) -> object:
        return self.open_file_for_identity(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert handle is self.handle
        return replace(self.facts, size=len(self.content))

    def rewind_file(self, handle: object) -> None:
        assert handle is self.handle
        self.cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert handle is self.handle
        chunk = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert handle is self.handle
        self.close_count += 1


class _Backend:
    supported = True

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[PodmanEndpointCommandRequest] = []
        self.on_execute: Any | None = None

    def windows_directory(self) -> str:
        return _WINDOWS

    def system_directory(self) -> str:
        return _SYSTEM

    def execute(self, request: PodmanEndpointCommandRequest) -> CommandProcessResult:
        self.requests.append(request)
        if self.on_execute is not None:
            self.on_execute(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, CommandProcessResult)
        return response


def _capture(
    *,
    responses: list[object] | None = None,
    api: _FileApi | None = None,
) -> tuple[
    BoundPodmanEndpointEvidence,
    BoundCommandRuntimeEvidence,
    _RuntimeCandidate,
    _FileApi,
    _Backend,
]:
    runtime, candidate = _runtime()
    selected_api = api or _FileApi()
    backend = _Backend(responses or [*_cycle(), *_cycle()])
    owner = capture_bound_podman_endpoint(
        runtime,
        _MACHINE,
        backend=backend,
        file_api=selected_api,  # type: ignore[arg-type]
    )
    return owner, runtime, candidate, selected_api, backend


def test_capture_binds_fixed_explicit_rootless_endpoint_and_retains_key() -> None:
    owner, runtime, candidate, api, backend = _capture()

    assert owner.endpoint.product is RuntimeProduct.PODMAN
    assert owner.endpoint.kind is EndpointKind.PODMAN_ROOTLESS_WSL
    assert owner.endpoint.rootless is True
    assert owner.endpoint.canonical_endpoint == _ENDPOINT
    assert owner.endpoint.identity_key is not None
    assert owner.endpoint.identity_key.final_path == PureWindowsPath(_KEY_FINAL)
    assert owner.endpoint.discovery_artifacts == ()
    assert owner.evidence.binding_sha256 == owner.endpoint.private_metadata_sha256
    assert owner.evidence.runtime_evidence_sha256 == "a" * 64
    assert api.opened == [_KEY_PATH]
    assert api.close_count == 0
    assert candidate.closed is False
    assert candidate.assert_count == 4

    assert [request.kind for request in backend.requests] == [
        PodmanEndpointCommandKind.MACHINE_INSPECT,
        PodmanEndpointCommandKind.CONNECTION_LIST,
        PodmanEndpointCommandKind.ENDPOINT_INFO,
    ] * 2
    info_request = backend.requests[2]
    assert info_request.arguments == (
        "--url",
        _ENDPOINT,
        "--identity",
        _KEY_PATH,
        "info",
        "--format",
        "json",
    )
    for request in backend.requests:
        assert request.executable_path == PureWindowsPath(_PODMAN_FINAL)
        assert request.environment == (("SystemRoot", _WINDOWS), ("WINDIR", _WINDOWS))
        assert request.working_directory == PureWindowsPath(_SYSTEM)
        assert request.stdin_closed is True
        assert request.shell is False

    rendered = "\n".join((repr(owner), repr(owner.evidence), repr(info_request)))
    assert _ENDPOINT not in rendered
    assert _KEY_PATH not in rendered
    assert _KEY_FINAL not in rendered
    assert _MACHINE not in rendered

    owner.close()
    assert owner.closed
    assert api.close_count == 1
    assert runtime.closed is False


def test_connection_name_and_default_are_metadata_only() -> None:
    first = _cycle(connections=_connections(name="first-label"))
    second = _cycle(
        connections=[
            {
                **_connections(name="second-label", user_only=True)[0],
                "Default": False,
            },
            *_connections(user_only=False)[1:],
        ]
    )
    third = _cycle(connections=_connections(name="third-label"))
    owner, runtime, _candidate, api, backend = _capture(
        responses=[*first, *second, *third]
    )

    assert owner.assert_unchanged(runtime, backend) is owner.evidence
    assert api.close_count == 0
    owner.close()


@pytest.mark.parametrize(
    ("responses", "expected_requests"),
    (
        (_cycle(machine=_machine(rootful=True)), 1),
        (_cycle(machine=_machine(state="stopped")), 1),
        (_cycle(machine=_machine(vm_type=None)), 1),
        (_cycle(machine=_machine(vm_type="hyperv")), 1),
        (
            _cycle(
                connections=_connections(
                    endpoint=(
                        f"ssh://{_USERNAME}@192.0.2.10:{_PORT}"
                        f"/run/user/{_UID}/podman/podman.sock"
                    )
                )
            ),
            2,
        ),
        (_cycle(connections=_connections(duplicate=True)), 2),
        (
            _cycle(
                connections=_connections(
                    endpoint=(
                        f"ssh://{_USERNAME}@127.0.0.1:{_PORT}"
                        "/run/user/4294967295/podman/podman.sock"
                    )
                )
            ),
            2,
        ),
        (
            _cycle(
                connections=[
                    {
                        **_connections(user_only=True)[0],
                        "URI": (f"ssh://root@127.0.0.1:{_PORT}/run/podman/podman.sock"),
                    }
                ]
            ),
            2,
        ),
        (_cycle(info=_info(rootless=False)), 3),
        (_cycle(info=_info(socket="/run/podman/podman.sock")), 3),
        (_cycle(info=_info(graph_root="/var/lib/containers/storage")), 3),
        (_cycle(info=_info(run_root="/run/containers/storage")), 3),
        (_cycle(info=_info(version="6.0.1")), 3),
    ),
)
def test_capture_rejects_unsafe_or_ambiguous_endpoint_facts(
    responses: list[CommandProcessResult], expected_requests: int
) -> None:
    runtime, _candidate = _runtime()
    api = _FileApi()
    backend = _Backend(list(responses))

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == expected_requests
    assert api.opened == []
    assert api.close_count == 0
    assert _ENDPOINT not in str(captured.value)
    assert _KEY_PATH not in repr(captured.value)


def test_endpoint_change_between_observations_closes_captured_key() -> None:
    changed_endpoint = (
        f"ssh://{_USERNAME}@127.0.0.1:{_PORT + 1}"
        f"/run/user/{_UID}/podman/podman.sock"
    )
    responses = [
        *_cycle(),
        *_cycle(
            machine=_machine(port=_PORT + 1),
            connections=_connections(endpoint=changed_endpoint),
        ),
    ]
    runtime, _candidate = _runtime()
    api = _FileApi()
    backend = _Backend(responses)

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_CHANGED
    assert api.close_count == 1


def test_machine_provider_change_between_observations_closes_captured_key() -> None:
    responses = [
        *_cycle(),
        *_cycle(machine=_machine(vm_type="hyperv")),
    ]
    runtime, _candidate = _runtime()
    api = _FileApi()
    backend = _Backend(responses)

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 4
    assert api.close_count == 1


def test_identity_key_final_path_must_match_discovered_key() -> None:
    api = _FileApi(final_path=r"\\?\C:\Users\reviewed-user\wrong-key")
    runtime, _candidate = _runtime()
    backend = _Backend([*_cycle(), *_cycle()])

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 3
    assert api.close_count == 1


@pytest.mark.parametrize(
    "identity_path",
    (
        f"{_KEY_PATH}:alternate-stream",
        r"C:\Users\reviewed-user\AppData\Local\CON",
        r"C:\Users\reviewed-user\\AppData\Local\containers\key",
    ),
)
def test_identity_key_rejects_unsafe_discovered_path(identity_path: str) -> None:
    runtime, _candidate = _runtime()
    api = _FileApi()
    backend = _Backend(_cycle(machine=_machine(identity=identity_path)))

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 1
    assert api.opened == []


def test_identity_key_rejects_cloud_placeholder_leaf() -> None:
    api = _FileApi()
    api.facts = replace(
        api.facts,
        attributes=api.facts.attributes | 0x00000400,
        reparse_tag=next(iter(KNOWN_CLOUD_REPARSE_TAGS)),
    )
    runtime, _candidate = _runtime()
    backend = _Backend([*_cycle(), *_cycle()])

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_INVALID
    assert len(backend.requests) == 3
    assert api.close_count == 1


def test_interruption_during_second_observation_closes_captured_key() -> None:
    runtime, _candidate = _runtime()
    api = _FileApi()
    backend = _Backend([*_cycle(), KeyboardInterrupt()])

    with pytest.raises(KeyboardInterrupt):
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert len(backend.requests) == 4
    assert api.close_count == 1


def test_interruption_after_owner_assembly_closes_transferred_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _candidate = _runtime()
    api = _FileApi()
    backend = _Backend([*_cycle(), *_cycle()])
    original = BoundPodmanEndpointEvidence
    accepted: list[BoundPodmanEndpointEvidence] = []

    def interrupt_after_acceptance(**kwargs: Any) -> BoundPodmanEndpointEvidence:
        accepted.append(original(**kwargs))
        raise KeyboardInterrupt

    monkeypatch.setattr(
        endpoint_module,
        "BoundPodmanEndpointEvidence",
        interrupt_after_acceptance,
    )

    with pytest.raises(KeyboardInterrupt):
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert len(accepted) == 1
    assert accepted[0].closed
    assert api.close_count == 1


def test_revalidation_detects_endpoint_repointing_and_keeps_owner_closeable() -> None:
    owner, runtime, _candidate, api, backend = _capture(
        responses=[
            *_cycle(),
            *_cycle(),
            *_cycle(info=_info(rootless=False)),
        ]
    )

    with pytest.raises(PodmanEndpointError) as captured:
        owner.assert_unchanged(runtime, backend)

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_CHANGED
    assert owner.closed is False
    owner.close()
    assert api.close_count == 1


def test_revalidation_detects_identity_key_content_change() -> None:
    owner, runtime, _candidate, api, backend = _capture(
        responses=[*_cycle(), *_cycle(), *_cycle()]
    )
    api.content = b"replaced-private-key-material"

    with pytest.raises(PodmanEndpointError) as captured:
        owner.assert_unchanged(runtime, backend)

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_CHANGED
    assert len(backend.requests) == 6
    owner.close()
    assert api.close_count == 1


def test_close_waits_for_active_endpoint_revalidation() -> None:
    owner, runtime, _candidate, api, backend = _capture(
        responses=[*_cycle(), *_cycle(), *_cycle()]
    )
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()

    def block(request: PodmanEndpointCommandRequest) -> None:
        if len(backend.requests) == 7:
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
    assert api.close_count == 1


def test_runtime_lease_blocks_close_during_endpoint_query() -> None:
    owner, runtime, candidate, _api, backend = _capture(
        responses=[*_cycle(), *_cycle(), *_cycle()]
    )
    entered = threading.Event()
    release = threading.Event()
    runtime_closed = threading.Event()

    def block(_request: PodmanEndpointCommandRequest) -> None:
        if len(backend.requests) == 7:
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
    request = PodmanEndpointCommandRequest(
        kind=PodmanEndpointCommandKind.ENDPOINT_INFO,
        executable_path=PureWindowsPath(_PODMAN_FINAL),
        arguments=(
            "--url",
            _ENDPOINT,
            "--identity",
            _KEY_PATH,
            "info",
            "--format",
            "json",
        ),
        environment=(("SystemRoot", _WINDOWS), ("WINDIR", _WINDOWS)),
        working_directory=PureWindowsPath(_SYSTEM),
    )

    assert dataclasses.is_dataclass(request)
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.kind = PodmanEndpointCommandKind.CONNECTION_LIST  # type: ignore[misc]
    assert _ENDPOINT not in repr(request)
    assert _KEY_PATH not in repr(request)
    with pytest.raises(ValueError):
        replace(request, arguments=("info", "--format", "json"))
    with pytest.raises(ValueError):
        replace(
            request,
            environment=(
                ("SystemRoot", _WINDOWS, "unexpected"),
                ("WINDIR", _WINDOWS, "unexpected"),
            ),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        replace(request, shell=True)


def test_native_endpoint_backend_accepts_only_endpoint_request_type() -> None:
    request = PodmanEndpointCommandRequest(
        kind=PodmanEndpointCommandKind.CONNECTION_LIST,
        executable_path=PureWindowsPath(_PODMAN_FINAL),
        arguments=("system", "connection", "list", "--format", "json"),
        environment=(("SystemRoot", _WINDOWS), ("WINDIR", _WINDOWS)),
        working_directory=PureWindowsPath(_SYSTEM),
    )
    expected = _result(_connections())

    class _Contained:
        supported = True

        def __init__(self) -> None:
            self.requests: list[PodmanEndpointCommandRequest] = []

        def windows_directory(self) -> str:
            return _WINDOWS

        def system_directory(self) -> str:
            return _SYSTEM

        def _execute_contained(
            self, selected: PodmanEndpointCommandRequest
        ) -> CommandProcessResult:
            self.requests.append(selected)
            return expected

    contained = _Contained()
    backend = object.__new__(native_module.NativeWindowsPodmanEndpointCommandBackend)
    backend._contained = contained  # type: ignore[assignment]  # noqa: SLF001

    assert backend.execute(request) is expected
    assert contained.requests == [request]
    assert _ENDPOINT not in repr(backend)
    with pytest.raises(CommandExecutionError):
        backend.execute(object())  # type: ignore[arg-type]


def test_duplicate_json_members_fail_closed_without_raw_output() -> None:
    runtime, _candidate = _runtime()
    api = _FileApi()
    duplicate = CommandProcessResult(
        stdout=(
            b'[{"Name":"podman-machine-default",'
            b'"Name":"other","State":"running","Rootful":false,'
            b'"SSHConfig":{"IdentityPath":"C:\\\\key",'
            b'"Port":52123,"RemoteUsername":"core"}}]'
        ),
        stderr=b"",
        exit_code=0,
        stdin_closed=True,
        stdout_streamed=True,
        stderr_streamed=True,
        process_tree_contained=True,
        process_tree_empty=True,
    )
    backend = _Backend([duplicate])

    with pytest.raises(PodmanEndpointError) as captured:
        capture_bound_podman_endpoint(
            runtime,
            _MACHINE,
            backend=backend,
            file_api=api,  # type: ignore[arg-type]
        )

    assert captured.value.code is PodmanEndpointErrorCode.ENDPOINT_INVALID
    assert "other" not in str(captured.value)


def test_podman_endpoint_resolver_remains_unwired_from_live_launcher_paths() -> None:
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
        assert not any("runtime_podman_endpoint" in item for item in imports)

    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_podman_endpoint.py"
    ).read_text(encoding="utf-8")
    assert "subprocess.run" not in source
    assert "subprocess.Popen" not in source
    assert "os.environ" not in source
