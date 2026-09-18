from __future__ import annotations

import hashlib
import sys
import threading
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_command_version as command_module  # noqa: E402
import towerscout_launcher.runtime_docker_inputs as inputs_module  # noqa: E402
from towerscout_launcher.runtime_command_version import (  # noqa: E402
    BoundCommandRuntimeEvidence,
    RuntimeCommandVerificationError,
    RuntimeCommandVerificationErrorCode,
)
from towerscout_launcher.runtime_docker_endpoint import (  # noqa: E402
    BoundDockerRuntimeEndpointInputs,
    DockerRuntimeEndpointInputs,
)
from towerscout_launcher.runtime_docker_inputs import (  # noqa: E402
    BoundDockerTargetSourceInputs,
    DockerInputError,
    DockerInputErrorCode,
    DockerTargetSourceInputs,
    capture_native_windows_docker_target_source_inputs,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.target_contracts import (  # noqa: E402
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    RuntimeIdentity,
    RuntimeProduct,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    FileSnapshot,
    PathClassification,
    PathLocality,
    ReparseKind,
    StableFileIdentity,
)

_POLICY_SHA256 = "b" * 64
_DOCKER_PATH = PureWindowsPath(
    r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker.exe"
)
_COMPOSE_PATH = PureWindowsPath(
    r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker-compose.exe"
)
_PRIVATE_PATH = r"C:\Users\PRIVATE\Docker"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _snapshot(path: PureWindowsPath, marker: int) -> FileSnapshot:
    return FileSnapshot(
        identity=StableFileIdentity(marker, marker.to_bytes(16, "big")),
        final_path=str(path),
        size=10_000 + marker,
        sha256=_digest(f"file-{marker}"),
        attributes=0,
        creation_time=100,
        last_write_time=200,
        reparse_tag=0,
        classification=PathClassification(
            locality=PathLocality.FIXED_LOCAL,
            reparse_kind=ReparseKind.NONE,
            hydrated=False,
            regular_file=True,
            single_link=True,
        ),
    )


class _Candidate:
    def __init__(self, snapshot: FileSnapshot) -> None:
        self.snapshot = snapshot
        self.closed = False

    def assert_unchanged(self) -> FileSnapshot:
        if self.closed:
            raise RuntimeError("closed")
        return self.snapshot

    def close(self) -> None:
        self.closed = True


def _compose_owner() -> tuple[BoundCommandRuntimeEvidence, _Candidate]:
    snapshot = _snapshot(_COMPOSE_PATH, 2)
    candidate = _Candidate(snapshot)
    owner = object.__new__(BoundCommandRuntimeEvidence)
    owner._active_owner = None  # noqa: SLF001
    owner._candidate = candidate  # type: ignore[assignment]  # noqa: SLF001
    owner._evidence = SimpleNamespace(  # type: ignore[assignment]  # noqa: SLF001
        product_id=RuntimeProductId.DOCKER_COMPOSE,
        exact_version="5.3.1",
        policy_sha256=_POLICY_SHA256,
        evidence_sha256=_digest("compose-evidence"),
        file_identity=snapshot.identity,
        file_sha256=snapshot.sha256,
        executable_path_sha256=command_module._path_sha256(  # noqa: SLF001
            _COMPOSE_PATH
        ),
    )
    owner._lifetime_lock = threading.RLock()  # noqa: SLF001
    return owner, candidate


def _runtime_endpoint_inputs(
    *,
    policy_sha256: str = _POLICY_SHA256,
    docker_path: PureWindowsPath = _DOCKER_PATH,
) -> DockerRuntimeEndpointInputs:
    snapshot = _snapshot(docker_path, 1)
    return DockerRuntimeEndpointInputs(
        runtime=RuntimeIdentity(
            product=RuntimeProduct.DOCKER,
            executable=FileIdentity(
                logical_name="docker.exe",
                final_path=docker_path,
                volume_serial=snapshot.identity.volume_serial,
                file_id=snapshot.identity.file_id,
                sha256=snapshot.sha256,
                size_bytes=snapshot.size,
            ),
            version="29.7.2",
            publisher_policy_sha256=policy_sha256,
        ),
        endpoint=EndpointIdentity(
            product=RuntimeProduct.DOCKER,
            kind=EndpointKind.DOCKER_NAMED_PIPE,
            canonical_endpoint="npipe:////./pipe/dockerDesktopLinuxEngine",
            private_metadata_sha256=_digest("endpoint"),
        ),
    )


def _pair(
    monkeypatch: pytest.MonkeyPatch,
    captures: list[DockerRuntimeEndpointInputs] | None = None,
) -> tuple[BoundDockerRuntimeEndpointInputs, dict[int, bool]]:
    pair = object.__new__(BoundDockerRuntimeEndpointInputs)
    state = {id(pair): False}
    values = captures or [_runtime_endpoint_inputs()]

    monkeypatch.setattr(
        BoundDockerRuntimeEndpointInputs,
        "closed",
        property(lambda self: state[id(self)]),
    )
    monkeypatch.setattr(
        BoundDockerRuntimeEndpointInputs,
        "supported",
        property(lambda self: not state[id(self)]),
    )
    monkeypatch.setattr(
        BoundDockerRuntimeEndpointInputs,
        "capture",
        lambda self: values.pop(0) if len(values) > 1 else values[0],
    )
    monkeypatch.setattr(
        BoundDockerRuntimeEndpointInputs,
        "close",
        lambda self: state.__setitem__(id(self), True),
    )
    return pair, state


def test_native_factory_binds_fixed_compose_product_and_retains_all_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, state = _pair(monkeypatch)
    compose, candidate = _compose_owner()
    opened: list[RuntimeProductId] = []

    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_docker_runtime_endpoint_inputs",
        lambda: pair,
    )

    def open_compose(product: RuntimeProductId) -> BoundCommandRuntimeEvidence:
        opened.append(product)
        return compose

    monkeypatch.setattr(
        inputs_module,
        "open_package_bound_command_runtime_evidence",
        open_compose,
    )

    owner = capture_native_windows_docker_target_source_inputs()
    inputs = owner.capture()

    assert isinstance(owner, BoundDockerTargetSourceInputs)
    assert isinstance(inputs, DockerTargetSourceInputs)
    assert opened == [RuntimeProductId.DOCKER_COMPOSE]
    assert inputs.runtime.product is RuntimeProduct.DOCKER
    assert inputs.endpoint.product is RuntimeProduct.DOCKER
    assert inputs.compose_provider.provider_id == "docker-compose"
    assert inputs.compose_provider.artifacts[0].final_path == _COMPOSE_PATH
    assert inputs.compose_provider.integrity_sha256 == compose.evidence.evidence_sha256
    assert owner.supported
    assert "redacted" in repr(owner).lower()
    assert _PRIVATE_PATH not in repr(owner)

    owner.close()
    owner.close()
    assert owner.closed
    assert state[id(pair)]
    assert candidate.closed


def test_source_owner_rejects_compose_drift_and_remains_closeable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, state = _pair(monkeypatch)
    compose, candidate = _compose_owner()
    owner = BoundDockerTargetSourceInputs(
        runtime_endpoint=pair,
        compose=compose,
    )
    candidate.snapshot = replace(candidate.snapshot, sha256=_digest("changed"))

    with pytest.raises(DockerInputError) as captured:
        owner.capture()

    assert captured.value.code is DockerInputErrorCode.COMPOSE_INVALID
    owner.close()
    assert state[id(pair)]
    assert candidate.closed


def test_source_owner_rejects_runtime_compose_policy_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, _state = _pair(
        monkeypatch,
        [_runtime_endpoint_inputs(policy_sha256="c" * 64)],
    )
    compose, _candidate = _compose_owner()
    owner = BoundDockerTargetSourceInputs(
        runtime_endpoint=pair,
        compose=compose,
    )

    with pytest.raises(DockerInputError) as captured:
        owner.capture()

    assert captured.value.code is DockerInputErrorCode.INPUTS_CHANGED
    owner.close()


def test_source_owner_rejects_compose_from_different_installation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, _state = _pair(
        monkeypatch,
        [
            _runtime_endpoint_inputs(
                docker_path=PureWindowsPath(r"C:\OtherDocker\bin\docker.exe")
            )
        ],
    )
    compose, _candidate = _compose_owner()
    owner = BoundDockerTargetSourceInputs(
        runtime_endpoint=pair,
        compose=compose,
    )

    with pytest.raises(DockerInputError) as captured:
        owner.capture()

    assert captured.value.code is DockerInputErrorCode.INPUTS_CHANGED
    owner.close()


def test_native_factory_closes_pair_when_compose_capture_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, state = _pair(monkeypatch)
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_docker_runtime_endpoint_inputs",
        lambda: pair,
    )

    def reject_compose(_product: RuntimeProductId) -> BoundCommandRuntimeEvidence:
        raise RuntimeCommandVerificationError(
            RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED
        ) from RuntimeError(_PRIVATE_PATH)

    monkeypatch.setattr(
        inputs_module,
        "open_package_bound_command_runtime_evidence",
        reject_compose,
    )

    with pytest.raises(DockerInputError) as captured:
        capture_native_windows_docker_target_source_inputs()

    assert captured.value.code is DockerInputErrorCode.COMPOSE_INVALID
    assert _PRIVATE_PATH not in str(captured.value)
    assert state[id(pair)]


def test_source_owner_serializes_capture_against_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, state = _pair(monkeypatch)
    compose, candidate = _compose_owner()
    owner = BoundDockerTargetSourceInputs(
        runtime_endpoint=pair,
        compose=compose,
    )
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()
    failures: list[BaseException] = []
    inputs = _runtime_endpoint_inputs()

    def blocked_capture(
        _self: BoundDockerRuntimeEndpointInputs,
    ) -> DockerRuntimeEndpointInputs:
        entered.set()
        assert release.wait(timeout=5)
        return inputs

    monkeypatch.setattr(
        BoundDockerRuntimeEndpointInputs,
        "capture",
        blocked_capture,
    )

    def capture() -> None:
        try:
            owner.capture()
        except BaseException as error:  # pragma: no cover - thread handoff
            failures.append(error)

    worker = threading.Thread(target=capture)
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
    assert failures == []
    assert closed.is_set()
    assert state[id(pair)]
    assert candidate.closed


def test_new_docker_source_factory_remains_unwired() -> None:
    source_name = "runtime_docker_inputs"
    for module_name in ("app.py", "discovery.py", "repair.py", "runtime_execution.py"):
        source = (LAUNCHER_ROOT / "towerscout_launcher" / module_name).read_text(
            encoding="utf-8"
        )
        assert source_name not in source
