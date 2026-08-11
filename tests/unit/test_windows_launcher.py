from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import struct
import sys
import uuid
import zipfile
from pathlib import Path
from urllib.request import ProxyHandler

import pytest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.coordination import (  # noqa: E402
    OperationGuard,
    acquire_single_instance,
)
from towerscout_launcher.app import build_confirmation_summary  # noqa: E402
from towerscout_launcher.discovery import (  # noqa: E402
    _ENGINE_COMMANDS,
    _RejectRedirects,
    _default_runner,
    build_repair_preview,
    choose_engine,
    load_package_identity,
    locate_package_root,
    probe_runtime,
    read_towerscout_status,
)
from towerscout_launcher.models import (  # noqa: E402
    LauncherSnapshot,
    PublicState,
    RuntimeProbe,
    TowerScoutStatus,
)
from towerscout_launcher.repair import (  # noqa: E402
    CertificateCandidate,
    NativeRepairAdapter,
    RepairCoordinator,
    RepairError,
    RepairState,
    _find_unique_trusted_root,
    _image_reference_matches,
    build_repair_target,
)
from build_provenance import (  # noqa: E402
    PROVENANCE_FILENAME,
    create_build_provenance_payload,
)
from inspect_build import inspect_build  # noqa: E402
from package_validation import (  # noqa: E402
    FULL_PACKAGE_REQUIRED_FILES,
    assemble_full_validation_package,
    assemble_validation_package,
)


@pytest.fixture
def launcher_tmp_path() -> Path:
    base = ROOT / ".agent_work" / "pytest-temp" / "launcher-manual"
    base.mkdir(parents=True, exist_ok=True)
    path = base / uuid.uuid4().hex
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _write_package(root: Path, *, release_version: str = "v0.1.3-rc.test") -> None:
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (root / "release-manifest.v1.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_version": release_version,
                "track": "agpl-yolo",
                "image": "ghcr.io/example/towerscout:test",
                "image_digest": "sha256:" + "a" * 64,
                "pytorch_flavor": "cpu",
            }
        ),
        encoding="utf-8",
    )
    (root / ".env").write_text(
        "\n".join(
            (
                "TOWERSCOUT_IMAGE=ghcr.io/example/towerscout:test",
                "TOWERSCOUT_IMAGE_DIGEST=sha256:" + "a" * 64,
                "TOWERSCOUT_CONTAINER_ENGINE=docker",
                "TOWERSCOUT_GPU_MODE=off",
                "TOWERSCOUT_PORT=5005",
                "TOWERSCOUT_PYTORCH_FLAVOR=cpu",
                "COMPOSE_PROJECT_NAME=towerscout-test",
                "GOOGLE_API_KEY=must_not_be_loaded",
            )
        )
        + "\n",
        encoding="utf-8",
    )


def _write_repair_scripts(root: Path) -> None:
    scripts = root / "scripts"
    scripts.mkdir(exist_ok=True)
    for name in (
        "repair-provider-tls.ps1",
        "import-tls-ca.ps1",
        "stop.ps1",
        "launch.ps1",
    ):
        (scripts / name).write_text("# fixed test script\n", encoding="utf-8")


def _repair_snapshot(root: Path, *, engine_hint: str = "docker") -> LauncherSnapshot:
    _write_package(root)
    _write_repair_scripts(root)
    package = load_package_identity(root)
    package = package.__class__(**{**package.__dict__, "engine_hint": engine_hint})
    runtimes = tuple(
        RuntimeProbe(name, PublicState.SUCCESS, True, True, "running")
        for name in ("docker", "podman")
    )
    status = TowerScoutStatus(
        PublicState.SUCCESS,
        "ready",
        "ready",
        runtime_engine=engine_hint,
        selected_device="cpu",
        pytorch_flavor="cpu",
        image_digest=package.image_digest,
    )
    return LauncherSnapshot(package, runtimes, status)


def _write_minimal_gui_pe(path: Path) -> None:
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x80 + 24, 0x20B)
    struct.pack_into("<H", data, 0x80 + 24 + 68, 2)
    path.write_bytes(data)


def _write_test_checksums(root: Path) -> None:
    checksum_path = root / "SHA256SUMS.txt"
    files = sorted(
        (path for path in root.rglob("*") if path.is_file() and path != checksum_path),
        key=lambda path: path.relative_to(root).as_posix().lower(),
    )
    checksum_path.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(root).as_posix()}\n"
            for path in files
        ),
        encoding="utf-8",
    )


def _write_full_validation_base(
    root: Path, *, source_ref: str, pytorch_flavor: str = "cpu"
) -> Path:
    identity = f"Task-087-validation-{source_ref[:12]}"
    package = root / f"towerscout-{identity}"
    package.mkdir()
    for relative in FULL_PACKAGE_REQUIRED_FILES - {
        ".env.example",
        "SHA256SUMS.txt",
        "SOURCE.txt",
        "compose.yaml",
        "release-manifest.v1.json",
    }:
        path = package.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"test fixture for {relative}\n", encoding="utf-8")

    digest = "sha256:" + "c" * 64
    image = f"ghcr.io/example/towerscout:v0.1.2-{pytorch_flavor}@{digest}"
    asset_hash = "d" * 64
    (package / "compose.yaml").write_text(
        "services:\n  towerscout:\n    image: ${TOWERSCOUT_IMAGE}\n",
        encoding="utf-8",
    )
    (package / ".env.example").write_text(
        "\n".join(
            (
                f"TOWERSCOUT_IMAGE={image}",
                f"TOWERSCOUT_IMAGE_DIGEST={digest}",
                "TOWERSCOUT_PORT=5000",
                "TOWERSCOUT_CONTAINER_ENGINE=",
                "TOWERSCOUT_GPU_MODE=off",
                f"TOWERSCOUT_PYTORCH_FLAVOR={pytorch_flavor}",
                "TOWERSCOUT_MODEL_UPLOAD_KEY=",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (package / "SOURCE.txt").write_text(
        f"TowerScout corresponding source notice\n\nSource ref: {source_ref}\n",
        encoding="utf-8",
    )
    (package / "release-manifest.v1.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "track": "agpl-yolo",
                "release_version": identity,
                "image": image,
                "image_digest": digest,
                "pytorch_flavor": pytorch_flavor,
                "corresponding_source": {"source_ref": source_ref},
                "release_artifacts": {
                    "control_zip": "",
                    "control_zip_sha256": "",
                    "control_zip_sha256_sidecar": "",
                    "control_zip_sha256_reason": (
                        "No control ZIP was generated because -NoZip was used."
                    ),
                    "asset_bundle": "towerscout-v0.1.2-assets-test.zip",
                    "asset_bundle_sha256": asset_hash,
                    "asset_bundle_sha256_sidecar": (
                        "towerscout-v0.1.2-assets-test.zip.sha256"
                    ),
                    "package_contents_sha256": "SHA256SUMS.txt",
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_test_checksums(package)
    return package


def _write_fake_build_provenance(build: Path, *, source_ref: str) -> dict[str, object]:
    payload = create_build_provenance_payload(
        repo_root=ROOT,
        build_dir=build,
        source_ref=source_ref,
    )
    (build / PROVENANCE_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _write_test_launcher_build(root: Path, *, source_ref: str) -> Path:
    build = root / "build" / "TowerScoutLauncher"
    build.mkdir(parents=True)
    _write_minimal_gui_pe(build / "TowerScoutLauncher.exe")
    tk_data = build / "_internal" / "_tk_data"
    tk_data.mkdir(parents=True)
    (tk_data / "license.terms").write_text("Tcl/Tk license", encoding="utf-8")
    _write_fake_build_provenance(build, source_ref=source_ref)
    return build


def test_package_identity_uses_only_allowlisted_release_fields(
    launcher_tmp_path: Path,
) -> None:
    _write_package(launcher_tmp_path)
    assert locate_package_root(launcher_tmp_path) == launcher_tmp_path.resolve()

    identity = load_package_identity(launcher_tmp_path)

    assert identity.release_version == "v0.1.3-rc.test"
    assert identity.engine_hint == "docker"
    assert identity.gpu_mode == "off"
    assert identity.port == 5005
    assert identity.image_digest == "sha256:" + "a" * 64
    assert "must_not_be_loaded" not in repr(identity)


@pytest.mark.parametrize("engine", ("docker", "podman"))
def test_runtime_probe_uses_only_fixed_direct_commands(
    launcher_tmp_path: Path, engine: str
) -> None:
    executable = launcher_tmp_path / f"{engine}.exe"
    executable.write_bytes(b"")
    observed: dict[str, object] = {}

    def runner(command, *, cwd, timeout):  # noqa: ANN001
        observed.update(command=tuple(command), cwd=cwd, timeout=timeout)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    result = probe_runtime(
        engine,
        launcher_tmp_path,
        resolver=lambda _: str(executable),
        runner=runner,
    )

    assert result.state is PublicState.SUCCESS
    assert (
        observed["command"] == (str(executable.resolve()),) + _ENGINE_COMMANDS[engine]
    )
    assert observed["cwd"] == launcher_tmp_path
    assert observed["timeout"] == 5.0
    command_text = " ".join(observed["command"])
    assert "powershell" not in command_text.lower()
    assert "cmd.exe" not in command_text.lower()


@pytest.mark.parametrize(
    ("platform_name", "expected_creation_flags"),
    (("win32", 0x08000000), ("linux", 0)),
)
def test_default_runner_uses_gui_safe_windows_child_process_contract(
    launcher_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    expected_creation_flags: int,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):  # noqa: ANN001
        observed.update(command=tuple(command), **kwargs)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(sys, "platform", platform_name)
    monkeypatch.setattr(
        subprocess,
        "CREATE_NO_WINDOW",
        0x08000000,
        raising=False,
    )
    monkeypatch.setattr("towerscout_launcher.discovery.subprocess.run", fake_run)

    result = _default_runner(
        ("docker.exe", "version"),
        cwd=launcher_tmp_path,
        timeout=5.0,
    )

    assert result.returncode == 0
    assert observed["command"] == ("docker.exe", "version")
    assert observed["cwd"] == launcher_tmp_path
    assert observed["shell"] is False
    assert observed["stdin"] is subprocess.DEVNULL
    assert observed["stdout"] is subprocess.PIPE
    assert observed["stderr"] is subprocess.PIPE
    assert observed["timeout"] == 5.0
    assert observed["creationflags"] == expected_creation_flags


def test_runtime_probe_reports_timeout_without_raw_details(
    launcher_tmp_path: Path,
) -> None:
    executable = launcher_tmp_path / "docker.exe"
    executable.write_bytes(b"")
    secret = "provider-key-and-local-path"

    def runner(command, *, cwd, timeout):  # noqa: ANN001
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output=secret,
            stderr=secret,
        )

    result = probe_runtime(
        "docker",
        launcher_tmp_path,
        resolver=lambda _: str(executable),
        runner=runner,
    )

    assert result.state is PublicState.ERROR
    assert result.installed is True
    assert result.reachable is False
    assert result.public_message == "Docker status check timed out after five seconds."
    assert secret not in result.public_message
    assert secret not in repr(result)


def test_runtime_probe_never_reflects_raw_failure_output(
    launcher_tmp_path: Path,
) -> None:
    executable = launcher_tmp_path / "docker.exe"
    executable.write_bytes(b"")
    secret = "provider-key-and-local-path"

    def runner(command, *, cwd, timeout):  # noqa: ANN001
        return subprocess.CompletedProcess(command, 1, secret, secret)

    result = probe_runtime(
        "docker",
        launcher_tmp_path,
        resolver=lambda _: str(executable),
        runner=runner,
    )

    assert result.state is PublicState.UNAVAILABLE
    assert secret not in result.public_message


def test_runtime_probe_rejects_non_json_success_output(launcher_tmp_path: Path) -> None:
    executable = launcher_tmp_path / "docker.exe"
    executable.write_bytes(b"")

    def runner(command, *, cwd, timeout):  # noqa: ANN001
        return subprocess.CompletedProcess(command, 0, "not-json", "")

    result = probe_runtime(
        "docker",
        launcher_tmp_path,
        resolver=lambda _: str(executable),
        runner=runner,
    )
    assert result.state is PublicState.ERROR
    assert result.reachable is False


def test_package_identity_rejects_manifest_env_digest_mismatch(
    launcher_tmp_path: Path,
) -> None:
    _write_package(launcher_tmp_path)
    env_path = launcher_tmp_path / ".env"
    env_path.write_text(
        env_path.read_text(encoding="utf-8").replace("a" * 64, "b" * 64),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="digest"):
        load_package_identity(launcher_tmp_path)


def test_engine_selection_requires_exact_choice_when_both_are_running(
    launcher_tmp_path: Path,
) -> None:
    _write_package(launcher_tmp_path)
    package = load_package_identity(launcher_tmp_path)
    package = package.__class__(**{**package.__dict__, "engine_hint": ""})
    runtimes = tuple(
        RuntimeProbe(name, PublicState.SUCCESS, True, True, "running")
        for name in ("docker", "podman")
    )
    status = TowerScoutStatus(PublicState.UNAVAILABLE, "unreachable", "not reachable")

    assert choose_engine(LauncherSnapshot(package, runtimes, status)) == ""


def test_preview_is_non_mutating_and_provider_scoped(launcher_tmp_path: Path) -> None:
    _write_package(launcher_tmp_path)
    package = load_package_identity(launcher_tmp_path)
    runtimes = (
        RuntimeProbe("docker", PublicState.SUCCESS, True, True, "running"),
        RuntimeProbe("podman", PublicState.SUCCESS, True, True, "running"),
    )
    status = TowerScoutStatus(
        PublicState.SUCCESS, "ready", "ready", runtime_engine="docker"
    )
    snapshot = LauncherSnapshot(package, runtimes, status)

    preview = build_repair_preview(snapshot, provider="azure", engine="podman")

    assert preview.state is PublicState.SUCCESS
    assert "Azure Maps" in preview.body
    assert "Podman" in preview.body
    assert "preview-only" in preview.body
    assert "did not inspect certificates" in preview.body


def test_repair_target_rejects_runtime_profile_mismatch(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path, engine_hint="docker")

    with pytest.raises(RepairError) as exc_info:
        build_repair_target(snapshot, provider="google", engine="podman")

    assert exc_info.value.category == "runtime_profile_mismatch"
    assert "different" not in repr(exc_info.value).lower()


def test_native_adapter_selects_private_candidate_without_script_host(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="google", engine="docker")
    observed: list[str] = []
    candidate = CertificateCandidate(
        pem="-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
        fingerprint_sha256="A" * 64,
        public_message="candidate selected",
    )

    def selector(provider: str) -> CertificateCandidate:
        observed.append(provider)
        return candidate

    adapter = NativeRepairAdapter(selector=selector)
    selected = adapter.select_candidate(target)

    assert selected is candidate
    assert observed == ["google"]
    assert "fixture" not in repr(selected)
    assert "A" * 64 not in repr(selected)


def test_native_chain_selection_requires_one_unique_trusted_root() -> None:
    intermediate_name = ((('commonName', 'TowerScout Test Intermediate'),),)
    root_name = ((('commonName', 'TowerScout Test Root'),),)
    leaf = {"issuer": intermediate_name}
    intermediate = {
        "subject": intermediate_name,
        "issuer": root_name,
    }
    root = {"subject": root_name, "issuer": root_name}

    assert _find_unique_trusted_root(
        leaf,
        ((intermediate, b"intermediate"), (root, b"root")),
    ) == b"root"

    with pytest.raises(RepairError) as exc_info:
        _find_unique_trusted_root(
            leaf,
            (
                (intermediate, b"intermediate-a"),
                (intermediate, b"intermediate-b"),
                (root, b"root"),
            ),
        )
    assert exc_info.value.category == "trusted_ca_ambiguous"


def test_native_adapter_rejects_selection_without_raw_output(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="azure", engine="docker")
    secret = "private-subject-thumbprint-and-local-path"

    def selector(provider: str) -> CertificateCandidate:
        raise RepairError("trusted_ca_ambiguous", "sanitized selection failure")

    adapter = NativeRepairAdapter(selector=selector)
    with pytest.raises(RepairError) as exc_info:
        adapter.select_candidate(target)

    assert exc_info.value.category == "trusted_ca_ambiguous"
    assert secret not in exc_info.value.public_message
    assert secret not in repr(exc_info.value)


def test_repair_coordinator_requires_confirmation_and_mutation_gate(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)

    class FakeAdapter:
        def select_candidate(self, target):  # noqa: ANN001
            return CertificateCandidate("private pem", "B" * 64, "selected")

        def apply_candidate(self, target, candidate):  # noqa: ANN001
            raise AssertionError("mutation must remain disabled")

        def restart(self, target):  # noqa: ANN001
            raise AssertionError("mutation must remain disabled")

    coordinator = RepairCoordinator(FakeAdapter())  # type: ignore[arg-type]
    transaction = coordinator.prepare(snapshot, provider="google", engine="docker")
    assert transaction.state is RepairState.PREPARED
    assert "B" * 64 not in repr(transaction)
    assert "private pem" not in repr(transaction)

    coordinator.confirm(transaction, "repair_tls_and_restart")
    assert transaction.state is RepairState.CONFIRMED
    with pytest.raises(RepairError) as exc_info:
        coordinator.execute(transaction)
    assert exc_info.value.category == "mutation_disabled"


def test_repair_coordinator_records_recovery_required_on_failure(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)

    class FailingAdapter:
        def select_candidate(self, target):  # noqa: ANN001
            return CertificateCandidate("private pem", "C" * 64, "selected")

        def apply_candidate(self, target, candidate):  # noqa: ANN001
            raise RepairError("repair_apply_failed", "sanitized failure")

        def restart(self, target):  # noqa: ANN001
            raise AssertionError("restart must not follow failed apply")

    coordinator = RepairCoordinator(  # type: ignore[arg-type]
        FailingAdapter(), mutation_enabled=True
    )
    transaction = coordinator.prepare(snapshot, provider="azure", engine="docker")
    coordinator.confirm(transaction, "repair_tls_and_restart")

    with pytest.raises(RepairError):
        coordinator.execute(transaction)

    assert transaction.state is RepairState.RECOVERY_REQUIRED
    assert "Task-086" in transaction.public_message
    assert "C" * 64 not in repr(transaction)


def test_repair_coordinator_reports_sanitized_transitions(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)

    class SuccessfulAdapter:
        def select_candidate(self, target):  # noqa: ANN001
            return CertificateCandidate("private pem", "C" * 64, "selected")

        def apply_candidate(self, target, candidate):  # noqa: ANN001
            return None

        def restart(self, target):  # noqa: ANN001
            return None

    coordinator = RepairCoordinator(  # type: ignore[arg-type]
        SuccessfulAdapter(), mutation_enabled=True
    )
    transaction = coordinator.prepare(snapshot, provider="google", engine="docker")
    summary = build_confirmation_summary(transaction.target)
    coordinator.confirm(transaction, "repair_tls_and_restart")
    transitions: list[tuple[RepairState, str]] = []

    coordinator.execute(
        transaction,
        on_transition=lambda item: transitions.append(
            (item.state, item.public_message)
        ),
    )

    assert [state for state, _ in transitions] == [
        RepairState.APPLYING,
        RepairState.RESTARTING,
        RepairState.SUCCEEDED,
    ]
    assert "Google Maps" in summary
    assert "towerscout-test" in summary
    assert "Named volumes are not requested for deletion" in summary
    assert str(launcher_tmp_path) not in summary
    assert "private pem" not in summary


def test_operation_guard_blocks_duplicate_operations() -> None:
    guard = OperationGuard()
    with guard.begin() as first:
        assert first is True
        with guard.begin() as duplicate:
            assert duplicate is False
    with guard.begin() as after_completion:
        assert after_completion is True


@pytest.mark.skipif(os.name != "nt", reason="Windows mutex contract")
def test_windows_mutex_blocks_second_launcher_instance() -> None:
    first = acquire_single_instance("unit-test-package")
    try:
        second = acquire_single_instance("unit-test-package")
        try:
            assert first.acquired is True
            assert second.acquired is False
        finally:
            second.close()
    finally:
        first.close()


def test_readiness_redirects_are_rejected_and_errors_are_sanitized(
    launcher_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_package(launcher_tmp_path)
    package = load_package_identity(launcher_tmp_path)

    class FailingOpener:
        def open(self, request, timeout):  # noqa: ANN001
            raise OSError("sensitive local failure")

    observed_handlers: tuple[object, ...] = ()

    def opener_factory(*handlers):  # noqa: ANN001
        nonlocal observed_handlers
        observed_handlers = handlers
        return FailingOpener()

    monkeypatch.setattr("towerscout_launcher.discovery.build_opener", opener_factory)
    status = read_towerscout_status(package)
    assert status.state is PublicState.UNAVAILABLE
    assert "sensitive" not in status.public_message
    assert isinstance(observed_handlers[0], ProxyHandler)
    assert observed_handlers[0].proxies == {}
    assert isinstance(observed_handlers[1], _RejectRedirects)


def test_pyinstaller_contract_is_windowed_onedir_without_upx() -> None:
    spec = (LAUNCHER_ROOT / "TowerScoutLauncher.spec").read_text(encoding="utf-8")
    assert "console=False" in spec
    assert spec.count("upx=False") >= 2
    assert "COLLECT(" in spec
    assert "onefile" not in spec.lower()
    entrypoint = (LAUNCHER_ROOT / "towerscout_launcher" / "__main__.py").read_text(
        encoding="utf-8"
    )
    assert "from towerscout_launcher.app import" in entrypoint
    build_command = (LAUNCHER_ROOT / "build.cmd").read_text(encoding="utf-8")
    assert "PyInstaller" in build_command
    assert "build_provenance.py" in build_command
    assert build_command.index("PyInstaller") < build_command.index(
        "build_provenance.py"
    )


def test_package_inspection_rejects_scripts_and_secrets(
    launcher_tmp_path: Path,
) -> None:
    build = launcher_tmp_path / "TowerScoutLauncher"
    build.mkdir()
    _write_minimal_gui_pe(build / "TowerScoutLauncher.exe")
    assert inspect_build(build) == []

    (build / "host-helper.ps1").write_text("not allowed", encoding="utf-8")
    errors = inspect_build(build)
    assert errors and "host-helper.ps1" in errors[0]


def test_launcher_source_contains_only_fixed_mutation_boundary() -> None:
    sources = {
        path.name: path.read_text(encoding="utf-8").lower()
        for path in (LAUNCHER_ROOT / "towerscout_launcher").glob("*.py")
    }
    source = "\n".join(sources.values())
    assert "shell=true" not in source
    assert "powershell" not in source
    assert "executionpolicy" not in source
    assert ".cmd" not in sources["repair.py"]
    assert "cmd.exe" not in source
    assert "host-helper" not in source
    assert "tcpserver" not in source
    assert "socketserver" not in source
    assert "repair-provider-tls" not in source
    assert "shell=false" in sources["repair.py"]
    assert '"sh", "-c"' not in sources["repair.py"]
    assert '"down", "-v"' not in sources["repair.py"]


def test_native_repair_accepts_only_safe_podman_image_normalization() -> None:
    digest = "sha256:" + "a" * 64
    expected = f"ghcr.io/example/towerscout:v0.1.2-cpu@{digest}"

    assert _image_reference_matches(
        expected, f"ghcr.io/example/towerscout@{digest}", digest
    )
    assert not _image_reference_matches(
        expected, f"ghcr.io/example/other@{digest}", digest
    )
    assert not _image_reference_matches(
        expected,
        "ghcr.io/example/towerscout@sha256:" + "b" * 64,
        digest,
    )


class _FakeRepairRuntime:
    def __init__(
        self,
        root: Path,
        *,
        fail_verification: bool = False,
        ambiguous_target: bool = False,
        fail_restart: bool = False,
    ) -> None:
        self.root = root
        self.container_id = "abc123"
        self.fail_verification = fail_verification
        self.ambiguous_target = ambiguous_target
        self.fail_restart = fail_restart
        self.commands: list[tuple[str, ...]] = []
        self.files = {
            "/etc/ssl/certs/ca-certificates.crt": b"SYSTEM-CA\n",
        }

    def resolver(self, engine: str) -> str:
        return f"C:/Program Files/{engine}/{engine}.exe"

    def _inspect(self) -> dict[str, object]:
        return {
            "Config": {
                "Image": "ghcr.io/example/towerscout:test",
                "Labels": {
                    "com.docker.compose.project": "towerscout-test",
                    "com.docker.compose.service": "towerscout",
                },
                "Env": [
                    "TOWERSCOUT_CONTAINER_ENGINE=docker",
                    "TOWERSCOUT_GPU_MODE=off",
                    "TOWERSCOUT_IMAGE_DIGEST=sha256:" + "a" * 64,
                ],
            },
            "NetworkSettings": {
                "Ports": {"5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5005"}]}
            },
        }

    def runner(self, command, *, cwd, timeout, environment):  # noqa: ANN001
        del cwd, timeout, environment
        args = tuple(command[1:])
        self.commands.append(args)
        output = ""
        returncode = 0
        executable_name = Path(command[0]).name.lower()
        if executable_name == "podman-compose.exe" and args == ("version",):
            output = "podman-compose version 1.5.0\n"
        elif args == ("compose", "version"):
            output = "podman-compose version 1.5.0\n"
        elif args[:2] == ("ps", "-a"):
            if "com.docker.compose.project" in " ".join(args):
                output = self.container_id + "\n"
            elif self.ambiguous_target:
                output = "def456\n"
        elif args[:3] == ("inspect", "--type", "container"):
            output = json.dumps(self._inspect())
        elif args[:2] == ("exec", self.container_id):
            operation = args[2:]
            if operation[:2] == ("test", "-f"):
                returncode = 0 if operation[2] in self.files else 1
            elif operation[:2] == ("rm", "-f"):
                self.files.pop(operation[2], None)
        elif args and args[0] == "exec" and "python" in args:
            if self.fail_verification:
                returncode = 1
            else:
                output = "tls_verified\n"
        elif args and args[0] == "cp":
            source, destination = args[1:3]
            if source.startswith(self.container_id + ":"):
                Path(destination).write_bytes(self.files[source.split(":", 1)[1]])
            elif destination.startswith(self.container_id + ":"):
                self.files[destination.split(":", 1)[1]] = Path(source).read_bytes()
        elif args and args[0] == "compose" and "up" in args and self.fail_restart:
            returncode = 1
        return subprocess.CompletedProcess(
            command, returncode, output, "private runtime detail"
        )


def _native_test_adapter(runtime: _FakeRepairRuntime) -> NativeRepairAdapter:
    return NativeRepairAdapter(
        selector=lambda _: CertificateCandidate("CANDIDATE-CA\n", "D" * 64, "selected"),
        resolver=runtime.resolver,
        runner=runtime.runner,
        status_reader=lambda package: TowerScoutStatus(
            PublicState.SUCCESS,
            "ready",
            "ready",
            runtime_engine="docker",
            selected_device="cpu",
            pytorch_flavor="cpu",
            image_digest=package.image_digest,
        ),
        sleeper=lambda _: None,
    )


def test_native_repair_stages_exact_container_and_preserves_environment(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="google", engine="docker")
    env_path = launcher_tmp_path / ".env"
    normalized_env = env_path.read_bytes().replace(b"\r\n", b"\n")
    env_path.write_bytes(normalized_env.replace(b"\n", b"\r\n"))
    runtime = _FakeRepairRuntime(launcher_tmp_path)
    adapter = _native_test_adapter(runtime)
    candidate = adapter.select_candidate(target)

    adapter.apply_candidate(target, candidate)

    env_bytes = env_path.read_bytes()
    env = env_bytes.decode("utf-8")
    assert "GOOGLE_API_KEY=must_not_be_loaded" in env
    assert b"GOOGLE_API_KEY=must_not_be_loaded\r\n" in env_bytes
    assert b"\n" not in env_bytes.replace(b"\r\n", b"")
    assert (
        "REQUESTS_CA_BUNDLE=/app/webapp/config/certs/towerscout-ca-bundle.pem" in env
    )
    assert "SSL_CERT_FILE=/app/webapp/config/certs/towerscout-ca-bundle.pem" in env
    assert runtime.files["/app/webapp/config/certs/local-ca.pem"] == b"CANDIDATE-CA\n"
    assert runtime.files["/app/webapp/config/certs/towerscout-ca-bundle.pem"] == (
        b"SYSTEM-CA\nCANDIDATE-CA\n"
    )
    assert all(
        "powershell" not in " ".join(command).lower()
        for command in runtime.commands
    )


def test_native_repair_rolls_back_failed_provider_verification(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="azure", engine="docker")
    runtime = _FakeRepairRuntime(launcher_tmp_path, fail_verification=True)
    adapter = _native_test_adapter(runtime)
    original_env = (launcher_tmp_path / ".env").read_bytes()

    with pytest.raises(RepairError) as exc_info:
        adapter.apply_candidate(target, adapter.select_candidate(target))

    assert exc_info.value.category == "runtime_operation_failed"
    assert (launcher_tmp_path / ".env").read_bytes() == original_env
    assert "/app/webapp/config/certs/local-ca.pem" not in runtime.files
    assert "/app/webapp/config/certs/towerscout-ca-bundle.pem" not in runtime.files
    assert not any((launcher_tmp_path / ".towerscout-runtime").glob("repair-*"))


def test_native_repair_rejects_ambiguous_container_before_staging(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="google", engine="docker")
    runtime = _FakeRepairRuntime(launcher_tmp_path, ambiguous_target=True)
    adapter = _native_test_adapter(runtime)

    with pytest.raises(RepairError) as exc_info:
        adapter.apply_candidate(target, adapter.select_candidate(target))

    assert exc_info.value.category == "container_target_ambiguous"
    assert not (launcher_tmp_path / ".towerscout-runtime").exists()


def test_native_repair_rejects_podman_without_approved_compose_provider(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path, engine_hint="podman")
    env_path = launcher_tmp_path / ".env"
    env_path.write_text(
        env_path.read_text(encoding="utf-8").replace(
            "TOWERSCOUT_CONTAINER_ENGINE=docker",
            "TOWERSCOUT_CONTAINER_ENGINE=podman",
        ),
        encoding="utf-8",
    )
    target = build_repair_target(snapshot, provider="google", engine="podman")
    runtime = _FakeRepairRuntime(launcher_tmp_path)
    adapter = _native_test_adapter(runtime)

    with pytest.raises(RepairError) as exc_info:
        adapter.apply_candidate(target, adapter.select_candidate(target))

    assert exc_info.value.category == "podman_provider_required"
    assert runtime.commands == []


def test_native_repair_rejects_docker_desktop_as_podman_provider(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path, engine_hint="podman")
    provider = (
        launcher_tmp_path
        / "Docker"
        / "Docker"
        / "resources"
        / "bin"
        / "docker-compose.exe"
    )
    provider.parent.mkdir(parents=True)
    provider.write_bytes(b"not executed")
    env_path = launcher_tmp_path / ".env"
    env_path.write_text(
        env_path.read_text(encoding="utf-8")
        .replace(
            "TOWERSCOUT_CONTAINER_ENGINE=docker",
            "TOWERSCOUT_CONTAINER_ENGINE=podman",
        )
        + f"PODMAN_COMPOSE_PROVIDER={provider}\n",
        encoding="utf-8",
    )
    target = build_repair_target(snapshot, provider="azure", engine="podman")
    runtime = _FakeRepairRuntime(launcher_tmp_path)
    adapter = _native_test_adapter(runtime)

    with pytest.raises(RepairError) as exc_info:
        adapter.apply_candidate(target, adapter.select_candidate(target))

    assert exc_info.value.category == "podman_provider_rejected"
    assert runtime.commands == []


def test_native_repair_accepts_explicit_approved_podman_provider(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path, engine_hint="podman")
    provider = launcher_tmp_path / "provider" / "podman-compose.exe"
    provider.parent.mkdir()
    provider.write_bytes(b"fixed test provider")
    env_path = launcher_tmp_path / ".env"
    env_path.write_text(
        env_path.read_text(encoding="utf-8")
        .replace(
            "TOWERSCOUT_CONTAINER_ENGINE=docker",
            "TOWERSCOUT_CONTAINER_ENGINE=podman",
        )
        + f"PODMAN_COMPOSE_PROVIDER={provider}\n",
        encoding="utf-8",
    )
    target = build_repair_target(snapshot, provider="google", engine="podman")
    runtime = _FakeRepairRuntime(launcher_tmp_path)
    adapter = _native_test_adapter(runtime)

    adapter._prepare_podman_provider(target)

    assert runtime.commands == [("version",), ("compose", "version")]


def test_native_repair_restart_preserves_volumes_and_revalidates_target(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="google", engine="docker")
    runtime = _FakeRepairRuntime(launcher_tmp_path)
    adapter = _native_test_adapter(runtime)

    adapter.apply_candidate(target, adapter.select_candidate(target))
    adapter.restart(target)

    down = next(command for command in runtime.commands if "down" in command)
    up = next(command for command in runtime.commands if "up" in command)
    assert down[-2:] == ("down", "--remove-orphans")
    assert "-v" not in down and "--volumes" not in down
    assert up[-2:] == ("up", "-d")
    assert not any((launcher_tmp_path / ".towerscout-runtime").glob("repair-*"))


def test_native_repair_restart_failure_restores_environment(
    launcher_tmp_path: Path,
) -> None:
    snapshot = _repair_snapshot(launcher_tmp_path)
    target = build_repair_target(snapshot, provider="google", engine="docker")
    runtime = _FakeRepairRuntime(launcher_tmp_path, fail_restart=True)
    adapter = _native_test_adapter(runtime)
    original_env = (launcher_tmp_path / ".env").read_bytes()

    adapter.apply_candidate(target, adapter.select_candidate(target))
    with pytest.raises(RepairError) as exc_info:
        adapter.restart(target)

    assert exc_info.value.category == "runtime_operation_failed"
    assert (launcher_tmp_path / ".env").read_bytes() == original_env
    assert "/app/webapp/config/certs/local-ca.pem" not in runtime.files
    assert "/app/webapp/config/certs/towerscout-ca-bundle.pem" not in runtime.files
    assert not any((launcher_tmp_path / ".towerscout-runtime").glob("repair-*"))


def test_validation_package_is_traceable_and_contains_no_control_stack(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "a" * 40
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)

    result = assemble_validation_package(
        repo_root=ROOT,
        launcher_build_dir=build,
        output_dir=launcher_tmp_path / "output",
        source_ref=source_ref,
    )

    assert result.identity == "Task-087-validation-aaaaaaaaaaaa"
    validation_manifest = json.loads(
        (result.package_dir / "validation-manifest.v1.json").read_text(encoding="utf-8")
    )
    assert validation_manifest["source_ref"] == source_ref
    assert validation_manifest["package_kind"] == "launcher-policy"
    assert validation_manifest["release_candidate"] is False
    assert validation_manifest["execution_authorized"] is False
    assert validation_manifest["merge_authorized"] is False
    assert validation_manifest["signed"] is False
    assert validation_manifest["launcher_tls_mutation_enabled"] is True
    assert (result.package_dir / "launcher" / "TowerScoutLauncher.exe").is_file()
    assert "services: {}" in (result.package_dir / "compose.yaml").read_text(
        encoding="utf-8"
    )
    packaged_names = {
        path.relative_to(result.package_dir).as_posix().lower()
        for path in result.package_dir.rglob("*")
        if path.is_file()
    }
    assert not any("host-helper" in name for name in packaged_names)
    assert not any(name.endswith((".bat", ".cmd", ".ps1")) for name in packaged_names)
    assert ".env" not in packaged_names


def test_validation_package_hashes_cover_every_packaged_file(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "b" * 40
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)

    result = assemble_validation_package(
        repo_root=ROOT,
        launcher_build_dir=build,
        output_dir=launcher_tmp_path / "output",
        source_ref=source_ref,
    )

    checksum_lines = (
        (result.package_dir / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    )
    checksummed_names = {line.split("  ", 1)[1] for line in checksum_lines}
    expected_names = {
        path.relative_to(result.package_dir).as_posix()
        for path in result.package_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    }
    assert checksummed_names == expected_names
    assert result.archive_path.is_file()
    assert (
        (result.archive_path.with_suffix(result.archive_path.suffix + ".sha256"))
        .read_text(encoding="utf-8")
        .startswith(result.archive_sha256)
    )


def test_validation_package_rejects_stale_launcher_source_provenance(
    launcher_tmp_path: Path,
) -> None:
    build = _write_test_launcher_build(
        launcher_tmp_path,
        source_ref="3" * 40,
    )

    with pytest.raises(ValueError, match="provenance source ref does not match"):
        assemble_validation_package(
            repo_root=ROOT,
            launcher_build_dir=build,
            output_dir=launcher_tmp_path / "output",
            source_ref="4" * 40,
        )


def test_validation_package_rejects_tampered_launcher_build_tree(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "5" * 40
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    license_path = build / "_internal" / "_tk_data" / "license.terms"
    license_path.write_text("tampered after provenance\n", encoding="utf-8")

    with pytest.raises(ValueError, match="provenance tree SHA-256 mismatch"):
        assemble_validation_package(
            repo_root=ROOT,
            launcher_build_dir=build,
            output_dir=launcher_tmp_path / "output",
            source_ref=source_ref,
        )


def test_validation_package_rejects_tampered_launcher_executable(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "7" * 40
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    executable = build / "TowerScoutLauncher.exe"
    executable.write_bytes(executable.read_bytes() + b"tampered")

    with pytest.raises(ValueError, match="provenance executable SHA-256 mismatch"):
        assemble_validation_package(
            repo_root=ROOT,
            launcher_build_dir=build,
            output_dir=launcher_tmp_path / "output",
            source_ref=source_ref,
        )


def test_validation_package_archive_failure_leaves_no_partial_outputs(
    launcher_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_ref = "6" * 40
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    output = launcher_tmp_path / "output"

    def fail_archive(package_dir, archive_path):  # noqa: ANN001
        archive_path.write_bytes(b"partial")
        raise OSError("injected archive failure")

    monkeypatch.setattr("package_validation._write_archive", fail_archive)

    with pytest.raises(OSError, match="injected archive failure"):
        assemble_validation_package(
            repo_root=ROOT,
            launcher_build_dir=build,
            output_dir=output,
            source_ref=source_ref,
        )

    assert output.is_dir()
    assert list(output.iterdir()) == []


def test_full_validation_package_composes_verified_runnable_base_atomically(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "e" * 40
    base = _write_full_validation_base(launcher_tmp_path, source_ref=source_ref)
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    original_env = (base / ".env.example").read_text(encoding="utf-8")

    result = assemble_full_validation_package(
        repo_root=ROOT,
        base_package_dir=base,
        launcher_build_dir=build,
        output_dir=launcher_tmp_path / "full-output",
        source_ref=source_ref,
        engine="docker",
        gpu_mode="off",
        port=5008,
        compose_project="towerscout-task087-full-test",
    )

    assert result.identity == "Task-087-validation-eeeeeeeeeeee"
    assert result.package_dir.name == "towerscout-Task-087-validation-eeeeeeeeeeee"
    assert (result.package_dir / "launcher" / "TowerScoutLauncher.exe").is_file()
    assert (result.package_dir / "scripts" / "repair-provider-tls.cmd").is_file()
    assert (result.package_dir / "scripts" / "repair-provider-tls.ps1").is_file()
    assert not (result.package_dir / ".env").exists()
    assert not any(
        "hosthelper"
        in path.relative_to(result.package_dir)
        .as_posix()
        .lower()
        .replace("-", "")
        .replace("_", "")
        for path in result.package_dir.rglob("*")
    )

    env_example = (result.package_dir / ".env.example").read_text(encoding="utf-8")
    assert "TOWERSCOUT_CONTAINER_ENGINE=docker" in env_example
    assert "TOWERSCOUT_GPU_MODE=off" in env_example
    assert "TOWERSCOUT_PORT=5008" in env_example
    assert "COMPOSE_PROJECT_NAME=towerscout-task087-full-test" in env_example
    assert (base / ".env.example").read_text(encoding="utf-8") == original_env
    assert not (base / "launcher").exists()

    validation = json.loads(
        (result.package_dir / "validation-manifest.v1.json").read_text(encoding="utf-8")
    )
    assert validation["package_kind"] == "full-runnable"
    assert validation["purpose"] == ("task-087-full-package-functional-validation-only")
    assert validation["source_ref"] == source_ref
    assert validation["engine"] == "docker"
    assert validation["gpu_mode"] == "off"
    assert validation["port"] == 5008
    assert validation["host_helper_packaged"] is False
    assert validation["launcher_tls_mutation_enabled"] is True
    assert validation["managed_endpoint_evidence_authorized"] is False
    packaged_provenance = json.loads(
        (result.package_dir / "launcher" / PROVENANCE_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    assert (
        validation["launcher_build_tree_sha256"]
        == packaged_provenance["build_tree_sha256"]
    )

    release_manifest = json.loads(
        (result.package_dir / "release-manifest.v1.json").read_text(encoding="utf-8")
    )
    assert release_manifest["validation"]["package_kind"] == "full-runnable"
    artifacts = release_manifest["release_artifacts"]
    assert artifacts["control_zip"] == result.archive_path.name
    assert artifacts["control_zip_sha256"] == ""
    assert artifacts["control_zip_sha256_sidecar"] == (
        result.archive_path.name + ".sha256"
    )

    checksum_lines = (
        (result.package_dir / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    )
    recorded = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in checksum_lines
    }
    expected = {
        path.relative_to(result.package_dir).as_posix()
        for path in result.package_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    }
    assert set(recorded) == expected
    assert all(
        recorded[relative]
        == hashlib.sha256(
            result.package_dir.joinpath(*relative.split("/")).read_bytes()
        ).hexdigest()
        for relative in expected
    )
    sidecar = result.archive_path.with_suffix(result.archive_path.suffix + ".sha256")
    assert sidecar.read_text(encoding="utf-8") == (
        f"{result.archive_sha256}  {result.archive_path.name}\n"
    )
    with zipfile.ZipFile(result.archive_path) as archive:
        assert all(
            name.startswith(result.package_dir.name + "/")
            for name in archive.namelist()
        )


def test_full_validation_package_rejects_tampered_base_without_partial_output(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "f" * 40
    base = _write_full_validation_base(launcher_tmp_path, source_ref=source_ref)
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    (base / "compose.yaml").write_text("tampered\n", encoding="utf-8")
    output = launcher_tmp_path / "full-output"

    with pytest.raises(ValueError, match="Compose file|checksum mismatch"):
        assemble_full_validation_package(
            repo_root=ROOT,
            base_package_dir=base,
            launcher_build_dir=build,
            output_dir=output,
            source_ref=source_ref,
            engine="docker",
            gpu_mode="off",
            port=5008,
            compose_project="towerscout-task087-full-test",
        )

    assert not output.exists()


@pytest.mark.parametrize(
    ("relative", "message"),
    (
        (".env", "live environment file"),
        ("scripts/lib/TowerScoutHostHelper.ps1", "host-helper artifact"),
        ("webapp/config/exported-root.pem", "certificate file"),
    ),
)
def test_full_validation_package_rejects_unsafe_artifacts_but_allows_task086(
    launcher_tmp_path: Path, relative: str, message: str
) -> None:
    source_ref = "1" * 40
    base = _write_full_validation_base(launcher_tmp_path, source_ref=source_ref)
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    unsafe = base.joinpath(*relative.split("/"))
    unsafe.parent.mkdir(parents=True, exist_ok=True)
    unsafe.write_text("not allowed\n", encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        assemble_full_validation_package(
            repo_root=ROOT,
            base_package_dir=base,
            launcher_build_dir=build,
            output_dir=launcher_tmp_path / "full-output",
            source_ref=source_ref,
            engine="docker",
            gpu_mode="off",
            port=5008,
            compose_project="towerscout-task087-full-test",
        )


def test_full_validation_package_rejects_populated_secret_setting(
    launcher_tmp_path: Path,
) -> None:
    source_ref = "2" * 40
    base = _write_full_validation_base(launcher_tmp_path, source_ref=source_ref)
    build = _write_test_launcher_build(launcher_tmp_path, source_ref=source_ref)
    env_path = base / ".env.example"
    env_path.write_text(
        env_path.read_text(encoding="utf-8") + "GOOGLE_API_KEY=not-for-packaging\n",
        encoding="utf-8",
    )
    _write_test_checksums(base)

    with pytest.raises(ValueError, match="populated secret setting"):
        assemble_full_validation_package(
            repo_root=ROOT,
            base_package_dir=base,
            launcher_build_dir=build,
            output_dir=launcher_tmp_path / "full-output",
            source_ref=source_ref,
            engine="docker",
            gpu_mode="off",
            port=5008,
            compose_project="towerscout-task087-full-test",
        )
