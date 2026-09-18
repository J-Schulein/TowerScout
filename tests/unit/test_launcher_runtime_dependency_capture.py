from __future__ import annotations

import hashlib
import struct
import sys
import threading
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_dependency_capture as capture_module  # noqa: E402
from towerscout_launcher.pe_dependencies import (  # noqa: E402
    PeDependencyManifest,
    PeImageMetadata,
)
from towerscout_launcher.runtime_dependency_capture import (  # noqa: E402
    CpythonDependencyCaptureError,
    CpythonDependencyCaptureErrorCode,
    capture_package_bound_cpython_dependency_inventory,
)
from towerscout_launcher.runtime_dependency_policy import (  # noqa: E402
    ApprovedDependencyFile,
    DependencySignaturePolicy,
    NonAmd64PeFile,
    PeMachine,
    load_package_bound_runtime_dependency_policy,
)
from towerscout_launcher.runtime_dependency_trust import (  # noqa: E402
    CpythonDependencyEvidence,
    DependencyFileObservation,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    capture_handle_bound_file,
)

_CURRENT_USER = "S-1-5-21-100-200-300-1001"
_ROOT = PureWindowsPath(r"C:\Python312")
_PYTHON = str(_ROOT / "python.exe")


def _file_id(value: str) -> bytes:
    return hashlib.sha256(value.casefold().encode("utf-8")).digest()[:16]


class _PathApi:
    supported = True

    def __init__(self) -> None:
        self.handles: dict[object, NativeDirectoryFacts] = {}
        self.security: dict[object, NativeSecurityFacts] = {}
        self.closed: list[object] = []

    def current_user_sid(self) -> str:
        return _CURRENT_USER

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        final = path if path.startswith("\\\\?\\") else rf"\\?\{path}"
        handle = object()
        self.handles[handle] = NativeDirectoryFacts(
            final_path=final,
            volume_serial=7,
            file_id=_file_id(final),
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )
        self.security[handle] = NativeSecurityFacts(
            owner_sid=_CURRENT_USER,
            dacl_present=True,
            allowed_aces=(AccessAllowedAce(_CURRENT_USER, 0x001F01FF, 0),),
        )
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        return self.handles[handle]

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self.security[handle]

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


class _FileApi:
    supported = True

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = {path.casefold(): value for path, value in files.items()}
        self.handles: dict[object, str] = {}
        self.cursors: dict[object, int] = {}
        self.closed: list[object] = []

    def open_file_for_identity(self, path: str) -> object:
        key = path.casefold()
        if key not in self.files:
            raise OSError("missing")
        handle = object()
        self.handles[handle] = key
        self.cursors[handle] = 0
        return handle

    def open_file_for_hydrated_identity(self, path: str) -> object:
        return self.open_file_for_identity(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        path = self.handles[handle]
        content = self.files[path]
        return NativeFileFacts(
            final_path=path,
            volume_serial=7,
            file_id=_file_id(path),
            attributes=0x80,
            link_count=1,
            size=len(content),
            creation_time=1,
            last_write_time=2,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def rewind_file(self, handle: object) -> None:
        self.cursors[handle] = 0

    def seek_file(self, handle: object, offset: int) -> None:
        self.cursors[handle] = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        path = self.handles[handle]
        cursor = self.cursors[handle]
        value = self.files[path][cursor : cursor + maximum]
        self.cursors[handle] += len(value)
        return value

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


def _dependency_evidence() -> CpythonDependencyEvidence:
    return CpythonDependencyEvidence(
        product_id=RuntimeProductId.CPYTHON,
        exact_version="3.12.10",
        policy_sha256="1" * 64,
        archive_sha256="2" * 64,
        inventory_sha256="3" * 64,
        static_import_surface_sha256="4" * 64,
        pe_file_count=47,
        amd64_loadable_count=43,
        signer_policy_count=5,
        exact_native_inventory_bound=True,
        static_dependency_manifests_closed=True,
        dynamic_load_policy_required=True,
    )


def _empty_manifest() -> PeDependencyManifest:
    digest = hashlib.sha256()
    for value in (
        b"TowerScout.PeDependencyManifest.v1",
        b"delay",
        b"forwarded",
    ):
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return PeDependencyManifest((), (), (), digest.hexdigest())


def _open(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN202
    policy = load_package_bound_runtime_dependency_policy()
    records = (*policy.cpython.loadable_files, *policy.cpython.non_amd64_pe_files)
    files = {
        str(_ROOT.joinpath(*record.path.split("/"))): record.path.encode("ascii")
        for record in records
    }
    file_api = _FileApi(files)
    executable = capture_handle_bound_file(Path(_PYTHON), api=file_api)
    path_api = _PathApi()

    def inspect(bound_file, record, **_kwargs):  # noqa: ANN001, ANN202
        machine = (
            PeMachine.AMD64
            if not isinstance(record, NonAmd64PeFile)
            else record.machine
        )
        return DependencyFileObservation(
            path=record.path,
            sha256=bound_file.snapshot.sha256,
            machine=machine,
            signer_certificate_sha256=None,
            dependency_manifest=None,
        )

    monkeypatch.setattr(
        capture_module,
        "validate_package_bound_cpython_dependency_observations",
        lambda observations: _dependency_evidence(),
    )
    monkeypatch.setattr(capture_module, "_default_inspector", inspect)
    owner = capture_package_bound_cpython_dependency_inventory(
        executable,
        path_api=path_api,
        file_api=file_api,
    )
    return owner, executable, path_api, file_api


def test_holds_exact_policy_inventory_through_synchronous_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, executable, path_api, file_api = _open(monkeypatch)

    with owner:
        evidence = owner.evidence
        assert evidence.held_file_count == 47
        assert evidence.held_directory_count >= 1
        assert evidence.exact_policy_paths_bound
        assert evidence.unsigned_state_structurally_verified
        assert evidence.handles_retained_through_operation
        assert not evidence.arbitrary_dynamic_destinations_denied_by_this_layer

        def operation() -> str:
            assert not file_api.closed
            assert not path_api.closed
            policy = owner.active_dynamic_load_policy()
            assert len(policy.exact_files) == 43
            assert sum(binding.entrypoint for binding in policy.exact_files) == 1
            assert "ntdll.dll" in policy.system_image_names
            assert "api-ms-win-core-path-l1-1-0.dll" in policy.system_image_names
            assert all(
                "Python312" not in repr(binding) for binding in policy.exact_files
            )
            return "complete"

        assert owner.run_while_held(operation) == "complete"
        assert owner.assert_unchanged() == evidence
        assert "Python312" not in repr(owner)

    assert len(file_api.closed) == 46
    assert path_api.closed
    assert not executable.closed
    executable.close()


def test_dynamic_load_bindings_are_available_only_during_held_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, executable, _path_api, _file_api = _open(monkeypatch)

    with pytest.raises(CpythonDependencyCaptureError) as failure:
        owner.active_dynamic_load_policy()
    assert failure.value.code is CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED

    captured = owner.run_while_held(owner.active_dynamic_load_policy)
    assert len(captured.exact_files) == 43

    with pytest.raises(CpythonDependencyCaptureError) as failure:
        owner.active_dynamic_load_policy()
    assert failure.value.code is CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED
    owner.close()
    executable.close()


def test_operation_failure_revalidates_and_preserves_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, executable, _path_api, _file_api = _open(monkeypatch)

    with owner, pytest.raises(KeyboardInterrupt):
        owner.run_while_held(lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
    executable.close()


def test_changed_dependency_fails_closed_before_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, executable, _path_api, file_api = _open(monkeypatch)
    policy = load_package_bound_runtime_dependency_policy()
    changed = next(
        record.path
        for record in policy.cpython.loadable_files
        if record.path.casefold() != "python.exe"
    )
    key = str(_ROOT.joinpath(*changed.split("/"))).casefold()
    file_api.files[key] += b"changed"
    called = False

    def operation() -> None:
        nonlocal called
        called = True

    with pytest.raises(CpythonDependencyCaptureError) as failure:
        owner.run_while_held(operation)
    assert failure.value.code is CpythonDependencyCaptureErrorCode.INVENTORY_CHANGED
    assert not called
    owner.close()
    executable.close()


def test_supplied_executable_cannot_close_until_operation_and_postcheck_finish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, executable, _path_api, _file_api = _open(monkeypatch)
    close_started = threading.Event()
    close_returned = threading.Event()

    def close_executable() -> None:
        close_started.set()
        executable.close()
        close_returned.set()

    thread: threading.Thread | None = None

    def operation() -> str:
        nonlocal thread
        thread = threading.Thread(target=close_executable)
        thread.start()
        assert close_started.wait(2)
        assert not close_returned.wait(0.05)
        return "complete"

    assert owner.run_while_held(operation) == "complete"
    assert thread is not None
    thread.join(2)
    assert close_returned.is_set()
    assert executable.closed
    owner.close()


def test_unsigned_proof_rejects_present_embedded_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = NonAmd64PeFile(
        path="unsigned.exe",
        sha256="0" * 64,
        machine=PeMachine.I386,
        signature_policy="upstream_unsigned_exact_hash_only",
    )
    monkeypatch.setattr(
        capture_module,
        "_metadata",
        lambda _bound: PeImageMetadata(0x014C, True),
    )

    with pytest.raises(CpythonDependencyCaptureError) as failure:
        capture_module._default_inspector(  # noqa: SLF001
            object(),  # type: ignore[arg-type]
            record,
            authenticode_backend=None,
            clock=None,
        )
    assert failure.value.code is CpythonDependencyCaptureErrorCode.INVENTORY_UNSAFE


def test_signed_default_inspector_requires_exact_signer_on_same_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = "a" * 64
    file_hash = "b" * 64
    manifest = _empty_manifest()
    record = ApprovedDependencyFile(
        path="signed.pyd",
        sha256=file_hash,
        signature_policy=DependencySignaturePolicy.EXACT_AUTHENTICODE_SIGNER,
        signer_certificate_sha256=signer,
        dependency_manifest_sha256=manifest.evidence_sha256,
    )
    bound = SimpleNamespace(snapshot=SimpleNamespace(sha256=file_hash))
    calls: list[str] = []
    monkeypatch.setattr(
        capture_module,
        "_metadata",
        lambda _bound: PeImageMetadata(0x8664, True),
    )
    monkeypatch.setattr(
        capture_module,
        "inspect_handle_bound_pe_dependencies",
        lambda _bound: manifest,
    )

    def verify(_bound, expected, **_kwargs):  # noqa: ANN001, ANN202
        calls.append(expected)
        return SimpleNamespace(
            file_sha256=file_hash,
            signer_certificate_sha256=signer,
        )

    monkeypatch.setattr(
        capture_module,
        "verify_package_bound_dependency_authenticode_signer",
        verify,
    )

    observation = capture_module._default_inspector(  # noqa: SLF001
        bound,  # type: ignore[arg-type]
        record,
        authenticode_backend=None,
        clock=None,
    )
    assert observation.signer_certificate_sha256 == signer
    assert observation.dependency_manifest == manifest
    assert calls == [signer]


def test_unsigned_default_inspector_never_converts_trust_failure_to_unsigned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_hash = "c" * 64
    manifest = _empty_manifest()
    record = ApprovedDependencyFile(
        path="unsigned.pyd",
        sha256=file_hash,
        signature_policy=(DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY),
        signer_certificate_sha256=None,
        dependency_manifest_sha256=manifest.evidence_sha256,
    )
    bound = SimpleNamespace(snapshot=SimpleNamespace(sha256=file_hash))
    monkeypatch.setattr(
        capture_module,
        "_metadata",
        lambda _bound: PeImageMetadata(0x8664, False),
    )
    monkeypatch.setattr(
        capture_module,
        "inspect_handle_bound_pe_dependencies",
        lambda _bound: manifest,
    )
    monkeypatch.setattr(
        capture_module,
        "verify_package_bound_dependency_authenticode_signer",
        lambda *_args, **_kwargs: pytest.fail("unsigned file reached trust verifier"),
    )

    observation = capture_module._default_inspector(  # noqa: SLF001
        bound,  # type: ignore[arg-type]
        record,
        authenticode_backend=None,
        clock=None,
    )
    assert observation.signer_certificate_sha256 is None
    assert observation.dependency_manifest == manifest


def test_capture_slice_remains_unwired_and_non_executable() -> None:
    source = Path(capture_module.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "CreateProcess" not in source
    assert "Popen" not in source

    for relative in (
        "towerscout_launcher/app.py",
        "towerscout_launcher/runtime_execution.py",
        "towerscout_launcher/runtime_verification.py",
        "towerscout_launcher/repair_controller.py",
    ):
        consumer = LAUNCHER_ROOT / relative
        if consumer.is_file():
            assert "runtime_dependency_capture" not in consumer.read_text(
                encoding="utf-8"
            )
