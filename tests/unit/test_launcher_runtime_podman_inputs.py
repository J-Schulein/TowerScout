from __future__ import annotations

import hashlib
import inspect
import sys
import threading
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_podman_inputs as inputs_module  # noqa: E402
from towerscout_launcher.runtime_dependency_capture import (  # noqa: E402
    HeldCpythonDependencyInventory,
)
from towerscout_launcher.runtime_load_trust import DirectoryEntry  # noqa: E402
from towerscout_launcher.runtime_podman_endpoint import (  # noqa: E402
    BoundPodmanRuntimeEndpointInputs,
    PodmanRuntimeEndpointInputs,
)
from towerscout_launcher.runtime_podman_inputs import (  # noqa: E402
    BoundManagedPodmanComposeProvider,
    BoundPodmanTargetSourceInputs,
    PodmanInputError,
    PodmanInputErrorCode,
    PodmanTargetSourceInputs,
    _capture_managed_podman_compose_provider,
    _parse_venv_config,
    capture_native_windows_managed_podman_compose_provider,
    capture_native_windows_podman_target_source_inputs,
)
from towerscout_launcher.runtime_podman_provider import (  # noqa: E402
    ManagedPodmanProviderInventoryEvidence,
)
from towerscout_launcher.runtime_policy import (  # noqa: E402
    RuntimeProductId,
    load_package_bound_runtime_policy,
)
from towerscout_launcher.runtime_verification import BoundRuntimeEvidence  # noqa: E402
from towerscout_launcher.target_contracts import (  # noqa: E402
    EndpointIdentity,
    EndpointKind,
    FileIdentity,
    RuntimeIdentity,
    RuntimeProduct,
)
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
_PACKAGE_ROOT = PureWindowsPath(r"C:\TowerScout")
_BASE_PYTHON = PureWindowsPath(r"C:\Python312\python.exe")


def _digest(value: str | bytes) -> str:
    encoded = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
        handle = object()
        self.handles[handle] = NativeDirectoryFacts(
            final_path=path,
            volume_serial=7,
            file_id=_file_id(path),
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


class _DirectoryApi:
    supported = True

    def __init__(self, entries: dict[str, tuple[DirectoryEntry, ...]]) -> None:
        self.entries = {path.casefold(): value for path, value in entries.items()}

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]:
        return self.entries[path.casefold()]


class _Candidate:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _entry(name: str, *, directory: bool = False) -> DirectoryEntry:
    return DirectoryEntry(name, directory, 0x10 if directory else 0x80, 0)


def _provider_fixture() -> tuple[
    dict[str, bytes],
    dict[str, tuple[DirectoryEntry, ...]],
    PureWindowsPath,
]:
    policy = load_package_bound_runtime_policy()
    provider = policy.podman_compose
    provider_root = _PACKAGE_ROOT.joinpath(
        *PureWindowsPath(provider.managed_install_root).parts
    )
    wheelhouse = provider_root / provider.inventory.wheelhouse_relative_path
    scripts = provider_root / ".venv" / "Scripts"
    site_packages = provider_root / ".venv" / "Lib" / "site-packages"
    catalog = _PACKAGE_ROOT / "scripts" / "podman-compose-providers.v1.json"
    module = site_packages / "podman_compose.py"
    files = {
        str(catalog): b"synthetic catalog",
        str(module): b"VERSION = '1.5.0'\n",
        str(scripts / "python.exe"): b"venv-python",
        str(scripts / "podman-compose.exe"): b"entrypoint",
        str(provider_root / ".venv" / "pyvenv.cfg"): (
            b"home = C:\\Python312\n"
            b"include-system-site-packages = false\n"
            b"version = 3.12.10\n"
            b"executable = C:\\Python312\\python.exe\n"
        ),
        str(_BASE_PYTHON): b"base-python",
    }
    for distribution in provider.distributions:
        files[str(wheelhouse / distribution.wheel_filename)] = (
            distribution.wheel_filename.encode("ascii")
        )
    entries = {
        str(provider_root): (
            _entry(".venv", directory=True),
            _entry("wheelhouse", directory=True),
        ),
        str(wheelhouse): tuple(
            _entry(value)
            for value in sorted(
                (item.wheel_filename for item in provider.distributions),
                key=lambda value: (value.casefold(), value),
            )
        ),
        str(scripts): (_entry("podman-compose.exe"), _entry("python.exe")),
        str(_PACKAGE_ROOT / "scripts"): (_entry("podman-compose-providers.v1.json"),),
        str(site_packages): (_entry("podman_compose.py"),),
    }
    return files, entries, provider_root


def _patch_provider_verifiers(
    monkeypatch: pytest.MonkeyPatch,
    file_api: _FileApi,
) -> None:
    policy = load_package_bound_runtime_policy()
    base_file = capture_handle_bound_file(Path(str(_BASE_PYTHON)), api=file_api)
    candidate = _Candidate()
    base_owner = object.__new__(BoundRuntimeEvidence)
    base_owner._candidate = candidate  # type: ignore[assignment]  # noqa: SLF001
    base_owner._evidence = SimpleNamespace(  # type: ignore[assignment]  # noqa: SLF001
        product_id=RuntimeProductId.CPYTHON,
        exact_version="3.12.10",
        policy_sha256=policy.content_sha256,
        evidence_sha256=_digest("base-evidence"),
        authenticode=SimpleNamespace(signer_certificate_sha256="a" * 64),
    )
    base_owner._lifetime_lock = threading.RLock()  # noqa: SLF001
    base_owner._active_owner = None  # noqa: SLF001

    def transfer(self: BoundRuntimeEvidence, slot: Any) -> None:
        assert self is base_owner
        slot._accept(base_file)  # noqa: SLF001
        candidate.closed = True

    monkeypatch.setattr(BoundRuntimeEvidence, "_transfer_bound_file", transfer)
    monkeypatch.setattr(
        inputs_module,
        "open_package_bound_runtime_evidence",
        lambda *_args, **_kwargs: base_owner,
    )
    monkeypatch.setattr(
        inputs_module,
        "verify_package_bound_pe_product",
        lambda *_args, **_kwargs: SimpleNamespace(
            product_id=RuntimeProductId.CPYTHON,
            exact_version="3.12.10",
            policy_sha256=policy.content_sha256,
            evidence_sha256=_digest("venv-pe"),
        ),
    )
    monkeypatch.setattr(
        inputs_module,
        "verify_package_bound_authenticode_signer",
        lambda *_args, **_kwargs: SimpleNamespace(
            signer_policy_product_ids=(RuntimeProductId.CPYTHON,),
            policy_sha256=policy.content_sha256,
            signer_certificate_sha256="a" * 64,
            evidence_sha256=_digest("venv-authenticode"),
        ),
    )

    dependency = object.__new__(HeldCpythonDependencyInventory)
    dependency_state = {id(dependency): False}
    monkeypatch.setattr(
        HeldCpythonDependencyInventory,
        "closed",
        property(lambda self: dependency_state[id(self)]),
    )
    monkeypatch.setattr(
        HeldCpythonDependencyInventory,
        "evidence",
        property(
            lambda _self: SimpleNamespace(
                dependency=SimpleNamespace(inventory_sha256=_digest("base-inventory"))
            )
        ),
    )
    monkeypatch.setattr(
        HeldCpythonDependencyInventory,
        "run_while_held",
        lambda _self, operation: base_file.run_while_held(operation),
    )
    monkeypatch.setattr(
        HeldCpythonDependencyInventory,
        "close",
        lambda self: dependency_state.__setitem__(id(self), True),
    )
    monkeypatch.setattr(
        inputs_module,
        "capture_package_bound_cpython_dependency_inventory",
        lambda executable, **_kwargs: dependency if executable is base_file else None,
    )

    def verify_inventory(
        *,
        catalog_bytes: bytes,
        wheels: tuple[Any, ...],
        installed_files: tuple[Any, ...],
    ) -> ManagedPodmanProviderInventoryEvidence:
        assert catalog_bytes == b"synthetic catalog"
        assert len(wheels) == 3
        assert len(installed_files) == 1
        return ManagedPodmanProviderInventoryEvidence(
            provider_id=policy.podman_compose.provider_id,
            provider_version=policy.podman_compose.exact_version,
            policy_sha256=policy.content_sha256,
            catalog_sha256=_digest(catalog_bytes),
            wheel_sha256s=tuple(_digest(item.contents) for item in wheels),
            distribution_count=3,
            installed_file_count=1,
            loadable_artifacts=installed_files,
            inventory_sha256=_digest("provider-inventory"),
        )

    monkeypatch.setattr(
        inputs_module,
        "verify_managed_podman_compose_source_inventory",
        verify_inventory,
    )


def _capture_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[BoundManagedPodmanComposeProvider, _DirectoryApi, _FileApi]:
    files, entries, _provider_root = _provider_fixture()
    file_api = _FileApi(files)
    directory_api = _DirectoryApi(entries)
    _patch_provider_verifiers(monkeypatch, file_api)
    owner = _capture_managed_podman_compose_provider(
        _PACKAGE_ROOT,
        path_api=_PathApi(),
        file_api=file_api,
        directory_api=directory_api,
    )
    return owner, directory_api, file_api


def _podman_pair_inputs(policy_sha256: str) -> PodmanRuntimeEndpointInputs:
    podman = FileIdentity(
        "podman.exe",
        PureWindowsPath(r"C:\Program Files\RedHat\Podman\podman.exe"),
        91,
        (91).to_bytes(16, "big"),
        sha256=_digest("podman"),
        size_bytes=10,
    )
    key = FileIdentity(
        "podman_identity_key",
        PureWindowsPath(r"C:\Users\PRIVATE\.ssh\podman-machine"),
        92,
        (92).to_bytes(16, "big"),
        sha256=_digest("key"),
        size_bytes=10,
    )
    return PodmanRuntimeEndpointInputs(
        RuntimeIdentity(RuntimeProduct.PODMAN, podman, "6.0.2", policy_sha256),
        EndpointIdentity(
            RuntimeProduct.PODMAN,
            EndpointKind.PODMAN_ROOTLESS_WSL,
            "ssh://core@127.0.0.1:52122/run/user/1000/podman/podman.sock",
            _digest("endpoint"),
            identity_key=key,
            rootless=True,
        ),
    )


def _pair(
    monkeypatch: pytest.MonkeyPatch,
    inputs: PodmanRuntimeEndpointInputs,
) -> tuple[BoundPodmanRuntimeEndpointInputs, dict[int, bool]]:
    owner = object.__new__(BoundPodmanRuntimeEndpointInputs)
    state = {id(owner): False}
    monkeypatch.setattr(
        BoundPodmanRuntimeEndpointInputs,
        "closed",
        property(lambda self: state[id(self)]),
    )
    monkeypatch.setattr(
        BoundPodmanRuntimeEndpointInputs,
        "supported",
        property(lambda self: not state[id(self)]),
    )
    monkeypatch.setattr(
        BoundPodmanRuntimeEndpointInputs,
        "capture",
        lambda _self: inputs,
    )
    monkeypatch.setattr(
        BoundPodmanRuntimeEndpointInputs,
        "close",
        lambda self: state.__setitem__(id(self), True),
    )
    return owner, state


def test_managed_provider_captures_complete_source_and_base_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _directory_api, _file_api = _capture_provider(monkeypatch)
    identity = owner.capture()

    assert identity.provider_id == "podman-compose-pypi-1.5.0"
    assert identity.artifacts[0].logical_name == "python.exe"
    assert identity.artifacts[1].logical_name == "podman_compose_module"
    assert any(
        item.logical_name == "podman_compose_entrypoint" for item in identity.artifacts
    )
    assert any(item.logical_name == "podman_venv_config" for item in identity.artifacts)
    assert (
        sum(
            item.logical_name.startswith("podman_provider_wheel_")
            for item in identity.artifacts
        )
        == 3
    )
    assert owner.supported
    assert "redacted" in repr(owner).lower()

    owner.close()
    owner.close()
    assert owner.closed


def test_managed_provider_rejects_post_capture_directory_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, directory_api, _file_api = _capture_provider(monkeypatch)
    site_packages = next(
        path
        for path in directory_api.entries
        if path.endswith(r"\.venv\lib\site-packages")
    )
    directory_api.entries[site_packages] += (_entry("sitecustomize.py"),)

    with pytest.raises(PodmanInputError) as captured:
        owner.capture()

    assert captured.value.code is PodmanInputErrorCode.INPUTS_CHANGED
    owner.close()


def test_managed_provider_rejects_held_file_content_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _directory_api, file_api = _capture_provider(monkeypatch)
    module_path = next(
        path for path in file_api.files if path.endswith("podman_compose.py")
    )
    file_api.files[module_path] = b"changed"

    with pytest.raises(PodmanInputError) as captured:
        owner.capture()

    assert captured.value.code is PodmanInputErrorCode.INPUTS_CHANGED
    owner.close()


def test_managed_provider_rejects_extra_empty_site_packages_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, entries, provider_root = _provider_fixture()
    site_packages = provider_root / ".venv" / "Lib" / "site-packages"
    entries[str(site_packages)] += (_entry("unowned", directory=True),)
    entries[str(site_packages / "unowned")] = ()
    file_api = _FileApi(files)
    _patch_provider_verifiers(monkeypatch, file_api)

    with pytest.raises(PodmanInputError) as captured:
        _capture_managed_podman_compose_provider(
            _PACKAGE_ROOT,
            path_api=_PathApi(),
            file_api=file_api,
            directory_api=_DirectoryApi(entries),
        )

    assert captured.value.code is PodmanInputErrorCode.PROVIDER_INVALID


def test_managed_provider_rejects_native_script_directory_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, entries, provider_root = _provider_fixture()
    scripts = provider_root / ".venv" / "Scripts"
    entries[str(scripts)] += (_entry("python312.dll"),)
    files[str(scripts / "python312.dll")] = b"attacker"
    file_api = _FileApi(files)
    _patch_provider_verifiers(monkeypatch, file_api)

    with pytest.raises(PodmanInputError) as captured:
        _capture_managed_podman_compose_provider(
            _PACKAGE_ROOT,
            path_api=_PathApi(),
            file_api=file_api,
            directory_api=_DirectoryApi(entries),
        )

    assert captured.value.code is PodmanInputErrorCode.PROVIDER_INVALID


@pytest.mark.parametrize(
    ("name", "directory"),
    (
        ("python._pth", False),
        ("python312._pth", False),
        ("pyvenv.cfg", False),
        ("python.exe.local", True),
        ("python312.zip", False),
        ("sitecustomize.py", False),
    ),
)
def test_managed_provider_rejects_interpreter_startup_path_override(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    directory: bool,
) -> None:
    files, entries, provider_root = _provider_fixture()
    scripts = provider_root / ".venv" / "Scripts"
    entries[str(scripts)] += (_entry(name, directory=directory),)
    file_api = _FileApi(files)
    _patch_provider_verifiers(monkeypatch, file_api)

    with pytest.raises(PodmanInputError) as captured:
        _capture_managed_podman_compose_provider(
            _PACKAGE_ROOT,
            path_api=_PathApi(),
            file_api=file_api,
            directory_api=_DirectoryApi(entries),
        )

    assert captured.value.code is PodmanInputErrorCode.PROVIDER_INVALID


def test_venv_config_requires_exact_authenticated_base_path() -> None:
    with pytest.raises(PodmanInputError) as captured:
        _parse_venv_config(
            b"home = C:\\OtherPython\n"
            b"include-system-site-packages = false\n"
            b"version = 3.12.10\n"
            b"executable = C:\\OtherPython\\python.exe\n",
            base_executable=_BASE_PYTHON,
            expected_version="3.12.10",
        )

    assert captured.value.code is PodmanInputErrorCode.PROVIDER_INVALID


def test_joined_source_owner_revalidates_runtime_endpoint_and_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _directory_api, _file_api = _capture_provider(monkeypatch)
    policy = load_package_bound_runtime_policy()
    pair, state = _pair(monkeypatch, _podman_pair_inputs(policy.content_sha256))
    owner = BoundPodmanTargetSourceInputs(runtime_endpoint=pair, provider=provider)

    inputs = owner.capture()

    assert isinstance(inputs, PodmanTargetSourceInputs)
    assert inputs.runtime.product is RuntimeProduct.PODMAN
    assert inputs.endpoint.rootless is True
    assert inputs.compose_provider == provider.identity
    owner.close()
    assert state[id(pair)]
    assert provider.closed


def test_native_join_factory_closes_runtime_endpoint_when_provider_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_package_bound_runtime_policy()
    pair, state = _pair(monkeypatch, _podman_pair_inputs(policy.content_sha256))
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_podman_runtime_endpoint_inputs",
        lambda _root: pair,
    )
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_managed_podman_compose_provider",
        lambda _root: (_ for _ in ()).throw(
            PodmanInputError(PodmanInputErrorCode.PROVIDER_INVALID)
        ),
    )

    with pytest.raises(PodmanInputError) as captured:
        capture_native_windows_podman_target_source_inputs(_PACKAGE_ROOT)

    assert captured.value.code is PodmanInputErrorCode.PROVIDER_INVALID
    assert state[id(pair)]


def test_native_join_factory_retries_transient_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_package_bound_runtime_policy()
    pair, state = _pair(monkeypatch, _podman_pair_inputs(policy.content_sha256))
    attempts = 0

    def close(candidate: BoundPodmanRuntimeEndpointInputs) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("transient path detail")
        state[id(candidate)] = True

    monkeypatch.setattr(BoundPodmanRuntimeEndpointInputs, "close", close)
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_podman_runtime_endpoint_inputs",
        lambda _root: pair,
    )
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_managed_podman_compose_provider",
        lambda _root: (_ for _ in ()).throw(
            PodmanInputError(PodmanInputErrorCode.PROVIDER_INVALID)
        ),
    )

    with pytest.raises(PodmanInputError) as captured:
        capture_native_windows_podman_target_source_inputs(_PACKAGE_ROOT)

    assert captured.value.code is PodmanInputErrorCode.PROVIDER_INVALID
    assert attempts == 2
    assert state[id(pair)]


def test_native_join_factory_preserves_cleanup_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_package_bound_runtime_policy()
    pair, state = _pair(monkeypatch, _podman_pair_inputs(policy.content_sha256))
    attempts = 0

    def close(candidate: BoundPodmanRuntimeEndpointInputs) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt()
        state[id(candidate)] = True

    monkeypatch.setattr(BoundPodmanRuntimeEndpointInputs, "close", close)
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_podman_runtime_endpoint_inputs",
        lambda _root: pair,
    )
    monkeypatch.setattr(
        inputs_module,
        "capture_native_windows_managed_podman_compose_provider",
        lambda _root: (_ for _ in ()).throw(RuntimeError("private path detail")),
    )

    with pytest.raises(KeyboardInterrupt):
        capture_native_windows_podman_target_source_inputs(_PACKAGE_ROOT)

    assert attempts == 2
    assert state[id(pair)]


def test_native_provider_factory_exposes_no_injectable_trust_seams() -> None:
    signature = inspect.signature(
        capture_native_windows_managed_podman_compose_provider
    )

    assert tuple(signature.parameters) == ("package_root",)


def test_new_podman_source_factory_remains_unwired() -> None:
    source_name = "runtime_podman_inputs"
    for module_name in ("app.py", "discovery.py", "repair.py", "runtime_execution.py"):
        source = (LAUNCHER_ROOT / "towerscout_launcher" / module_name).read_text(
            encoding="utf-8"
        )
        assert source_name not in source
