from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import replace
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_load_trust as runtime_load_trust  # noqa: E402
from towerscout_launcher.runtime_load_trust import (  # noqa: E402
    DirectoryEntry,
    LoadableAuthentication,
    NativeRuntimeLoadInventoryApi,
    RuntimeLoadTrustError,
    RuntimeLoadTrustErrorCode,
    capture_runtime_load_prerequisites,
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
_APP = r"\\?\C:\Program Files\Vendor"
_EXE = _APP + r"\docker-compose.exe"
_SYSTEM = r"C:\Windows\System32"
_WINDOWS = r"C:\Windows"


def _file_id(value: str) -> bytes:
    digest = hashlib.sha256(value.casefold().encode("utf-8")).digest()
    return digest[:16]


def _directory_facts(path: str) -> NativeDirectoryFacts:
    final = path if path.startswith("\\\\?\\") else rf"\\?\{path}"
    return NativeDirectoryFacts(
        final_path=final,
        volume_serial=9,
        file_id=_file_id(final),
        attributes=0x10,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


def _security() -> NativeSecurityFacts:
    return NativeSecurityFacts(
        owner_sid=_CURRENT_USER,
        dacl_present=True,
        allowed_aces=(AccessAllowedAce(_CURRENT_USER, 0x001F01FF, 0),),
    )


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
        self.handles[handle] = _directory_facts(path)
        self.security[handle] = _security()
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        return self.handles[handle]

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self.security.get(handle, _security())

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
            raise OSError("missing private file")
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
            volume_serial=9,
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

    def read_file(self, handle: object, maximum: int) -> bytes:
        path = self.handles[handle]
        cursor = self.cursors[handle]
        chunk = self.files[path][cursor : cursor + maximum]
        self.cursors[handle] += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


class _InventoryApi:
    supported = True

    def __init__(self, entries: tuple[DirectoryEntry, ...] = ()) -> None:
        self.entries = entries
        self.dll_directory = ""
        self.list_hook = None

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]:
        del path
        if self.list_hook is not None:
            hook = self.list_hook
            self.list_hook = None
            hook()
        return self.entries

    def current_dll_directory(self) -> str:
        return self.dll_directory

    def system_directory(self) -> str:
        return _SYSTEM

    def windows_directory(self) -> str:
        return _WINDOWS


def _authenticate(
    bound_file, product_id: RuntimeProductId
) -> LoadableAuthentication:  # noqa: ANN001
    return LoadableAuthentication(
        signer_product_ids=(product_id,),
        evidence_sha256=hashlib.sha256(
            bound_file.snapshot.sha256.encode("ascii")
        ).hexdigest(),
    )


def _open(
    *,
    entries: tuple[DirectoryEntry, ...] = (),
    files: dict[str, bytes] | None = None,
):  # noqa: ANN202
    file_api = _FileApi({_EXE: b"exe", **(files or {})})
    executable = capture_handle_bound_file(Path(_EXE), api=file_api)
    path_api = _PathApi()
    inventory = _InventoryApi(entries)
    owner = capture_runtime_load_prerequisites(
        RuntimeProductId.DOCKER_COMPOSE,
        executable,
        path_api=path_api,
        inventory_api=inventory,
        file_api=file_api,
        authenticate=_authenticate,
    )
    return owner, executable, path_api, inventory, file_api


def test_empty_adjacent_load_surface_binds_app_system_and_windows_directories() -> None:
    owner, executable, _path_api, _inventory, _file_api = _open()
    with owner:
        assert owner.evidence.product_id is RuntimeProductId.DOCKER_COMPOSE
        assert owner.evidence.executable_identity == executable.snapshot.identity
        assert owner.evidence.executable_sha256 == executable.snapshot.sha256
        assert len(owner.evidence.immediate_surface_sha256) == 64
        assert owner.evidence.loadable_count == 0
        assert owner.evidence.requires_empty_parent_dll_directory
        assert owner.evidence.requires_system32_working_directory
        assert owner.evidence.requires_empty_path
        assert owner.evidence.immediate_application_directory_bound
        assert owner.evidence.transitive_dependency_policy_required
        assert owner.assert_unchanged() == owner.evidence
        assert "Program Files" not in repr(owner)
        assert _CURRENT_USER not in repr(owner.evidence)
    executable.close()


def test_adjacent_dlls_and_pyds_are_held_hashed_acl_checked_and_authenticated() -> None:
    entries = (
        DirectoryEntry("helper.DLL", False, 0x80, 0),
        DirectoryEntry("extension.pyd", False, 0x80, 0),
        DirectoryEntry("readme.txt", False, 0x80, 0),
    )
    files = {
        _APP + r"\helper.DLL": b"MZdll",
        _APP + r"\extension.pyd": b"MZpyd",
        _APP + r"\readme.txt": b"not an executable image",
    }
    owner, executable, path_api, _inventory, file_api = _open(
        entries=entries, files=files
    )

    with owner:
        assert owner.evidence.loadable_count == 2
        assert owner.evidence.held_application_file_count == 3
        assert owner.assert_unchanged() == owner.evidence
        assert len(file_api.closed) == 0
        assert len(path_api.security) > 0

    # The closure owns all three adjacent files but not the executable supplied
    # by its caller, so closing it cannot invalidate that executable owner.
    assert len(file_api.closed) == 3
    assert not executable.closed
    executable.close()


def test_pe_image_with_arbitrary_long_name_is_authenticated_and_held() -> None:
    name = "dependency-image-with-an-arbitrary-extension.bin"
    entry = DirectoryEntry(name, False, 0x80, 0)
    owner, executable, _path_api, _inventory, file_api = _open(
        entries=(entry,),
        files={_APP + "\\" + name: b"MZportable-executable"},
    )

    with owner:
        assert owner.evidence.loadable_count == 1
        assert owner.evidence.held_application_file_count == 1
        assert owner.assert_unchanged() == owner.evidence

    assert len(file_api.closed) == 1
    executable.close()


@pytest.mark.parametrize(
    "entry",
    (
        DirectoryEntry("docker-compose.exe.local", True, 0x10, 0),
        DirectoryEntry("docker-compose.exe.manifest", False, 0x80, 0),
        DirectoryEntry("HELPER.dll", False, 0x480, 0xA000000C),
    ),
)
def test_redirection_manifest_or_reparse_loadable_fails_closed(
    entry: DirectoryEntry,
) -> None:
    files = {_APP + "\\" + entry.name: b"unsafe"} if not entry.is_directory else {}
    file_api = _FileApi({_EXE: b"exe", **files})
    executable = capture_handle_bound_file(Path(_EXE), api=file_api)

    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        capture_runtime_load_prerequisites(
            RuntimeProductId.DOCKER_COMPOSE,
            executable,
            path_api=_PathApi(),
            inventory_api=_InventoryApi((entry,)),
            file_api=file_api,
            authenticate=_authenticate,
        )

    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE
    executable.close()


def test_nonempty_parent_dll_directory_fails_before_module_capture() -> None:
    file_api = _FileApi({_EXE: b"exe"})
    executable = capture_handle_bound_file(Path(_EXE), api=file_api)
    inventory = _InventoryApi()
    inventory.dll_directory = r"C:\Users\private-user\attacker"

    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        capture_runtime_load_prerequisites(
            RuntimeProductId.DOCKER_COMPOSE,
            executable,
            path_api=_PathApi(),
            inventory_api=inventory,
            file_api=file_api,
            authenticate=_authenticate,
        )

    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE
    assert "private-user" not in str(exc_info.value)
    executable.close()


def test_inventory_security_and_file_drift_are_detected() -> None:
    entry = DirectoryEntry("helper.dll", False, 0x80, 0)
    module_path = _APP + r"\helper.dll"
    owner, executable, path_api, inventory, file_api = _open(
        entries=(entry,), files={module_path: b"MZdll"}
    )

    inventory.entries = ()
    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        owner.assert_unchanged()
    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED
    inventory.entries = (entry,)

    module_handle = next(
        handle
        for handle, path in file_api.handles.items()
        if path == module_path.casefold()
    )
    path_api.security[module_handle] = replace(
        _security(),
        owner_sid="S-1-5-21-999-888-777-1009",
    )
    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        owner.assert_unchanged()
    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED

    owner.close()
    executable.close()


def test_same_thread_close_during_load_revalidation_fails_without_closing() -> None:
    owner, executable, _path_api, inventory, _file_api = _open()
    inventory.list_hook = owner.close

    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        owner.assert_unchanged()

    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_CHANGED
    assert not owner.closed
    owner.close()
    executable.close()


def test_interruption_before_file_ownership_transfer_closes_all_captured_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = DirectoryEntry("helper.dll", False, 0x80, 0)
    module_path = _APP + r"\helper.dll"
    file_api = _FileApi({_EXE: b"exe", module_path: b"MZdll"})
    executable = capture_handle_bound_file(Path(_EXE), api=file_api)
    path_api = _PathApi()

    def interrupt(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime_load_trust, "_HeldApplicationFile", interrupt)
    with pytest.raises(KeyboardInterrupt):
        capture_runtime_load_prerequisites(
            RuntimeProductId.DOCKER_COMPOSE,
            executable,
            path_api=path_api,
            inventory_api=_InventoryApi((entry,)),
            file_api=file_api,
            authenticate=_authenticate,
        )

    assert len(file_api.closed) == 1
    assert len(path_api.closed) == len(path_api.handles)
    executable.close()


def test_wrong_signer_or_case_colliding_inventory_fails_closed() -> None:
    entry = DirectoryEntry("helper.dll", False, 0x80, 0)
    module_path = _APP + r"\helper.dll"
    file_api = _FileApi({_EXE: b"exe", module_path: b"MZdll"})
    executable = capture_handle_bound_file(Path(_EXE), api=file_api)

    def wrong_signer(bound_file, product_id):  # noqa: ANN001, ANN202
        del bound_file, product_id
        return LoadableAuthentication(
            signer_product_ids=(RuntimeProductId.PODMAN_CLI,),
            evidence_sha256="a" * 64,
        )

    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        capture_runtime_load_prerequisites(
            RuntimeProductId.DOCKER_COMPOSE,
            executable,
            path_api=_PathApi(),
            inventory_api=_InventoryApi((entry,)),
            file_api=file_api,
            authenticate=wrong_signer,
        )
    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE

    with pytest.raises(RuntimeLoadTrustError) as exc_info:
        capture_runtime_load_prerequisites(
            RuntimeProductId.DOCKER_COMPOSE,
            executable,
            path_api=_PathApi(),
            inventory_api=_InventoryApi(
                (
                    DirectoryEntry("helper.dll", False, 0x80, 0),
                    DirectoryEntry("HELPER.DLL", False, 0x80, 0),
                )
            ),
            file_api=file_api,
            authenticate=_authenticate,
        )
    assert exc_info.value.code is RuntimeLoadTrustErrorCode.LOAD_PATH_UNSAFE
    executable.close()


def test_directory_entry_representation_redacts_the_leaf_name() -> None:
    entry = DirectoryEntry("private-helper.dll", False, 0x80, 0)

    assert "private-helper" not in repr(entry)


@pytest.mark.parametrize(
    "entry",
    (
        ("alternate:stream.dll", False, 0x80, 0),
        ("trailing-dot.", False, 0x80, 0),
        ("mismatched-directory", True, 0x80, 0),
    ),
)
def test_directory_entry_rejects_noncanonical_or_inconsistent_facts(
    entry: tuple[str, bool, int, int],
) -> None:
    with pytest.raises(ValueError):
        DirectoryEntry(*entry)


def test_source_slice_remains_unwired_from_launcher_and_mutation_paths() -> None:
    for relative in (
        "app.py",
        "discovery.py",
        "repair.py",
        "runtime_execution.py",
        "coordination.py",
    ):
        source = (LAUNCHER_ROOT / "towerscout_launcher" / relative).read_text(
            encoding="utf-8"
        )
        assert "runtime_load_trust" not in source
        assert "windows_path_trust" not in source


def test_native_inventory_api_degrades_closed_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "name", "posix")
        api = NativeRuntimeLoadInventoryApi()

    assert not api.supported
    with pytest.raises(OSError):
        api.current_dll_directory()


@pytest.mark.skipif(os.name != "nt", reason="native Windows load inventory proof")
def test_native_inventory_api_reads_empty_parent_dll_directory() -> None:
    api = NativeRuntimeLoadInventoryApi()

    assert api.supported
    assert api.current_dll_directory() == ""
    assert PureWindowsPath(api.system_directory()).is_absolute()
    assert PureWindowsPath(api.windows_directory()).is_absolute()
    entries = api.list_directory(str(LAUNCHER_ROOT / "towerscout_launcher"))
    assert entries
    assert len({entry.name.casefold() for entry in entries}) == len(entries)
