from __future__ import annotations

import hashlib
import inspect
import json
import sys
import threading
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_load_trust import DirectoryEntry  # noqa: E402
from towerscout_launcher.runtime_package_inputs import (  # noqa: E402
    BoundPackageEnvironmentInputs,
    PackageInputError,
    PackageInputErrorCode,
    _capture_package_environment_inputs,
    capture_native_windows_package_environment_inputs,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    ABSENT_FILE_SHA256,
    GpuMode,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    KNOWN_CLOUD_REPARSE_TAGS,
    HandleBoundFile,
    NativeFileFacts,
)

_ROOT = PureWindowsPath(r"C:\Users\reviewed-user\TowerScout")
_POLICY = _ROOT / "launcher" / "towerscout_launcher"
_FROZEN_POLICY = _ROOT / "launcher" / "_internal" / "towerscout_launcher"
_DIGEST = "sha256:" + "1" * 64
_IMAGE = "ghcr.io/j-schulein/towerscout:v0.1.3-preview.1@" + _DIGEST
_MACHINE = "podman-machine-default"
_USER_SID = "S-1-5-21-1000"


def _key(path: str | PureWindowsPath) -> str:
    value = str(path).replace("/", "\\")
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return value.casefold()


def _manifest(**updates: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "track": "agpl-yolo",
        "release_version": "v0.1.3-preview.1",
        "image": _IMAGE,
        "image_digest": _DIGEST,
        "pytorch_flavor": "cpu",
        "corresponding_source": {"source_ref": "a" * 40},
    }
    value.update(updates)
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def _environment(*extra: str) -> bytes:
    lines = [
        f"TOWERSCOUT_IMAGE={_IMAGE}",
        f"TOWERSCOUT_IMAGE_DIGEST={_DIGEST}",
        "TOWERSCOUT_PYTORCH_FLAVOR=cpu",
        "TOWERSCOUT_GPU_MODE=off",
        "TOWERSCOUT_GPU_AUTO_OVERLAY=0",
        "TOWERSCOUT_PODMAN_GPU_OVERLAY=0",
        f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}",
        "TOWERSCOUT_CONTAINER_ENGINE=podman",
        "TOWERSCOUT_PORT=5000",
        "COMPOSE_PROJECT_NAME=towerscout",
        "GOOGLE_MAPS_API_KEY=super-secret-value",
        *extra,
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _files(*, env_present: bool = True) -> dict[str, bytes]:
    result = {
        _key(_ROOT / "release-manifest.v1.json"): _manifest(),
        _key(_ROOT / "compose.yaml"): b"services:\n  towerscout:\n",
        _key(_ROOT / "compose.gpu.yaml"): b"services:\n  towerscout: {}\n",
        _key(_ROOT / "compose.gpu.podman.yaml"): b"services:\n  towerscout: {}\n",
        _key(_POLICY / "runtime-policy.v1.json"): b"{}\n",
        _key(_POLICY / "runtime-dependency-policy.v1.json"): b"{}\n",
        _key(_ROOT / ".env.example"): _environment(),
    }
    if env_present:
        result[_key(_ROOT / ".env")] = _environment()
    return result


@dataclass(frozen=True, slots=True)
class _PathHandle:
    path: str
    sequence: int


class _PathApi:
    supported = True

    def __init__(self, *, frozen_policy: bool = False, ambiguous: bool = False) -> None:
        self.existing = {_key(_ROOT), _key(_POLICY)}
        if frozen_policy or ambiguous:
            self.existing.add(_key(_FROZEN_POLICY))
        if frozen_policy and not ambiguous:
            self.existing.remove(_key(_POLICY))
        self.opened: list[_PathHandle] = []
        self.closed: list[_PathHandle] = []

    def current_user_sid(self) -> str:
        return _USER_SID

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        normalized = _key(path)
        policy_prefixes = (_key(_POLICY), _key(_FROZEN_POLICY))
        if any(normalized.startswith(prefix) for prefix in policy_prefixes) and not any(
            normalized == existing or existing.startswith(normalized + "\\")
            for existing in self.existing
        ):
            raise OSError("missing")
        handle = _PathHandle(path, len(self.opened))
        self.opened.append(handle)
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, _PathHandle)
        identity = hashlib.sha256(_key(handle.path).encode("utf-16-le")).digest()[:16]
        return NativeDirectoryFacts(
            final_path=handle.path,
            volume_serial=1234,
            file_id=identity,
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _PathHandle)
        return NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(),
        )

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PathHandle)
        self.closed.append(handle)


@dataclass(frozen=True, slots=True)
class _FileHandle:
    path: str
    sequence: int


class _FileApi:
    supported = True

    def __init__(self, contents: dict[str, bytes]) -> None:
        self.contents = contents
        self.opened: list[_FileHandle] = []
        self.closed: list[_FileHandle] = []
        self.cursors: dict[_FileHandle, int] = {}
        self.final_path_override: dict[str, str] = {}
        self.link_count = 1

    def open_file_for_identity(self, path: str) -> object:
        normalized = _key(path)
        if normalized not in self.contents:
            raise OSError("missing")
        handle = _FileHandle(normalized, len(self.opened))
        self.opened.append(handle)
        self.cursors[handle] = 0
        return handle

    def open_file_for_hydrated_identity(self, path: str) -> object:
        return self.open_file_for_identity(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _FileHandle)
        contents = self.contents[handle.path]
        raw_path = self.final_path_override.get(handle.path, handle.path)
        final_path = (
            raw_path if raw_path.startswith("\\\\?\\") else "\\\\?\\" + raw_path
        )
        return NativeFileFacts(
            final_path=final_path,
            volume_serial=1234,
            file_id=hashlib.sha256(handle.path.encode("utf-16-le")).digest()[:16],
            attributes=0x80,
            link_count=self.link_count,
            size=len(contents),
            creation_time=10,
            last_write_time=20,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def rewind_file(self, handle: object) -> None:
        assert isinstance(handle, _FileHandle)
        self.cursors[handle] = 0

    def seek_file(self, handle: object, offset: int) -> None:
        assert isinstance(handle, _FileHandle)
        self.cursors[handle] = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert isinstance(handle, _FileHandle)
        cursor = self.cursors[handle]
        contents = self.contents[handle.path]
        chunk = contents[cursor : cursor + maximum]
        self.cursors[handle] = cursor + len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _FileHandle)
        self.closed.append(handle)


class _InventoryApi:
    supported = True

    def __init__(self, *, env_present: bool, frozen_policy: bool = False) -> None:
        root_names = [
            "release-manifest.v1.json",
            ".env.example",
            "compose.yaml",
            "compose.gpu.yaml",
            "compose.gpu.podman.yaml",
            "launcher",
        ]
        if env_present:
            root_names.append(".env")
        self.root_entries = tuple(
            DirectoryEntry(
                name, name == "launcher", 0x10 if name == "launcher" else 0x80, 0
            )
            for name in root_names
        )
        self.policy_entries = tuple(
            DirectoryEntry(name, False, 0x80, 0)
            for name in (
                "runtime-policy.v1.json",
                "runtime-dependency-policy.v1.json",
            )
        )
        self.policy_path = _FROZEN_POLICY if frozen_policy else _POLICY

    def list_directory(self, path: str) -> tuple[DirectoryEntry, ...]:
        normalized = _key(path)
        if normalized == _key(_ROOT):
            return self.root_entries
        if normalized == _key(self.policy_path):
            return self.policy_entries
        raise OSError("unexpected")


def _capture(
    *,
    env_present: bool = True,
    path_api: _PathApi | None = None,
    file_api: _FileApi | None = None,
    inventory_api: _InventoryApi | None = None,
) -> tuple[BoundPackageEnvironmentInputs, _PathApi, _FileApi, _InventoryApi]:
    selected_path = path_api or _PathApi()
    selected_file = file_api or _FileApi(_files(env_present=env_present))
    selected_inventory = inventory_api or _InventoryApi(env_present=env_present)
    owner = _capture_package_environment_inputs(
        _ROOT,
        path_api=selected_path,
        file_api=selected_file,
        inventory_api=selected_inventory,
    )
    return owner, selected_path, selected_file, selected_inventory


def test_capture_existing_environment_binds_exact_package_fields_and_redacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TOWERSCOUT_PODMAN_MACHINE", "ambient-attacker")
    owner, path_api, file_api, _inventory = _capture()

    captured = owner.capture()

    assert captured.environment_file == captured.environment_source
    assert captured.environment_source.logical_name == ".env"
    assert captured.environment_sha256 == captured.environment_source.sha256
    planned = _environment() + (
        "REQUESTS_CA_BUNDLE=/app/webapp/config/certs/towerscout-ca-bundle.pem\r\n"
        "SSL_CERT_FILE=/app/webapp/config/certs/towerscout-ca-bundle.pem\r\n"
    ).encode("ascii")
    assert captured.planned_environment_sha256 == hashlib.sha256(planned).hexdigest()
    assert captured.release_identity == "v0.1.3-preview.1+" + "a" * 40
    assert captured.pinned_image_digest == _DIGEST
    assert captured.configured_image_reference == _IMAGE
    assert captured.pytorch_flavor == "cpu"
    assert captured.engine_hint == "podman"
    assert captured.requested_gpu_mode is GpuMode.OFF
    assert captured.podman_machine == _MACHINE
    assert captured.compose_project == "towerscout"
    assert captured.port == 5000
    assert len(captured.package_binding_sha256) == 64
    with pytest.raises(ValueError, match="binding"):
        replace(captured, package_binding_sha256="0" * 64)
    assert tuple(item.logical_name for item in captured.compose_files) == (
        "compose.yaml",
        "compose.gpu.yaml",
        "compose.gpu.podman.yaml",
    )
    rendered = f"{owner!r}\n{captured!r}"
    assert _MACHINE not in rendered
    assert _IMAGE not in rendered
    assert "super-secret-value" not in rendered
    assert "ambient-attacker" not in rendered
    assert not file_api.closed
    assert len(path_api.closed) < len(path_api.opened)

    owner.close()
    assert owner.closed
    assert len(file_api.closed) == len(file_api.opened)
    assert len(path_api.closed) == len(path_api.opened)


def test_absent_environment_uses_authenticated_template_and_retained_absence() -> None:
    owner, _path_api, _file_api, inventory = _capture(env_present=False)

    captured = owner.capture()
    assert captured.environment_file is None
    assert captured.environment_source.logical_name == ".env.example"
    assert captured.environment_sha256 == ABSENT_FILE_SHA256

    inventory.root_entries += (DirectoryEntry(".env", False, 0x80, 0),)
    with pytest.raises(PackageInputError) as failure:
        owner.capture()
    assert failure.value.code is PackageInputErrorCode.INPUTS_CHANGED
    assert failure.value.__context__ is None
    owner.close()


def test_planned_environment_hash_changes_only_two_ca_settings_and_preserves_bom() -> (
    None
):
    original = b"\xef\xbb\xbf" + _environment(
        "REQUESTS_CA_BUNDLE=/etc/ssl/old.pem",
        "SSL_CERT_FILE=/etc/ssl/old.pem",
    )
    expected = original.replace(
        b"REQUESTS_CA_BUNDLE=/etc/ssl/old.pem",
        b"REQUESTS_CA_BUNDLE=/app/webapp/config/certs/towerscout-ca-bundle.pem",
    ).replace(
        b"SSL_CERT_FILE=/etc/ssl/old.pem",
        b"SSL_CERT_FILE=/app/webapp/config/certs/towerscout-ca-bundle.pem",
    )
    file_api = _FileApi(_files())
    file_api.contents[_key(_ROOT / ".env")] = original

    owner, *_ = _capture(file_api=file_api)
    captured = owner.capture()
    assert captured.planned_environment_sha256 == hashlib.sha256(expected).hexdigest()
    assert captured.environment_source.size_bytes == len(original)
    owner.close()


@pytest.mark.parametrize(
    "contents",
    (
        _environment("GOOGLE_MAPS_API_KEY=duplicate-secret"),
        _environment("towerscout_gpu_mode=on"),
        _environment("BROKEN-LINE"),
        _environment("TOWERSCOUT_PODMAN_MACHINE=other"),
        _environment("requests_ca_bundle=/tmp/attacker.pem"),
        _environment().replace(b"\r\n", b"\r", 1),
        b"\xef\xbb\xbf" + _environment(),
    ),
)
def test_environment_parser_rejects_ambiguity_but_accepts_optional_bom(
    contents: bytes,
) -> None:
    file_api = _FileApi(_files())
    file_api.contents[_key(_ROOT / ".env")] = contents
    should_pass = contents.startswith(b"\xef\xbb\xbf")

    if should_pass:
        owner, *_ = _capture(file_api=file_api)
        owner.close()
    else:
        with pytest.raises(PackageInputError) as failure:
            _capture(file_api=file_api)
        assert failure.value.code is PackageInputErrorCode.PACKAGE_INVALID
        assert failure.value.__context__ is None


@pytest.mark.parametrize(
    "manifest",
    (
        b'{"schema_version":1,"schema_version":1}',
        _manifest(image="ghcr.io/attacker/image@" + _DIGEST),
        _manifest(release_version="template"),
        _manifest(corresponding_source={"source_ref": "not-a-commit"}),
        _manifest(schema_version=True),
    ),
)
def test_manifest_parser_rejects_duplicate_or_inconsistent_identity(
    manifest: bytes,
) -> None:
    file_api = _FileApi(_files())
    file_api.contents[_key(_ROOT / "release-manifest.v1.json")] = manifest

    with pytest.raises(PackageInputError) as failure:
        _capture(file_api=file_api)
    assert failure.value.code is PackageInputErrorCode.PACKAGE_INVALID
    assert failure.value.__context__ is None


def test_manifest_parser_enforces_bounded_json_shape() -> None:
    nested: object = "leaf"
    for _index in range(18):
        nested = [nested]
    for manifest in (
        _manifest(extra=nested),
        _manifest(extra=1.5),
        _manifest(extra="x" * 32_768),
        _manifest(extra=2**80),
    ):
        file_api = _FileApi(_files())
        file_api.contents[_key(_ROOT / "release-manifest.v1.json")] = manifest
        with pytest.raises(PackageInputError) as failure:
            _capture(file_api=file_api)
        assert failure.value.code is PackageInputErrorCode.PACKAGE_INVALID


def test_capture_detects_same_handle_content_and_directory_drift() -> None:
    owner, _path_api, file_api, inventory = _capture()
    file_api.contents[_key(_ROOT / "compose.yaml")] = b"attacker\n"
    with pytest.raises(PackageInputError) as failure:
        owner.capture()
    assert failure.value.code is PackageInputErrorCode.INPUTS_CHANGED

    file_api.contents[_key(_ROOT / "compose.yaml")] = b"services:\n  towerscout:\n"
    inventory.policy_entries += (DirectoryEntry("extra.json", False, 0x80, 0),)
    with pytest.raises(PackageInputError) as failure:
        owner.capture()
    assert failure.value.code is PackageInputErrorCode.INPUTS_CHANGED
    owner.close()


def test_capture_rejects_reparse_case_collision_and_ambiguous_policy_layout() -> None:
    for inventory in (
        _InventoryApi(env_present=True),
        _InventoryApi(env_present=True),
    ):
        if inventory is not None and not any(
            item.reparse_tag for item in inventory.root_entries
        ):
            if _entry_case := next(
                (item for item in inventory.root_entries if item.name == "launcher"),
                None,
            ):
                inventory.root_entries = tuple(
                    (
                        DirectoryEntry(
                            item.name,
                            item.is_directory,
                            item.attributes | 0x400,
                            0xA000000C,
                        )
                        if item is _entry_case
                        else item
                    )
                    for item in inventory.root_entries
                )
                break
    with pytest.raises(PackageInputError) as reparse_failure:
        _capture(inventory_api=inventory)
    assert reparse_failure.value.code is PackageInputErrorCode.PACKAGE_INVALID

    collision = _InventoryApi(env_present=True)
    collision.root_entries += (DirectoryEntry(".ENV", False, 0x80, 0),)
    with pytest.raises(PackageInputError) as collision_failure:
        _capture(inventory_api=collision)
    assert collision_failure.value.code is PackageInputErrorCode.PACKAGE_INVALID

    with pytest.raises(PackageInputError) as ambiguity_failure:
        _capture(path_api=_PathApi(ambiguous=True))
    assert ambiguity_failure.value.code is PackageInputErrorCode.PACKAGE_INVALID


def test_inventory_accepts_hydrated_onedrive_entry_but_rejects_placeholder() -> None:
    cloud_tag = next(iter(KNOWN_CLOUD_REPARSE_TAGS))
    hydrated = _InventoryApi(env_present=True)
    hydrated.root_entries += (
        DirectoryEntry("hydrated.txt", False, 0x80 | 0x400, cloud_tag),
    )
    owner, *_ = _capture(inventory_api=hydrated)
    owner.close()

    placeholder = _InventoryApi(env_present=True)
    placeholder.root_entries += (
        DirectoryEntry(
            "placeholder.txt",
            False,
            0x80 | 0x400 | 0x1000,
            cloud_tag,
        ),
    )
    with pytest.raises(PackageInputError) as failure:
        _capture(inventory_api=placeholder)
    assert failure.value.code is PackageInputErrorCode.PACKAGE_INVALID


def test_capture_rejects_wrong_final_path_and_multiple_links() -> None:
    outside = _FileApi(_files())
    outside.final_path_override[_key(_ROOT / ".env")] = r"C:\Attacker\.env"
    with pytest.raises(PackageInputError) as outside_failure:
        _capture(file_api=outside)
    assert outside_failure.value.code is PackageInputErrorCode.PACKAGE_INVALID

    linked = _FileApi(_files())
    linked.link_count = 2
    with pytest.raises(PackageInputError) as link_failure:
        _capture(file_api=linked)
    assert link_failure.value.code is PackageInputErrorCode.PACKAGE_INVALID


def test_frozen_policy_layout_is_supported_without_policy_ambiguity() -> None:
    contents = _files()
    for name in (
        "runtime-policy.v1.json",
        "runtime-dependency-policy.v1.json",
    ):
        contents[_key(_FROZEN_POLICY / name)] = contents.pop(_key(_POLICY / name))
    owner, *_ = _capture(
        path_api=_PathApi(frozen_policy=True),
        file_api=_FileApi(contents),
        inventory_api=_InventoryApi(env_present=True, frozen_policy=True),
    )
    captured = owner.capture()
    expected_parent = PureWindowsPath(
        r"\\?\C:\Users\reviewed-user\TowerScout\launcher"
        r"\_internal\towerscout_launcher"
    )
    assert (
        captured.security_artifacts.runtime_policy.final_path.parent == expected_parent
    )
    owner.close()


def test_close_retries_after_interruption_and_waits_for_active_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _path_api, _file_api, _inventory = _capture()
    original_close = HandleBoundFile.close
    attempts = 0

    def interrupt_once(selected: HandleBoundFile) -> None:
        nonlocal attempts
        if attempts == 0:
            attempts += 1
            raise KeyboardInterrupt
        original_close(selected)

    monkeypatch.setattr(HandleBoundFile, "close", interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        owner.close()
    assert owner.closed

    owner, _path_api, _file_api, _inventory = _capture()
    entered = threading.Event()
    release = threading.Event()
    done = threading.Event()
    original_capture = BoundPackageEnvironmentInputs._capture_owned  # noqa: SLF001

    def hold(selected: BoundPackageEnvironmentInputs, *args: object) -> object:
        entered.set()
        release.wait(timeout=5)
        return original_capture(selected, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(BoundPackageEnvironmentInputs, "_capture_owned", hold)
    worker = threading.Thread(target=owner.capture)
    worker.start()
    assert entered.wait(timeout=5)

    def close_owner() -> None:
        owner.close()
        done.set()

    closer = threading.Thread(target=close_owner)
    closer.start()
    assert not done.wait(timeout=0.1)
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)
    assert done.is_set()
    assert owner.closed


def test_failed_construction_retries_cleanup_and_preserves_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_api = _FileApi(_files())
    file_api.contents[_key(_ROOT / ".env")] = _environment("TOWERSCOUT_GPU_MODE=on")
    path_api = _PathApi()
    original_close = HandleBoundFile.close
    attempts = 0

    def interrupt_once(selected: HandleBoundFile) -> None:
        nonlocal attempts
        if attempts == 0:
            attempts += 1
            raise KeyboardInterrupt
        original_close(selected)

    monkeypatch.setattr(HandleBoundFile, "close", interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        _capture(path_api=path_api, file_api=file_api)
    assert len(file_api.closed) == len(file_api.opened)
    assert len(path_api.closed) == len(path_api.opened)


def test_public_factory_has_no_injectable_seam_and_source_remains_unwired() -> None:
    assert tuple(
        inspect.signature(capture_native_windows_package_environment_inputs).parameters
    ) == ("package_root",)
    for name in ("app.py", "discovery.py", "repair.py", "runtime_execution.py"):
        source = (LAUNCHER_ROOT / "towerscout_launcher" / name).read_text(
            encoding="utf-8"
        )
        assert "runtime_package_inputs" not in source
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_package_inputs.py"
    ).read_text(encoding="utf-8")
    assert "os.environ" not in source
    assert "os.getenv" not in source
    assert "getenv(" not in source


def test_sanitized_error_and_owner_representations_hide_private_values() -> None:
    owner, *_ = _capture()
    captured = owner.capture()
    error = PackageInputError(PackageInputErrorCode.PACKAGE_INVALID)
    rendered = f"{owner!r}\n{captured!r}\n{error!r}\n{error}"
    for private in (_MACHINE, _IMAGE, "super-secret-value", str(_ROOT)):
        assert private not in rendered
    owner.close()


def test_path_acl_failure_is_sanitized_before_any_package_file_is_retained() -> None:
    class _UnsafePathApi(_PathApi):
        def query_security(self, handle: object) -> NativeSecurityFacts:
            assert isinstance(handle, _PathHandle)
            return NativeSecurityFacts(
                owner_sid=_USER_SID,
                dacl_present=True,
                allowed_aces=(AccessAllowedAce("S-1-1-0", 0x2, 0),),
            )

    file_api = _FileApi(_files())
    path_api = _UnsafePathApi()
    with pytest.raises(PackageInputError) as failure:
        _capture(path_api=path_api, file_api=file_api)
    assert failure.value.code is PackageInputErrorCode.PACKAGE_INVALID
    assert not file_api.opened
    assert len(path_api.closed) == len(path_api.opened)
