from __future__ import annotations

import hashlib
import sys
import threading
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_package_config import (  # noqa: E402
    BoundPodmanMachineConfiguration,
    PackageConfigurationError,
    PackageConfigurationErrorCode,
    capture_bound_podman_machine_configuration,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    AccessAllowedAce,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathHierarchyTrust,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    KNOWN_CLOUD_REPARSE_TAGS,
    NativeFileFacts,
)

_PACKAGE_ROOT = PureWindowsPath(r"C:\Users\reviewed-user\TowerScout")
_ENV_FINAL = r"\\?\C:\Users\reviewed-user\TowerScout\.env"
_MACHINE = "podman-machine-default"
_USER_SID = "S-1-5-21-1000"


@dataclass(frozen=True, slots=True)
class _PathHandle:
    path: str
    follow_reparse: bool
    sequence: int


class _PathApi:
    supported = True

    def __init__(self, *, unsafe_acl: bool = False) -> None:
        self.unsafe_acl = unsafe_acl
        self.changed = False
        self.opened: list[_PathHandle] = []
        self.closed: list[_PathHandle] = []

    def current_user_sid(self) -> str:
        return _USER_SID

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        handle = _PathHandle(path, follow_reparse, len(self.opened))
        self.opened.append(handle)
        return handle

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, _PathHandle)
        identity = hashlib.sha256(handle.path.casefold().encode("utf-16-le")).digest()[
            :16
        ]
        if self.changed:
            identity = bytes([identity[0] ^ 0xFF]) + identity[1:]
        return NativeDirectoryFacts(
            final_path=handle.path,
            volume_serial=0x123456,
            file_id=identity,
            attributes=0x10,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, _PathHandle)
        aces = (AccessAllowedAce("S-1-1-0", 0x00000002, 0),) if self.unsafe_acl else ()
        return NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=aces,
        )

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PathHandle)
        self.closed.append(handle)


@dataclass(frozen=True, slots=True)
class _FileHandle:
    sequence: int


class _FileApi:
    supported = True

    def __init__(
        self,
        contents: bytes,
        *,
        final_path: str = _ENV_FINAL,
        link_count: int = 1,
        cloud: bool = False,
        absent: bool = False,
    ) -> None:
        self.contents = contents
        self.final_path = final_path
        self.link_count = link_count
        self.cloud = cloud
        self.absent = absent
        self.opened: list[tuple[str, _FileHandle]] = []
        self.closed: list[_FileHandle] = []
        self.cursors: dict[_FileHandle, int] = {}

    def _open(self, path: str) -> object:
        if self.absent:
            raise OSError("absent")
        handle = _FileHandle(len(self.opened) + 1)
        self.opened.append((path, handle))
        self.cursors[handle] = 0
        return handle

    def open_file_for_identity(self, path: str) -> object:
        return self._open(path)

    def open_file_for_hydrated_identity(self, path: str) -> object:
        return self._open(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert isinstance(handle, _FileHandle)
        assert handle in self.cursors
        reparse_tag = next(iter(KNOWN_CLOUD_REPARSE_TAGS)) if self.cloud else 0
        attributes = 0x80
        if self.cloud:
            attributes |= 0x400
            if handle.sequence == 1:
                attributes |= 0x1000
        return NativeFileFacts(
            final_path=self.final_path,
            volume_serial=0x123456,
            file_id=bytes.fromhex("44" * 16),
            attributes=attributes,
            link_count=self.link_count,
            size=len(self.contents),
            creation_time=10,
            last_write_time=20,
            drive_type=3,
            file_type=1,
            reparse_tag=reparse_tag,
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
        chunk = self.contents[cursor : cursor + maximum]
        self.cursors[handle] = cursor + len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _FileHandle)
        self.closed.append(handle)


def _capture(
    contents: bytes | None = None,
    *,
    path_api: _PathApi | None = None,
    file_api: _FileApi | None = None,
) -> tuple[BoundPodmanMachineConfiguration, _PathApi, _FileApi]:
    selected_path_api = path_api or _PathApi()
    selected_file_api = file_api or _FileApi(
        contents
        if contents is not None
        else f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}\n".encode("ascii")
    )
    owner = capture_bound_podman_machine_configuration(
        _PACKAGE_ROOT,
        path_api=selected_path_api,  # type: ignore[arg-type]
        file_api=selected_file_api,  # type: ignore[arg-type]
    )
    return owner, selected_path_api, selected_file_api


def _machine(owner: BoundPodmanMachineConfiguration) -> str:
    return owner._run_while_held(lambda machine, _evidence: machine)  # noqa: SLF001


def test_capture_binds_existing_package_env_and_redacts_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TOWERSCOUT_PODMAN_MACHINE", "ambient-attacker-machine")
    owner, path_api, file_api = _capture()

    assert _machine(owner) == _MACHINE
    assert owner.evidence.environment_source.logical_name == ".env"
    assert owner.evidence.environment_source.final_path == PureWindowsPath(_ENV_FINAL)
    assert (
        owner.evidence.configured_machine_sha256
        == hashlib.sha256(_MACHINE.encode("ascii")).hexdigest()
    )
    assert len(path_api.closed) == 0
    assert len(file_api.closed) == 0
    assert file_api.opened[0][0].casefold().endswith(r"\towerscout\.env")

    rendered = f"{owner!r}\n{owner.evidence!r}"
    assert _MACHINE not in rendered
    assert "ambient-attacker-machine" not in rendered

    owner.close()
    assert owner.closed
    assert len(file_api.closed) == 1
    assert len(path_api.closed) == len(path_api.opened)


@pytest.mark.parametrize(
    "contents",
    (
        b"OTHER=value\n",
        b"TOWERSCOUT_PODMAN_MACHINE=one\nTOWERSCOUT_PODMAN_MACHINE=two\n",
        b"towerscout_podman_machine=lowercase\n",
        b'TOWERSCOUT_PODMAN_MACHINE="quoted"\n',
        b"TOWERSCOUT_PODMAN_MACHINE=bad machine\n",
        b"\xef\xbb\xbfTOWERSCOUT_PODMAN_MACHINE=machine\n",
        b"TOWERSCOUT_PODMAN_MACHINE=machine\x00\n",
        b"TOWERSCOUT_PODMAN_MACHINE=\xff\n",
        b"TOWERSCOUT_PODMAN_MACHINE=machine\rOTHER=value\n",
        "TOWERSCOUT_PODMAN_MACHINE=machine\u2028OTHER=value\n".encode("utf-8"),
    ),
)
def test_capture_rejects_missing_ambiguous_or_malformed_setting(
    contents: bytes,
) -> None:
    path_api = _PathApi()
    file_api = _FileApi(contents)

    with pytest.raises(PackageConfigurationError) as captured:
        _capture(path_api=path_api, file_api=file_api)

    assert captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_INVALID
    assert _MACHINE not in str(captured.value)
    assert len(file_api.closed) == 1
    assert len(path_api.closed) == len(path_api.opened)


def test_capture_rejects_absent_env_until_secure_absence_proof_exists() -> None:
    path_api = _PathApi()
    file_api = _FileApi(b"", absent=True)

    with pytest.raises(PackageConfigurationError) as captured:
        _capture(path_api=path_api, file_api=file_api)

    assert captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_INVALID
    assert not file_api.closed
    assert len(path_api.closed) == len(path_api.opened)


def test_capture_rejects_oversized_or_multilink_env() -> None:
    for file_api in (
        _FileApi(b"x" * 262_145),
        _FileApi(
            f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}\n".encode("ascii"),
            link_count=2,
        ),
    ):
        path_api = _PathApi()
        with pytest.raises(PackageConfigurationError) as captured:
            _capture(path_api=path_api, file_api=file_api)
        assert (
            captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_INVALID
        )
        assert len(file_api.closed) == 1
        assert len(path_api.closed) == len(path_api.opened)


def test_capture_rejects_env_outside_resolved_package_root() -> None:
    path_api = _PathApi()
    file_api = _FileApi(
        f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}\n".encode("ascii"),
        final_path=r"\\?\C:\Attacker\.env",
    )

    with pytest.raises(PackageConfigurationError) as captured:
        _capture(path_api=path_api, file_api=file_api)

    assert captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_INVALID
    assert len(file_api.closed) == 1
    assert len(path_api.closed) == len(path_api.opened)


def test_capture_rejects_broad_package_root_writer_before_opening_env() -> None:
    path_api = _PathApi(unsafe_acl=True)
    file_api = _FileApi(f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}\n".encode("ascii"))

    with pytest.raises(PackageConfigurationError) as captured:
        _capture(path_api=path_api, file_api=file_api)

    assert captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_INVALID
    assert not file_api.opened
    assert len(path_api.closed) == len(path_api.opened)


def test_capture_accepts_stably_hydrated_known_cloud_env_leaf() -> None:
    file_api = _FileApi(
        f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}\n".encode("ascii"),
        cloud=True,
    )
    owner, path_api, _ = _capture(file_api=file_api)

    assert _machine(owner) == _MACHINE
    assert len(file_api.opened) == 2
    assert len(file_api.closed) == 1

    owner.close()
    assert len(file_api.closed) == 2
    assert len(path_api.closed) == len(path_api.opened)


def test_revalidation_detects_file_or_package_path_change() -> None:
    owner, path_api, file_api = _capture()
    file_api.contents = b"TOWERSCOUT_PODMAN_MACHINE=replaced\n"

    with pytest.raises(PackageConfigurationError) as captured:
        owner.assert_unchanged()
    assert captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_CHANGED

    file_api.contents = f"TOWERSCOUT_PODMAN_MACHINE={_MACHINE}\n".encode("ascii")
    path_api.changed = True
    with pytest.raises(PackageConfigurationError) as captured:
        owner.assert_unchanged()
    assert captured.value.code is PackageConfigurationErrorCode.CONFIGURATION_CHANGED

    owner.close()


def test_close_waits_for_active_configuration_lease() -> None:
    owner, _path_api, _file_api = _capture()
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()

    def hold() -> None:
        owner._run_while_held(  # noqa: SLF001
            lambda _machine, _evidence: (entered.set(), release.wait(timeout=5))
        )

    worker = threading.Thread(target=hold)
    worker.start()
    assert entered.wait(timeout=5)

    closer = threading.Thread(target=lambda: (owner.close(), closed.set()))
    closer.start()
    assert not closed.wait(timeout=0.1)
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    assert not worker.is_alive()
    assert not closer.is_alive()
    assert closed.is_set()
    assert owner.closed


def test_callback_failure_is_preserved_without_leaking_configuration() -> None:
    owner, _path_api, _file_api = _capture()

    with pytest.raises(RuntimeError, match="caller failure"):
        owner._run_while_held(  # noqa: SLF001
            lambda _machine, _evidence: (_ for _ in ()).throw(
                RuntimeError("caller failure")
            )
        )

    assert not owner.closed
    assert _MACHINE not in repr(owner)
    owner.close()


def test_ambient_environment_is_never_read_by_configuration_module() -> None:
    source = Path(
        ROOT / "launcher" / "towerscout_launcher" / "runtime_package_config.py"
    ).read_text(encoding="utf-8")

    assert "os.environ" not in source
    assert "os.getenv" not in source
    assert "dotenv" not in source


def test_close_retries_package_root_after_interruption_closes_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, path_api, file_api = _capture()
    original_close = PathHierarchyTrust.close
    attempts = 0

    def interrupt_once(selected: PathHierarchyTrust) -> None:
        nonlocal attempts
        if attempts == 0:
            attempts += 1
            raise KeyboardInterrupt
        original_close(selected)

    monkeypatch.setattr(PathHierarchyTrust, "close", interrupt_once)

    with pytest.raises(KeyboardInterrupt):
        owner.close()

    assert owner.closed
    assert not owner._fully_closed  # noqa: SLF001
    assert len(file_api.closed) == 1
    assert not path_api.closed

    owner.close()
    assert owner._fully_closed  # noqa: SLF001
    assert len(path_api.closed) == len(path_api.opened)
