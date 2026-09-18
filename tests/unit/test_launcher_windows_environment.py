from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.target_contracts import ABSENT_FILE_SHA256  # noqa: E402
from towerscout_launcher.windows_environment import (  # noqa: E402
    BoundEnvironmentAbsence,
    EnvironmentAbsenceError,
    EnvironmentAbsenceErrorCode,
    EnvironmentAbsenceEvidence,
    capture_bound_environment_absence,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeWindowsFileApi,
    StableFileIdentity,
)

_PACKAGE_ROOT = PureWindowsPath(r"C:\Users\reviewed-user\TowerScout")
_PRIVATE_PATH = r"C:\Users\reviewed-user\TowerScout\.env"
_USER_SID = "S-1-5-21-1000"


@dataclass(frozen=True, slots=True)
class _PathHandle:
    path: str
    follow_reparse: bool
    sequence: int


class _PathApi:
    supported = True

    def __init__(self) -> None:
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
        return NativeSecurityFacts(
            owner_sid=_USER_SID,
            dacl_present=True,
            allowed_aces=(),
        )

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PathHandle)
        self.closed.append(handle)


@dataclass(frozen=True, slots=True)
class _PresenceHandle:
    sequence: int


class _PresenceApi:
    def __init__(self, *, present: bool = False, supported: bool = True) -> None:
        self.supported = supported
        self.present = present
        self.failure: Exception | None = None
        self.probed: list[str] = []
        self.opened: list[_PresenceHandle] = []
        self.closed: list[_PresenceHandle] = []

    def open_file_if_exists(self, path: str) -> object | None:
        self.probed.append(path)
        if self.failure is not None:
            raise self.failure
        if not self.present:
            return None
        handle = _PresenceHandle(len(self.opened) + 1)
        self.opened.append(handle)
        return handle

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, _PresenceHandle)
        self.closed.append(handle)


def test_capture_binds_absence_to_held_package_root() -> None:
    path_api = _PathApi()
    presence_api = _PresenceApi()

    with capture_bound_environment_absence(
        _PACKAGE_ROOT,
        path_api=path_api,
        presence_api=presence_api,
    ) as owner:
        assert owner.evidence.environment_sha256 == ABSENT_FILE_SHA256
        assert owner.assert_unchanged() == owner.evidence
        assert "reviewed-user" not in repr(owner)
        assert "reviewed-user" not in repr(owner.evidence)

    assert len(presence_api.probed) == 2
    assert all(
        path.casefold().endswith(r"\towerscout\.env") for path in presence_api.probed
    )
    assert len(path_api.closed) == len(path_api.opened)


def test_capture_rejects_present_environment_and_closes_probe_handle() -> None:
    path_api = _PathApi()
    presence_api = _PresenceApi(present=True)

    with pytest.raises(EnvironmentAbsenceError) as failure:
        capture_bound_environment_absence(
            _PACKAGE_ROOT,
            path_api=path_api,
            presence_api=presence_api,
        )

    assert failure.value.code is EnvironmentAbsenceErrorCode.ENVIRONMENT_PRESENT
    assert presence_api.closed == presence_api.opened
    assert len(path_api.closed) == len(path_api.opened)


def test_assert_unchanged_rejects_environment_created_after_capture() -> None:
    path_api = _PathApi()
    presence_api = _PresenceApi()
    owner = capture_bound_environment_absence(
        _PACKAGE_ROOT,
        path_api=path_api,
        presence_api=presence_api,
    )
    presence_api.present = True

    with pytest.raises(EnvironmentAbsenceError) as failure:
        owner.assert_unchanged()

    assert failure.value.code is EnvironmentAbsenceErrorCode.ENVIRONMENT_PRESENT
    assert presence_api.closed == presence_api.opened
    owner.close()


def test_assert_unchanged_rejects_package_root_identity_drift() -> None:
    path_api = _PathApi()
    presence_api = _PresenceApi()
    owner = capture_bound_environment_absence(
        _PACKAGE_ROOT,
        path_api=path_api,
        presence_api=presence_api,
    )
    path_api.changed = True

    with pytest.raises(EnvironmentAbsenceError) as failure:
        owner.assert_unchanged()

    assert failure.value.code is EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED
    owner.close()


@pytest.mark.parametrize(
    "presence_api",
    [
        _PresenceApi(supported=False),
        _PresenceApi(),
    ],
)
def test_capture_sanitizes_unavailable_presence_probe(
    presence_api: _PresenceApi,
) -> None:
    if presence_api.supported:
        presence_api.failure = OSError(_PRIVATE_PATH)

    with pytest.raises(EnvironmentAbsenceError) as failure:
        capture_bound_environment_absence(
            _PACKAGE_ROOT,
            path_api=_PathApi(),
            presence_api=presence_api,
        )

    assert failure.value.code is EnvironmentAbsenceErrorCode.VERIFICATION_UNAVAILABLE
    assert _PRIVATE_PATH not in str(failure.value)
    assert _PRIVATE_PATH not in repr(failure.value)


@pytest.mark.parametrize(
    "package_root",
    [
        PureWindowsPath("TowerScout"),
        PureWindowsPath("C:\\"),
        PureWindowsPath("C:\\invalid\x00root"),
    ],
)
def test_capture_rejects_invalid_package_root(package_root: PureWindowsPath) -> None:
    with pytest.raises(EnvironmentAbsenceError) as failure:
        capture_bound_environment_absence(
            package_root,
            path_api=_PathApi(),
            presence_api=_PresenceApi(),
        )

    assert failure.value.code is EnvironmentAbsenceErrorCode.INPUT_INVALID


def test_evidence_rejects_noncanonical_absence_marker() -> None:
    identity = StableFileIdentity(1, bytes.fromhex("11" * 16))

    with pytest.raises(ValueError, match="evidence"):
        EnvironmentAbsenceEvidence(
            schema_version=1,
            package_root_identity=identity,
            environment_sha256="0" * 64,
            binding_sha256="0" * 64,
        )


def test_owner_rejects_a_leaf_outside_the_held_package_root() -> None:
    path_api = _PathApi()
    presence_api = _PresenceApi()
    captured = capture_bound_environment_absence(
        _PACKAGE_ROOT,
        path_api=path_api,
        presence_api=presence_api,
    )
    package_root = capture_path_hierarchy(
        str(_PACKAGE_ROOT),
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=path_api,
    )

    with pytest.raises(ValueError, match="absence"):
        BoundEnvironmentAbsence(
            api=presence_api,
            environment_path=r"C:\Users\reviewed-user\other\.env",
            package_root=package_root,
            evidence=captured.evidence,
        )

    package_root.close()
    captured.close()


def test_close_is_idempotent_and_closed_owner_fails_closed() -> None:
    owner = capture_bound_environment_absence(
        _PACKAGE_ROOT,
        path_api=_PathApi(),
        presence_api=_PresenceApi(),
    )

    owner.close()
    owner.close()

    with pytest.raises(EnvironmentAbsenceError) as failure:
        owner.assert_unchanged()
    assert failure.value.code is EnvironmentAbsenceErrorCode.ENVIRONMENT_CHANGED


@pytest.mark.skipif(os.name != "nt", reason="native Windows absence proof")
def test_native_presence_probe_distinguishes_absent_and_present(tmp_path: Path) -> None:
    api = NativeWindowsFileApi()
    candidate = tmp_path / "presence.txt"

    assert api.open_file_if_exists(str(candidate)) is None
    candidate.write_bytes(b"present")
    handle = api.open_file_if_exists(str(candidate))
    assert handle is not None
    api.close_handle(handle)
