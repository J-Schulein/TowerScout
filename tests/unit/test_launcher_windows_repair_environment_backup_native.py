from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_windows_recovery_environment_restore_native import (  # noqa: E402
    _Api,
    _DESTINATION,
    _File,
    _Handle,
    _identity,
    _root,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
)
from towerscout_launcher.windows_repair_environment_backup_native import (  # noqa: E402
    NativeRepairEnvironmentBackupError,
    NativeRepairEnvironmentBackupErrorCode,
    capture_repair_environment_backup_while_package_root_held,
)


class _BackupApi(_Api):
    def __init__(self) -> None:
        super().__init__()
        self.security_evidence: dict[str, bytes] = {}
        self.mutate_after_first_close = False
        self.close_calls = 0

    def query_security_evidence(
        self,
        handle: object,
    ) -> tuple[NativeSecurityFacts, bytes]:
        assert isinstance(handle, _Handle)
        return self.query_security(handle), self.security_evidence[handle.path]

    def close_handle(self, handle: object) -> None:
        super().close_handle(handle)
        self.close_calls += 1
        if self.mutate_after_first_close and self.close_calls == 1:
            self.files[_DESTINATION].contents = b"changed"


def _stream(root: PathHierarchyTrust) -> JournalStreamIdentity:
    return JournalStreamIdentity(
        1,
        "a" * 32,
        "b" * 64,
        root.root_snapshot.identity,
    )


def _present_api(contents: bytes = b"PRIVATE=one\r\n") -> _BackupApi:
    api = _BackupApi()
    evidence = NativeWindowsPathTrustApi._security_evidence(
        "S-1-5-21-1000",
        True,
        False,
        b"private-dacl",
    )
    api.security_evidence[_DESTINATION] = evidence
    api.files[_DESTINATION] = _File(
        _identity(8),
        contents,
        0x20,
        hashlib.sha256(evidence).hexdigest(),
    )
    return api


def test_captures_exact_present_environment_twice_under_package_root() -> None:
    root_value, _path_api = _root()
    assert isinstance(root_value, PathHierarchyTrust)
    root = root_value
    api = _present_api()

    backup = root.run_while_held(
        lambda: capture_repair_environment_backup_while_package_root_held(
            root,
            _stream(root),
            api=api,
        )
    )

    assert backup.existed is True
    assert backup.identity == _identity(8)
    assert backup.contents == b"PRIVATE=one\r\n"
    assert backup.security is not None
    assert backup.security.file_attributes == 0x20
    assert (
        backup.security.security_descriptor_sha256 == api.files[_DESTINATION].descriptor
    )
    assert api.close_calls == 2
    root.close()


def test_captures_exact_absence_twice_without_private_material() -> None:
    root_value, _path_api = _root()
    assert isinstance(root_value, PathHierarchyTrust)
    root = root_value
    api = _BackupApi()

    backup = root.run_while_held(
        lambda: capture_repair_environment_backup_while_package_root_held(
            root,
            _stream(root),
            api=api,
        )
    )

    assert backup.existed is False
    assert backup.contents is None
    assert backup.security is None
    root.close()


def test_rejects_environment_change_between_complete_captures() -> None:
    root_value, _path_api = _root()
    assert isinstance(root_value, PathHierarchyTrust)
    root = root_value
    api = _present_api()
    api.mutate_after_first_close = True

    with pytest.raises(NativeRepairEnvironmentBackupError) as caught:
        root.run_while_held(
            lambda: capture_repair_environment_backup_while_package_root_held(
                root,
                _stream(root),
                api=api,
            )
        )

    assert caught.value.code is NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED
    assert "PRIVATE" not in repr(caught.value)
    root.close()


def test_rejects_security_evidence_that_does_not_match_native_facts() -> None:
    root_value, _path_api = _root()
    assert isinstance(root_value, PathHierarchyTrust)
    root = root_value
    api = _present_api()
    api.security_evidence[_DESTINATION] = b"substituted-evidence"

    with pytest.raises(NativeRepairEnvironmentBackupError) as caught:
        root.run_while_held(
            lambda: capture_repair_environment_backup_while_package_root_held(
                root,
                _stream(root),
                api=api,
            )
        )

    assert caught.value.code is NativeRepairEnvironmentBackupErrorCode.VERIFY_FAILED
    assert "substituted" not in repr(caught.value)
    root.close()


def test_rejects_stream_for_another_package_root() -> None:
    root_value, _path_api = _root()
    assert isinstance(root_value, PathHierarchyTrust)
    root = root_value
    wrong = JournalStreamIdentity(1, "a" * 32, "b" * 64, _identity(99))

    with pytest.raises(NativeRepairEnvironmentBackupError) as caught:
        root.run_while_held(
            lambda: capture_repair_environment_backup_while_package_root_held(
                root,
                wrong,
                api=_BackupApi(),
            )
        )

    assert caught.value.code is NativeRepairEnvironmentBackupErrorCode.INPUT_INVALID
    root.close()
