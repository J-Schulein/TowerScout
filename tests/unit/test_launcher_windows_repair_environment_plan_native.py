from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path, PureWindowsPath
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_runtime_execution import _target  # noqa: E402
from test_launcher_windows_recovery_environment_restore_native import (  # noqa: E402
    _Api,
    _File,
    _identity,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    FileIdentity,
    RuntimeProduct,
)
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    plan_ca_environment_replacement,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathHierarchyTrust,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_backup import (  # noqa: E402
    EnvironmentExactStateBackup,
    WindowsFileSecurityMetadata,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
)
from towerscout_launcher.windows_repair_environment_plan_native import (  # noqa: E402
    NativeRepairEnvironmentPlanError,
    NativeRepairEnvironmentPlanErrorCode,
    build_repair_environment_plan_while_package_root_held,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


class _TargetPathApi:
    supported = True

    def __init__(self, path: str, identity: StableFileIdentity) -> None:
        self.path = path
        self.identity = identity

    def current_user_sid(self) -> str:
        return "S-1-5-21-1000"

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        return path

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, str)
        return NativeDirectoryFacts(
            handle,
            self.identity.volume_serial,
            self.identity.file_id,
            0x10,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, str)
        return NativeSecurityFacts(self.current_user_sid(), True, ())

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, str)


def _arrange(
    *,
    environment_present: bool,
) -> tuple[
    object,
    PathHierarchyTrust,
    EnvironmentExactStateBackup,
    _Api,
    bytes,
]:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    package_identity = StableFileIdentity(
        target.package_root.volume_serial,
        target.package_root.file_id,
    )
    root = capture_path_hierarchy(
        str(target.package_root.final_path),
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_TargetPathApi(str(target.package_root.final_path), package_identity),
    )
    assert isinstance(root, PathHierarchyTrust)
    source = b"GOOGLE_API_KEY=private-value\r\n"
    expected = plan_ca_environment_replacement(
        source,
        original_present=environment_present,
    )
    name = ".env" if environment_present else ".env.example"
    path = str(PureWindowsPath(target.package_root.final_path, name))
    source_identity = StableFileIdentity(
        package_identity.volume_serial,
        _identity(8).file_id,
    )
    source_file = FileIdentity(
        logical_name=name,
        final_path=PureWindowsPath(path),
        volume_serial=source_identity.volume_serial,
        file_id=source_identity.file_id,
        sha256=hashlib.sha256(source).hexdigest(),
        size_bytes=len(source),
    )
    compose = replace(
        target.compose,
        environment_sha256=expected.original_sha256,
        planned_environment_sha256=expected.candidate_sha256,
        environment_source=source_file,
        environment_file=source_file if environment_present else None,
    )
    target = replace(target, compose=compose)
    stream = JournalStreamIdentity(
        1,
        "a" * 32,
        target.target_token.digest_sha256,
        package_identity,
    )
    if environment_present:
        backup = EnvironmentExactStateBackup(
            1,
            stream,
            source_identity,
            source,
            WindowsFileSecurityMetadata(1, 0x20, b"security-evidence"),
        )
    else:
        backup = EnvironmentExactStateBackup(1, stream, None, None, None)
    api = _Api()
    if not environment_present:
        api.files[path] = _File(source_identity, source, 0x20, "b" * 64)
    return target, root, backup, api, source


@pytest.mark.parametrize("environment_present", (False, True))
def test_builds_exact_plan_from_backup_or_fixed_template(
    environment_present: bool,
) -> None:
    target, root, backup, api, source = _arrange(
        environment_present=environment_present
    )

    plan = root.run_while_held(
        lambda: build_repair_environment_plan_while_package_root_held(
            root,
            target,  # type: ignore[arg-type]
            backup,
            api=api,
        )
    )

    assert plan.original_contents == (source if environment_present else None)
    assert plan.candidate_sha256 == target.compose.planned_environment_sha256
    expected_opens = 0 if environment_present else 2
    assert sum(event.startswith("open:") for event in api.events) == expected_opens
    root.close()


def test_rejects_template_change_between_complete_captures() -> None:
    target, root, backup, api, _source = _arrange(environment_present=False)
    original_close = api.close_handle
    closes = 0

    def close_and_change(handle: object) -> None:
        nonlocal closes
        original_close(handle)
        closes += 1
        if closes == 1:
            path = str(target.compose.environment_source.final_path)
            api.files[path].contents = b"changed"

    api.close_handle = close_and_change  # type: ignore[method-assign]

    with pytest.raises(NativeRepairEnvironmentPlanError) as caught:
        root.run_while_held(
            lambda: build_repair_environment_plan_while_package_root_held(
                root,
                target,  # type: ignore[arg-type]
                backup,
                api=api,
            )
        )

    assert caught.value.code is NativeRepairEnvironmentPlanErrorCode.VERIFY_FAILED
    assert "changed" not in repr(caught.value)
    root.close()


def test_rejects_backup_for_another_target_token() -> None:
    target, root, backup, api, _source = _arrange(environment_present=True)
    wrong = EnvironmentExactStateBackup(
        1,
        JournalStreamIdentity(
            1,
            backup.stream.journal_id,
            "f" * 64,
            backup.stream.package_root_identity,
        ),
        backup.identity,
        backup.contents,
        backup.security,
    )

    with pytest.raises(NativeRepairEnvironmentPlanError) as caught:
        root.run_while_held(
            lambda: build_repair_environment_plan_while_package_root_held(
                root,
                target,  # type: ignore[arg-type]
                wrong,
                api=api,
            )
        )

    assert caught.value.code is NativeRepairEnvironmentPlanErrorCode.INPUT_INVALID
    root.close()
