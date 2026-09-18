from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_runtime_target_observation_backend import _backend  # noqa: E402
from test_launcher_windows_recovery_backup_storage import (  # noqa: E402
    _BlobStorage,
    _GenerationStorage,
    _NameSource,
    _Protection,
    _Root,
    _certificate_plan,
)
from towerscout_launcher.runtime_target_resolution import (  # noqa: E402
    capture_bound_resolved_repair_target,
)
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    plan_ca_environment_replacement,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    PathTrustPurpose,
)
from towerscout_launcher.windows_recovery_backup import (  # noqa: E402
    CertificateBackupDestination,
    CertificateExactStateBackup,
    CertificateFileExactStateBackup,
    EnvironmentExactStateBackup,
    WindowsFileSecurityMetadata,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from towerscout_launcher.windows_recovery_readiness_authority import (  # noqa: E402
    derive_rollback_readiness_authority,
)
from towerscout_launcher.windows_recovery_runtime_authority import (  # noqa: E402
    derive_rollback_runtime_recovery_authority,
)
from towerscout_launcher.windows_recovery_scan import (  # noqa: E402
    PackageRecoveryJournalScan,
)
from towerscout_launcher.windows_repair_rollback_preparation_native import (  # noqa: E402
    NativeRepairRollbackPreparationError,
    NativeRepairRollbackPreparationErrorCode,
    PreparedRepairRollback,
    prepare_native_windows_repair_rollback,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402
from towerscout_launcher.windows_transaction_context import (  # noqa: E402
    HeldWindowsTransactionContext,
)
import towerscout_launcher.windows_repair_rollback_preparation_native as native  # noqa: E402


class _JournalIds:
    def new_journal_id(self) -> str:
        return "a" * 32


class _PackageRoot:
    def __init__(self, identity: StableFileIdentity) -> None:
        self.root_snapshot = SimpleNamespace(identity=identity)
        self.evidence = SimpleNamespace(purpose=PathTrustPurpose.PACKAGE_ROOT)
        self.closed = False
        self.active = False

    def run_while_held(self, operation: Callable[[], Any]) -> Any:
        assert not self.closed and not self.active
        self.active = True
        try:
            return operation()
        finally:
            self.active = False

    def assert_unchanged_while_held(self) -> object:
        assert self.active and not self.closed
        return self.evidence

    def close(self) -> None:
        self.closed = True


class _ProtectedRoot(_Root, _Protection):
    def __init__(self) -> None:
        _Root.__init__(self)
        self.closed = False

    def assert_unchanged(self) -> object:
        assert not self.closed
        return self

    def close(self) -> None:
        self.closed = True


class _Locks:
    closed = False
    environment_abandoned = False
    target_abandoned = False

    def close(self) -> None:
        self.closed = True


def _context(owner: object, protected: _ProtectedRoot) -> HeldWindowsTransactionContext:
    target = getattr(owner, "target")
    package_identity = StableFileIdentity(
        target.package_root.volume_serial,
        target.package_root.file_id,
    )
    return HeldWindowsTransactionContext(
        target_token_sha256=target.target_token.digest_sha256,
        package_root=_PackageRoot(package_identity),  # type: ignore[arg-type]
        protected_root=protected,  # type: ignore[arg-type]
        locks=_Locks(),  # type: ignore[arg-type]
        recovery_scan=PackageRecoveryJournalScan(1, package_identity),
    )


def _patch_exact_inputs(monkeypatch: pytest.MonkeyPatch, owner: object) -> None:
    target = getattr(owner, "target")
    package_identity = StableFileIdentity(
        target.package_root.volume_serial,
        target.package_root.file_id,
    )
    contents = b"GOOGLE_API_KEY=private-value\r\n"
    environment_identity = StableFileIdentity(
        package_identity.volume_serial,
        b"e" * 16,
    )

    def environment_backup(
        _root: object,
        stream: JournalStreamIdentity,
    ) -> EnvironmentExactStateBackup:
        return EnvironmentExactStateBackup(
            1,
            stream,
            environment_identity,
            contents,
            WindowsFileSecurityMetadata(1, 0x20, b"security-evidence"),
        )

    def certificate_backup(
        _owner: object,
        stream: JournalStreamIdentity,
    ) -> CertificateExactStateBackup:
        return CertificateExactStateBackup(
            1,
            stream,
            CertificateFileExactStateBackup(
                1,
                CertificateBackupDestination.LOCAL_CA,
                b"original-local-ca",
                0o644,
            ),
            CertificateFileExactStateBackup(
                1,
                CertificateBackupDestination.CA_BUNDLE,
                b"original-ca-bundle",
                0o644,
            ),
        )

    environment_plan = plan_ca_environment_replacement(
        contents,
        original_present=True,
    )
    runtime = derive_rollback_runtime_recovery_authority(target)
    readiness = derive_rollback_readiness_authority(
        target_token_sha256=target.target_token.digest_sha256,
        package_root_identity=package_identity,
        condition=RollbackReadinessCondition.DEGRADED,
        provider_outcome=RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
    )
    monkeypatch.setattr(
        native,
        "capture_repair_environment_backup_while_package_root_held",
        environment_backup,
    )
    monkeypatch.setattr(
        native,
        "capture_repair_certificate_backup_while_target_held",
        certificate_backup,
    )
    monkeypatch.setattr(
        native,
        "build_repair_environment_plan_while_package_root_held",
        lambda *_args: environment_plan,
    )
    monkeypatch.setattr(
        native,
        "build_repair_certificate_plan_while_target_held",
        lambda *_args: _certificate_plan(),
    )
    monkeypatch.setattr(
        native, "derive_rollback_runtime_recovery_authority", lambda *_args: runtime
    )
    monkeypatch.setattr(
        native,
        "capture_repair_readiness_authority_while_target_held",
        lambda *_args: readiness,
    )


def test_composes_exact_inputs_through_activated_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _authority, _executor, backend = _backend()
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    protected = _ProtectedRoot()
    context = _context(owner, protected)
    generations = _GenerationStorage(protected)
    blobs = _BlobStorage(protected)
    _patch_exact_inputs(monkeypatch, owner)

    prepared = prepare_native_windows_repair_rollback(
        owner,
        context,
        journal_id_source=_JournalIds(),
        backup_name_source=_NameSource(),
        journal_storage=generations,  # type: ignore[arg-type]
        pointer_storage=generations,  # type: ignore[arg-type]
        backup_storage=blobs,  # type: ignore[arg-type]
    )

    assert isinstance(prepared, PreparedRepairRollback)
    assert prepared.stream.journal_id == "a" * 32
    assert len(prepared.activated.selection.generations) == 3
    assert generations.pointer_replacements == 1
    assert len(blobs.created) == 2
    assert owner.closed is context.closed is False
    context.close()
    owner.close()


def test_sanitizes_exact_input_capture_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _authority, _executor, backend = _backend()
    owner = capture_bound_resolved_repair_target(plan, backend=backend)
    protected = _ProtectedRoot()
    context = _context(owner, protected)
    _patch_exact_inputs(monkeypatch, owner)
    monkeypatch.setattr(
        native,
        "capture_repair_environment_backup_while_package_root_held",
        lambda *_args: (_ for _ in ()).throw(OSError("private package path")),
    )

    with pytest.raises(NativeRepairRollbackPreparationError) as caught:
        prepare_native_windows_repair_rollback(
            owner,
            context,
            journal_id_source=_JournalIds(),
            backup_name_source=_NameSource(),
            journal_storage=_GenerationStorage(protected),  # type: ignore[arg-type]
            pointer_storage=_GenerationStorage(protected),  # type: ignore[arg-type]
            backup_storage=_BlobStorage(protected),  # type: ignore[arg-type]
        )

    assert (
        caught.value.code is NativeRepairRollbackPreparationErrorCode.PREPARATION_FAILED
    )
    assert "private" not in repr(caught.value)
    assert caught.value.__cause__ is None
    context.close()
    owner.close()
