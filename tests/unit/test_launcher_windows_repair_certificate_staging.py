from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable, TypeVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
TEST_ROOT = Path(__file__).resolve().parent
for candidate in (LAUNCHER_ROOT, TEST_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from test_launcher_windows_recovery_certificate_storage_native import (  # noqa: E402
    _Api,
    _replacement_plan,
)
from test_launcher_windows_recovery_scan import (  # noqa: E402
    _chain as _recovery_chain,
    _Protection as _RecoveryProtection,
)
from test_launcher_windows_repair_transaction_journal_storage import (  # noqa: E402
    _Protection as _ForwardProtection,
    _Storage,
)
from towerscout_launcher.windows_certificate_replacement import (  # noqa: E402
    CertificateReplacementPlan,
)
from towerscout_launcher.windows_recovery_certificate_storage_native import (  # noqa: E402
    NativeWindowsRepairCertificateTempStorage,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    EnvironmentJournalPointer,
    select_environment_journal_chain,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    PersistedEnvironmentJournalChain,
)
from towerscout_launcher.windows_repair_certificate_staging import (  # noqa: E402
    NativeRepairCertificateTempNameSource,
    RepairCertificateStagingError,
    RepairCertificateStagingErrorCode,
    stage_repair_certificate_candidates,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionStreamIdentity,
    RepairTransactionState,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_Result = TypeVar("_Result")
_ROOT = r"C:\Protected\TowerScout\Recovery\v1"


class _Root:
    def run_journal_storage(self, operation: Callable[[str], _Result]) -> _Result:
        return operation(_ROOT)


class _Names:
    def __init__(self) -> None:
        self.values = [
            "repair-certificate-" + "3" * 32 + ".tmp",
            "repair-certificate-" + "4" * 32 + ".tmp",
        ]
        self.calls = 0

    def new_certificate_temp_name(self) -> str:
        value = self.values[self.calls]
        self.calls += 1
        return value


class _FailingThirdGenerationStorage(_Storage):
    def __init__(self) -> None:
        super().__init__()
        self.fail_third = True

    def create_generation(self, root_path: str, name: str, contents: bytes):
        if self.fail_third and name.endswith("00000000000000000003.generation"):
            raise OSError("private third-generation failure")
        return super().create_generation(root_path, name, contents)


class _FailingVerifiedPointerStorage(_Storage):
    def __init__(self) -> None:
        super().__init__()
        self.pointer_writes = 0

    def replace_pointer(self, root_path: str, name: str, contents: bytes):
        self.pointer_writes += 1
        if self.pointer_writes == 3:
            raise OSError("private verified-pointer failure")
        return super().replace_pointer(root_path, name, contents)


def _stage(
    backing: _Storage,
    api: _Api,
    names: _Names,
    plan: CertificateReplacementPlan,
):
    pending = _recovery_chain(
        journal_id="b" * 32,
        package_root_identity=StableFileIdentity(7, (9).to_bytes(16, "big")),
        provider_environment=False,
        repair_armed=True,
        target_token_sha256="d" * 64,
    )
    rollback_pointer = EnvironmentJournalPointer(
        1,
        pending.selection.tip.stream.journal_id,
        pending.selection.tip.sequence,
        pending.selection.tip_generation_sha256,
    )
    rollback = PersistedEnvironmentJournalChain(
        pending.sealed_generations,
        pending.file_identities,
        select_environment_journal_chain(
            pending.sealed_generations,
            rollback_pointer,
            expected_stream=pending.selection.tip.stream,
            protection=_RecoveryProtection(),
        ),
    )
    stream = RepairTransactionStreamIdentity(
        1,
        "a" * 32,
        rollback.selection.tip.stream.journal_id,
        rollback.selection.tip_generation_sha256,
        rollback.selection.tip.stream.target_token_sha256,
        rollback.selection.tip.stream.package_root_identity,
    )
    return stage_repair_certificate_candidates(
        stream,
        rollback,
        plan,
        root=_Root(),
        name_source=names,
        certificate_storage=NativeWindowsRepairCertificateTempStorage(api=api),
        generation_storage=backing,
        pointer_storage=backing,
        protection=_ForwardProtection(),
    )


def test_native_forward_certificate_temp_names_are_bounded_and_unique() -> None:
    source = NativeRepairCertificateTempNameSource()

    first = source.new_certificate_temp_name()
    second = source.new_certificate_temp_name()

    assert first != second
    assert len(first) == len("repair-certificate-") + 32 + len(".tmp")
    assert first.startswith("repair-certificate-")
    assert first.endswith(".tmp")


def test_staging_rejects_rollback_armed_without_current_pointer() -> None:
    identity = StableFileIdentity(7, (9).to_bytes(16, "big"))
    pending = _recovery_chain(
        journal_id="b" * 32,
        package_root_identity=identity,
        provider_environment=False,
        repair_armed=True,
        target_token_sha256="d" * 64,
    )
    stream = RepairTransactionStreamIdentity(
        1,
        "a" * 32,
        pending.selection.tip.stream.journal_id,
        pending.selection.tip_generation_sha256,
        pending.selection.tip.stream.target_token_sha256,
        identity,
    )
    api = _Api()

    with pytest.raises(RepairCertificateStagingError) as captured:
        stage_repair_certificate_candidates(
            stream,
            pending,
            _replacement_plan(),
            root=_Root(),
            name_source=_Names(),
            certificate_storage=NativeWindowsRepairCertificateTempStorage(api=api),
            generation_storage=_Storage(),
            pointer_storage=_Storage(),
            protection=_ForwardProtection(),
        )

    assert captured.value.code is RepairCertificateStagingErrorCode.INPUT_INVALID
    assert api.files == {}


def test_stages_both_candidates_through_verified_generation_idempotently() -> None:
    backing = _Storage()
    api = _Api()
    names = _Names()
    plan = _replacement_plan()

    first = _stage(backing, api, names, plan)
    second = _stage(backing, api, names, plan)

    assert first.selection.tip.state is RepairTransactionState.CERTIFICATE_TEMP_VERIFIED
    assert second.selection.generation_sha256s == first.selection.generation_sha256s
    assert second.selection.tip.record.certificate_temp_identities is not None
    assert names.calls == 2
    assert len(backing.generations) == 3
    assert len(backing.pointers) == 1


def test_retry_after_verified_bytes_before_generation_append_is_exact() -> None:
    backing = _FailingThirdGenerationStorage()
    api = _Api()
    names = _Names()
    plan = _replacement_plan()

    with pytest.raises(RepairCertificateStagingError) as captured:
        _stage(backing, api, names, plan)

    assert captured.value.code is RepairCertificateStagingErrorCode.JOURNAL_INVALID
    assert len(backing.generations) == 2
    assert len(api.files) == 2

    backing.fail_third = False
    recovered = _stage(backing, api, names, plan)

    assert (
        recovered.selection.tip.state
        is RepairTransactionState.CERTIFICATE_TEMP_VERIFIED
    )
    assert names.calls == 2
    assert len(backing.generations) == 3


def test_existing_forward_plan_rejects_substituted_candidate_without_write() -> None:
    backing = _FailingThirdGenerationStorage()
    api = _Api()
    names = _Names()
    original = _replacement_plan()
    with pytest.raises(RepairCertificateStagingError):
        _stage(backing, api, names, original)
    substituted = CertificateReplacementPlan(
        original.provider,
        "b" * 64,
        original.local_ca_contents,
        original.ca_bundle_contents,
    )

    with pytest.raises(RepairCertificateStagingError) as captured:
        _stage(backing, api, names, substituted)

    assert captured.value.code is RepairCertificateStagingErrorCode.JOURNAL_INVALID
    assert names.calls == 2
    assert len(backing.generations) == 2


def test_retry_repairs_pointer_after_verified_generation_was_durable() -> None:
    backing = _FailingVerifiedPointerStorage()
    api = _Api()
    names = _Names()
    plan = _replacement_plan()

    with pytest.raises(RepairCertificateStagingError) as captured:
        _stage(backing, api, names, plan)

    assert captured.value.code is RepairCertificateStagingErrorCode.JOURNAL_INVALID
    assert len(backing.generations) == 3

    recovered = _stage(backing, api, names, plan)

    assert (
        recovered.selection.tip.state
        is RepairTransactionState.CERTIFICATE_TEMP_VERIFIED
    )
    assert names.calls == 2
    assert backing.pointer_writes == 4
