from __future__ import annotations

import hashlib
from pathlib import Path, PureWindowsPath
import sys
from types import SimpleNamespace
from typing import Callable, TypeVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    CertificateTargetDestination,
    ObservationOperation,
)
from towerscout_launcher.runtime_target_observation_backend import (  # noqa: E402
    TargetObservationProcessResult,
)
from towerscout_launcher.windows_recovery import (  # noqa: E402
    CertificateDestinationRestoreEvidence,
)
from towerscout_launcher.windows_repair_certificate_apply import (  # noqa: E402
    RepairCertificateApplyError,
    RepairCertificateApplyErrorCode,
    _apply_destination,
    apply_repair_certificates,
)

from test_launcher_runtime_execution import _target  # noqa: E402
from test_launcher_windows_recovery_certificate_storage_native import (  # noqa: E402
    _Api,
    _replacement_plan,
)
from test_launcher_windows_recovery_scan import _Protection  # noqa: E402
from test_launcher_windows_repair_certificate_staging import (  # noqa: E402
    _Names,
    _Root,
)
from test_launcher_windows_repair_transaction_journal_storage import (  # noqa: E402
    _Protection as _ForwardProtection,
    _Storage,
)
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    GENESIS_GENERATION_SHA256,
    BackupPreparingRecord,
    BackupVerifiedRecord,
    EnvironmentJournalGeneration,
    EnvironmentJournalPointer,
    EnvironmentJournalState,
    JournalStreamIdentity,
    RollbackArmedRecord,
    RollbackProviderOutcome,
    RollbackReadinessCondition,
    protect_environment_journal_generation,
    select_environment_journal_chain,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    PersistedEnvironmentJournalChain,
)
from towerscout_launcher.windows_recovery_certificate_storage_native import (  # noqa: E402
    NativeWindowsRepairCertificateTempStorage,
)
from towerscout_launcher.windows_repair_certificate_staging import (  # noqa: E402
    stage_repair_certificate_candidates,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
    RepairTransactionStreamIdentity,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_LOCAL = CertificateTargetDestination.LOCAL_CA
_BUNDLE = CertificateTargetDestination.CA_BUNDLE
_TEMP_NAME = "repair-certificate-" + "3" * 32 + ".tmp"
_SOURCE = PureWindowsPath(
    r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1" f"\\{_TEMP_NAME}"
)
_Result = TypeVar("_Result")


def _evidence(
    destination: CertificateTargetDestination,
    present: bool,
    sha256: str | None = None,
    size: int | None = None,
    mode: int | None = None,
) -> CertificateDestinationRestoreEvidence:
    digest = hashlib.sha256(
        f"{destination.value}:{present}:{sha256}:{size}:{mode}".encode("ascii")
    ).hexdigest()
    return CertificateDestinationRestoreEvidence(
        1,
        present,
        sha256,
        size,
        mode,
        digest,
    )


class _Owner:
    def __init__(self, target: object | None = None) -> None:
        self.target = (
            SimpleNamespace(container=SimpleNamespace(container_id="d" * 64))
            if target is None
            else target
        )
        self.closed = False
        self.assertions = 0
        self.states = {
            _LOCAL: _evidence(_LOCAL, True, "1" * 64, 11, 0o600),
            _BUNDLE: _evidence(_BUNDLE, False),
        }
        self.stages = {
            _LOCAL: _evidence(_LOCAL, False),
            _BUNDLE: _evidence(_BUNDLE, False),
        }
        self.candidates = {
            _LOCAL: ("2" * 64, 12, 0o644),
            _BUNDLE: ("3" * 64, 13, 0o644),
        }
        self.calls: list[str] = []

    def assert_unchanged(self) -> None:
        self.assertions += 1

    def execute_scoped_process(self, operation: str, arguments: tuple[object, ...]):
        self.calls.append(operation)
        destination = arguments[1]
        assert isinstance(destination, CertificateTargetDestination)
        operations = {
            "certificate_stage_candidate": ObservationOperation.CERTIFICATE_STAGE_CANDIDATE,
            "certificate_apply_candidate": ObservationOperation.CERTIFICATE_APPLY_CANDIDATE,
            "certificate_remove_staged_candidate": (
                ObservationOperation.CERTIFICATE_REMOVE_STAGED_CANDIDATE
            ),
        }
        if operation == "certificate_stage_candidate":
            sha256, size, _mode = self.candidates[destination]
            self.stages[destination] = _evidence(destination, True, sha256, size, 0o600)
        elif operation == "certificate_apply_candidate":
            sha256, size, mode = self.candidates[destination]
            self.states[destination] = _evidence(destination, True, sha256, size, mode)
            self.stages[destination] = _evidence(destination, False)
        elif operation == "certificate_remove_staged_candidate":
            self.stages[destination] = _evidence(destination, False)
        return TargetObservationProcessResult(
            operations[operation],
            "f" * 64,
            b"",
            hashlib.sha256(b"").hexdigest(),
            0,
            False,
            None,
        )


def _observe(
    owner: _Owner,
    destination: CertificateTargetDestination,
    *,
    restore_temp_name: str | None = None,
) -> CertificateDestinationRestoreEvidence:
    return (
        owner.stages[destination]
        if restore_temp_name is not None
        else owner.states[destination]
    )


class _Temps:
    def __init__(self) -> None:
        self.closed = False

    def run_while_held(self, operation: Callable[[object], _Result]) -> _Result:
        from towerscout_launcher.windows_recovery_certificate_storage_native import (
            HeldCertificateRestoreTempPaths,
        )

        return operation(HeldCertificateRestoreTempPaths(_SOURCE, _SOURCE))

    def close(self) -> None:
        self.closed = True


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _rollback(target: object, plan: object) -> PersistedEnvironmentJournalChain:
    package_root = StableFileIdentity(
        target.package_root.volume_serial,
        target.package_root.file_id,
    )
    stream = JournalStreamIdentity(
        1,
        "b" * 32,
        target.target_token.digest_sha256,
        package_root,
    )
    preparing = BackupPreparingRecord(
        1,
        package_root,
        "recovery-backup-" + "c" * 32 + ".blob",
        "recovery-backup-" + "d" * 32 + ".blob",
        "e" * 64,
        12,
        False,
        plan.provider,
        plan.windows_root_fingerprint_sha256,
        "f" * 64,
        tuple(hashlib.sha256(str(index).encode()).hexdigest() for index in range(8)),
        True,
        RollbackReadinessCondition.DEGRADED,
        "3" * 64,
        RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE,
        local_ca_present=True,
        local_ca_sha256="1" * 64,
        local_ca_mode=0o600,
        ca_bundle_present=False,
        local_ca_candidate_sha256=plan.local_ca_sha256,
        local_ca_candidate_size=len(plan.local_ca_contents),
        local_ca_candidate_mode=plan.local_ca_mode,
        ca_bundle_candidate_sha256=plan.ca_bundle_sha256,
        ca_bundle_candidate_size=len(plan.ca_bundle_contents),
        ca_bundle_candidate_mode=plan.ca_bundle_mode,
    )
    records: list[tuple[EnvironmentJournalState, object]] = [
        (EnvironmentJournalState.BACKUP_PREPARING, preparing)
    ]
    protection = _Protection()
    sealed = []
    previous = GENESIS_GENERATION_SHA256
    for sequence, (state, record) in enumerate(records, start=1):
        generation = EnvironmentJournalGeneration(
            1, stream, sequence, previous, state, record
        )
        protected = protect_environment_journal_generation(
            generation, protection=protection
        )
        sealed.append(protected)
        previous = protected.generation_sha256
    verified = BackupVerifiedRecord(
        1,
        previous,
        package_root,
        _identity(31),
        "4" * 64,
        101,
        _identity(32),
        "5" * 64,
        202,
    )
    generation = EnvironmentJournalGeneration(
        1, stream, 2, previous, EnvironmentJournalState.BACKUP_VERIFIED, verified
    )
    protected = protect_environment_journal_generation(
        generation, protection=protection
    )
    sealed.append(protected)
    previous = protected.generation_sha256
    armed = RollbackArmedRecord(
        1,
        previous,
        package_root,
        _identity(31),
        "4" * 64,
        101,
        _identity(32),
        "5" * 64,
        202,
    )
    generation = EnvironmentJournalGeneration(
        1, stream, 3, previous, EnvironmentJournalState.ROLLBACK_ARMED, armed
    )
    protected = protect_environment_journal_generation(
        generation, protection=protection
    )
    sealed.append(protected)
    pointer = EnvironmentJournalPointer(
        1, stream.journal_id, 3, protected.generation_sha256
    )
    selection = select_environment_journal_chain(
        tuple(sealed), pointer, expected_stream=stream, protection=protection
    )
    return PersistedEnvironmentJournalChain(
        tuple(sealed), (_identity(40), _identity(41), _identity(42)), selection
    )


@pytest.mark.parametrize(
    ("destination", "original_present", "original_sha256", "original_mode"),
    (
        (_LOCAL, True, "1" * 64, 0o600),
        (_BUNDLE, False, None, None),
    ),
)
def test_apply_destination_stages_normalizes_and_atomically_applies(
    monkeypatch: pytest.MonkeyPatch,
    destination: CertificateTargetDestination,
    original_present: bool,
    original_sha256: str | None,
    original_mode: int | None,
) -> None:
    monkeypatch.setattr(
        "towerscout_launcher.windows_repair_certificate_apply."
        "observe_certificate_destination_while_target_held",
        _observe,
    )
    owner = _Owner()
    candidate_sha256, candidate_size, candidate_mode = owner.candidates[destination]

    final = _apply_destination(
        owner,  # type: ignore[arg-type]
        destination,
        _TEMP_NAME,
        _SOURCE,
        original_present=original_present,
        original_sha256=original_sha256,
        original_mode=original_mode,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        candidate_mode=candidate_mode,
    )

    assert final.contents_sha256 == candidate_sha256
    assert final.mode == 0o644
    assert owner.stages[destination].present is False
    assert owner.calls == [
        "certificate_stage_candidate",
        "certificate_apply_candidate",
    ]


def test_apply_destination_reconciles_applied_candidate_and_exact_stage_residue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "towerscout_launcher.windows_repair_certificate_apply."
        "observe_certificate_destination_while_target_held",
        _observe,
    )
    owner = _Owner()
    candidate_sha256, candidate_size, candidate_mode = owner.candidates[_LOCAL]
    owner.states[_LOCAL] = _evidence(
        _LOCAL, True, candidate_sha256, candidate_size, candidate_mode
    )
    owner.stages[_LOCAL] = _evidence(
        _LOCAL, True, candidate_sha256, candidate_size, 0o600
    )

    final = _apply_destination(
        owner,  # type: ignore[arg-type]
        _LOCAL,
        _TEMP_NAME,
        _SOURCE,
        original_present=True,
        original_sha256="1" * 64,
        original_mode=0o600,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        candidate_mode=candidate_mode,
    )

    assert final.contents_sha256 == candidate_sha256
    assert owner.calls == ["certificate_remove_staged_candidate"]


def test_apply_destination_blocks_unrelated_destination_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "towerscout_launcher.windows_repair_certificate_apply."
        "observe_certificate_destination_while_target_held",
        _observe,
    )
    owner = _Owner()
    owner.states[_LOCAL] = _evidence(_LOCAL, True, "9" * 64, 99, 0o644)

    with pytest.raises(RepairCertificateApplyError) as captured:
        _apply_destination(
            owner,  # type: ignore[arg-type]
            _LOCAL,
            _TEMP_NAME,
            _SOURCE,
            original_present=True,
            original_sha256="1" * 64,
            original_mode=0o600,
            candidate_sha256="2" * 64,
            candidate_size=12,
            candidate_mode=0o644,
        )

    assert captured.value.code is RepairCertificateApplyErrorCode.TARGET_MISMATCH
    assert owner.calls == []


def test_apply_repair_certificates_persists_fourth_generation_after_exact_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _python, _identity_key = _target(RuntimeProduct.DOCKER)
    plan = _replacement_plan()
    rollback = _rollback(target, plan)
    storage = _Storage()
    forward = stage_repair_certificate_candidates(
        RepairTransactionStreamIdentity(
            1,
            "a" * 32,
            rollback.selection.tip.stream.journal_id,
            rollback.selection.tip_generation_sha256,
            rollback.selection.tip.stream.target_token_sha256,
            rollback.selection.tip.stream.package_root_identity,
        ),
        rollback,
        plan,
        root=_Root(),
        name_source=_Names(),
        certificate_storage=NativeWindowsRepairCertificateTempStorage(api=_Api()),
        generation_storage=storage,
        pointer_storage=storage,
        protection=_ForwardProtection(),
    )
    owner = _Owner(target)
    owner.candidates = {
        _LOCAL: (plan.local_ca_sha256, len(plan.local_ca_contents), plan.local_ca_mode),
        _BUNDLE: (
            plan.ca_bundle_sha256,
            len(plan.ca_bundle_contents),
            plan.ca_bundle_mode,
        ),
    }
    temps = _Temps()
    monkeypatch.setattr(
        "towerscout_launcher.windows_repair_certificate_apply."
        "BoundResolvedRepairTarget",
        _Owner,
    )
    monkeypatch.setattr(
        "towerscout_launcher.windows_repair_certificate_apply."
        "observe_certificate_destination_while_target_held",
        _observe,
    )

    applied = apply_repair_certificates(
        owner,  # type: ignore[arg-type]
        rollback,
        forward,
        plan,
        root=_Root(),
        generation_storage=storage,
        pointer_storage=storage,
        protection=_ForwardProtection(),
        temp_capture=lambda _root, _forward, _plan: temps,  # type: ignore[arg-type]
    )

    assert applied.selection.tip.state is RepairTransactionState.CERTIFICATES_APPLIED
    assert applied.selection.tip.sequence == 4
    assert len(storage.generations) == 4
    assert owner.states[_LOCAL].contents_sha256 == plan.local_ca_sha256
    assert owner.states[_BUNDLE].contents_sha256 == plan.ca_bundle_sha256
    assert owner.assertions == 1
    assert temps.closed
