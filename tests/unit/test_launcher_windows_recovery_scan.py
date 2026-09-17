from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_scan as scan  # noqa: E402
from towerscout_launcher.windows_environment_replacement_native import (  # noqa: E402
    EnvironmentAppliedRecord,
    EnvironmentTempCreatedRecord,
    EnvironmentTempPlanRecord,
    EnvironmentTempVerifiedRecord,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    DirectoryTrustSnapshot,
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathHierarchyEvidence,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    BackupPreparingRecord,
    EnvironmentJournalGeneration,
    EnvironmentJournalState,
    GENESIS_GENERATION_SHA256,
    JournalStreamIdentity,
    protect_environment_journal_generation,
    select_environment_journal_chain,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    PersistedEnvironmentJournalChain,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    StableFileIdentity,
    derive_environment_mutex_name,
)


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(11, value.to_bytes(16, "big"))


class _PathApi:
    supported = True

    def __init__(self, identity: StableFileIdentity) -> None:
        self.identity = identity
        self.final_path = r"\\?\C:\TowerScout"
        self.security = NativeSecurityFacts("S-1-5-21-1000", True, ())

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        del handle
        return NativeDirectoryFacts(
            self.final_path,
            self.identity.volume_serial,
            self.identity.file_id,
            0x10,
            3,
            1,
            0,
        )

    def query_security(self, handle: object) -> NativeSecurityFacts:
        del handle
        return self.security

    def close_handle(self, handle: object) -> None:
        del handle


def _package_root(identity: StableFileIdentity) -> PathHierarchyTrust:
    api = _PathApi(identity)
    snapshot = DirectoryTrustSnapshot(
        identity,
        api.final_path,
        0x10,
        0,
        api.security,
        True,
    )
    return PathHierarchyTrust(
        api,
        "S-1-5-21-1000",
        (object(), object()),
        (snapshot, snapshot),
        PathHierarchyEvidence(PathTrustPurpose.PACKAGE_ROOT, 1, 1, identity),
    )


class _Protection:
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        return CurrentUserProtectedBlob(purpose, b"sealed:" + plaintext)

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        assert blob.purpose is purpose
        assert blob.ciphertext.startswith(b"sealed:")
        return blob.ciphertext[7:]


def _chain(
    *,
    journal_id: str,
    package_root_identity: StableFileIdentity,
    provider_environment: bool,
    provider_applied: bool = False,
) -> PersistedEnvironmentJournalChain:
    protection = _Protection()
    stream = JournalStreamIdentity(
        1,
        journal_id,
        "b" * 64,
        package_root_identity,
    )
    if provider_environment:
        state = EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED
        record = EnvironmentTempPlanRecord(
            1,
            package_root_identity,
            "c" * 64,
            "d" * 64,
            12,
            ".towerscout-env-" + "e" * 32 + ".tmp",
            True,
            _identity(8),
            13,
            0x20,
            "f" * 64,
        )
    else:
        state = EnvironmentJournalState.BACKUP_PREPARING
        record = BackupPreparingRecord(
            1,
            package_root_identity,
            "recovery-backup-" + "c" * 32 + ".blob",
            "recovery-backup-" + "d" * 32 + ".blob",
            "e" * 64,
            12,
            False,
        )
    generations: list[tuple[EnvironmentJournalState, object]] = [(state, record)]
    if provider_applied:
        assert provider_environment
        assert type(record) is EnvironmentTempPlanRecord
        created = EnvironmentTempCreatedRecord(
            1,
            "0" * 64,
            package_root_identity,
            _identity(9),
            record.candidate_sha256,
            record.candidate_size,
            0x80,
            "1" * 64,
            record.temp_name,
        )
        verified = EnvironmentTempVerifiedRecord(
            1,
            "0" * 64,
            package_root_identity,
            created.temp_identity,
            created.candidate_sha256,
            created.candidate_size,
            created.candidate_file_attributes,
            created.candidate_security_descriptor_sha256,
            created.temp_name,
        )
        applied = EnvironmentAppliedRecord(
            1,
            "0" * 64,
            package_root_identity,
            created.temp_identity,
            created.candidate_sha256,
            created.candidate_size,
            record.original_file_attributes or 0,
            record.original_security_descriptor_sha256 or "2" * 64,
            created.temp_name,
        )
        generations.extend(
            (
                (EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED, created),
                (EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED, verified),
                (EnvironmentJournalState.ENVIRONMENT_APPLIED, applied),
            )
        )
    sealed_items = []
    previous = GENESIS_GENERATION_SHA256
    for sequence, (selected_state, selected_record) in enumerate(
        generations,
        start=1,
    ):
        if type(selected_record) is EnvironmentTempCreatedRecord:
            selected_record = EnvironmentTempCreatedRecord(
                1,
                previous,
                selected_record.package_root_identity,
                selected_record.temp_identity,
                selected_record.candidate_sha256,
                selected_record.candidate_size,
                selected_record.candidate_file_attributes,
                selected_record.candidate_security_descriptor_sha256,
                selected_record.temp_name,
            )
        elif type(selected_record) is EnvironmentTempVerifiedRecord:
            selected_record = EnvironmentTempVerifiedRecord(
                1,
                previous,
                selected_record.package_root_identity,
                selected_record.temp_identity,
                selected_record.candidate_sha256,
                selected_record.candidate_size,
                selected_record.candidate_file_attributes,
                selected_record.candidate_security_descriptor_sha256,
                selected_record.temp_name,
            )
        elif type(selected_record) is EnvironmentAppliedRecord:
            selected_record = EnvironmentAppliedRecord(
                1,
                previous,
                selected_record.package_root_identity,
                selected_record.candidate_identity,
                selected_record.candidate_sha256,
                selected_record.candidate_size,
                selected_record.candidate_file_attributes,
                selected_record.candidate_security_descriptor_sha256,
                selected_record.temp_name,
            )
        sealed = protect_environment_journal_generation(
            EnvironmentJournalGeneration(
                1,
                stream,
                sequence,
                previous,
                selected_state,
                selected_record,  # type: ignore[arg-type]
            ),
            protection=protection,
        )
        sealed_items.append(sealed)
        previous = sealed.generation_sha256
    selection = select_environment_journal_chain(
        tuple(sealed_items),
        None,
        expected_stream=stream,
        protection=protection,
    )
    return PersistedEnvironmentJournalChain(
        tuple(sealed_items),
        tuple(_identity(90 + index) for index in range(len(sealed_items))),
        selection,
    )


def test_classification_ignores_foreign_package_journals() -> None:
    package_root = _identity(1)
    foreign = _chain(
        journal_id="a" * 32,
        package_root_identity=_identity(2),
        provider_environment=False,
    )

    result = scan.classify_package_recovery_journals((foreign,), package_root)

    assert result.repair_pending is False
    assert result.provider_environment_pending is False
    assert result.mutation_blocked is False


def test_classification_reports_both_pending_protocols() -> None:
    package_root = _identity(1)
    repair = _chain(
        journal_id="a" * 32,
        package_root_identity=package_root,
        provider_environment=False,
    )
    provider = _chain(
        journal_id="b" * 32,
        package_root_identity=package_root,
        provider_environment=True,
    )

    result = scan.classify_package_recovery_journals(
        (provider, repair),
        package_root,
    )

    assert result.repair is repair
    assert result.provider_environment is provider
    assert result.repair_pending is True
    assert result.provider_environment_pending is True
    assert result.mutation_blocked is True
    assert "a" * 32 not in repr(result)


def test_external_provider_environment_state_blocks_matching_package() -> None:
    package_root = _identity(1)

    result = scan.classify_package_recovery_journals(
        (),
        package_root,
        external_provider_environment_pending=True,
    )

    assert result.provider_environment is None
    assert result.external_provider_environment_pending is True
    assert result.provider_environment_pending is True
    assert result.mutation_blocked is True


def test_external_provider_name_scan_binds_exact_environment_mutex_digest() -> None:
    package_root = _identity(1)
    digest = derive_environment_mutex_name(package_root).removeprefix(
        "Global\\TowerScoutEnv-v1-"
    )
    foreign_digest = derive_environment_mutex_name(_identity(2)).removeprefix(
        "Global\\TowerScoutEnv-v1-"
    )

    assert scan._external_provider_environment_is_pending(  # noqa: SLF001
        (
            f"provider-env-{digest}-00000000000000000001.generation",
            f"provider-env-{digest}.pointer",
            f"provider-env-{foreign_digest}-00000000000000000001.generation",
        ),
        package_root,
    )
    assert not scan._external_provider_environment_is_pending(  # noqa: SLF001
        (f"provider-env-{foreign_digest}.pointer",),
        package_root,
    )


def test_external_provider_name_scan_rejects_malformed_matching_entry() -> None:
    package_root = _identity(1)
    digest = derive_environment_mutex_name(package_root).removeprefix(
        "Global\\TowerScoutEnv-v1-"
    )

    with pytest.raises(scan.RecoveryJournalScanError) as failure:
        scan._external_provider_environment_is_pending(  # noqa: SLF001
            (f"provider-env-{digest}-unexpected.tmp",),
            package_root,
        )

    assert failure.value.code is scan.RecoveryJournalScanErrorCode.STATE_AMBIGUOUS


def test_applied_provider_journals_are_terminal_and_do_not_block_next_update() -> None:
    package_root = _identity(1)
    terminal = _chain(
        journal_id="a" * 32,
        package_root_identity=package_root,
        provider_environment=True,
        provider_applied=True,
    )

    result = scan.classify_package_recovery_journals((terminal,), package_root)

    assert result.provider_environment_pending is False
    assert result.mutation_blocked is False


def test_cleaned_repair_journal_is_terminal_and_does_not_block_next_update() -> None:
    package_root = _identity(1)
    stream = JournalStreamIdentity(1, "a" * 32, "b" * 64, package_root)
    chain = SimpleNamespace(
        selection=SimpleNamespace(
            tip=SimpleNamespace(
                stream=stream,
                state=EnvironmentJournalState.CLEANED,
            ),
            generations=(
                SimpleNamespace(state=EnvironmentJournalState.BACKUP_PREPARING),
            ),
        )
    )

    assert scan._pending_protocol(chain, package_root) is None  # type: ignore[arg-type]  # noqa: SLF001


def test_terminal_provider_history_allows_one_new_pending_stream() -> None:
    package_root = _identity(1)
    first = _chain(
        journal_id="a" * 32,
        package_root_identity=package_root,
        provider_environment=True,
        provider_applied=True,
    )
    second = _chain(
        journal_id="b" * 32,
        package_root_identity=package_root,
        provider_environment=True,
        provider_applied=True,
    )
    pending = _chain(
        journal_id="c" * 32,
        package_root_identity=package_root,
        provider_environment=True,
    )

    result = scan.classify_package_recovery_journals(
        (first, pending, second),
        package_root,
    )

    assert result.provider_environment is pending
    assert result.provider_environment_pending is True


@pytest.mark.parametrize("provider_environment", (False, True))
def test_classification_rejects_multiple_matching_journals_per_protocol(
    provider_environment: bool,
) -> None:
    package_root = _identity(1)
    first = _chain(
        journal_id="a" * 32,
        package_root_identity=package_root,
        provider_environment=provider_environment,
    )
    second = _chain(
        journal_id="b" * 32,
        package_root_identity=package_root,
        provider_environment=provider_environment,
    )

    with pytest.raises(scan.RecoveryJournalScanError) as failure:
        scan.classify_package_recovery_journals((first, second), package_root)

    assert failure.value.code is scan.RecoveryJournalScanErrorCode.STATE_AMBIGUOUS


def test_classification_rejects_duplicate_stream() -> None:
    package_root = _identity(1)
    chain = _chain(
        journal_id="a" * 32,
        package_root_identity=package_root,
        provider_environment=False,
    )

    with pytest.raises(scan.RecoveryJournalScanError) as failure:
        scan.classify_package_recovery_journals((chain, chain), package_root)

    assert failure.value.code is scan.RecoveryJournalScanErrorCode.STATE_AMBIGUOUS


def test_classification_rejects_duplicate_stream_across_packages() -> None:
    package_root = _identity(1)
    matching = _chain(
        journal_id="a" * 32,
        package_root_identity=package_root,
        provider_environment=False,
    )
    foreign = _chain(
        journal_id="a" * 32,
        package_root_identity=_identity(2),
        provider_environment=False,
    )

    with pytest.raises(scan.RecoveryJournalScanError) as failure:
        scan.classify_package_recovery_journals((foreign, matching), package_root)

    assert failure.value.code is scan.RecoveryJournalScanErrorCode.STATE_AMBIGUOUS


def test_classification_rejects_invalid_inputs_without_detail() -> None:
    with pytest.raises(scan.RecoveryJournalScanError) as failure:
        scan.classify_package_recovery_journals(  # type: ignore[arg-type]
            [],
            _identity(1),
        )

    assert failure.value.code is scan.RecoveryJournalScanErrorCode.INPUT_INVALID
    assert "private" not in str(failure.value).lower()


def test_scan_wrapper_requires_held_package_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = _package_root(_identity(1))
    monkeypatch.setattr(
        scan,
        "discover_persisted_environment_journal_chains",
        lambda **_kwargs: (),
    )

    with pytest.raises(scan.RecoveryJournalScanError) as failure:
        scan.scan_package_recovery_journals_from_held_root(
            package_root,
            protected_root=object(),  # type: ignore[arg-type]
            generation_storage=object(),  # type: ignore[arg-type]
            pointer_storage=object(),  # type: ignore[arg-type]
            protection=object(),  # type: ignore[arg-type]
        )

    assert failure.value.code is scan.RecoveryJournalScanErrorCode.PACKAGE_ROOT_CHANGED
    package_root.close()


def test_scan_wrapper_classifies_while_package_root_is_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_identity = _identity(1)
    package_root = _package_root(package_identity)
    repair = _chain(
        journal_id="a" * 32,
        package_root_identity=package_identity,
        provider_environment=False,
    )
    calls = 0

    def discover(**_kwargs: object) -> tuple[PersistedEnvironmentJournalChain, ...]:
        nonlocal calls
        package_root.assert_unchanged_while_held()
        calls += 1
        return (repair,)

    monkeypatch.setattr(
        scan,
        "discover_persisted_environment_journal_chains",
        discover,
    )

    class Root:
        def run_journal_storage(self, operation):  # type: ignore[no-untyped-def]
            package_root.assert_unchanged_while_held()
            return operation("protected-root")

    class Storage:
        @staticmethod
        def list_names(root_path: str) -> tuple[str, ...]:
            assert root_path == "protected-root"
            return ()

    result = package_root.run_while_held(
        lambda: scan.scan_package_recovery_journals_from_held_root(
            package_root,
            protected_root=Root(),  # type: ignore[arg-type]
            generation_storage=Storage(),  # type: ignore[arg-type]
            pointer_storage=object(),  # type: ignore[arg-type]
            protection=object(),  # type: ignore[arg-type]
        )
    )

    assert calls == 1
    assert result.repair is repair
    assert result.mutation_blocked is True
    package_root.close()
