from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = ROOT / "tests" / "unit"
for path in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_launcher_windows_recovery_scan import (  # noqa: E402
    _chain as _provider_chain,
    _Protection as _ProviderProtection,
)
from test_launcher_windows_repair_certificate_execution_native import (  # noqa: E402
    _applied_setup,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    EnvironmentJournalPointer,
    select_environment_journal_chain,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    PersistedEnvironmentJournalChain,
)
from towerscout_launcher.windows_repair_environment_execution_native import (  # noqa: E402
    AppliedRepairEnvironment,
    apply_native_windows_repair_environment,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
)
import towerscout_launcher.windows_repair_environment_execution_native as native  # noqa: E402


class _ProviderIds:
    def new_provider_journal_id(self) -> str:
        return "c" * 32


def _current_prefix(
    provider: PersistedEnvironmentJournalChain,
    count: int,
) -> PersistedEnvironmentJournalChain:
    sealed = provider.sealed_generations[:count]
    generation = provider.selection.generations[count - 1]
    pointer = EnvironmentJournalPointer(
        1,
        generation.stream.journal_id,
        generation.sequence,
        provider.selection.generation_sha256s[count - 1],
    )
    return PersistedEnvironmentJournalChain(
        sealed,
        provider.file_identities[:count],
        select_environment_journal_chain(
            sealed,
            pointer,
            expected_stream=generation.stream,
            protection=_ProviderProtection(),
        ),
    )


def test_applies_provider_environment_and_links_all_forward_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, context, certificates, _protected, storage = _applied_setup(monkeypatch)
    stream = certificates.prepared.stream
    provider = _provider_chain(
        journal_id="c" * 32,
        package_root_identity=stream.package_root_identity,
        provider_environment=True,
        provider_applied=True,
        target_token_sha256=stream.target_token_sha256,
    )
    provider_staged = _current_prefix(provider, 3)
    provider_applied = _current_prefix(provider, 4)
    monkeypatch.setattr(
        native,
        "stage_or_resume_persisted_environment_candidate",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        native,
        "load_persisted_environment_journal_chain_from_held_root",
        lambda *_args, **_kwargs: provider_staged,
    )
    monkeypatch.setattr(
        native,
        "persist_environment_applied_generation",
        lambda **_kwargs: provider_applied,
    )

    applied = apply_native_windows_repair_environment(
        owner,  # type: ignore[arg-type]
        context,  # type: ignore[arg-type]
        certificates,
        journal_id_source=_ProviderIds(),
        journal_storage=storage,
        pointer_storage=storage,
    )

    assert isinstance(applied, AppliedRepairEnvironment)
    assert applied.provider.selection.tip.sequence == 4
    assert len(applied.forward.selection.generations) == 8
    assert (
        applied.forward.selection.tip.state
        is RepairTransactionState.ENVIRONMENT_APPLIED
    )
    context.close()
    owner.close()
