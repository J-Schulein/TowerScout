from __future__ import annotations

from pathlib import Path
import sys

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
from test_launcher_windows_repair_transaction_journal_storage import (  # noqa: E402
    _append_through,
    _Protection,
    _Root,
    _Storage,
    _stream,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    EnvironmentJournalPointer,
    select_environment_journal_chain,
)
from towerscout_launcher.windows_recovery_journal_storage import (  # noqa: E402
    PersistedEnvironmentJournalChain,
)
from towerscout_launcher.windows_repair_provider_linkage import (  # noqa: E402
    persist_forward_provider_linkage,
)
from towerscout_launcher.windows_repair_transaction_journal import (  # noqa: E402
    RepairTransactionState,
)
from towerscout_launcher.windows_repair_transaction_journal_storage import (  # noqa: E402
    ensure_persisted_repair_transaction_pointer_from_held_root,
)


def _current_provider() -> PersistedEnvironmentJournalChain:
    provider = _provider_chain(
        journal_id="e" * 32,
        package_root_identity=_stream().package_root_identity,
        provider_environment=True,
        provider_applied=True,
        target_token_sha256="d" * 64,
    )
    pointer = EnvironmentJournalPointer(
        1,
        provider.selection.tip.stream.journal_id,
        provider.selection.tip.sequence,
        provider.selection.tip_generation_sha256,
    )
    return PersistedEnvironmentJournalChain(
        provider.sealed_generations,
        provider.file_identities,
        select_environment_journal_chain(
            provider.sealed_generations,
            pointer,
            expected_stream=provider.selection.tip.stream,
            protection=_ProviderProtection(),
        ),
    )


def test_persists_all_exact_provider_links_and_is_idempotent() -> None:
    storage = _Storage()
    protection = _Protection()
    _append_through(4, backing=storage, protection=protection)
    current = ensure_persisted_repair_transaction_pointer_from_held_root(
        r"C:\Protected\TowerScout\Recovery\v1",
        _stream(),
        generation_storage=storage,
        pointer_storage=storage,
        protection=protection,
    )
    assert current is not None
    provider = _current_provider()

    linked = persist_forward_provider_linkage(
        current,
        provider,
        root=_Root(),
        generation_storage=storage,
        pointer_storage=storage,
        protection=protection,
    )
    repeated = persist_forward_provider_linkage(
        linked,
        provider,
        root=_Root(),
        generation_storage=storage,
        pointer_storage=storage,
        protection=protection,
    )

    assert len(linked.selection.generations) == 8
    assert linked.selection.tip.state is RepairTransactionState.ENVIRONMENT_APPLIED
    assert repeated.selection.generation_sha256s == linked.selection.generation_sha256s
    assert tuple(
        item.record.provider_sequence for item in linked.selection.generations[4:]
    ) == (1, 2, 3, 4)
