"""Read-only cross-protocol recovery-journal scanning for Gate A."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import NoReturn

from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery_journal import (
    EnvironmentJournalState,
    JournalPointerDisposition,
    JournalProtectionPort,
)
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    discover_persisted_environment_journal_chains,
)
from .windows_repair_transaction_journal import (
    RepairTransactionJournalError,
    RepairTransactionState,
    authenticate_provider_link,
)
from .windows_repair_transaction_journal_storage import (
    PersistedRepairTransactionChain,
    discover_persisted_repair_transaction_chains,
)
from .windows_security import (
    StableFileIdentity,
    WindowsSecurityError,
    derive_environment_mutex_name,
)

_SCHEMA_VERSION = 1
_EXTERNAL_PROVIDER_GENERATION = re.compile(
    r"^provider-env-([0-9a-f]{64})-([0-9]{20})\.generation$"
)
_EXTERNAL_PROVIDER_POINTER = re.compile(
    r"^provider-env-([0-9a-f]{64})\.pointer(?:\.tmp)?$"
)
_REPAIR_STATES = frozenset(
    {
        EnvironmentJournalState.BACKUP_PREPARING,
        EnvironmentJournalState.BACKUP_VERIFIED,
        EnvironmentJournalState.ROLLBACK_ARMED,
        EnvironmentJournalState.ROLLBACK_STARTED,
        EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_PLANNED,
        EnvironmentJournalState.ENVIRONMENT_RESTORE_TEMP_CREATED,
    }
)
_PROVIDER_ENVIRONMENT_STATES = frozenset(
    {
        EnvironmentJournalState.ENVIRONMENT_TEMP_PLANNED,
        EnvironmentJournalState.ENVIRONMENT_TEMP_CREATED,
        EnvironmentJournalState.ENVIRONMENT_TEMP_VERIFIED,
        EnvironmentJournalState.ENVIRONMENT_APPLIED,
    }
)
_TERMINAL_REPAIR_STATES = frozenset(
    {
        EnvironmentJournalState.ABORTED_WITHOUT_MUTATION,
        EnvironmentJournalState.CLEANED,
    }
)


def _repair_is_terminal(chain: PersistedEnvironmentJournalChain) -> bool:
    state = chain.selection.tip.state
    return state is EnvironmentJournalState.CLEANED or (
        state is EnvironmentJournalState.ABORTED_WITHOUT_MUTATION
        and chain.selection.pointer_disposition is JournalPointerDisposition.CURRENT
    )


def _chain_matches(
    chain: PersistedEnvironmentJournalChain,
    package_root_identity: StableFileIdentity,
    states: frozenset[EnvironmentJournalState],
) -> bool:
    return (
        chain.selection.tip.stream.package_root_identity == package_root_identity
        and chain.selection.generations[0].state in states
    )


def _valid_forward_binding(
    repair: PersistedEnvironmentJournalChain | None,
    forward: PersistedRepairTransactionChain | None,
    provider: PersistedEnvironmentJournalChain | None,
) -> bool:
    if forward is None:
        return provider is None
    if repair is None:
        return False
    repair_selection = repair.selection
    forward_stream = forward.selection.tip.stream
    if (
        len(repair_selection.generations) < 3
        or forward_stream.rollback_journal_id != repair_selection.tip.stream.journal_id
        or forward_stream.rollback_armed_generation_sha256
        != repair_selection.generation_sha256s[2]
        or forward_stream.target_token_sha256
        != repair_selection.tip.stream.target_token_sha256
        or forward_stream.package_root_identity
        != repair_selection.tip.stream.package_root_identity
    ):
        return False
    has_environment_link = any(
        generation.state
        in {
            RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
            RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
            RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
            RepairTransactionState.ENVIRONMENT_APPLIED,
        }
        for generation in forward.selection.generations
    )
    if provider is None:
        return not has_environment_link
    if not has_environment_link:
        return False
    try:
        authenticate_provider_link(forward.selection, provider)
    except RepairTransactionJournalError:
        return False
    return True


def _bound_repair_for_forward(
    forward: PersistedRepairTransactionChain,
    repairs: tuple[PersistedEnvironmentJournalChain, ...],
    chains: tuple[PersistedEnvironmentJournalChain, ...],
) -> PersistedEnvironmentJournalChain | None:
    stream = forward.selection.tip.stream
    matches = tuple(
        repair
        for repair in repairs
        if len(repair.selection.generations) >= 3
        and stream.rollback_journal_id == repair.selection.tip.stream.journal_id
        and stream.rollback_armed_generation_sha256
        == repair.selection.generation_sha256s[2]
        and stream.target_token_sha256
        == repair.selection.tip.stream.target_token_sha256
        and stream.package_root_identity
        == repair.selection.tip.stream.package_root_identity
    )
    if len(matches) != 1:
        return None
    linked_ids = {
        generation.record.provider_journal_id
        for generation in forward.selection.generations
        if generation.state
        in {
            RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
            RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
            RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
            RepairTransactionState.ENVIRONMENT_APPLIED,
        }
    }
    provider: PersistedEnvironmentJournalChain | None = None
    if linked_ids:
        if len(linked_ids) != 1:
            return None
        linked_id = next(iter(linked_ids))
        providers = tuple(
            chain
            for chain in chains
            if chain.selection.tip.stream.journal_id == linked_id
        )
        if len(providers) != 1:
            return None
        provider = providers[0]
    return matches[0] if _valid_forward_binding(matches[0], forward, provider) else None


class RecoveryJournalScanErrorCode(str, Enum):
    INPUT_INVALID = "recovery_journal_scan_input_invalid"
    STATE_AMBIGUOUS = "recovery_journal_state_ambiguous"
    PACKAGE_ROOT_CHANGED = "recovery_journal_package_root_changed"


class RecoveryJournalScanError(RuntimeError):
    """Sanitized failure while classifying protected recovery journals."""

    _MESSAGES = {
        RecoveryJournalScanErrorCode.INPUT_INVALID: (
            "The protected recovery journal scan request is invalid."
        ),
        RecoveryJournalScanErrorCode.STATE_AMBIGUOUS: (
            "Protected recovery journal state is ambiguous."
        ),
        RecoveryJournalScanErrorCode.PACKAGE_ROOT_CHANGED: (
            "The package root changed during recovery journal inspection."
        ),
    }

    def __init__(self, code: RecoveryJournalScanErrorCode) -> None:
        if type(code) is not RecoveryJournalScanErrorCode:
            raise ValueError("Unknown recovery journal scan error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryJournalScanError(code={self.code.value!r})"


def _fail(code: RecoveryJournalScanErrorCode) -> NoReturn:
    raise RecoveryJournalScanError(code) from None


@dataclass(frozen=True, slots=True, repr=False)
class PackageRecoveryJournalScan:
    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    repair: PersistedEnvironmentJournalChain | None = field(
        default=None,
        repr=False,
    )
    provider_environment: PersistedEnvironmentJournalChain | None = field(
        default=None,
        repr=False,
    )
    external_provider_environment_pending: bool = False
    forward: PersistedRepairTransactionChain | None = field(
        default=None,
        repr=False,
    )
    repair_provider_environment: PersistedEnvironmentJournalChain | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or (
                self.repair is not None
                and type(self.repair) is not PersistedEnvironmentJournalChain
            )
            or (
                self.provider_environment is not None
                and type(self.provider_environment)
                is not PersistedEnvironmentJournalChain
            )
            or (
                self.repair is not None
                and not _chain_matches(
                    self.repair,
                    self.package_root_identity,
                    _REPAIR_STATES,
                )
            )
            or (self.repair is not None and _repair_is_terminal(self.repair))
            or (
                self.provider_environment is not None
                and not _chain_matches(
                    self.provider_environment,
                    self.package_root_identity,
                    _PROVIDER_ENVIRONMENT_STATES,
                )
            )
            or type(self.external_provider_environment_pending) is not bool
            or (
                self.forward is not None
                and (
                    type(self.forward) is not PersistedRepairTransactionChain
                    or self.forward.selection.tip.stream.package_root_identity
                    != self.package_root_identity
                    or self.forward.selection.tip.state
                    is RepairTransactionState.CLEANED
                )
            )
            or (
                self.repair_provider_environment is not None
                and (
                    type(self.repair_provider_environment)
                    is not PersistedEnvironmentJournalChain
                    or self.forward is None
                )
            )
            or not _valid_forward_binding(
                self.repair,
                self.forward,
                self.repair_provider_environment,
            )
        ):
            raise ValueError("Package recovery journal scan is invalid.")

    @property
    def repair_pending(self) -> bool:
        return self.repair is not None

    @property
    def provider_environment_pending(self) -> bool:
        return (
            self.provider_environment is not None
            or self.external_provider_environment_pending
        )

    @property
    def forward_pending(self) -> bool:
        return self.forward is not None

    @property
    def mutation_blocked(self) -> bool:
        return (
            self.repair_pending
            or self.forward_pending
            or self.provider_environment_pending
        )

    def __repr__(self) -> str:
        return (
            "PackageRecoveryJournalScan("
            f"repair_pending={self.repair_pending!r}, "
            f"forward_pending={self.forward_pending!r}, "
            "provider_environment_pending="
            f"{self.provider_environment_pending!r}, <redacted>)"
        )


def _valid_classification_inputs(
    chains: tuple[PersistedEnvironmentJournalChain, ...],
    forward_chains: tuple[PersistedRepairTransactionChain, ...],
    package_root_identity: StableFileIdentity,
    external_provider_environment_pending: bool,
) -> bool:
    return not (
        type(chains) is not tuple
        or type(package_root_identity) is not StableFileIdentity
        or type(forward_chains) is not tuple
        or type(external_provider_environment_pending) is not bool
        or any(type(chain) is not PersistedEnvironmentJournalChain for chain in chains)
        or any(
            type(chain) is not PersistedRepairTransactionChain
            for chain in forward_chains
        )
    )


def _pending_protocol(
    chain: PersistedEnvironmentJournalChain,
    package_root_identity: StableFileIdentity,
) -> str | None:
    tip = chain.selection.tip
    if tip.stream.package_root_identity != package_root_identity:
        return None
    first_state = chain.selection.generations[0].state
    if first_state in _REPAIR_STATES:
        return None if _repair_is_terminal(chain) else "repair"
    if first_state in _PROVIDER_ENVIRONMENT_STATES:
        return (
            None
            if tip.state is EnvironmentJournalState.ENVIRONMENT_APPLIED
            else "provider"
        )
    _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)


def classify_package_recovery_journals(
    chains: tuple[PersistedEnvironmentJournalChain, ...],
    package_root_identity: StableFileIdentity,
    *,
    external_provider_environment_pending: bool = False,
    forward_chains: tuple[PersistedRepairTransactionChain, ...] = (),
) -> PackageRecoveryJournalScan:
    """Classify authenticated pending protocols bound to one package root."""

    if not _valid_classification_inputs(
        chains,
        forward_chains,
        package_root_identity,
        external_provider_environment_pending,
    ):
        _fail(RecoveryJournalScanErrorCode.INPUT_INVALID)
    journal_ids = tuple(
        chain.selection.tip.stream.journal_id for chain in chains
    ) + tuple(chain.selection.tip.stream.journal_id for chain in forward_chains)
    if len(set(journal_ids)) != len(journal_ids):
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)

    repair_protocols: list[PersistedEnvironmentJournalChain] = []
    provider_environment: list[PersistedEnvironmentJournalChain] = []
    for chain in chains:
        first_state = chain.selection.generations[0].state
        if (
            chain.selection.tip.stream.package_root_identity == package_root_identity
            and first_state in _REPAIR_STATES
        ):
            repair_protocols.append(chain)
        protocol = _pending_protocol(chain, package_root_identity)
        if protocol == "provider":
            provider_environment.append(chain)
    all_forward = [
        chain
        for chain in forward_chains
        if chain.selection.tip.stream.package_root_identity == package_root_identity
    ]
    pairs: list[
        tuple[PersistedRepairTransactionChain, PersistedEnvironmentJournalChain]
    ] = []
    for candidate in all_forward:
        bound = _bound_repair_for_forward(
            candidate,
            tuple(repair_protocols),
            chains,
        )
        if bound is None:
            _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
        pairs.append((candidate, bound))
    successful_repair_ids = {
        id(repair)
        for forward_chain, repair in pairs
        if forward_chain.selection.tip.state is RepairTransactionState.CLEANED
    }
    repair = [
        chain
        for chain in repair_protocols
        if not _repair_is_terminal(chain) and id(chain) not in successful_repair_ids
    ]
    forward = [
        forward_chain
        for forward_chain, bound_repair in pairs
        if forward_chain.selection.tip.state is not RepairTransactionState.CLEANED
        and bound_repair.selection.tip.state is not EnvironmentJournalState.CLEANED
    ]
    repair_provider_environment: PersistedEnvironmentJournalChain | None = None
    if len(forward) > 1 or len(repair) > 1:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    if forward:
        selected_forward = forward[0]
        if not repair:
            _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
        selected_repair = repair[0]
        forward_stream = selected_forward.selection.tip.stream
        repair_selection = selected_repair.selection
        if (
            len(repair_selection.generations) < 3
            or forward_stream.rollback_journal_id
            != repair_selection.tip.stream.journal_id
            or forward_stream.rollback_armed_generation_sha256
            != repair_selection.generation_sha256s[2]
            or forward_stream.target_token_sha256
            != repair_selection.tip.stream.target_token_sha256
            or forward_stream.package_root_identity
            != repair_selection.tip.stream.package_root_identity
        ):
            _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
        linked_generation = next(
            (
                generation
                for generation in reversed(selected_forward.selection.generations)
                if generation.state
                in {
                    RepairTransactionState.ENVIRONMENT_TEMP_PLANNED,
                    RepairTransactionState.ENVIRONMENT_TEMP_CREATED,
                    RepairTransactionState.ENVIRONMENT_TEMP_VERIFIED,
                    RepairTransactionState.ENVIRONMENT_APPLIED,
                }
            ),
            None,
        )
        if linked_generation is not None:
            linked_id = linked_generation.record.provider_journal_id
            matches = [
                chain
                for chain in chains
                if chain.selection.tip.stream.journal_id == linked_id
            ]
            if len(matches) != 1:
                _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
            try:
                authenticate_provider_link(selected_forward.selection, matches[0])
            except RepairTransactionJournalError:
                _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
            repair_provider_environment = matches[0]
            provider_environment = [
                chain for chain in provider_environment if chain is not matches[0]
            ]
    if len(provider_environment) > 1:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    try:
        return PackageRecoveryJournalScan(
            schema_version=_SCHEMA_VERSION,
            package_root_identity=package_root_identity,
            repair=None if not repair else repair[0],
            provider_environment=(
                None if not provider_environment else provider_environment[0]
            ),
            external_provider_environment_pending=(
                external_provider_environment_pending
            ),
            forward=None if not forward else forward[0],
            repair_provider_environment=repair_provider_environment,
        )
    except ValueError:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)


def _external_provider_environment_is_pending(
    names: tuple[str, ...],
    package_root_identity: StableFileIdentity,
) -> bool:
    if (
        type(names) is not tuple
        or len(names) > 256
        or any(type(name) is not str for name in names)
        or len(set(names)) != len(names)
        or type(package_root_identity) is not StableFileIdentity
    ):
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    mutex_name = derive_environment_mutex_name(package_root_identity)
    digest = mutex_name.removeprefix("Global\\TowerScoutEnv-v1-")
    if len(digest) != 64:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    prefix = f"provider-env-{digest}"
    matching = tuple(name for name in names if name.startswith(prefix))
    for name in matching:
        generation = _EXTERNAL_PROVIDER_GENERATION.fullmatch(name)
        pointer = _EXTERNAL_PROVIDER_POINTER.fullmatch(name)
        matched_digest = (
            generation.group(1)
            if generation is not None
            else pointer.group(1) if pointer is not None else None
        )
        if matched_digest != digest:
            _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    return bool(matching)


def _scan_external_provider_environment(
    *,
    protected_root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    package_root_identity: StableFileIdentity,
) -> bool:
    try:
        run = getattr(protected_root, "run_journal_storage")
        list_names = getattr(generation_storage, "list_names")
        if not callable(run) or not callable(list_names):
            raise TypeError("Protected recovery storage is unavailable.")
        result = run(
            lambda root_path: _external_provider_environment_is_pending(
                list_names(root_path),
                package_root_identity,
            )
        )
    except RecoveryJournalScanError:
        raise
    except Exception:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    if type(result) is not bool:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    return result


def scan_package_recovery_journals_from_held_root(
    package_root: PathHierarchyTrust,
    *,
    protected_root: JournalStorageRootPort,
    generation_storage: JournalGenerationStoragePort,
    pointer_storage: JournalPointerStoragePort,
    protection: JournalProtectionPort,
) -> PackageRecoveryJournalScan:
    """Scan while the caller retains its package-root trust lease."""

    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
    ):
        _fail(RecoveryJournalScanErrorCode.INPUT_INVALID)
    try:
        package_root.assert_unchanged_while_held()
        package_root_identity = package_root.root_snapshot.identity
        chains = discover_persisted_environment_journal_chains(
            root=protected_root,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
        forward_chains = discover_persisted_repair_transaction_chains(
            root=protected_root,
            generation_storage=generation_storage,
            pointer_storage=pointer_storage,
            protection=protection,
        )
        external_provider_pending = _scan_external_provider_environment(
            protected_root=protected_root,
            generation_storage=generation_storage,
            package_root_identity=package_root_identity,
        )
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(RecoveryJournalScanErrorCode.PACKAGE_ROOT_CHANGED)
    return classify_package_recovery_journals(
        chains,
        package_root_identity,
        external_provider_environment_pending=external_provider_pending,
        forward_chains=forward_chains,
    )


__all__ = [
    "PackageRecoveryJournalScan",
    "RecoveryJournalScanError",
    "RecoveryJournalScanErrorCode",
    "classify_package_recovery_journals",
    "scan_package_recovery_journals_from_held_root",
]
