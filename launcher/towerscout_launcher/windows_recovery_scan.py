"""Read-only cross-protocol recovery-journal scanning for Gate A."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn

from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery_journal import EnvironmentJournalState, JournalProtectionPort
from .windows_recovery_journal_storage import (
    JournalGenerationStoragePort,
    JournalPointerStoragePort,
    JournalStorageRootPort,
    PersistedEnvironmentJournalChain,
    discover_persisted_environment_journal_chains,
)
from .windows_security import StableFileIdentity, WindowsSecurityError

_SCHEMA_VERSION = 1
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


def _chain_matches(
    chain: PersistedEnvironmentJournalChain,
    package_root_identity: StableFileIdentity,
    states: frozenset[EnvironmentJournalState],
) -> bool:
    return (
        chain.selection.tip.stream.package_root_identity == package_root_identity
        and chain.selection.generations[0].state in states
    )


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
            or (
                self.provider_environment is not None
                and not _chain_matches(
                    self.provider_environment,
                    self.package_root_identity,
                    _PROVIDER_ENVIRONMENT_STATES,
                )
            )
        ):
            raise ValueError("Package recovery journal scan is invalid.")

    @property
    def repair_pending(self) -> bool:
        return self.repair is not None

    @property
    def provider_environment_pending(self) -> bool:
        return self.provider_environment is not None

    @property
    def mutation_blocked(self) -> bool:
        return self.repair_pending or self.provider_environment_pending

    def __repr__(self) -> str:
        return (
            "PackageRecoveryJournalScan("
            f"repair_pending={self.repair_pending!r}, "
            "provider_environment_pending="
            f"{self.provider_environment_pending!r}, <redacted>)"
        )


def classify_package_recovery_journals(
    chains: tuple[PersistedEnvironmentJournalChain, ...],
    package_root_identity: StableFileIdentity,
) -> PackageRecoveryJournalScan:
    """Classify authenticated pending protocols bound to one package root."""

    if (
        type(chains) is not tuple
        or type(package_root_identity) is not StableFileIdentity
        or any(type(chain) is not PersistedEnvironmentJournalChain for chain in chains)
    ):
        _fail(RecoveryJournalScanErrorCode.INPUT_INVALID)
    journal_ids = tuple(chain.selection.tip.stream.journal_id for chain in chains)
    if len(set(journal_ids)) != len(journal_ids):
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)

    repair: list[PersistedEnvironmentJournalChain] = []
    provider_environment: list[PersistedEnvironmentJournalChain] = []
    for chain in chains:
        tip = chain.selection.tip
        if tip.stream.package_root_identity != package_root_identity:
            continue
        first_state = chain.selection.generations[0].state
        if first_state in _REPAIR_STATES:
            repair.append(chain)
        elif first_state in _PROVIDER_ENVIRONMENT_STATES:
            provider_environment.append(chain)
        else:
            _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    if len(repair) > 1 or len(provider_environment) > 1:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)
    try:
        return PackageRecoveryJournalScan(
            _SCHEMA_VERSION,
            package_root_identity,
            None if not repair else repair[0],
            None if not provider_environment else provider_environment[0],
        )
    except ValueError:
        _fail(RecoveryJournalScanErrorCode.STATE_AMBIGUOUS)


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
        package_root.assert_unchanged_while_held()
    except WindowsSecurityError:
        _fail(RecoveryJournalScanErrorCode.PACKAGE_ROOT_CHANGED)
    return classify_package_recovery_journals(chains, package_root_identity)


__all__ = [
    "PackageRecoveryJournalScan",
    "RecoveryJournalScanError",
    "RecoveryJournalScanErrorCode",
    "classify_package_recovery_journals",
    "scan_package_recovery_journals_from_held_root",
]
