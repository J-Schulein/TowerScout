"""Capture authenticated pre-mutation readiness for one exact repair target."""

from __future__ import annotations

from enum import Enum
from typing import NoReturn

from .runtime_target_observation import ObservationOperation
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_recovery_journal import (
    RollbackProviderOutcome,
    RollbackReadinessCondition,
)
from .windows_recovery_readiness_authority import (
    RollbackReadinessAuthority,
    derive_rollback_readiness_authority,
)
from .windows_security import StableFileIdentity


class NativeRepairReadinessErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_readiness_input_invalid"
    PROBE_FAILED = "native_repair_readiness_probe_failed"
    NOT_REPAIRABLE = "native_repair_readiness_not_repairable"


class NativeRepairReadinessError(RuntimeError):
    _MESSAGES = {
        NativeRepairReadinessErrorCode.INPUT_INVALID: (
            "The repair readiness request is invalid."
        ),
        NativeRepairReadinessErrorCode.PROBE_FAILED: (
            "The current TowerScout readiness could not be verified safely."
        ),
        NativeRepairReadinessErrorCode.NOT_REPAIRABLE: (
            "The current provider result does not authorize TLS repair."
        ),
    }

    def __init__(self, code: NativeRepairReadinessErrorCode) -> None:
        if type(code) is not NativeRepairReadinessErrorCode:
            raise ValueError("Unknown native repair readiness error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairReadinessError(code={self.code.value!r})"


def _fail(code: NativeRepairReadinessErrorCode) -> NoReturn:
    raise NativeRepairReadinessError(code) from None


def _probe(
    owner: BoundResolvedRepairTarget,
    operation: str,
    expected: ObservationOperation,
) -> bytes:
    failed = False
    value: object = None
    try:
        value = owner.execute_scoped_process(
            operation,
            (owner.target.container.container_id,),
        )
    except Exception:
        failed = True
    if (
        failed
        or type(value) is not TargetObservationProcessResult
        or value.operation is not expected
        or value.exit_code != 0
    ):
        _fail(NativeRepairReadinessErrorCode.PROBE_FAILED)
    return value.stdout


def capture_repair_readiness_authority_while_target_held(
    owner: BoundResolvedRepairTarget,
) -> RollbackReadinessAuthority:
    """Require a fresh repairable provider failure before rollback is armed."""

    if type(owner) is not BoundResolvedRepairTarget or owner.closed:
        _fail(NativeRepairReadinessErrorCode.INPUT_INVALID)
    readiness = {
        b"setup_required\n": RollbackReadinessCondition.SETUP_REQUIRED,
        b"degraded\n": RollbackReadinessCondition.DEGRADED,
        b"ready\n": RollbackReadinessCondition.READY,
    }.get(
        _probe(
            owner,
            "rollback_readiness_probe",
            ObservationOperation.ROLLBACK_READINESS_PROBE,
        )
    )
    provider = {
        b"success\n": RollbackProviderOutcome.SUCCESS,
        b"repairable_tls_failure\n": (RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE),
        b"provider_recheck_indeterminate\n": (
            RollbackProviderOutcome.PROVIDER_RECHECK_INDETERMINATE
        ),
    }.get(
        _probe(
            owner,
            "rollback_provider_probe",
            ObservationOperation.ROLLBACK_PROVIDER_PROBE,
        )
    )
    if (
        type(readiness) is not RollbackReadinessCondition
        or type(provider) is not RollbackProviderOutcome
    ):
        _fail(NativeRepairReadinessErrorCode.PROBE_FAILED)
    if provider is not RollbackProviderOutcome.REPAIRABLE_TLS_FAILURE:
        _fail(NativeRepairReadinessErrorCode.NOT_REPAIRABLE)
    target = owner.target
    try:
        package_identity = StableFileIdentity(
            target.package_root.volume_serial,
            target.package_root.file_id,
        )
        return derive_rollback_readiness_authority(
            target_token_sha256=target.target_token.digest_sha256,
            package_root_identity=package_identity,
            condition=readiness,
            provider_outcome=provider,
        )
    except ValueError:
        _fail(NativeRepairReadinessErrorCode.PROBE_FAILED)


__all__ = [
    "NativeRepairReadinessError",
    "NativeRepairReadinessErrorCode",
    "capture_repair_readiness_authority_while_target_held",
]
