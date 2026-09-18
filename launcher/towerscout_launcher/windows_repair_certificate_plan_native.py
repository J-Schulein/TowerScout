"""Build the exact certificate replacement plan through retained authority."""

from __future__ import annotations

from enum import Enum
from typing import NoReturn

from .runtime_target_observation import ObservationOperation
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .trust_policy import SelectedWindowsRootMaterial
from .windows_certificate_replacement import (
    MAX_CA_BUNDLE_BYTES,
    CertificateReplacementPlan,
    plan_certificate_replacement,
)


class NativeRepairCertificatePlanErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_certificate_plan_input_invalid"
    READ_FAILED = "native_repair_certificate_plan_read_failed"
    PLAN_INVALID = "native_repair_certificate_plan_invalid"


class NativeRepairCertificatePlanError(RuntimeError):
    _MESSAGES = {
        NativeRepairCertificatePlanErrorCode.INPUT_INVALID: (
            "The repair certificate plan request is invalid."
        ),
        NativeRepairCertificatePlanErrorCode.READ_FAILED: (
            "The container certificate bundle could not be read safely."
        ),
        NativeRepairCertificatePlanErrorCode.PLAN_INVALID: (
            "The repair certificate replacement plan is invalid."
        ),
    }

    def __init__(self, code: NativeRepairCertificatePlanErrorCode) -> None:
        if type(code) is not NativeRepairCertificatePlanErrorCode:
            raise ValueError("Unknown native repair certificate plan error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairCertificatePlanError(code={self.code.value!r})"


def _fail(code: NativeRepairCertificatePlanErrorCode) -> NoReturn:
    raise NativeRepairCertificatePlanError(code) from None


def build_repair_certificate_plan_while_target_held(
    owner: BoundResolvedRepairTarget,
) -> CertificateReplacementPlan:
    """Read one fixed system bundle and append the retained reviewed root."""

    if type(owner) is not BoundResolvedRepairTarget or owner.closed:
        _fail(NativeRepairCertificatePlanErrorCode.INPUT_INVALID)
    selected_root: SelectedWindowsRootMaterial | None = None
    result: object = None
    read_failed = False
    try:
        selected_root = owner.certificate_material
        result = owner.execute_scoped_process(
            "certificate_read_system_bundle",
            (owner.target.container.container_id,),
        )
    except Exception:
        read_failed = True
    if (
        read_failed
        or type(selected_root) is not SelectedWindowsRootMaterial
        or type(result) is not TargetObservationProcessResult
        or result.operation is not ObservationOperation.CERTIFICATE_READ_SYSTEM_BUNDLE
        or result.exit_code != 0
        or not 1 <= len(result.stdout) <= MAX_CA_BUNDLE_BYTES
    ):
        _fail(NativeRepairCertificatePlanErrorCode.READ_FAILED)
    plan: CertificateReplacementPlan | None = None
    plan_failed = False
    try:
        plan = plan_certificate_replacement(selected_root, result.stdout)
    except Exception:
        plan_failed = True
    if (
        plan_failed
        or type(plan) is not CertificateReplacementPlan
        or plan.provider is not owner.target.provider
        or plan.windows_root_fingerprint_sha256
        != owner.target.certificate.windows_root_fingerprint_sha256
        or plan.local_ca_sha256 != owner.target.certificate.candidate_content_sha256
    ):
        _fail(NativeRepairCertificatePlanErrorCode.PLAN_INVALID)
    return plan


__all__ = [
    "NativeRepairCertificatePlanError",
    "NativeRepairCertificatePlanErrorCode",
    "build_repair_certificate_plan_while_target_held",
]
