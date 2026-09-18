"""Pure exact-state classification for atomic Windows ``.env`` promotion.

The models bind a verified same-directory candidate to the exact original
destination state.  They classify only a complete pre-call or post-call state;
they do not open, replace, move, remove, or journal any file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn

from .windows_environment_replacement_native import EnvironmentTempVerifiedRecord
from .windows_recovery_environment_restore import EnvironmentDestinationObservation
from .windows_security import StableFileIdentity

_SCHEMA_VERSION = 1


class EnvironmentPromotionDecisionErrorCode(str, Enum):
    INPUT_INVALID = "environment_promotion_decision_input_invalid"


class EnvironmentPromotionDecisionError(RuntimeError):
    """Sanitized failure at the environment-promotion decision boundary."""

    def __init__(self, code: EnvironmentPromotionDecisionErrorCode) -> None:
        if type(code) is not EnvironmentPromotionDecisionErrorCode:
            raise ValueError("Unknown environment promotion decision error code.")
        self.code = code
        super().__init__("The environment promotion decision request is invalid.")

    def __repr__(self) -> str:
        return f"EnvironmentPromotionDecisionError(code={self.code.value!r})"


class EnvironmentPromotionState(str, Enum):
    READY_EXISTING = "ready_existing"
    READY_ABSENT = "ready_absent"
    APPLIED = "applied"
    THIRD_STATE = "third_state"


class EnvironmentPromotionAction(str, Enum):
    REPLACE_EXISTING = "replace_existing"
    MOVE_NEW = "move_new"
    ALREADY_APPLIED = "already_applied"
    BLOCK = "block"


def _fail() -> NoReturn:
    raise EnvironmentPromotionDecisionError(
        EnvironmentPromotionDecisionErrorCode.INPUT_INVALID
    )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentPromotionAuthority:
    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    original: EnvironmentDestinationObservation = field(repr=False)
    verified: EnvironmentTempVerifiedRecord = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.original) is not EnvironmentDestinationObservation
            or type(self.verified) is not EnvironmentTempVerifiedRecord
            or self.verified.package_root_identity != self.package_root_identity
            or self.verified.temp_identity == self.package_root_identity
            or self.verified.temp_identity.volume_serial
            != self.package_root_identity.volume_serial
            or (
                self.original.present
                and (
                    self.original.identity == self.package_root_identity
                    or self.original.identity == self.verified.temp_identity
                    or self.original.identity is None
                    or self.original.identity.volume_serial
                    != self.package_root_identity.volume_serial
                )
            )
        ):
            raise ValueError("Environment promotion authority is invalid.")

    @property
    def expected_applied(self) -> EnvironmentDestinationObservation:
        """Return the exact post-call destination state required by Win32."""

        attributes = (
            self.original.file_attributes
            if self.original.present
            else self.verified.candidate_file_attributes
        )
        descriptor = (
            self.original.security_descriptor_sha256
            if self.original.present
            else self.verified.candidate_security_descriptor_sha256
        )
        assert type(attributes) is int
        assert type(descriptor) is str
        return EnvironmentDestinationObservation(
            True,
            self.verified.temp_identity,
            self.verified.candidate_sha256,
            self.verified.candidate_size,
            attributes,
            descriptor,
        )

    def __repr__(self) -> str:
        return (
            "EnvironmentPromotionAuthority("
            f"original_present={self.original.present!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentPromotionObservation:
    destination: EnvironmentDestinationObservation = field(repr=False)
    temp: EnvironmentDestinationObservation = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.destination) is not EnvironmentDestinationObservation
            or type(self.temp) is not EnvironmentDestinationObservation
            or (
                self.destination.present
                and self.temp.present
                and self.destination.identity == self.temp.identity
            )
        ):
            raise ValueError("Environment promotion observation is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentPromotionObservation("
            f"destination_present={self.destination.present!r}, "
            f"temp_present={self.temp.present!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True)
class EnvironmentPromotionDecision:
    state: EnvironmentPromotionState
    action: EnvironmentPromotionAction

    def __post_init__(self) -> None:
        expected = {
            EnvironmentPromotionState.READY_EXISTING: (
                EnvironmentPromotionAction.REPLACE_EXISTING,
            ),
            EnvironmentPromotionState.READY_ABSENT: (
                EnvironmentPromotionAction.MOVE_NEW,
            ),
            EnvironmentPromotionState.APPLIED: (
                EnvironmentPromotionAction.ALREADY_APPLIED,
            ),
            EnvironmentPromotionState.THIRD_STATE: (EnvironmentPromotionAction.BLOCK,),
        }
        if (
            type(self.state) is not EnvironmentPromotionState
            or type(self.action) is not EnvironmentPromotionAction
            or self.action not in expected[self.state]
        ):
            raise ValueError("Environment promotion decision is invalid.")


def _matches_verified_temp(
    authority: EnvironmentPromotionAuthority,
    observation: EnvironmentDestinationObservation,
) -> bool:
    verified = authority.verified
    return bool(
        observation.present
        and observation.identity == verified.temp_identity
        and observation.sha256 == verified.candidate_sha256
        and observation.size == verified.candidate_size
        and observation.file_attributes == verified.candidate_file_attributes
        and observation.security_descriptor_sha256
        == verified.candidate_security_descriptor_sha256
    )


def decide_environment_promotion(
    authority: EnvironmentPromotionAuthority,
    observed: EnvironmentPromotionObservation,
) -> EnvironmentPromotionDecision:
    """Select the only mutation authorized by two exact path observations."""

    if (
        type(authority) is not EnvironmentPromotionAuthority
        or type(observed) is not EnvironmentPromotionObservation
    ):
        _fail()
    if observed.destination == authority.expected_applied and not observed.temp.present:
        return EnvironmentPromotionDecision(
            EnvironmentPromotionState.APPLIED,
            EnvironmentPromotionAction.ALREADY_APPLIED,
        )
    if not _matches_verified_temp(authority, observed.temp):
        return EnvironmentPromotionDecision(
            EnvironmentPromotionState.THIRD_STATE,
            EnvironmentPromotionAction.BLOCK,
        )
    if authority.original.present and observed.destination == authority.original:
        return EnvironmentPromotionDecision(
            EnvironmentPromotionState.READY_EXISTING,
            EnvironmentPromotionAction.REPLACE_EXISTING,
        )
    if not authority.original.present and not observed.destination.present:
        return EnvironmentPromotionDecision(
            EnvironmentPromotionState.READY_ABSENT,
            EnvironmentPromotionAction.MOVE_NEW,
        )
    return EnvironmentPromotionDecision(
        EnvironmentPromotionState.THIRD_STATE,
        EnvironmentPromotionAction.BLOCK,
    )


__all__ = [
    "EnvironmentPromotionAction",
    "EnvironmentPromotionAuthority",
    "EnvironmentPromotionDecision",
    "EnvironmentPromotionDecisionError",
    "EnvironmentPromotionDecisionErrorCode",
    "EnvironmentPromotionObservation",
    "EnvironmentPromotionState",
    "decide_environment_promotion",
]
