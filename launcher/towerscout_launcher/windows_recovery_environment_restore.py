"""Pure exact-state classification for Windows environment rollback.

This Gate-A layer decides whether a journal-authorized rollback may leave an
already restored ``.env`` unchanged, restore over the exact transaction
candidate, or remove that exact candidate when the original was absent. It
does not open, replace, remove, or otherwise mutate any file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import NoReturn

from .windows_environment_replacement import MAX_ENVIRONMENT_BYTES
from .windows_security import StableFileIdentity

_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EnvironmentRestoreDecisionErrorCode(str, Enum):
    INPUT_INVALID = "environment_restore_decision_input_invalid"


class EnvironmentRestoreDecisionError(RuntimeError):
    """Sanitized failure at the pure environment-restore decision boundary."""

    def __init__(self, code: EnvironmentRestoreDecisionErrorCode) -> None:
        if type(code) is not EnvironmentRestoreDecisionErrorCode:
            raise ValueError("Unknown environment restore decision error code.")
        self.code = code
        super().__init__("The environment restore decision request is invalid.")

    def __repr__(self) -> str:
        return f"EnvironmentRestoreDecisionError(code={self.code.value!r})"


class EnvironmentRestoreContentState(str, Enum):
    ORIGINAL = "original"
    CANDIDATE = "candidate"
    ABSENT = "absent"
    THIRD_STATE = "third_state"


class EnvironmentRestoreAction(str, Enum):
    ALREADY_RESTORED = "already_restored"
    RESTORE_ORIGINAL = "restore_original"
    REMOVE_CANDIDATE = "remove_candidate"
    BLOCK = "block"


def _fail() -> NoReturn:
    raise EnvironmentRestoreDecisionError(
        EnvironmentRestoreDecisionErrorCode.INPUT_INVALID
    )


def _valid_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentDestinationObservation:
    present: bool
    identity: StableFileIdentity | None = field(default=None, repr=False)
    sha256: str | None = field(default=None, repr=False)
    size: int | None = None
    file_attributes: int | None = None
    security_descriptor_sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.present) is not bool:
            raise ValueError("Environment destination observation is invalid.")
        values = (
            self.identity,
            self.sha256,
            self.size,
            self.file_attributes,
            self.security_descriptor_sha256,
        )
        if self.present:
            if (
                type(self.identity) is not StableFileIdentity
                or not _valid_hash(self.sha256)
                or type(self.size) is not int
                or not 0 <= self.size <= MAX_ENVIRONMENT_BYTES
                or type(self.file_attributes) is not int
                or not 0 <= self.file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.security_descriptor_sha256)
            ):
                raise ValueError("Environment destination observation is invalid.")
        elif any(value is not None for value in values):
            raise ValueError("Environment destination observation is invalid.")

    def __repr__(self) -> str:
        return (
            f"EnvironmentDestinationObservation(present={self.present!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentRestoreAuthority:
    schema_version: int
    package_root_identity: StableFileIdentity = field(repr=False)
    original_present: bool
    original_identity: StableFileIdentity | None = field(default=None, repr=False)
    original_sha256: str | None = field(default=None, repr=False)
    original_size: int | None = None
    original_file_attributes: int | None = None
    original_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )
    candidate_sha256: str = field(default="", repr=False)
    candidate_size: int = 0
    candidate_identity: StableFileIdentity | None = field(default=None, repr=False)
    candidate_file_attributes: int | None = None
    candidate_security_descriptor_sha256: str | None = field(
        default=None,
        repr=False,
    )
    restore_temp_identity: StableFileIdentity | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.package_root_identity) is not StableFileIdentity
            or type(self.original_present) is not bool
            or not _valid_hash(self.candidate_sha256)
            or type(self.candidate_size) is not int
            or not 1 <= self.candidate_size <= MAX_ENVIRONMENT_BYTES
        ):
            raise ValueError("Environment restore authority is invalid.")
        original_values = (
            self.original_identity,
            self.original_sha256,
            self.original_size,
            self.original_file_attributes,
            self.original_security_descriptor_sha256,
            self.restore_temp_identity,
        )
        if self.original_present:
            identities = (self.original_identity, self.restore_temp_identity)
            if (
                any(type(identity) is not StableFileIdentity for identity in identities)
                or len(set(identities)) != len(identities)
                or self.package_root_identity in identities
                or not _valid_hash(self.original_sha256)
                or type(self.original_size) is not int
                or not 0 <= self.original_size <= MAX_ENVIRONMENT_BYTES
                or type(self.original_file_attributes) is not int
                or not 0 <= self.original_file_attributes <= 0xFFFFFFFF
                or not _valid_hash(self.original_security_descriptor_sha256)
            ):
                raise ValueError("Environment restore authority is invalid.")
        elif any(value is not None for value in original_values):
            raise ValueError("Environment restore authority is invalid.")
        candidate_values = (
            self.candidate_identity,
            self.candidate_file_attributes,
            self.candidate_security_descriptor_sha256,
        )
        if self.candidate_identity is None:
            if any(value is not None for value in candidate_values):
                raise ValueError("Environment restore authority is invalid.")
        elif (
            type(self.candidate_identity) is not StableFileIdentity
            or self.candidate_identity
            in {
                self.package_root_identity,
                self.original_identity,
                self.restore_temp_identity,
            }
            or type(self.candidate_file_attributes) is not int
            or not 0 <= self.candidate_file_attributes <= 0xFFFFFFFF
            or not _valid_hash(self.candidate_security_descriptor_sha256)
        ):
            raise ValueError("Environment restore authority is invalid.")

    def __repr__(self) -> str:
        return (
            "EnvironmentRestoreAuthority("
            f"original_present={self.original_present!r}, "
            f"candidate_applied={self.candidate_identity is not None!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True)
class EnvironmentRestoreDecision:
    content_state: EnvironmentRestoreContentState
    action: EnvironmentRestoreAction

    def __post_init__(self) -> None:
        expected = {
            EnvironmentRestoreContentState.ORIGINAL: (
                EnvironmentRestoreAction.ALREADY_RESTORED,
            ),
            EnvironmentRestoreContentState.CANDIDATE: (
                EnvironmentRestoreAction.RESTORE_ORIGINAL,
                EnvironmentRestoreAction.REMOVE_CANDIDATE,
            ),
            EnvironmentRestoreContentState.ABSENT: (
                EnvironmentRestoreAction.ALREADY_RESTORED,
                EnvironmentRestoreAction.BLOCK,
            ),
            EnvironmentRestoreContentState.THIRD_STATE: (
                EnvironmentRestoreAction.BLOCK,
            ),
        }
        if (
            type(self.content_state) is not EnvironmentRestoreContentState
            or type(self.action) is not EnvironmentRestoreAction
            or self.action not in expected[self.content_state]
        ):
            raise ValueError("Environment restore decision is invalid.")


def _matches_original(
    authority: EnvironmentRestoreAuthority,
    observed: EnvironmentDestinationObservation,
) -> bool:
    return bool(
        authority.original_present
        and observed.present
        and observed.identity
        in {authority.original_identity, authority.restore_temp_identity}
        and observed.sha256 == authority.original_sha256
        and observed.size == authority.original_size
        and observed.file_attributes == authority.original_file_attributes
        and observed.security_descriptor_sha256
        == authority.original_security_descriptor_sha256
    )


def _matches_candidate(
    authority: EnvironmentRestoreAuthority,
    observed: EnvironmentDestinationObservation,
) -> bool:
    return bool(
        authority.candidate_identity is not None
        and observed.present
        and observed.identity == authority.candidate_identity
        and observed.sha256 == authority.candidate_sha256
        and observed.size == authority.candidate_size
        and observed.file_attributes == authority.candidate_file_attributes
        and observed.security_descriptor_sha256
        == authority.candidate_security_descriptor_sha256
    )


def decide_environment_restore(
    authority: EnvironmentRestoreAuthority,
    observed: EnvironmentDestinationObservation,
) -> EnvironmentRestoreDecision:
    """Classify one exact observation and select the only safe rollback action."""

    if (
        type(authority) is not EnvironmentRestoreAuthority
        or type(observed) is not EnvironmentDestinationObservation
    ):
        _fail()
    if not observed.present:
        state = EnvironmentRestoreContentState.ABSENT
    elif _matches_original(authority, observed):
        state = EnvironmentRestoreContentState.ORIGINAL
    elif _matches_candidate(authority, observed):
        state = EnvironmentRestoreContentState.CANDIDATE
    else:
        state = EnvironmentRestoreContentState.THIRD_STATE

    if state is EnvironmentRestoreContentState.ORIGINAL:
        action = EnvironmentRestoreAction.ALREADY_RESTORED
    elif state is EnvironmentRestoreContentState.CANDIDATE:
        action = (
            EnvironmentRestoreAction.RESTORE_ORIGINAL
            if authority.original_present
            else EnvironmentRestoreAction.REMOVE_CANDIDATE
        )
    elif (
        state is EnvironmentRestoreContentState.ABSENT
        and not authority.original_present
    ):
        action = EnvironmentRestoreAction.ALREADY_RESTORED
    else:
        action = EnvironmentRestoreAction.BLOCK
    return EnvironmentRestoreDecision(state, action)


__all__ = [
    "EnvironmentDestinationObservation",
    "EnvironmentRestoreAction",
    "EnvironmentRestoreAuthority",
    "EnvironmentRestoreContentState",
    "EnvironmentRestoreDecision",
    "EnvironmentRestoreDecisionError",
    "EnvironmentRestoreDecisionErrorCode",
    "decide_environment_restore",
]
