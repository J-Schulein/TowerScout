"""Narrow storage contract for a Windows environment-restore temporary file.

The port can create or verify only the zero-byte file already named by an
authenticated recovery-journal record. It cannot write content, move, replace,
or remove the package environment file.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol

from .windows_path_trust import PathHierarchyTrust
from .windows_recovery_journal import (
    EnvironmentRestoreTempCreatedRecord,
    EnvironmentRestoreTempPlanRecord,
)
from .windows_security import StableFileIdentity


class RecoveryEnvironmentStorageErrorCode(str, Enum):
    INPUT_INVALID = "recovery_environment_storage_input_invalid"
    STORAGE_UNAVAILABLE = "recovery_environment_storage_unavailable"
    CREATE_FAILED = "recovery_environment_storage_create_failed"
    CLEANUP_FAILED = "recovery_environment_storage_cleanup_failed"
    VERIFY_FAILED = "recovery_environment_storage_verify_failed"


class RecoveryEnvironmentStorageError(RuntimeError):
    """Sanitized failure at the environment-restore temp storage boundary."""

    _MESSAGES = {
        RecoveryEnvironmentStorageErrorCode.INPUT_INVALID: (
            "The environment restore storage request is invalid."
        ),
        RecoveryEnvironmentStorageErrorCode.STORAGE_UNAVAILABLE: (
            "Secure environment restore storage is unavailable."
        ),
        RecoveryEnvironmentStorageErrorCode.CREATE_FAILED: (
            "The environment restore temporary file could not be created safely."
        ),
        RecoveryEnvironmentStorageErrorCode.CLEANUP_FAILED: (
            "The environment restore temporary file could not be reconciled safely."
        ),
        RecoveryEnvironmentStorageErrorCode.VERIFY_FAILED: (
            "The environment restore temporary file could not be verified safely."
        ),
    }

    def __init__(self, code: RecoveryEnvironmentStorageErrorCode) -> None:
        if type(code) is not RecoveryEnvironmentStorageErrorCode:
            raise ValueError("Unknown environment restore storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryEnvironmentStorageError(code={self.code.value!r})"


class EnvironmentRestoreTempStoragePort(Protocol):
    def create_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        plan: EnvironmentRestoreTempPlanRecord,
    ) -> StableFileIdentity: ...

    def verify_environment_restore_temp_from_held_package_root(
        self,
        package_root: PathHierarchyTrust,
        created: EnvironmentRestoreTempCreatedRecord,
    ) -> StableFileIdentity: ...


__all__ = [
    "EnvironmentRestoreTempStoragePort",
    "RecoveryEnvironmentStorageError",
    "RecoveryEnvironmentStorageErrorCode",
]
