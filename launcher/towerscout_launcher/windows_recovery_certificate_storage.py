"""Narrow storage contract for protected certificate restore temps.

The port creates, writes, and reverifies only the two optional files named by
an authenticated rollback journal. It cannot enumerate the protected root,
address any runtime destination, or remove an authenticated nonempty temp.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .windows_recovery_journal import (
    CertificateRestoreTempCreatedRecord,
    CertificateRestoreTempPlanRecord,
    CertificateRestoreTempVerifiedRecord,
)
from .windows_security import StableFileIdentity


class RecoveryCertificateStorageErrorCode(str, Enum):
    INPUT_INVALID = "recovery_certificate_storage_input_invalid"
    STORAGE_UNAVAILABLE = "recovery_certificate_storage_unavailable"
    CREATE_FAILED = "recovery_certificate_storage_create_failed"
    WRITE_FAILED = "recovery_certificate_storage_write_failed"
    CLEANUP_FAILED = "recovery_certificate_storage_cleanup_failed"
    VERIFY_FAILED = "recovery_certificate_storage_verify_failed"


class RecoveryCertificateStorageError(RuntimeError):
    """Sanitized certificate restore-temp storage failure."""

    _MESSAGES = {
        RecoveryCertificateStorageErrorCode.INPUT_INVALID: (
            "The certificate restore storage request is invalid."
        ),
        RecoveryCertificateStorageErrorCode.STORAGE_UNAVAILABLE: (
            "Secure certificate restore storage is unavailable."
        ),
        RecoveryCertificateStorageErrorCode.CREATE_FAILED: (
            "A certificate restore temporary file could not be created safely."
        ),
        RecoveryCertificateStorageErrorCode.WRITE_FAILED: (
            "A certificate restore temporary file could not be written safely."
        ),
        RecoveryCertificateStorageErrorCode.CLEANUP_FAILED: (
            "A certificate restore temporary file could not be reconciled safely."
        ),
        RecoveryCertificateStorageErrorCode.VERIFY_FAILED: (
            "A certificate restore temporary file could not be verified safely."
        ),
    }

    def __init__(self, code: RecoveryCertificateStorageErrorCode) -> None:
        if type(code) is not RecoveryCertificateStorageErrorCode:
            raise ValueError("Unknown certificate restore storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryCertificateStorageError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class CertificateRestoreTempIdentities:
    local_ca: StableFileIdentity | None
    ca_bundle: StableFileIdentity | None

    def __post_init__(self) -> None:
        if (
            (
                self.local_ca is not None
                and type(self.local_ca) is not StableFileIdentity
            )
            or (
                self.ca_bundle is not None
                and type(self.ca_bundle) is not StableFileIdentity
            )
            or (self.local_ca is not None and self.local_ca == self.ca_bundle)
        ):
            raise ValueError("Certificate restore temp identities are invalid.")

    def __repr__(self) -> str:
        return "CertificateRestoreTempIdentities(<redacted>)"


class CertificateRestoreTempStoragePort(Protocol):
    def create_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
    ) -> CertificateRestoreTempIdentities: ...

    def verify_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
        created: CertificateRestoreTempCreatedRecord,
    ) -> CertificateRestoreTempIdentities: ...

    def write_and_verify_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
        created: CertificateRestoreTempCreatedRecord,
        *,
        local_ca_contents: bytes | None,
        ca_bundle_contents: bytes | None,
    ) -> CertificateRestoreTempIdentities: ...

    def verify_written_certificate_restore_temps(
        self,
        root_path: str,
        plan: CertificateRestoreTempPlanRecord,
        verified: CertificateRestoreTempVerifiedRecord,
    ) -> CertificateRestoreTempIdentities: ...


__all__ = [
    "CertificateRestoreTempIdentities",
    "CertificateRestoreTempStoragePort",
    "RecoveryCertificateStorageError",
    "RecoveryCertificateStorageErrorCode",
]
