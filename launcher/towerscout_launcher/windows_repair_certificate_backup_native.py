"""Capture exact pre-repair certificate bytes under retained target authority."""

from __future__ import annotations

from enum import Enum
import hashlib
from typing import NoReturn

from .runtime_target_observation import (
    CertificateTargetDestination,
    ObservationOperation,
)
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_resolution import BoundResolvedRepairTarget
from .windows_recovery_backup import (
    CertificateBackupDestination,
    CertificateExactStateBackup,
    CertificateFileExactStateBackup,
)
from .windows_recovery_certificate_restore_native import (
    observe_certificate_destination_while_target_held,
)
from .windows_recovery import CertificateDestinationRestoreEvidence
from .windows_recovery_journal import JournalStreamIdentity
from .windows_security import StableFileIdentity


class NativeRepairCertificateBackupErrorCode(str, Enum):
    INPUT_INVALID = "native_repair_certificate_backup_input_invalid"
    READ_FAILED = "native_repair_certificate_backup_read_failed"
    VERIFY_FAILED = "native_repair_certificate_backup_verify_failed"


class NativeRepairCertificateBackupError(RuntimeError):
    _MESSAGES = {
        NativeRepairCertificateBackupErrorCode.INPUT_INVALID: (
            "The repair certificate backup request is invalid."
        ),
        NativeRepairCertificateBackupErrorCode.READ_FAILED: (
            "The original container certificate could not be read safely."
        ),
        NativeRepairCertificateBackupErrorCode.VERIFY_FAILED: (
            "The original container certificate could not be verified safely."
        ),
    }

    def __init__(self, code: NativeRepairCertificateBackupErrorCode) -> None:
        if type(code) is not NativeRepairCertificateBackupErrorCode:
            raise ValueError("Unknown native repair certificate backup error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRepairCertificateBackupError(code={self.code.value!r})"


def _fail(code: NativeRepairCertificateBackupErrorCode) -> NoReturn:
    raise NativeRepairCertificateBackupError(code) from None


def _capture_destination(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
) -> CertificateFileExactStateBackup:
    backup_destination = (
        CertificateBackupDestination.LOCAL_CA
        if destination is CertificateTargetDestination.LOCAL_CA
        else CertificateBackupDestination.CA_BUNDLE
    )
    read_failed = False
    before: CertificateDestinationRestoreEvidence | None = None
    result: object = None
    after: CertificateDestinationRestoreEvidence | None = None
    try:
        before = observe_certificate_destination_while_target_held(owner, destination)
        if before.present:
            result = owner.execute_scoped_process(
                "certificate_read_destination",
                (owner.target.container.container_id, destination),
            )
        after = observe_certificate_destination_while_target_held(
            owner,
            destination,
        )
    except Exception:
        read_failed = True
    if read_failed or before is None:
        _fail(NativeRepairCertificateBackupErrorCode.READ_FAILED)
    if after != before:
        _fail(NativeRepairCertificateBackupErrorCode.VERIFY_FAILED)
    if not before.present:
        try:
            return CertificateFileExactStateBackup(1, backup_destination, None, None)
        except ValueError:
            _fail(NativeRepairCertificateBackupErrorCode.VERIFY_FAILED)
    if (
        type(result) is not TargetObservationProcessResult
        or result.operation is not ObservationOperation.CERTIFICATE_READ_DESTINATION
        or result.exit_code != 0
        or before.contents_sha256 != hashlib.sha256(result.stdout).hexdigest()
        or before.size != len(result.stdout)
        or type(before.mode) is not int
    ):
        _fail(NativeRepairCertificateBackupErrorCode.VERIFY_FAILED)
    try:
        return CertificateFileExactStateBackup(
            1,
            backup_destination,
            result.stdout,
            before.mode,
        )
    except ValueError:
        _fail(NativeRepairCertificateBackupErrorCode.VERIFY_FAILED)


def capture_repair_certificate_backup_while_target_held(
    owner: BoundResolvedRepairTarget,
    stream: JournalStreamIdentity,
) -> CertificateExactStateBackup:
    """Capture both fixed destinations with observe/read/observe stability proof."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(stream) is not JournalStreamIdentity
    ):
        _fail(NativeRepairCertificateBackupErrorCode.INPUT_INVALID)
    target = owner.target
    try:
        package_identity = StableFileIdentity(
            target.package_root.volume_serial,
            target.package_root.file_id,
        )
    except ValueError:
        _fail(NativeRepairCertificateBackupErrorCode.INPUT_INVALID)
    if (
        stream.target_token_sha256 != target.target_token.digest_sha256
        or stream.package_root_identity != package_identity
    ):
        _fail(NativeRepairCertificateBackupErrorCode.INPUT_INVALID)
    local_ca = _capture_destination(owner, CertificateTargetDestination.LOCAL_CA)
    ca_bundle = _capture_destination(owner, CertificateTargetDestination.CA_BUNDLE)
    try:
        return CertificateExactStateBackup(1, stream, local_ca, ca_bundle)
    except ValueError:
        _fail(NativeRepairCertificateBackupErrorCode.VERIFY_FAILED)


__all__ = [
    "NativeRepairCertificateBackupError",
    "NativeRepairCertificateBackupErrorCode",
    "capture_repair_certificate_backup_while_target_held",
]
