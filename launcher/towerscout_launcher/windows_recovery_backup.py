"""Purpose-separated exact-state backup envelopes for Windows recovery.

This source-only Gate-A layer binds encrypted environment and fixed certificate
file backups to one authenticated recovery-journal stream. It does not persist
backup blobs, advance recovery state, restore files, or enable repair/runtime
mutation.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, NoReturn, Protocol

from .windows_environment_replacement import MAX_ENVIRONMENT_BYTES
from .windows_protected_state import CurrentUserProtectedBlob, ProtectedDataPurpose
from .windows_recovery_journal import JournalStreamIdentity
from .windows_security import StableFileIdentity

_SCHEMA_VERSION = 1
_MAX_ENVIRONMENT_BACKUP_BYTES = 512 * 1024
_MAX_CERTIFICATE_BACKUP_BYTES = 2 * 1024 * 1024
_MAX_SECURITY_DESCRIPTOR_BYTES = 64 * 1024
_MAX_CERTIFICATE_BYTES = 256 * 1024
_MAX_CERTIFICATE_BUNDLE_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JOURNAL_ID = re.compile(r"^[0-9a-f]{32}$")
ABSENT_BACKUP_CONTENT_SHA256 = hashlib.sha256(
    b"TowerScout.AbsentRecoveryBackupContent.v1"
).hexdigest()


class RecoveryBackupErrorCode(str, Enum):
    INPUT_INVALID = "recovery_backup_input_invalid"
    BACKUP_INVALID = "recovery_backup_invalid"
    AUTHENTICATION_FAILED = "recovery_backup_authentication_failed"


class RecoveryBackupError(RuntimeError):
    """Sanitized failure at the encrypted recovery-backup boundary."""

    _MESSAGES = {
        RecoveryBackupErrorCode.INPUT_INVALID: (
            "The recovery backup request is invalid."
        ),
        RecoveryBackupErrorCode.BACKUP_INVALID: (
            "A protected recovery backup is invalid."
        ),
        RecoveryBackupErrorCode.AUTHENTICATION_FAILED: (
            "A recovery backup could not be authenticated."
        ),
    }

    def __init__(self, code: RecoveryBackupErrorCode) -> None:
        if type(code) is not RecoveryBackupErrorCode:
            raise ValueError("Unknown recovery backup error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryBackupError(code={self.code.value!r})"


def _fail(code: RecoveryBackupErrorCode) -> NoReturn:
    raise RecoveryBackupError(code)


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _content_sha256(contents: bytes | None) -> str:
    return ABSENT_BACKUP_CONTENT_SHA256 if contents is None else _sha256(contents)


@dataclass(frozen=True, slots=True, repr=False)
class WindowsFileSecurityMetadata:
    schema_version: int
    file_attributes: int
    security_descriptor: bytes = field(repr=False)
    security_descriptor_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.file_attributes) is not int
            or not 0 <= self.file_attributes <= 0xFFFFFFFF
            or type(self.security_descriptor) is not bytes
            or not 1 <= len(self.security_descriptor) <= _MAX_SECURITY_DESCRIPTOR_BYTES
        ):
            raise ValueError("Windows file security metadata is invalid.")
        object.__setattr__(
            self,
            "security_descriptor_sha256",
            _sha256(self.security_descriptor),
        )

    def __repr__(self) -> str:
        return "WindowsFileSecurityMetadata(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class EnvironmentExactStateBackup:
    schema_version: int
    stream: JournalStreamIdentity = field(repr=False)
    contents: bytes | None = field(repr=False)
    security: WindowsFileSecurityMetadata | None = field(repr=False)
    contents_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.stream) is not JournalStreamIdentity
            or (
                self.contents is not None
                and (
                    type(self.contents) is not bytes
                    or len(self.contents) > MAX_ENVIRONMENT_BYTES
                )
            )
            or (self.contents is None and self.security is not None)
            or (
                self.contents is not None
                and type(self.security) is not WindowsFileSecurityMetadata
            )
        ):
            raise ValueError("Environment exact-state backup is invalid.")
        object.__setattr__(self, "contents_sha256", _content_sha256(self.contents))

    @property
    def existed(self) -> bool:
        return self.contents is not None

    def __repr__(self) -> str:
        return "EnvironmentExactStateBackup(" f"existed={self.existed!r}, <redacted>)"


class CertificateBackupDestination(str, Enum):
    LOCAL_CA = "local_ca"
    CA_BUNDLE = "ca_bundle"


@dataclass(frozen=True, slots=True, repr=False)
class CertificateFileExactStateBackup:
    schema_version: int
    destination: CertificateBackupDestination
    contents: bytes | None = field(repr=False)
    mode: int | None
    contents_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        maximum = {
            CertificateBackupDestination.LOCAL_CA: _MAX_CERTIFICATE_BYTES,
            CertificateBackupDestination.CA_BUNDLE: _MAX_CERTIFICATE_BUNDLE_BYTES,
        }.get(self.destination)
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.destination) is not CertificateBackupDestination
            or maximum is None
            or (
                self.contents is not None
                and (type(self.contents) is not bytes or len(self.contents) > maximum)
            )
            or (self.contents is None and self.mode is not None)
            or (
                self.contents is not None
                and (type(self.mode) is not int or not 0 <= self.mode <= 0o7777)
            )
        ):
            raise ValueError("Certificate-file exact-state backup is invalid.")
        object.__setattr__(self, "contents_sha256", _content_sha256(self.contents))

    @property
    def existed(self) -> bool:
        return self.contents is not None

    def __repr__(self) -> str:
        return (
            "CertificateFileExactStateBackup("
            f"destination={self.destination.value!r}, "
            f"existed={self.existed!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CertificateExactStateBackup:
    schema_version: int
    stream: JournalStreamIdentity = field(repr=False)
    local_ca: CertificateFileExactStateBackup = field(repr=False)
    ca_bundle: CertificateFileExactStateBackup = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.stream) is not JournalStreamIdentity
            or type(self.local_ca) is not CertificateFileExactStateBackup
            or self.local_ca.destination is not CertificateBackupDestination.LOCAL_CA
            or type(self.ca_bundle) is not CertificateFileExactStateBackup
            or self.ca_bundle.destination is not CertificateBackupDestination.CA_BUNDLE
        ):
            raise ValueError("Certificate exact-state backup is invalid.")

    def __repr__(self) -> str:
        return "CertificateExactStateBackup(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SealedEnvironmentExactStateBackup:
    protected_blob: CurrentUserProtectedBlob = field(repr=False)
    backup_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.protected_blob) is not CurrentUserProtectedBlob
            or self.protected_blob.purpose
            is not ProtectedDataPurpose.ENVIRONMENT_BACKUP
            or not _valid_hash(self.backup_sha256)
            or self.backup_sha256 != self.protected_blob.ciphertext_sha256
        ):
            raise ValueError("Sealed environment backup is invalid.")

    def __repr__(self) -> str:
        return "SealedEnvironmentExactStateBackup(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SealedCertificateExactStateBackup:
    protected_blob: CurrentUserProtectedBlob = field(repr=False)
    backup_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.protected_blob) is not CurrentUserProtectedBlob
            or self.protected_blob.purpose
            is not ProtectedDataPurpose.CERTIFICATE_BACKUP
            or not _valid_hash(self.backup_sha256)
            or self.backup_sha256 != self.protected_blob.ciphertext_sha256
        ):
            raise ValueError("Sealed certificate backup is invalid.")

    def __repr__(self) -> str:
        return "SealedCertificateExactStateBackup(<redacted>)"


class BackupProtectionPort(Protocol):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob: ...

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes: ...


def _valid_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("Non-finite JSON value.")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii", errors="strict")


def _load_canonical_json(raw: bytes, *, maximum: int) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise ValueError("Backup bytes are invalid.")
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            raise ValueError("Backup encoding is invalid.")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if type(parsed) is not dict or _canonical_json(parsed) != raw:
            raise ValueError("Backup encoding is not canonical.")
        return parsed
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        _fail(RecoveryBackupErrorCode.BACKUP_INVALID)


def _exact_keys(value: object, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise ValueError("Backup object shape is invalid.")
    return value


def _encode_bytes(contents: bytes | None) -> str | None:
    if contents is None:
        return None
    return base64.b64encode(contents).decode("ascii")


def _decode_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if type(value) is not str:
        raise ValueError("Backup content encoding is invalid.")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeError, binascii.Error, ValueError):
        raise ValueError("Backup content encoding is invalid.") from None
    if base64.b64encode(decoded) != encoded:
        raise ValueError("Backup content encoding is not canonical.")
    return decoded


def _identity_to_json(identity: StableFileIdentity) -> dict[str, Any]:
    return {
        "file_id": identity.file_id.hex(),
        "volume_serial": identity.volume_serial,
    }


def _identity_from_json(value: object) -> StableFileIdentity:
    item = _exact_keys(value, frozenset({"file_id", "volume_serial"}))
    file_id = item["file_id"]
    volume_serial = item["volume_serial"]
    if (
        type(file_id) is not str
        or re.fullmatch(r"[0-9a-f]{32}", file_id) is None
        or type(volume_serial) is not int
    ):
        raise ValueError("Backup file identity is invalid.")
    return StableFileIdentity(volume_serial, bytes.fromhex(file_id))


def _stream_to_json(stream: JournalStreamIdentity) -> dict[str, Any]:
    return {
        "journal_id": stream.journal_id,
        "package_root_identity": _identity_to_json(stream.package_root_identity),
        "schema_version": stream.schema_version,
        "target_token_sha256": stream.target_token_sha256,
    }


def _stream_from_json(value: object) -> JournalStreamIdentity:
    item = _exact_keys(
        value,
        frozenset(
            {
                "journal_id",
                "package_root_identity",
                "schema_version",
                "target_token_sha256",
            }
        ),
    )
    if (
        type(item["journal_id"]) is not str
        or _JOURNAL_ID.fullmatch(item["journal_id"]) is None
    ):
        raise ValueError("Backup journal identity is invalid.")
    return JournalStreamIdentity(
        item["schema_version"],
        item["journal_id"],
        item["target_token_sha256"],
        _identity_from_json(item["package_root_identity"]),
    )


def _security_to_json(
    security: WindowsFileSecurityMetadata | None,
) -> dict[str, Any] | None:
    if security is None:
        return None
    return {
        "file_attributes": security.file_attributes,
        "schema_version": security.schema_version,
        "security_descriptor": _encode_bytes(security.security_descriptor),
        "security_descriptor_sha256": security.security_descriptor_sha256,
    }


def _security_from_json(value: object) -> WindowsFileSecurityMetadata | None:
    if value is None:
        return None
    item = _exact_keys(
        value,
        frozenset(
            {
                "file_attributes",
                "schema_version",
                "security_descriptor",
                "security_descriptor_sha256",
            }
        ),
    )
    descriptor = _decode_bytes(item["security_descriptor"])
    if descriptor is None or not _valid_hash(item["security_descriptor_sha256"]):
        raise ValueError("Backup security metadata is invalid.")
    security = WindowsFileSecurityMetadata(
        item["schema_version"],
        item["file_attributes"],
        descriptor,
    )
    if security.security_descriptor_sha256 != item["security_descriptor_sha256"]:
        raise ValueError("Backup security metadata digest is invalid.")
    return security


def _environment_to_bytes(backup: EnvironmentExactStateBackup) -> bytes:
    return _canonical_json(
        {
            "contents": _encode_bytes(backup.contents),
            "contents_sha256": backup.contents_sha256,
            "schema_version": backup.schema_version,
            "security": _security_to_json(backup.security),
            "stream": _stream_to_json(backup.stream),
        }
    )


def _environment_from_bytes(raw: bytes) -> EnvironmentExactStateBackup:
    try:
        item = _exact_keys(
            _load_canonical_json(raw, maximum=_MAX_ENVIRONMENT_BACKUP_BYTES),
            frozenset(
                {
                    "contents",
                    "contents_sha256",
                    "schema_version",
                    "security",
                    "stream",
                }
            ),
        )
        contents = _decode_bytes(item["contents"])
        if not _valid_hash(item["contents_sha256"]):
            raise ValueError("Environment backup digest is invalid.")
        backup = EnvironmentExactStateBackup(
            item["schema_version"],
            _stream_from_json(item["stream"]),
            contents,
            _security_from_json(item["security"]),
        )
        if backup.contents_sha256 != item["contents_sha256"]:
            raise ValueError("Environment backup digest is invalid.")
        return backup
    except RecoveryBackupError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(RecoveryBackupErrorCode.BACKUP_INVALID)


def _certificate_file_to_json(
    backup: CertificateFileExactStateBackup,
) -> dict[str, Any]:
    return {
        "contents": _encode_bytes(backup.contents),
        "contents_sha256": backup.contents_sha256,
        "destination": backup.destination.value,
        "mode": backup.mode,
        "schema_version": backup.schema_version,
    }


def _certificate_file_from_json(
    value: object,
) -> CertificateFileExactStateBackup:
    item = _exact_keys(
        value,
        frozenset(
            {"contents", "contents_sha256", "destination", "mode", "schema_version"}
        ),
    )
    contents = _decode_bytes(item["contents"])
    if not _valid_hash(item["contents_sha256"]):
        raise ValueError("Certificate backup digest is invalid.")
    backup = CertificateFileExactStateBackup(
        item["schema_version"],
        CertificateBackupDestination(item["destination"]),
        contents,
        item["mode"],
    )
    if backup.contents_sha256 != item["contents_sha256"]:
        raise ValueError("Certificate backup digest is invalid.")
    return backup


def _certificate_to_bytes(backup: CertificateExactStateBackup) -> bytes:
    return _canonical_json(
        {
            "ca_bundle": _certificate_file_to_json(backup.ca_bundle),
            "local_ca": _certificate_file_to_json(backup.local_ca),
            "schema_version": backup.schema_version,
            "stream": _stream_to_json(backup.stream),
        }
    )


def _certificate_from_bytes(raw: bytes) -> CertificateExactStateBackup:
    try:
        item = _exact_keys(
            _load_canonical_json(raw, maximum=_MAX_CERTIFICATE_BACKUP_BYTES),
            frozenset({"ca_bundle", "local_ca", "schema_version", "stream"}),
        )
        return CertificateExactStateBackup(
            item["schema_version"],
            _stream_from_json(item["stream"]),
            _certificate_file_from_json(item["local_ca"]),
            _certificate_file_from_json(item["ca_bundle"]),
        )
    except RecoveryBackupError:
        raise
    except (KeyError, TypeError, ValueError):
        _fail(RecoveryBackupErrorCode.BACKUP_INVALID)


def _protect(
    plaintext: bytes,
    purpose: ProtectedDataPurpose,
    protection: BackupProtectionPort,
) -> CurrentUserProtectedBlob:
    try:
        operation = getattr(protection, "protect")
        if not callable(operation):
            raise TypeError("Backup protection is unavailable.")
        protected = operation(plaintext, purpose)
    except Exception:
        _fail(RecoveryBackupErrorCode.AUTHENTICATION_FAILED)
    if (
        type(protected) is not CurrentUserProtectedBlob
        or protected.purpose is not purpose
    ):
        _fail(RecoveryBackupErrorCode.AUTHENTICATION_FAILED)
    return protected


def _unprotect(
    blob: CurrentUserProtectedBlob,
    purpose: ProtectedDataPurpose,
    protection: BackupProtectionPort,
) -> bytes:
    try:
        operation = getattr(protection, "unprotect")
        if not callable(operation):
            raise TypeError("Backup authentication is unavailable.")
        plaintext = operation(blob, purpose)
    except Exception:
        _fail(RecoveryBackupErrorCode.AUTHENTICATION_FAILED)
    if type(plaintext) is not bytes:
        _fail(RecoveryBackupErrorCode.AUTHENTICATION_FAILED)
    return plaintext


def protect_environment_exact_state_backup(
    backup: EnvironmentExactStateBackup,
    *,
    protection: BackupProtectionPort,
) -> SealedEnvironmentExactStateBackup:
    if type(backup) is not EnvironmentExactStateBackup:
        _fail(RecoveryBackupErrorCode.INPUT_INVALID)
    protected = _protect(
        _environment_to_bytes(backup),
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        protection,
    )
    try:
        return SealedEnvironmentExactStateBackup(
            protected,
            protected.ciphertext_sha256,
        )
    except ValueError:
        _fail(RecoveryBackupErrorCode.AUTHENTICATION_FAILED)


def authenticate_environment_exact_state_backup(
    sealed: SealedEnvironmentExactStateBackup,
    *,
    expected_stream: JournalStreamIdentity,
    protection: BackupProtectionPort,
) -> EnvironmentExactStateBackup:
    if (
        type(sealed) is not SealedEnvironmentExactStateBackup
        or type(expected_stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryBackupErrorCode.INPUT_INVALID)
    plaintext = _unprotect(
        sealed.protected_blob,
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        protection,
    )
    backup = _environment_from_bytes(plaintext)
    if backup.stream != expected_stream:
        _fail(RecoveryBackupErrorCode.BACKUP_INVALID)
    return backup


def protect_certificate_exact_state_backup(
    backup: CertificateExactStateBackup,
    *,
    protection: BackupProtectionPort,
) -> SealedCertificateExactStateBackup:
    if type(backup) is not CertificateExactStateBackup:
        _fail(RecoveryBackupErrorCode.INPUT_INVALID)
    protected = _protect(
        _certificate_to_bytes(backup),
        ProtectedDataPurpose.CERTIFICATE_BACKUP,
        protection,
    )
    try:
        return SealedCertificateExactStateBackup(
            protected,
            protected.ciphertext_sha256,
        )
    except ValueError:
        _fail(RecoveryBackupErrorCode.AUTHENTICATION_FAILED)


def authenticate_certificate_exact_state_backup(
    sealed: SealedCertificateExactStateBackup,
    *,
    expected_stream: JournalStreamIdentity,
    protection: BackupProtectionPort,
) -> CertificateExactStateBackup:
    if (
        type(sealed) is not SealedCertificateExactStateBackup
        or type(expected_stream) is not JournalStreamIdentity
    ):
        _fail(RecoveryBackupErrorCode.INPUT_INVALID)
    plaintext = _unprotect(
        sealed.protected_blob,
        ProtectedDataPurpose.CERTIFICATE_BACKUP,
        protection,
    )
    backup = _certificate_from_bytes(plaintext)
    if backup.stream != expected_stream:
        _fail(RecoveryBackupErrorCode.BACKUP_INVALID)
    return backup


__all__ = [
    "ABSENT_BACKUP_CONTENT_SHA256",
    "BackupProtectionPort",
    "CertificateBackupDestination",
    "CertificateExactStateBackup",
    "CertificateFileExactStateBackup",
    "EnvironmentExactStateBackup",
    "RecoveryBackupError",
    "RecoveryBackupErrorCode",
    "SealedCertificateExactStateBackup",
    "SealedEnvironmentExactStateBackup",
    "WindowsFileSecurityMetadata",
    "authenticate_certificate_exact_state_backup",
    "authenticate_environment_exact_state_backup",
    "protect_certificate_exact_state_backup",
    "protect_environment_exact_state_backup",
]
