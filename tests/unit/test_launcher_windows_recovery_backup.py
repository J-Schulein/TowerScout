from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_backup as backup  # noqa: E402
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
    ProtectedStateError,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402


class _Protection:
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        prefix = {
            ProtectedDataPurpose.ENVIRONMENT_BACKUP: b"TSE1",
            ProtectedDataPurpose.CERTIFICATE_BACKUP: b"TSC1",
        }[purpose]
        return CurrentUserProtectedBlob(purpose, prefix + plaintext)

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        prefix = {
            ProtectedDataPurpose.ENVIRONMENT_BACKUP: b"TSE1",
            ProtectedDataPurpose.CERTIFICATE_BACKUP: b"TSC1",
        }[purpose]
        if blob.purpose is not purpose or not blob.ciphertext.startswith(prefix):
            raise ProtectedStateError("protected_data_invalid")
        return blob.ciphertext[len(prefix) :]


class _PlaintextProtection(_Protection):
    def __init__(self, plaintext: bytes) -> None:
        self.plaintext = plaintext

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        return self.plaintext


class _UnexpectedProtection(_Protection):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        del plaintext, purpose
        raise KeyError("provider-secret-protection-detail")

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        del blob, purpose
        raise KeyError("provider-secret-authentication-detail")


class _InterruptingProtection(_Protection):
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        del plaintext, purpose
        raise KeyboardInterrupt


def _identity(seed: int) -> StableFileIdentity:
    return StableFileIdentity(seed, seed.to_bytes(16, "big"))


def _stream(*, journal_id: str = "a" * 32) -> JournalStreamIdentity:
    return JournalStreamIdentity(1, journal_id, "b" * 64, _identity(7))


def _environment(
    *,
    stream: JournalStreamIdentity | None = None,
    contents: bytes | None = b"GOOGLE_API_KEY=private-value\r\n",
) -> backup.EnvironmentExactStateBackup:
    security = (
        None
        if contents is None
        else backup.WindowsFileSecurityMetadata(
            1,
            0x20,
            b"self-relative-security-descriptor",
        )
    )
    return backup.EnvironmentExactStateBackup(
        1,
        stream or _stream(),
        contents,
        security,
    )


def _certificates(
    *,
    stream: JournalStreamIdentity | None = None,
) -> backup.CertificateExactStateBackup:
    return backup.CertificateExactStateBackup(
        1,
        stream or _stream(),
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.LOCAL_CA,
            b"-----BEGIN CERTIFICATE-----\nprivate-ca\n",
            0o644,
        ),
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.CA_BUNDLE,
            None,
            None,
        ),
    )


def test_environment_backup_round_trip_is_exact_bound_and_redacted() -> None:
    protection = _Protection()
    expected = _environment()

    sealed = backup.protect_environment_exact_state_backup(
        expected,
        protection=protection,
    )
    restored = backup.authenticate_environment_exact_state_backup(
        sealed,
        expected_stream=expected.stream,
        protection=protection,
    )

    assert restored == expected
    assert restored.existed
    assert (
        restored.contents_sha256 == hashlib.sha256(expected.contents or b"").hexdigest()
    )
    rendered = repr(expected) + repr(expected.security) + repr(sealed)
    assert "private-value" not in rendered
    assert "security-descriptor" not in rendered
    assert expected.stream.target_token_sha256 not in rendered


def test_absent_environment_backup_round_trip_preserves_absence() -> None:
    protection = _Protection()
    expected = _environment(contents=None)

    sealed = backup.protect_environment_exact_state_backup(
        expected,
        protection=protection,
    )
    restored = backup.authenticate_environment_exact_state_backup(
        sealed,
        expected_stream=expected.stream,
        protection=protection,
    )

    assert restored == expected
    assert not restored.existed
    assert restored.contents_sha256 == backup.ABSENT_BACKUP_CONTENT_SHA256


def test_certificate_backup_round_trip_preserves_fixed_states_and_redacts() -> None:
    protection = _Protection()
    expected = _certificates()

    sealed = backup.protect_certificate_exact_state_backup(
        expected,
        protection=protection,
    )
    restored = backup.authenticate_certificate_exact_state_backup(
        sealed,
        expected_stream=expected.stream,
        protection=protection,
    )

    assert restored == expected
    assert restored.local_ca.existed
    assert restored.local_ca.mode == 0o644
    assert not restored.ca_bundle.existed
    rendered = repr(expected) + repr(expected.local_ca) + repr(sealed)
    assert "private-ca" not in rendered
    assert expected.stream.target_token_sha256 not in rendered


def test_exact_state_models_reject_inconsistent_presence_metadata() -> None:
    with pytest.raises(ValueError):
        backup.EnvironmentExactStateBackup(
            1,
            _stream(),
            None,
            backup.WindowsFileSecurityMetadata(1, 0x20, b"descriptor"),
        )
    with pytest.raises(ValueError):
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.LOCAL_CA,
            b"certificate",
            None,
        )
    with pytest.raises(ValueError):
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.CA_BUNDLE,
            None,
            0o644,
        )


def test_certificate_backup_requires_each_fixed_destination_once() -> None:
    local_ca = backup.CertificateFileExactStateBackup(
        1,
        backup.CertificateBackupDestination.LOCAL_CA,
        None,
        None,
    )

    with pytest.raises(ValueError):
        backup.CertificateExactStateBackup(1, _stream(), local_ca, local_ca)


def test_backup_authentication_rejects_cross_stream_replay() -> None:
    protection = _Protection()
    expected = _environment()
    sealed = backup.protect_environment_exact_state_backup(
        expected,
        protection=protection,
    )

    with pytest.raises(backup.RecoveryBackupError) as failure:
        backup.authenticate_environment_exact_state_backup(
            sealed,
            expected_stream=_stream(journal_id="f" * 32),
            protection=protection,
        )

    assert failure.value.code is backup.RecoveryBackupErrorCode.BACKUP_INVALID


def test_sealed_backup_rejects_cross_purpose_blob() -> None:
    environment_blob = CurrentUserProtectedBlob(
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
        b"ciphertext",
    )

    with pytest.raises(ValueError):
        backup.SealedCertificateExactStateBackup(
            environment_blob,
            environment_blob.ciphertext_sha256,
        )


def test_malformed_noncanonical_and_digest_drift_are_sanitized() -> None:
    protection = _Protection()
    expected = _environment()
    sealed = backup.protect_environment_exact_state_backup(
        expected,
        protection=protection,
    )
    plaintext = protection.unprotect(
        sealed.protected_blob,
        ProtectedDataPurpose.ENVIRONMENT_BACKUP,
    )
    document = json.loads(plaintext)
    document["contents_sha256"] = "9" * 64
    drifted = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")

    for invalid in (plaintext.replace(b":", b": ", 1), drifted):
        with pytest.raises(backup.RecoveryBackupError) as failure:
            backup.authenticate_environment_exact_state_backup(
                sealed,
                expected_stream=expected.stream,
                protection=_PlaintextProtection(invalid),
            )
        assert failure.value.code is backup.RecoveryBackupErrorCode.BACKUP_INVALID
        assert "private-value" not in str(failure.value)


def test_invalid_protection_is_sanitized_and_process_control_propagates() -> None:
    expected = _environment()
    sealed = backup.protect_environment_exact_state_backup(
        expected,
        protection=_Protection(),
    )

    with pytest.raises(backup.RecoveryBackupError) as protect_failure:
        backup.protect_environment_exact_state_backup(
            expected,
            protection=_UnexpectedProtection(),
        )
    assert (
        protect_failure.value.code
        is backup.RecoveryBackupErrorCode.AUTHENTICATION_FAILED
    )
    assert "provider-secret" not in str(protect_failure.value)

    with pytest.raises(backup.RecoveryBackupError) as unprotect_failure:
        backup.authenticate_environment_exact_state_backup(
            sealed,
            expected_stream=expected.stream,
            protection=_UnexpectedProtection(),
        )
    assert (
        unprotect_failure.value.code
        is backup.RecoveryBackupErrorCode.AUTHENTICATION_FAILED
    )
    assert "provider-secret" not in str(unprotect_failure.value)

    with pytest.raises(KeyboardInterrupt):
        backup.protect_environment_exact_state_backup(
            expected,
            protection=_InterruptingProtection(),
        )


def test_public_entry_points_reject_wrong_model_types() -> None:
    with pytest.raises(backup.RecoveryBackupError) as environment_failure:
        backup.protect_environment_exact_state_backup(
            cast(backup.EnvironmentExactStateBackup, _certificates()),
            protection=_Protection(),
        )
    assert (
        environment_failure.value.code is backup.RecoveryBackupErrorCode.INPUT_INVALID
    )

    with pytest.raises(backup.RecoveryBackupError) as certificate_failure:
        backup.protect_certificate_exact_state_backup(
            cast(backup.CertificateExactStateBackup, _environment()),
            protection=_Protection(),
        )
    assert (
        certificate_failure.value.code is backup.RecoveryBackupErrorCode.INPUT_INVALID
    )
