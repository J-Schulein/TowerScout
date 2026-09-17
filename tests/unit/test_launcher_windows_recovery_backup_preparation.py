from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Callable, TypeVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.windows_recovery_backup as backup  # noqa: E402
import towerscout_launcher.windows_recovery_backup_preparation as preparation  # noqa: E402
import towerscout_launcher.windows_recovery_journal as journal  # noqa: E402
import towerscout_launcher.windows_recovery_journal_storage as storage  # noqa: E402
from towerscout_launcher.windows_environment_replacement import (  # noqa: E402
    EnvironmentReplacementPlan,
    plan_ca_environment_replacement,
)
from towerscout_launcher.windows_protected_state import (  # noqa: E402
    CurrentUserProtectedBlob,
    ProtectedDataPurpose,
)
from towerscout_launcher.windows_security import StableFileIdentity  # noqa: E402

_Result = TypeVar("_Result")
_ENVIRONMENT = b"GOOGLE_API_KEY=private-value\r\n"
_ENVIRONMENT_TEMPLATE = b"TOWERSCOUT_GPU_MODE=auto\r\n"


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


def _stream(*, journal_id: str = "a" * 32) -> journal.JournalStreamIdentity:
    return journal.JournalStreamIdentity(1, journal_id, "b" * 64, _identity(7))


def _environment_plan(
    contents: bytes | None = _ENVIRONMENT,
) -> EnvironmentReplacementPlan:
    return plan_ca_environment_replacement(
        contents if contents is not None else _ENVIRONMENT_TEMPLATE,
        original_present=contents is not None,
    )


class _Protection:
    def protect(
        self,
        plaintext: bytes,
        purpose: ProtectedDataPurpose,
    ) -> CurrentUserProtectedBlob:
        return CurrentUserProtectedBlob(
            purpose, purpose.value.encode("ascii") + plaintext
        )

    def unprotect(
        self,
        blob: CurrentUserProtectedBlob,
        purpose: ProtectedDataPurpose,
    ) -> bytes:
        prefix = purpose.value.encode("ascii")
        if blob.purpose is not purpose or not blob.ciphertext.startswith(prefix):
            raise ValueError("sensitive authentication detail")
        return blob.ciphertext[len(prefix) :]


class _NameSource:
    def __init__(self) -> None:
        self.calls = 0

    def new_backup_name(self) -> str:
        self.calls += 1
        return f"recovery-backup-{self.calls:032x}.blob"


class _Root:
    def __init__(self) -> None:
        self.active = False

    def run_journal_storage(
        self,
        operation: Callable[[str], _Result],
    ) -> _Result:
        self.active = True
        try:
            return operation(r"C:\Users\private\AppData\Local\TowerScout\Recovery\v1")
        finally:
            self.active = False


class _Storage:
    def __init__(self, root: _Root) -> None:
        self.root = root
        self.files: dict[str, storage.StoredJournalGenerationFile] = {}
        self.created: list[str] = []

    def list_names(self, root_path: str) -> tuple[str, ...]:
        assert self.root.active
        del root_path
        return tuple(self.files)

    def read_generation(
        self,
        root_path: str,
        name: str,
        maximum: int,
    ) -> storage.StoredJournalGenerationFile:
        assert self.root.active
        del root_path
        stored = self.files[name]
        assert len(stored.contents) <= maximum
        return stored

    def create_generation(
        self,
        root_path: str,
        name: str,
        contents: bytes,
    ) -> storage.StoredJournalGenerationFile:
        assert self.root.active
        del root_path
        if name in self.files:
            raise FileExistsError("sensitive collision detail")
        stored = storage.StoredJournalGenerationFile(
            _identity(20 + len(self.files)),
            contents,
        )
        self.files[name] = stored
        self.created.append(name)
        return stored


def _sealed_backups(
    protection: _Protection,
    *,
    stream: journal.JournalStreamIdentity | None = None,
    environment_contents: bytes | None = _ENVIRONMENT,
) -> tuple[
    journal.JournalStreamIdentity,
    backup.SealedEnvironmentExactStateBackup,
    backup.SealedCertificateExactStateBackup,
]:
    selected_stream = stream or _stream()
    environment = backup.EnvironmentExactStateBackup(
        1,
        selected_stream,
        environment_contents,
        (
            None
            if environment_contents is None
            else backup.WindowsFileSecurityMetadata(1, 0x20, b"private-descriptor")
        ),
    )
    certificates = backup.CertificateExactStateBackup(
        1,
        selected_stream,
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.LOCAL_CA,
            b"private-local-ca",
            0o644,
        ),
        backup.CertificateFileExactStateBackup(
            1,
            backup.CertificateBackupDestination.CA_BUNDLE,
            None,
            None,
        ),
    )
    return (
        selected_stream,
        backup.protect_environment_exact_state_backup(
            environment,
            protection=protection,
        ),
        backup.protect_certificate_exact_state_backup(
            certificates,
            protection=protection,
        ),
    )


def test_persist_backup_preparing_authenticates_summarizes_and_rereads() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    root = _Root()
    backend = _Storage(root)
    names = _NameSource()

    persisted = preparation.persist_backup_preparing_generation(
        environment,
        certificates,
        environment_plan=_environment_plan(),
        stream=stream,
        name_source=names,
        root=root,
        storage=backend,
        backup_protection=protection,
        journal_protection=protection,
    )

    record = persisted.selection.tip.record
    assert type(record) is journal.BackupPreparingRecord
    assert (
        persisted.selection.tip.state
        is journal.EnvironmentJournalState.BACKUP_PREPARING
    )
    assert record.environment_present
    plan = _environment_plan()
    assert record.environment_candidate_sha256 == plan.candidate_sha256
    assert record.environment_candidate_size == len(plan.candidate_contents)
    assert (
        record.environment_sha256
        == hashlib.sha256(b"GOOGLE_API_KEY=private-value\r\n").hexdigest()
    )
    assert record.environment_file_attributes == 0x20
    assert record.local_ca_present
    assert record.local_ca_mode == 0o644
    assert not record.ca_bundle_present
    assert names.calls == 2
    assert backend.created == [f"journal-{'a' * 32}-{1:020d}.generation"]
    assert not root.active
    rendered = repr(record) + repr(persisted)
    assert "private-value" not in rendered
    assert "private-local-ca" not in rendered
    assert "private-descriptor" not in rendered


def test_persist_backup_preparing_preserves_absent_environment() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(
        protection,
        environment_contents=None,
    )

    persisted = preparation.persist_backup_preparing_generation(
        environment,
        certificates,
        environment_plan=_environment_plan(None),
        stream=stream,
        name_source=_NameSource(),
        root=(root := _Root()),
        storage=_Storage(root),
        backup_protection=protection,
        journal_protection=protection,
    )

    record = persisted.selection.tip.record
    assert type(record) is journal.BackupPreparingRecord
    assert not record.environment_present
    assert record.environment_sha256 is None
    assert record.environment_file_attributes is None
    assert record.environment_security_descriptor_sha256 is None
    plan = _environment_plan(None)
    assert record.environment_candidate_sha256 == plan.candidate_sha256
    assert record.environment_candidate_size == len(plan.candidate_contents)


def test_persist_backup_preparing_rejects_plan_original_drift_before_write() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    names = _NameSource()
    root = _Root()
    backend = _Storage(root)

    with pytest.raises(preparation.RecoveryBackupPreparationError) as failure:
        preparation.persist_backup_preparing_generation(
            environment,
            certificates,
            environment_plan=plan_ca_environment_replacement(
                b"OTHER=changed\r\n",
                original_present=True,
            ),
            stream=stream,
            name_source=names,
            root=root,
            storage=backend,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert (
        failure.value.code
        is preparation.RecoveryBackupPreparationErrorCode.PLAN_INVALID
    )
    assert names.calls == 0
    assert not backend.created


def test_persist_backup_preparing_rejects_cross_stream_before_name_or_write() -> None:
    protection = _Protection()
    _source_stream, environment, certificates = _sealed_backups(protection)
    names = _NameSource()
    root = _Root()
    backend = _Storage(root)

    with pytest.raises(backup.RecoveryBackupError) as failure:
        preparation.persist_backup_preparing_generation(
            environment,
            certificates,
            environment_plan=_environment_plan(),
            stream=_stream(journal_id="f" * 32),
            name_source=names,
            root=root,
            storage=backend,
            backup_protection=protection,
            journal_protection=protection,
        )

    assert failure.value.code is backup.RecoveryBackupErrorCode.BACKUP_INVALID
    assert names.calls == 0
    assert not backend.created


def test_persist_backup_preparing_retry_fails_closed_without_second_write() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)
    names = _NameSource()
    root = _Root()
    backend = _Storage(root)
    arguments = {
        "stream": stream,
        "environment_plan": _environment_plan(),
        "name_source": names,
        "root": root,
        "storage": backend,
        "backup_protection": protection,
        "journal_protection": protection,
    }
    preparation.persist_backup_preparing_generation(
        environment,
        certificates,
        **arguments,
    )

    with pytest.raises(journal.RecoveryJournalError) as failure:
        preparation.persist_backup_preparing_generation(
            environment,
            certificates,
            **arguments,
        )

    assert failure.value.code is journal.RecoveryJournalErrorCode.CHAIN_INVALID
    assert len(backend.created) == 1


def test_persist_backup_preparing_rejects_invalid_or_reused_names() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)

    for name_source in (
        type("InvalidNames", (), {"new_backup_name": lambda self: "../backup"})(),
        type(
            "ReusedNames",
            (),
            {"new_backup_name": lambda self: ("recovery-backup-" + "1" * 32 + ".blob")},
        )(),
    ):
        root = _Root()
        backend = _Storage(root)
        with pytest.raises(preparation.RecoveryBackupPreparationError) as failure:
            preparation.persist_backup_preparing_generation(
                environment,
                certificates,
                environment_plan=_environment_plan(),
                stream=stream,
                name_source=name_source,
                root=root,
                storage=backend,
                backup_protection=protection,
                journal_protection=protection,
            )
        assert (
            failure.value.code
            is preparation.RecoveryBackupPreparationErrorCode.PLAN_INVALID
        )
        assert not backend.created


def test_name_source_failure_is_sanitized_and_process_control_propagates() -> None:
    protection = _Protection()
    stream, environment, certificates = _sealed_backups(protection)

    class _FailingNames:
        def new_backup_name(self) -> str:
            raise KeyError("private name-source detail")

    class _InterruptingNames:
        def new_backup_name(self) -> str:
            raise KeyboardInterrupt

    root = _Root()
    backend = _Storage(root)
    with pytest.raises(preparation.RecoveryBackupPreparationError) as failure:
        preparation.persist_backup_preparing_generation(
            environment,
            certificates,
            environment_plan=_environment_plan(),
            stream=stream,
            name_source=_FailingNames(),
            root=root,
            storage=backend,
            backup_protection=protection,
            journal_protection=protection,
        )
    assert (
        failure.value.code
        is preparation.RecoveryBackupPreparationErrorCode.NAME_GENERATION_FAILED
    )
    assert "private" not in str(failure.value)
    assert not backend.created

    with pytest.raises(KeyboardInterrupt):
        preparation.persist_backup_preparing_generation(
            environment,
            certificates,
            environment_plan=_environment_plan(),
            stream=stream,
            name_source=_InterruptingNames(),
            root=root,
            storage=backend,
            backup_protection=protection,
            journal_protection=protection,
        )
    assert not backend.created


def test_native_backup_names_are_distinct_and_fixed_format() -> None:
    source = preparation.NativeRecoveryBackupNameSource()

    first = source.new_backup_name()
    second = source.new_backup_name()

    assert first != second
    assert re.fullmatch(r"recovery-backup-[0-9a-f]{32}\.blob", first)
    assert re.fullmatch(r"recovery-backup-[0-9a-f]{32}\.blob", second)
