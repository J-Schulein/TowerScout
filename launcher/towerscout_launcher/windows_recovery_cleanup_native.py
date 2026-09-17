"""Native exact-artifact cleanup for a terminal Windows rollback.

The adapter derives every removable leaf from one authenticated recovery
chain.  It never enumerates, globs, or removes journal generations.  Existing
artifacts are deleted only after their path, stable identity, bytes, locality,
single-link state, and protected current-user/SYSTEM DACL are verified twice.
Absence is idempotent so a cleanup-pending generation can resume safely.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import ntpath
import re
import struct
from typing import Callable, NoReturn, Protocol, TypeVar

from .windows_path_trust import (
    AccessAllowedAce,
    NativeSecurityFacts,
    NativeWindowsPathTrustApi,
    PathHierarchyTrust,
    PathTrustPurpose,
)
from .windows_recovery import RecoveryCleanupEvidence
from .windows_recovery_journal import (
    BackupPreparingRecord,
    BackupVerifiedRecord,
    CertificateRestoreTempPlanRecord,
    CertificateRestoreTempVerifiedRecord,
    EnvironmentJournalState,
    EnvironmentRestoreTempPlanRecord,
    EnvironmentRestoreTempVerifiedRecord,
    JournalStreamIdentity,
    RecoveryCleanedRecord,
    RecoveryCleanupPendingRecord,
    RollbackVerifiedRecord,
)
from .windows_recovery_journal_storage import PersistedEnvironmentJournalChain
from .windows_security import (
    NativeFileFacts,
    NativeWindowsFileApi,
    StableFileIdentity,
    WindowsSecurityError,
)

_MAX_PATH_CHARACTERS = 32_768
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_HASH_CHUNK_BYTES = 65_536
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_SID = re.compile(r"^S-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_BACKUP_NAME = re.compile(r"^recovery-backup-[0-9a-f]{32}\.blob$")
_ENVIRONMENT_TEMP_NAME = re.compile(r"^\.towerscout-env-[0-9a-f]{32}\.tmp$")
_CERTIFICATE_TEMP_NAME = re.compile(
    r"""^recovery-certificate-
    [0-9a-f]{32}\.tmp$""",
    re.VERBOSE,
)
_CLEANUP_STATES = frozenset(
    {
        EnvironmentJournalState.ROLLBACK_VERIFIED,
        EnvironmentJournalState.RECOVERY_CLEANUP_PENDING,
    }
)
_CLEANED_STATES = frozenset({EnvironmentJournalState.CLEANED})
_Result = TypeVar("_Result")


class RecoveryCleanupStorageErrorCode(str, Enum):
    INPUT_INVALID = "recovery_cleanup_storage_input_invalid"
    PLATFORM_UNAVAILABLE = "recovery_cleanup_storage_platform_unavailable"
    AUTHORITY_INVALID = "recovery_cleanup_storage_authority_invalid"
    VERIFY_FAILED = "recovery_cleanup_storage_verify_failed"
    DELETE_FAILED = "recovery_cleanup_storage_delete_failed"


class RecoveryCleanupStorageError(RuntimeError):
    """Sanitized failure at the native terminal-cleanup boundary."""

    _MESSAGES = {
        RecoveryCleanupStorageErrorCode.INPUT_INVALID: (
            "The recovery cleanup request is invalid."
        ),
        RecoveryCleanupStorageErrorCode.PLATFORM_UNAVAILABLE: (
            "Secure Windows recovery cleanup is unavailable."
        ),
        RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID: (
            "The recovery cleanup authority is invalid."
        ),
        RecoveryCleanupStorageErrorCode.VERIFY_FAILED: (
            "A recovery artifact could not be verified safely."
        ),
        RecoveryCleanupStorageErrorCode.DELETE_FAILED: (
            "A verified recovery artifact could not be removed safely."
        ),
    }

    def __init__(self, code: RecoveryCleanupStorageErrorCode) -> None:
        if type(code) is not RecoveryCleanupStorageErrorCode:
            raise ValueError("Unknown recovery cleanup storage error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RecoveryCleanupStorageError(code={self.code.value!r})"


class _ArtifactLocation(str, Enum):
    PACKAGE_ROOT = "package_root"
    PROTECTED_ROOT = "protected_root"


@dataclass(frozen=True, slots=True, repr=False)
class _CleanupArtifact:
    location: _ArtifactLocation
    name: str
    identity: StableFileIdentity
    contents_sha256: str
    size: int

    def __repr__(self) -> str:
        location = self.location.value
        return f"_CleanupArtifact(location={location!r}, <redacted>)"


class _WindowsRecoveryCleanupApi(Protocol):
    @property
    def supported(self) -> bool: ...

    def current_user_sid(self) -> str: ...

    def open_file_for_delete_if_exists(self, path: str) -> object | None: ...

    def reopen_file_if_exists(self, path: str) -> object | None: ...

    def query_file(self, handle: object) -> NativeFileFacts: ...

    def query_security(self, handle: object) -> NativeSecurityFacts: ...

    def seek_file(self, handle: object, offset: int) -> None: ...

    def read_file(self, handle: object, maximum: int) -> bytes: ...

    def mark_file_for_deletion(self, handle: object) -> None: ...

    def close_handle(self, handle: object) -> None: ...


class NativeWindowsRecoveryCleanupApi:
    """Windows primitives limited to exact-file inspection and deletion."""

    __slots__ = ("_files", "_paths")

    def __init__(self) -> None:
        self._files = NativeWindowsFileApi()
        self._paths = NativeWindowsPathTrustApi()

    @property
    def supported(self) -> bool:
        return self._files.supported and self._paths.supported

    def current_user_sid(self) -> str:
        return self._paths.current_user_sid()

    def open_file_for_delete_if_exists(self, path: str) -> object | None:
        return self._files.open_file_for_delete_if_exists(path)

    def reopen_file_if_exists(self, path: str) -> object | None:
        return self._files.open_file_if_exists(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        return self._files.query_file(handle)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        return self._paths.query_security(handle)

    def seek_file(self, handle: object, offset: int) -> None:
        self._files.seek_file(handle, offset)

    def read_file(self, handle: object, maximum: int) -> bytes:
        return self._files.read_file(handle, maximum)

    def mark_file_for_deletion(self, handle: object) -> None:
        self._files.mark_file_for_deletion(handle)

    def close_handle(self, handle: object) -> None:
        self._files.close_handle(handle)


def _fail(code: RecoveryCleanupStorageErrorCode) -> NoReturn:
    raise RecoveryCleanupStorageError(code) from None


def _call(
    operation: Callable[[], _Result],
    code: RecoveryCleanupStorageErrorCode,
) -> _Result:
    try:
        return operation()
    except RecoveryCleanupStorageError:
        raise
    except Exception:
        _fail(code)


def _safe_close(api: _WindowsRecoveryCleanupApi, handle: object) -> None:
    try:
        api.close_handle(handle)
    except BaseException:
        return


def _path_key(path: str) -> str:
    value = path
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _artifact_path(root_path: str, artifact: _CleanupArtifact) -> str:
    expected_pattern = _ENVIRONMENT_TEMP_NAME
    if artifact.location is _ArtifactLocation.PROTECTED_ROOT:
        expected_pattern = _CERTIFICATE_TEMP_NAME
        if artifact.name.endswith(".blob"):
            expected_pattern = _BACKUP_NAME
    if (
        type(root_path) is not str
        or not root_path
        or "\x00" in root_path
        or len(root_path) > _MAX_PATH_CHARACTERS
        or not ntpath.isabs(root_path)
        or expected_pattern.fullmatch(artifact.name) is None
    ):
        _fail(RecoveryCleanupStorageErrorCode.INPUT_INVALID)
    path = ntpath.join(root_path, artifact.name)
    parent_matches = _path_key(ntpath.dirname(path)) == _path_key(root_path)
    if len(path) > _MAX_PATH_CHARACTERS or not parent_matches:
        _fail(RecoveryCleanupStorageErrorCode.INPUT_INVALID)
    return path


def _terminal_chain_valid(
    chain: PersistedEnvironmentJournalChain,
    stream: JournalStreamIdentity,
) -> bool:
    if type(chain) is not PersistedEnvironmentJournalChain:
        return False
    generations = chain.selection.generations
    if len(generations) not in {17, 18, 19}:
        return False
    if any(generation.stream != stream for generation in generations):
        return False
    if type(generations[16].record) is not RollbackVerifiedRecord:
        return False
    if len(generations) == 17:
        terminal_state = chain.selection.tip.state
        return terminal_state is EnvironmentJournalState.ROLLBACK_VERIFIED
    if len(generations) == 18:
        return type(generations[17].record) in {
            RecoveryCleanupPendingRecord,
            RecoveryCleanedRecord,
        }
    return (
        type(generations[17].record) is RecoveryCleanupPendingRecord
        and type(generations[18].record) is RecoveryCleanedRecord
    )


def _cleanup_artifacts(
    chain: PersistedEnvironmentJournalChain,
    stream: JournalStreamIdentity,
) -> tuple[_CleanupArtifact, ...]:
    if not _terminal_chain_valid(chain, stream):
        _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
    generations = chain.selection.generations
    expected_types = {
        0: BackupPreparingRecord,
        1: BackupVerifiedRecord,
        4: EnvironmentRestoreTempPlanRecord,
        6: EnvironmentRestoreTempVerifiedRecord,
        9: CertificateRestoreTempPlanRecord,
        11: CertificateRestoreTempVerifiedRecord,
    }
    if any(
        type(generations[index].record) is not expected
        for index, expected in expected_types.items()
    ):
        _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
    records = tuple(generation.record for generation in generations)
    if any(
        getattr(record, "package_root_identity", stream.package_root_identity)
        != stream.package_root_identity
        for record in records
    ):
        _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)

    preparing = generations[0].record
    verified_backups = generations[1].record
    environment_plan = generations[4].record
    environment_verified = generations[6].record
    certificate_plan = generations[9].record
    certificate_verified = generations[11].record
    assert type(preparing) is BackupPreparingRecord
    assert type(verified_backups) is BackupVerifiedRecord
    assert type(environment_plan) is EnvironmentRestoreTempPlanRecord
    assert type(environment_verified) is EnvironmentRestoreTempVerifiedRecord
    assert type(certificate_plan) is CertificateRestoreTempPlanRecord
    assert type(certificate_verified) is CertificateRestoreTempVerifiedRecord

    artifacts: list[_CleanupArtifact] = []
    if environment_plan.environment_present:
        if (
            environment_plan.temp_name is None
            or environment_plan.environment_sha256 is None
            or environment_plan.environment_size is None
            or environment_verified.temp_name != environment_plan.temp_name
            or environment_verified.temp_identity is None
        ):
            _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
        artifacts.append(
            _CleanupArtifact(
                _ArtifactLocation.PACKAGE_ROOT,
                environment_plan.temp_name,
                environment_verified.temp_identity,
                environment_plan.environment_sha256,
                environment_plan.environment_size,
            )
        )
    elif environment_verified.temp_identity is not None:
        _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)

    certificate_pairs = (
        (
            certificate_plan.local_ca_present,
            certificate_plan.local_ca_temp_name,
            certificate_verified.local_ca_temp_identity,
            certificate_plan.local_ca_sha256,
            certificate_plan.local_ca_size,
        ),
        (
            certificate_plan.ca_bundle_present,
            certificate_plan.ca_bundle_temp_name,
            certificate_verified.ca_bundle_temp_identity,
            certificate_plan.ca_bundle_sha256,
            certificate_plan.ca_bundle_size,
        ),
    )
    for present, name, identity, contents_sha256, size in certificate_pairs:
        if present:
            if (
                name is None
                or identity is None
                or contents_sha256 is None
                or size is None
            ):
                _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
            artifacts.append(
                _CleanupArtifact(
                    _ArtifactLocation.PROTECTED_ROOT,
                    name,
                    identity,
                    contents_sha256,
                    size,
                )
            )
        elif any(
            value is not None
            for value in (
                name,
                identity,
                contents_sha256,
                size,
            )
        ):
            _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)

    artifacts.extend(
        (
            _CleanupArtifact(
                _ArtifactLocation.PROTECTED_ROOT,
                preparing.environment_backup_name,
                verified_backups.environment_backup_identity,
                verified_backups.environment_ciphertext_sha256,
                verified_backups.environment_ciphertext_size,
            ),
            _CleanupArtifact(
                _ArtifactLocation.PROTECTED_ROOT,
                preparing.certificate_backup_name,
                verified_backups.certificate_backup_identity,
                verified_backups.certificate_ciphertext_sha256,
                verified_backups.certificate_ciphertext_size,
            ),
        )
    )
    artifact_names = {(item.location, item.name) for item in artifacts}
    if len(artifact_names) != len(artifacts):
        _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
    return tuple(artifacts)


def _evidence_sha256(
    stream: JournalStreamIdentity,
    artifacts: tuple[_CleanupArtifact, ...],
) -> str:
    values = [
        b"TowerScout.WindowsRecoveryCleanupEvidence.v1",
        stream.journal_id.encode("ascii"),
        stream.target_token_sha256.encode("ascii"),
        stream.package_root_identity.volume_serial.to_bytes(8, "big"),
        stream.package_root_identity.file_id,
    ]
    for artifact in artifacts:
        values.extend(
            (
                artifact.location.value.encode("ascii"),
                artifact.name.encode("ascii"),
                artifact.identity.volume_serial.to_bytes(8, "big"),
                artifact.identity.file_id,
                artifact.contents_sha256.encode("ascii"),
                artifact.size.to_bytes(8, "big"),
            )
        )
    digest = hashlib.sha256()
    for value in values:
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _current_user_sid(api: _WindowsRecoveryCleanupApi) -> str:
    sid = _call(
        api.current_user_sid,
        RecoveryCleanupStorageErrorCode.PLATFORM_UNAVAILABLE,
    )
    if type(sid) is not str or _SID.fullmatch(sid) is None:
        _fail(RecoveryCleanupStorageErrorCode.PLATFORM_UNAVAILABLE)
    return sid


def _validate_security(security: object, current_user_sid: str) -> None:
    accepted = {current_user_sid.upper(), _SYSTEM_SID}
    allowed_principals = (
        set()
        if type(security) is not NativeSecurityFacts
        else {ace.principal_sid.upper() for ace in security.allowed_aces}
    )
    if (
        type(security) is not NativeSecurityFacts
        or security.owner_sid.upper() != current_user_sid.upper()
        or not security.dacl_present
        or not security.dacl_protected
        or len(security.allowed_aces) != 2
        or allowed_principals != accepted
        or any(
            type(ace) is not AccessAllowedAce
            or ace.access_mask != _FILE_ALL_ACCESS
            or ace.flags != 0
            for ace in security.allowed_aces
        )
    ):
        _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)


def _read_exact(
    api: _WindowsRecoveryCleanupApi,
    handle: object,
    size: int,
) -> bytes:
    _call(
        lambda: api.seek_file(handle, 0),
        RecoveryCleanupStorageErrorCode.VERIFY_FAILED,
    )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _call(
            lambda: api.read_file(handle, min(remaining, _HASH_CHUNK_BYTES)),
            RecoveryCleanupStorageErrorCode.VERIFY_FAILED,
        )
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _inspect_artifact(
    api: _WindowsRecoveryCleanupApi,
    handle: object,
    *,
    path: str,
    artifact: _CleanupArtifact,
    current_user_sid: str,
) -> None:
    facts = _call(
        lambda: api.query_file(handle),
        RecoveryCleanupStorageErrorCode.VERIFY_FAILED,
    )
    if type(facts) is not NativeFileFacts:
        _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
    try:
        identity = StableFileIdentity(facts.volume_serial, facts.file_id)
    except ValueError:
        _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
    if (
        identity != artifact.identity
        or _path_key(facts.final_path) != _path_key(path)
        or _path_key(ntpath.dirname(facts.final_path))
        != _path_key(ntpath.dirname(path))
        or facts.drive_type != 3
        or facts.file_type != 1
        or facts.attributes
        & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        or facts.reparse_tag != 0
        or facts.link_count != 1
        or facts.size != artifact.size
        or not 0 <= facts.size <= _MAX_ARTIFACT_BYTES
    ):
        _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
    _validate_security(
        _call(
            lambda: api.query_security(handle),
            RecoveryCleanupStorageErrorCode.VERIFY_FAILED,
        ),
        current_user_sid,
    )
    contents = _read_exact(api, handle, artifact.size)
    if hashlib.sha256(contents).hexdigest() != artifact.contents_sha256:
        _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)


def _verify_absent(
    api: _WindowsRecoveryCleanupApi,
    path: str,
) -> None:
    handle = _call(
        lambda: api.reopen_file_if_exists(path),
        RecoveryCleanupStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return
    _safe_close(api, handle)
    _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)


def _delete_exact_or_accept_absence(
    api: _WindowsRecoveryCleanupApi,
    *,
    path: str,
    artifact: _CleanupArtifact,
    current_user_sid: str,
) -> None:
    handle = _call(
        lambda: api.open_file_for_delete_if_exists(path),
        RecoveryCleanupStorageErrorCode.VERIFY_FAILED,
    )
    if handle is None:
        return
    held: object | None = handle
    operation_failed = False
    try:
        _inspect_artifact(
            api,
            handle,
            path=path,
            artifact=artifact,
            current_user_sid=current_user_sid,
        )
        _inspect_artifact(
            api,
            handle,
            path=path,
            artifact=artifact,
            current_user_sid=current_user_sid,
        )
        try:
            api.mark_file_for_deletion(handle)
        except RecoveryCleanupStorageError:
            raise
        except Exception:
            operation_failed = True
        try:
            api.close_handle(handle)
        except RecoveryCleanupStorageError:
            raise
        except Exception:
            operation_failed = True
        else:
            held = None
    finally:
        if held is not None:
            _safe_close(api, held)

    remaining = _call(
        lambda: api.reopen_file_if_exists(path),
        RecoveryCleanupStorageErrorCode.DELETE_FAILED,
    )
    if remaining is not None:
        _safe_close(api, remaining)
        _fail(
            RecoveryCleanupStorageErrorCode.DELETE_FAILED
            if operation_failed
            else RecoveryCleanupStorageErrorCode.VERIFY_FAILED
        )


class NativeWindowsRecoveryCleanup:
    """Delete and reverify only terminal, journal-bound recovery artifacts."""

    __slots__ = ("_api",)

    def __init__(
        self,
        *,
        api: _WindowsRecoveryCleanupApi | None = None,
    ) -> None:
        self._api = NativeWindowsRecoveryCleanupApi() if api is None else api

    def __repr__(self) -> str:
        return "NativeWindowsRecoveryCleanup(<redacted>)"

    def _context(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        chain: PersistedEnvironmentJournalChain,
        permitted_states: frozenset[EnvironmentJournalState],
    ) -> tuple[
        tuple[tuple[str, _CleanupArtifact], ...],
        RecoveryCleanupEvidence,
    ]:
        root_evidence = (
            None
            if type(package_root) is not PathHierarchyTrust
            else package_root.evidence
        )
        if (
            type(package_root) is not PathHierarchyTrust
            or package_root.closed
            or root_evidence is None
            or root_evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
            or type(stream) is not JournalStreamIdentity
            or root_evidence.root_identity != stream.package_root_identity
            or type(protected_root_path) is not str
            or not protected_root_path
        ):
            _fail(RecoveryCleanupStorageErrorCode.INPUT_INVALID)
        try:
            package_root.assert_unchanged_while_held()
        except WindowsSecurityError:
            _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
        supported = _call(
            lambda: self._api.supported,
            RecoveryCleanupStorageErrorCode.PLATFORM_UNAVAILABLE,
        )
        if supported is not True:
            _fail(RecoveryCleanupStorageErrorCode.PLATFORM_UNAVAILABLE)
        artifacts = _cleanup_artifacts(chain, stream)
        if chain.selection.tip.state not in permitted_states:
            _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
        package_path = package_root.root_snapshot.final_path
        paths = tuple(
            (
                _artifact_path(
                    (
                        package_path
                        if artifact.location is _ArtifactLocation.PACKAGE_ROOT
                        else protected_root_path
                    ),
                    artifact,
                ),
                artifact,
            )
            for artifact in artifacts
        )
        try:
            evidence = RecoveryCleanupEvidence(
                1,
                stream.target_token_sha256,
                stream.package_root_identity,
                _evidence_sha256(stream, artifacts),
            )
        except ValueError:
            _fail(RecoveryCleanupStorageErrorCode.AUTHORITY_INVALID)
        return paths, evidence

    def cleanup_rollback_artifacts_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        chain: PersistedEnvironmentJournalChain,
    ) -> RecoveryCleanupEvidence:
        paths, evidence = self._context(
            package_root,
            protected_root_path,
            stream,
            chain,
            _CLEANUP_STATES,
        )
        current_user_sid = _current_user_sid(self._api)
        for path, artifact in paths:
            try:
                package_root.assert_unchanged_while_held()
            except WindowsSecurityError:
                _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
            _delete_exact_or_accept_absence(
                self._api,
                path=path,
                artifact=artifact,
                current_user_sid=current_user_sid,
            )
        for path, _artifact in paths:
            _verify_absent(self._api, path)
        try:
            package_root.assert_unchanged_while_held()
        except WindowsSecurityError:
            _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
        return evidence

    def verify_rollback_artifacts_cleaned_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        chain: PersistedEnvironmentJournalChain,
    ) -> RecoveryCleanupEvidence:
        paths, evidence = self._context(
            package_root,
            protected_root_path,
            stream,
            chain,
            _CLEANED_STATES,
        )
        for path, _artifact in paths:
            _verify_absent(self._api, path)
        try:
            package_root.assert_unchanged_while_held()
        except WindowsSecurityError:
            _fail(RecoveryCleanupStorageErrorCode.VERIFY_FAILED)
        return evidence


__all__ = [
    "NativeWindowsRecoveryCleanup",
    "NativeWindowsRecoveryCleanupApi",
    "RecoveryCleanupStorageError",
    "RecoveryCleanupStorageErrorCode",
]
