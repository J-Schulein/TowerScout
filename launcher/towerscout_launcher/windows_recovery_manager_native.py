"""Production composition for the native Windows rollback manager.

This module binds the already-reviewed narrow recovery ports to one retained
protected-state root.  It reconstructs certificate identity only from an
authenticated recovery chain and owns the protected root through terminal
cleanup.  Target/package-root ownership remains with the transaction layer.
"""

from __future__ import annotations

import threading
from enum import Enum
from typing import NoReturn

from .target_contracts import CertificateIdentity
from .windows_environment_replacement_native import NativeEnvironmentTempNameSource
from .windows_path_trust import PathHierarchyTrust
from .windows_protected_state import (
    ProtectedStateRoot,
    capture_native_windows_protected_state_root,
)
from .windows_recovery_backup_storage_native import (
    NativeWindowsRecoveryBackupBlobStorage,
)
from .windows_recovery_certificate_restore_native import (
    NativeWindowsCertificateRestoration,
)
from .windows_recovery_certificate_storage_native import (
    NativeCertificateRestoreTempNameSource,
    NativeWindowsCertificateRestoreTempStorage,
)
from .windows_recovery_cleanup_native import NativeWindowsRecoveryCleanup
from .windows_recovery_environment_restore_native import (
    NativeWindowsEnvironmentRestoreStorage,
)
from .windows_recovery_environment_storage_native import (
    NativeWindowsEnvironmentRestoreTempStorage,
)
from .windows_recovery_journal import (
    BackupPreparingRecord,
    JournalStreamIdentity,
)
from .windows_recovery_journal_storage import PersistedEnvironmentJournalChain
from .windows_recovery_journal_storage_native import (
    NativeWindowsJournalGenerationStorage,
    NativeWindowsJournalPointerStorage,
)
from .windows_recovery_runtime_authority import RollbackRuntimeRecoveryAuthority
from .windows_recovery_manager import (
    WindowsRecoveryManagerPorts,
    resume_persisted_rollback_from_held_package_root,
)
from .windows_recovery_runtime_available_native import (
    NativeWindowsRollbackRuntimeAvailability,
)
from .windows_recovery_runtime_restart_native import (
    NativeWindowsRollbackRuntimeRestart,
)
from .windows_recovery_verification_native import NativeWindowsRollbackVerification


class NativeWindowsRecoveryManagerErrorCode(str, Enum):
    INPUT_INVALID = "native_recovery_manager_input_invalid"
    CAPTURE_UNAVAILABLE = "native_recovery_manager_capture_unavailable"
    CLOSED = "native_recovery_manager_closed"


class NativeWindowsRecoveryManagerError(RuntimeError):
    """Sanitized failure at the production recovery-composition boundary."""

    _MESSAGES = {
        NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID: (
            "The native recovery manager request is invalid."
        ),
        NativeWindowsRecoveryManagerErrorCode.CAPTURE_UNAVAILABLE: (
            "The native recovery manager could not retain protected recovery state."
        ),
        NativeWindowsRecoveryManagerErrorCode.CLOSED: (
            "The native recovery manager is no longer available."
        ),
    }

    def __init__(self, code: NativeWindowsRecoveryManagerErrorCode) -> None:
        if type(code) is not NativeWindowsRecoveryManagerErrorCode:
            raise ValueError("Unknown native recovery manager error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeWindowsRecoveryManagerError(code={self.code.value!r})"


def _fail(code: NativeWindowsRecoveryManagerErrorCode) -> NoReturn:
    raise NativeWindowsRecoveryManagerError(code) from None


def certificate_identity_from_recovery_chain(
    chain: PersistedEnvironmentJournalChain,
) -> CertificateIdentity:
    """Reconstruct the exact selected-root identity from authenticated state."""

    if (
        type(chain) is not PersistedEnvironmentJournalChain
        or not chain.selection.generations
        or type(chain.selection.generations[0].record) is not BackupPreparingRecord
        or chain.selection.tip.stream != chain.selection.generations[0].stream
    ):
        _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)
    preparing = chain.selection.generations[0].record
    try:
        return CertificateIdentity(
            preparing.certificate_provider,
            preparing.windows_root_fingerprint_sha256,
            preparing.local_ca_candidate_sha256,
        )
    except (TypeError, ValueError):
        _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)


def rollback_runtime_authority_from_recovery_chain(
    chain: PersistedEnvironmentJournalChain,
) -> RollbackRuntimeRecoveryAuthority:
    """Reconstruct stage-stable runtime authority from authenticated state."""

    if (
        type(chain) is not PersistedEnvironmentJournalChain
        or not chain.selection.generations
        or type(chain.selection.generations[0].record) is not BackupPreparingRecord
        or chain.selection.tip.stream != chain.selection.generations[0].stream
    ):
        _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)
    preparing = chain.selection.generations[0].record
    stream = chain.selection.tip.stream
    try:
        return RollbackRuntimeRecoveryAuthority(
            1,
            stream.target_token_sha256,
            stream.package_root_identity,
            preparing.rollback_runtime_evidence_sha256,
            preparing.rollback_volume_evidence_sha256s,
            preparing.runtime_was_running,
        )
    except (TypeError, ValueError):
        _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)


def build_native_windows_recovery_manager_ports(
    certificate: CertificateIdentity,
    protected_root: ProtectedStateRoot,
) -> WindowsRecoveryManagerPorts:
    """Bind every production rollback port to one retained protected root."""

    try:
        root_valid = (
            type(certificate) is CertificateIdentity
            and protected_root.closed is False
            and callable(protected_root.run_journal_storage)
            and callable(protected_root.protect)
            and callable(protected_root.unprotect)
        )
    except Exception:
        root_valid = False
    if not root_valid:
        _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)
    backup_storage = NativeWindowsRecoveryBackupBlobStorage()
    environment_restoration = NativeWindowsEnvironmentRestoreStorage()
    try:
        return WindowsRecoveryManagerPorts(
            root=protected_root,
            journal_storage=NativeWindowsJournalGenerationStorage(),
            pointer_storage=NativeWindowsJournalPointerStorage(),
            backup_verification=backup_storage,
            backup_storage=backup_storage,
            backup_protection=protected_root,
            journal_protection=protected_root,
            environment_name_source=NativeEnvironmentTempNameSource(),
            environment_storage=NativeWindowsEnvironmentRestoreTempStorage(),
            environment_restoration=environment_restoration,
            runtime_availability=NativeWindowsRollbackRuntimeAvailability(certificate),
            certificate_name_source=NativeCertificateRestoreTempNameSource(),
            certificate_storage=NativeWindowsCertificateRestoreTempStorage(),
            certificate_restoration=NativeWindowsCertificateRestoration(certificate),
            runtime_restart=NativeWindowsRollbackRuntimeRestart(certificate),
            rollback_verification=NativeWindowsRollbackVerification(
                certificate,
                environment=environment_restoration,
            ),
            cleanup=NativeWindowsRecoveryCleanup(),
        )
    except NativeWindowsRecoveryManagerError:
        raise
    except Exception:
        _fail(NativeWindowsRecoveryManagerErrorCode.CAPTURE_UNAVAILABLE)


class NativeWindowsRecoveryManager:
    """Own one protected root and the complete native rollback port set."""

    __slots__ = ("_active", "_lock", "_ports", "_protected_root")

    def __init__(
        self,
        protected_root: ProtectedStateRoot,
        ports: WindowsRecoveryManagerPorts,
    ) -> None:
        try:
            valid = (
                protected_root.closed is False
                and type(ports) is WindowsRecoveryManagerPorts
                and ports.root is protected_root
                and ports.backup_protection is protected_root
                and ports.journal_protection is protected_root
            )
        except Exception:
            valid = False
        if not valid:
            try:
                protected_root.close()
            except BaseException:
                pass
            _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)
        self._lock = threading.RLock()
        self._active = False
        self._protected_root: ProtectedStateRoot | None = protected_root
        self._ports = ports

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._protected_root is None

    @property
    def ports(self) -> WindowsRecoveryManagerPorts:
        with self._lock:
            if self._protected_root is None:
                _fail(NativeWindowsRecoveryManagerErrorCode.CLOSED)
            return self._ports

    def resume(
        self,
        *,
        package_root: PathHierarchyTrust,
        initial_chain: PersistedEnvironmentJournalChain,
        provider_stream: JournalStreamIdentity | None,
    ) -> PersistedEnvironmentJournalChain:
        with self._lock:
            if self._protected_root is None or self._active:
                _fail(NativeWindowsRecoveryManagerErrorCode.CLOSED)
            if (
                type(package_root) is not PathHierarchyTrust
                or type(initial_chain) is not PersistedEnvironmentJournalChain
                or (
                    provider_stream is not None
                    and type(provider_stream) is not JournalStreamIdentity
                )
            ):
                _fail(NativeWindowsRecoveryManagerErrorCode.INPUT_INVALID)
            self._active = True
            try:
                stream = initial_chain.selection.tip.stream
                return resume_persisted_rollback_from_held_package_root(
                    stream=stream,
                    provider_stream=provider_stream,
                    package_root=package_root,
                    initial_chain=initial_chain,
                    ports=self._ports,
                )
            finally:
                self._active = False

    def close(self) -> None:
        with self._lock:
            root = self._protected_root
            if root is None:
                return
            if self._active:
                _fail(NativeWindowsRecoveryManagerErrorCode.CLOSED)
            self._protected_root = None
            try:
                root.close()
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                _fail(NativeWindowsRecoveryManagerErrorCode.CLOSED)

    def __enter__(self) -> NativeWindowsRecoveryManager:
        if self.closed:
            _fail(NativeWindowsRecoveryManagerErrorCode.CLOSED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return f"NativeWindowsRecoveryManager(state={state!r}, <redacted>)"


def capture_native_windows_recovery_manager(
    chain: PersistedEnvironmentJournalChain,
) -> NativeWindowsRecoveryManager:
    """Capture protected state and bind all ports for one authenticated chain."""

    certificate = certificate_identity_from_recovery_chain(chain)
    protected_root: ProtectedStateRoot | None = None
    try:
        protected_root = capture_native_windows_protected_state_root()
        ports = build_native_windows_recovery_manager_ports(certificate, protected_root)
        return NativeWindowsRecoveryManager(protected_root, ports)
    except NativeWindowsRecoveryManagerError:
        if protected_root is not None and not protected_root.closed:
            try:
                protected_root.close()
            except BaseException:
                pass
        raise
    except BaseException as error:
        if protected_root is not None:
            try:
                protected_root.close()
            except BaseException:
                pass
        if not isinstance(error, Exception):
            raise
        _fail(NativeWindowsRecoveryManagerErrorCode.CAPTURE_UNAVAILABLE)


__all__ = [
    "NativeWindowsRecoveryManager",
    "NativeWindowsRecoveryManagerError",
    "NativeWindowsRecoveryManagerErrorCode",
    "build_native_windows_recovery_manager_ports",
    "capture_native_windows_recovery_manager",
    "certificate_identity_from_recovery_chain",
    "rollback_runtime_authority_from_recovery_chain",
]
