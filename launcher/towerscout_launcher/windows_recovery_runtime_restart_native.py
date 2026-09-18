"""Native exact-profile restart adapter for authenticated Windows rollback.

Rollback must reread the restored package environment, so an ordinary
container restart is insufficient. This adapter allows only the fixed Compose
``up -d --no-deps --force-recreate towerscout`` transition, never a volume
delete. It retires the old exact-target owner at the mutation boundary and then
captures a new complete target. Generation-14 retry accepts only the old exact
container, an exact already-recreated container, or exact absence that can be
rebuilt by the reviewed prior-profile recovery path.
"""

from __future__ import annotations

from enum import Enum
from typing import NoReturn, Protocol

from .runtime_target_factory import capture_native_windows_resolved_target
from .runtime_target_observation import ObservationOperation
from .runtime_target_observation_backend import TargetObservationProcessResult
from .target_contracts import CertificateIdentity, MapProvider, ResolvedRepairTarget
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery import RollbackRuntimeRestartEvidence
from .windows_recovery_journal import (
    JournalStreamIdentity,
    RollbackRuntimeRestartedRecord,
    RollbackRuntimeRestartingRecord,
)
from .windows_recovery_runtime_authority import RollbackRuntimeRecoveryAuthority
from .windows_recovery_runtime_available_native import (
    AbsentRollbackRuntimeCapture,
    BoundAbsentRollbackRuntimeTarget,
    ExistingRollbackRuntimeObservation,
    capture_native_absent_rollback_runtime_target,
    observe_rollback_runtime_target,
)
from .windows_security import StableFileIdentity


class NativeRollbackRuntimeRestartErrorCode(str, Enum):
    INPUT_INVALID = "rollback_runtime_restart_input_invalid"
    CAPTURE_UNAVAILABLE = "rollback_runtime_restart_capture_unavailable"
    TARGET_MISMATCH = "rollback_runtime_restart_target_mismatch"
    RESTART_FAILED = "rollback_runtime_restart_failed"
    VERIFY_FAILED = "rollback_runtime_restart_verify_failed"


class NativeRollbackRuntimeRestartError(RuntimeError):
    """Sanitized exact-profile rollback restart failure."""

    _MESSAGES = {
        NativeRollbackRuntimeRestartErrorCode.INPUT_INVALID: (
            "The rollback runtime restart request is invalid."
        ),
        NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE: (
            "The rollback runtime could not be inspected for restart."
        ),
        NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH: (
            "The rollback runtime no longer matches the durable restart intent."
        ),
        NativeRollbackRuntimeRestartErrorCode.RESTART_FAILED: (
            "The exact rollback runtime could not be restarted safely."
        ),
        NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED: (
            "The restarted rollback runtime could not be verified safely."
        ),
    }

    def __init__(self, code: NativeRollbackRuntimeRestartErrorCode) -> None:
        if type(code) is not NativeRollbackRuntimeRestartErrorCode:
            raise ValueError("Unknown rollback runtime restart error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeRollbackRuntimeRestartError(code={self.code.value!r})"


class _ResolvedTargetOwner(Protocol):
    @property
    def target(self) -> ResolvedRepairTarget: ...

    @property
    def closed(self) -> bool: ...

    def assert_unchanged(self) -> object: ...

    def execute_scoped_transition(
        self,
        operation: str,
        arguments: tuple[object, ...],
    ) -> object: ...

    def close(self) -> None: ...


class ResolvedTargetCapture(Protocol):
    def __call__(self, provider: MapProvider) -> _ResolvedTargetOwner: ...


def _fail(code: NativeRollbackRuntimeRestartErrorCode) -> NoReturn:
    raise NativeRollbackRuntimeRestartError(code) from None


def _assert_package_root(
    package_root: PathHierarchyTrust,
    stream: JournalStreamIdentity,
) -> None:
    if (
        type(package_root) is not PathHierarchyTrust
        or package_root.closed
        or package_root.evidence.purpose is not PathTrustPurpose.PACKAGE_ROOT
        or package_root.root_snapshot.identity != stream.package_root_identity
    ):
        _fail(NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH)
    try:
        package_root.assert_unchanged_while_held()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH)


def _stable_observation_matches(
    observed: ExistingRollbackRuntimeObservation,
    *,
    stream: JournalStreamIdentity,
    package_root_identity: StableFileIdentity,
    runtime_evidence_sha256: str,
    volume_evidence_sha256s: tuple[str, ...],
) -> bool:
    return (
        type(observed) is ExistingRollbackRuntimeObservation
        and observed.target_token_sha256 == stream.target_token_sha256
        and observed.package_root_identity == stream.package_root_identity
        and observed.package_root_identity == package_root_identity
        and observed.runtime_evidence_sha256 == runtime_evidence_sha256
        and observed.volume_evidence_sha256s == volume_evidence_sha256s
    )


def _evidence(
    observed: ExistingRollbackRuntimeObservation,
) -> RollbackRuntimeRestartEvidence:
    return RollbackRuntimeRestartEvidence(
        1,
        observed.target_token_sha256,
        observed.package_root_identity,
        observed.runtime_evidence_sha256,
        observed.container_evidence_sha256,
        observed.volume_evidence_sha256s,
    )


def _close_present(owner: _ResolvedTargetOwner | None) -> bool:
    if owner is None or owner.closed:
        return False
    failed = False
    try:
        owner.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        return failed or owner.closed is not True
    except Exception:
        return True


def _close_absent(owner: BoundAbsentRollbackRuntimeTarget | None) -> bool:
    if owner is None or owner.closed:
        return False
    failed = False
    try:
        owner.close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        return failed or owner.closed is not True
    except Exception:
        return True


def _observe_present(
    owner: _ResolvedTargetOwner,
    target_token_sha256: str,
) -> ExistingRollbackRuntimeObservation:
    if owner.closed:
        _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
    failed = False
    observed: ExistingRollbackRuntimeObservation | None = None
    try:
        owner.assert_unchanged()
        observed = observe_rollback_runtime_target(owner.target, target_token_sha256)
        owner.assert_unchanged()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    if failed or observed is None:
        _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
    return observed


class NativeWindowsRollbackRuntimeRestart:
    """Recreate and reverify only one authenticated prior Compose profile."""

    __slots__ = ("_absent_capture", "_certificate", "_present_capture")

    def __init__(
        self,
        certificate: CertificateIdentity,
        *,
        present_capture: ResolvedTargetCapture = capture_native_windows_resolved_target,
        absent_capture: AbsentRollbackRuntimeCapture = (
            capture_native_absent_rollback_runtime_target
        ),
    ) -> None:
        if (
            type(certificate) is not CertificateIdentity
            or not callable(present_capture)
            or not callable(absent_capture)
        ):
            raise ValueError("Rollback runtime restart configuration is invalid.")
        self._certificate = certificate
        self._present_capture = present_capture
        self._absent_capture = absent_capture

    def _try_present(self) -> _ResolvedTargetOwner | None:
        owner: _ResolvedTargetOwner | None = None
        try:
            owner = self._present_capture(self._certificate.provider)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
        if owner is not None and owner.closed:
            return None
        return owner

    @staticmethod
    def _authority(
        stream: JournalStreamIdentity,
        intent: RollbackRuntimeRestartingRecord,
    ) -> RollbackRuntimeRecoveryAuthority:
        try:
            return RollbackRuntimeRecoveryAuthority(
                1,
                stream.target_token_sha256,
                intent.package_root_identity,
                intent.runtime_evidence_sha256,
                intent.volume_evidence_sha256s,
                True,
            )
        except ValueError:
            _fail(NativeRollbackRuntimeRestartErrorCode.INPUT_INVALID)

    def _capture_after_transition(
        self,
        stream: JournalStreamIdentity,
        authority: RollbackRuntimeRecoveryAuthority,
        prior_container_evidence_sha256: str,
    ) -> tuple[_ResolvedTargetOwner, ExistingRollbackRuntimeObservation]:
        present = self._try_present()
        absent: BoundAbsentRollbackRuntimeTarget | None = None
        primary: BaseException | None = None
        try:
            if present is None:
                absent = self._absent_capture(self._certificate, authority)
                if absent.closed:
                    _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
                absent.assert_unchanged()
                present = absent.recreate_prior_profile()
                if absent.closed is not True:
                    _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
            observed = _observe_present(present, stream.target_token_sha256)
            if (
                not _stable_observation_matches(
                    observed,
                    stream=stream,
                    package_root_identity=authority.package_root_identity,
                    runtime_evidence_sha256=authority.runtime_evidence_sha256,
                    volume_evidence_sha256s=authority.volume_evidence_sha256s,
                )
                or observed.container_evidence_sha256 == prior_container_evidence_sha256
            ):
                _fail(NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH)
            return present, observed
        except BaseException as error:
            primary = error
        cleanup_failed = _close_present(present)
        cleanup_failed = _close_absent(absent) or cleanup_failed
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup_failed:
            _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
        if isinstance(primary, NativeRollbackRuntimeRestartError):
            raise primary from None
        _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)

    def restart_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        intent: RollbackRuntimeRestartingRecord,
    ) -> RollbackRuntimeRestartEvidence:
        if (
            type(stream) is not JournalStreamIdentity
            or type(intent) is not RollbackRuntimeRestartingRecord
            or intent.package_root_identity != stream.package_root_identity
        ):
            _fail(NativeRollbackRuntimeRestartErrorCode.INPUT_INVALID)
        _assert_package_root(package_root, stream)
        authority = self._authority(stream, intent)
        present = self._try_present()
        absent: BoundAbsentRollbackRuntimeTarget | None = None
        result: RollbackRuntimeRestartEvidence | None = None
        primary: BaseException | None = None
        try:
            if present is None:
                absent = self._absent_capture(self._certificate, authority)
                if absent.closed:
                    _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
                absent.assert_unchanged()
                present = absent.recreate_prior_profile()
                if absent.closed is not True:
                    _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
                observed = _observe_present(present, stream.target_token_sha256)
            else:
                observed = _observe_present(present, stream.target_token_sha256)
                if not _stable_observation_matches(
                    observed,
                    stream=stream,
                    package_root_identity=intent.package_root_identity,
                    runtime_evidence_sha256=intent.runtime_evidence_sha256,
                    volume_evidence_sha256s=intent.volume_evidence_sha256s,
                ):
                    _fail(NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH)
                if (
                    observed.container_evidence_sha256
                    == intent.container_evidence_sha256
                ):
                    transition_invalid = False
                    try:
                        executed = present.execute_scoped_transition(
                            "restart_prior_profile",
                            (),
                        )
                        if isinstance(executed, TargetObservationProcessResult):
                            transition_invalid = (
                                type(executed) is not TargetObservationProcessResult
                                or executed.operation
                                is not ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE
                            )
                        else:
                            transition_invalid = True
                    except BaseException as error:
                        if not isinstance(error, Exception):
                            raise
                    if not present.closed:
                        _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
                    present = None
                    if transition_invalid:
                        _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
                    present, observed = self._capture_after_transition(
                        stream,
                        authority,
                        intent.container_evidence_sha256,
                    )
            if (
                not _stable_observation_matches(
                    observed,
                    stream=stream,
                    package_root_identity=intent.package_root_identity,
                    runtime_evidence_sha256=intent.runtime_evidence_sha256,
                    volume_evidence_sha256s=intent.volume_evidence_sha256s,
                )
                or observed.container_evidence_sha256
                == intent.container_evidence_sha256
            ):
                _fail(NativeRollbackRuntimeRestartErrorCode.RESTART_FAILED)
            _assert_package_root(package_root, stream)
            result = _evidence(observed)
        except BaseException as error:
            primary = error
        cleanup_failed = _close_present(present)
        cleanup_failed = _close_absent(absent) or cleanup_failed
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup_failed:
            _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
        if isinstance(primary, NativeRollbackRuntimeRestartError):
            raise primary from None
        if primary is not None or result is None:
            _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
        return result

    def verify_restarted_rollback_runtime_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        stream: JournalStreamIdentity,
        restarted: RollbackRuntimeRestartedRecord,
    ) -> RollbackRuntimeRestartEvidence:
        if (
            type(stream) is not JournalStreamIdentity
            or type(restarted) is not RollbackRuntimeRestartedRecord
            or restarted.package_root_identity != stream.package_root_identity
        ):
            _fail(NativeRollbackRuntimeRestartErrorCode.INPUT_INVALID)
        _assert_package_root(package_root, stream)
        owner = self._try_present()
        result: RollbackRuntimeRestartEvidence | None = None
        primary: BaseException | None = None
        try:
            if owner is None:
                _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
            observed = _observe_present(owner, stream.target_token_sha256)
            if (
                not _stable_observation_matches(
                    observed,
                    stream=stream,
                    package_root_identity=restarted.package_root_identity,
                    runtime_evidence_sha256=restarted.runtime_evidence_sha256,
                    volume_evidence_sha256s=restarted.volume_evidence_sha256s,
                )
                or observed.container_evidence_sha256
                != restarted.container_evidence_sha256
            ):
                _fail(NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH)
            _assert_package_root(package_root, stream)
            result = _evidence(observed)
        except BaseException as error:
            primary = error
        cleanup_failed = _close_present(owner)
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup_failed:
            _fail(NativeRollbackRuntimeRestartErrorCode.VERIFY_FAILED)
        if isinstance(primary, NativeRollbackRuntimeRestartError):
            raise primary from None
        if primary is not None or result is None:
            _fail(NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE)
        return result

    def __repr__(self) -> str:
        return (
            "NativeWindowsRollbackRuntimeRestart("
            f"provider={self._certificate.provider.value!r}, <redacted>)"
        )


__all__ = [
    "NativeRollbackRuntimeRestartError",
    "NativeRollbackRuntimeRestartErrorCode",
    "NativeWindowsRollbackRuntimeRestart",
    "ResolvedTargetCapture",
]
