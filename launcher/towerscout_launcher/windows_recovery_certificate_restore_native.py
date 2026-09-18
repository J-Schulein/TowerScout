"""Native exact-target certificate rollback under retained Windows authority."""

from __future__ import annotations

import hashlib
import json
import struct
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol, TypeVar

from .runtime_target_observation import (
    CertificateTargetDestination,
    ObservationOperation,
)
from .runtime_target_observation_backend import TargetObservationProcessResult
from .runtime_target_factory import capture_native_windows_resolved_target
from .runtime_target_resolution import BoundResolvedRepairTarget
from .target_contracts import CertificateIdentity, MapProvider
from .windows_path_trust import PathHierarchyTrust, PathTrustPurpose
from .windows_recovery import (
    CertificateDestinationRestoreEvidence,
    CertificateRestorationEvidence,
)
from .windows_recovery_certificate_restore import (
    CertificateDestinationObservation,
    CertificateDestinationRestoreAuthority,
    CertificateRestorationAuthority,
    CertificateRestoreAction,
    decide_certificate_restore,
)
from .windows_recovery_certificate_storage_native import (
    HeldCertificateRestoreTempPaths,
    HeldCertificateRestoreTemps,
    capture_held_certificate_restore_temps,
)
from .windows_recovery_journal import JournalStreamIdentity
from .windows_recovery_runtime_available_native import (
    observe_rollback_runtime_target,
)

_DESTINATION_EVIDENCE_DOMAIN = b"TowerScout.CertificateRestoreDestinationEvidence.v1"
_Result = TypeVar("_Result")


class NativeCertificateRestorationErrorCode(str, Enum):
    INPUT_INVALID = "input_invalid"
    CAPTURE_UNAVAILABLE = "capture_unavailable"
    TARGET_MISMATCH = "target_mismatch"
    VERIFY_FAILED = "verify_failed"


class NativeCertificateRestorationError(RuntimeError):
    _MESSAGES = {
        NativeCertificateRestorationErrorCode.INPUT_INVALID: (
            "The certificate-restoration input is invalid."
        ),
        NativeCertificateRestorationErrorCode.CAPTURE_UNAVAILABLE: (
            "Secure certificate restoration is unavailable."
        ),
        NativeCertificateRestorationErrorCode.TARGET_MISMATCH: (
            "The authenticated certificate-restoration target changed."
        ),
        NativeCertificateRestorationErrorCode.VERIFY_FAILED: (
            "Certificate restoration could not be verified."
        ),
    }

    def __init__(self, code: NativeCertificateRestorationErrorCode) -> None:
        if type(code) is not NativeCertificateRestorationErrorCode:
            raise ValueError("Unknown certificate-restoration error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"NativeCertificateRestorationError(code={self.code.value!r})"


class ResolvedTargetCapture(Protocol):
    def __call__(self, provider: MapProvider) -> BoundResolvedRepairTarget: ...


class HeldTempCapture(Protocol):
    def __call__(
        self,
        root_path: str,
        authority: CertificateRestorationAuthority,
    ) -> HeldCertificateRestoreTemps: ...


class _HeldTemps(Protocol):
    @property
    def closed(self) -> bool: ...

    def run_while_held(
        self,
        operation: Callable[[HeldCertificateRestoreTempPaths], _Result],
    ) -> _Result: ...

    def close(self) -> None: ...


def _fail(code: NativeCertificateRestorationErrorCode) -> NoReturn:
    raise NativeCertificateRestorationError(code) from None


def _add(digest: Any, value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def _destination_evidence_sha256(
    destination: CertificateTargetDestination,
    observation: CertificateDestinationObservation,
) -> str:
    digest = hashlib.sha256()
    values = (
        _DESTINATION_EVIDENCE_DOMAIN,
        destination.value.encode("ascii"),
        (b"present" if observation.present else b"absent"),
        (observation.sha256 or "").encode("ascii"),
        str(observation.size if observation.size is not None else -1).encode("ascii"),
        format(observation.mode if observation.mode is not None else 0, "o").encode(
            "ascii"
        ),
    )
    for value in values:
        _add(digest, value)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON member.")
        output[key] = value
    return output


def _parse_observation(raw: bytes) -> CertificateDestinationObservation:
    try:
        if not raw or len(raw) > 8 * 1024:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if type(value) is not dict or type(value.get("present")) is not bool:
            raise ValueError
        if value["present"] is False:
            if set(value) != {"present"}:
                raise ValueError
            return CertificateDestinationObservation(False)
        if set(value) != {"present", "sha256", "size", "mode"}:
            raise ValueError
        return CertificateDestinationObservation(
            True,
            value["sha256"],
            value["size"],
            value["mode"],
        )
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)


def _process_result(
    value: object, operation: ObservationOperation
) -> TargetObservationProcessResult:
    if (
        type(value) is not TargetObservationProcessResult
        or value.operation is not operation
    ):
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
    return value


def _observe(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
    *,
    restore_temp_name: str | None = None,
) -> CertificateDestinationObservation:
    result = _process_result(
        owner.execute_scoped_process(
            "certificate_observe",
            (
                owner.target.container.container_id,
                destination,
                restore_temp_name,
            ),
        ),
        ObservationOperation.CERTIFICATE_OBSERVE,
    )
    if result.exit_code != 0:
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
    return _parse_observation(result.stdout)


def _exact_staged_original(
    observation: CertificateDestinationObservation,
    authority: CertificateDestinationRestoreAuthority,
) -> bool:
    return (
        observation.present
        and observation.sha256 == authority.original_sha256
        and observation.size == authority.original_size
    )


def _restore_present_original(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
    authority: CertificateDestinationRestoreAuthority,
    source_path: PureWindowsPath | None,
) -> CertificateDestinationObservation:
    if (
        source_path is None
        or authority.restore_temp_name is None
        or authority.original_sha256 is None
        or authority.original_size is None
        or authority.original_mode is None
    ):
        _fail(NativeCertificateRestorationErrorCode.INPUT_INVALID)
    staged = _observe(
        owner,
        destination,
        restore_temp_name=authority.restore_temp_name,
    )
    if not staged.present:
        _process_result(
            owner.execute_scoped_process(
                "certificate_stage_original",
                (
                    owner.target.container.container_id,
                    destination,
                    authority.restore_temp_name,
                    source_path,
                ),
            ),
            ObservationOperation.CERTIFICATE_STAGE_ORIGINAL,
        )
        staged = _observe(
            owner,
            destination,
            restore_temp_name=authority.restore_temp_name,
        )
    if not _exact_staged_original(staged, authority):
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
    _process_result(
        owner.execute_scoped_process(
            "certificate_apply_original",
            (
                owner.target.container.container_id,
                destination,
                authority.restore_temp_name,
                authority.original_sha256,
                authority.original_size,
                authority.original_mode,
                authority.candidate_sha256,
                authority.candidate_size,
                authority.candidate_mode,
            ),
        ),
        ObservationOperation.CERTIFICATE_APPLY_ORIGINAL,
    )
    final = _observe(owner, destination)
    if (
        decide_certificate_restore(authority, final).action
        is not CertificateRestoreAction.ALREADY_RESTORED
        or _observe(
            owner,
            destination,
            restore_temp_name=authority.restore_temp_name,
        ).present
    ):
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
    return final


def _remove_candidate(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
    authority: CertificateDestinationRestoreAuthority,
) -> CertificateDestinationObservation:
    _process_result(
        owner.execute_scoped_process(
            "certificate_remove_candidate",
            (
                owner.target.container.container_id,
                destination,
                authority.candidate_sha256,
                authority.candidate_size,
                authority.candidate_mode,
            ),
        ),
        ObservationOperation.CERTIFICATE_REMOVE_CANDIDATE,
    )
    final = _observe(owner, destination)
    if (
        decide_certificate_restore(authority, final).action
        is not CertificateRestoreAction.ALREADY_RESTORED
    ):
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
    return final


def _remove_staged_original_if_present(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
    authority: CertificateDestinationRestoreAuthority,
) -> None:
    if not authority.original_present or authority.restore_temp_name is None:
        return
    staged = _observe(
        owner,
        destination,
        restore_temp_name=authority.restore_temp_name,
    )
    if not staged.present:
        return
    if not _exact_staged_original(staged, authority) or staged.mode is None:
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
    _process_result(
        owner.execute_scoped_process(
            "certificate_remove_staged_original",
            (
                owner.target.container.container_id,
                destination,
                authority.restore_temp_name,
                authority.original_sha256,
                authority.original_size,
                staged.mode,
            ),
        ),
        ObservationOperation.CERTIFICATE_REMOVE_STAGED_ORIGINAL,
    )
    if _observe(
        owner,
        destination,
        restore_temp_name=authority.restore_temp_name,
    ).present:
        _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)


def _restore_destination(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
    authority: CertificateDestinationRestoreAuthority,
    source_path: PureWindowsPath | None,
) -> CertificateDestinationObservation:
    before = _observe(owner, destination)
    action = decide_certificate_restore(authority, before).action
    if action is CertificateRestoreAction.ALREADY_RESTORED:
        _remove_staged_original_if_present(owner, destination, authority)
        return before
    if action is CertificateRestoreAction.RESTORE_ORIGINAL:
        return _restore_present_original(owner, destination, authority, source_path)
    if action is CertificateRestoreAction.REMOVE_CANDIDATE:
        return _remove_candidate(owner, destination, authority)
    _fail(NativeCertificateRestorationErrorCode.TARGET_MISMATCH)


def _destination_evidence(
    destination: CertificateTargetDestination,
    observation: CertificateDestinationObservation,
) -> CertificateDestinationRestoreEvidence:
    return CertificateDestinationRestoreEvidence(
        1,
        observation.present,
        observation.sha256,
        observation.size,
        observation.mode,
        _destination_evidence_sha256(destination, observation),
    )


def observe_certificate_destination_while_target_held(
    owner: BoundResolvedRepairTarget,
    destination: CertificateTargetDestination,
) -> CertificateDestinationRestoreEvidence:
    """Freshly observe one fixed certificate destination under target authority."""

    if (
        type(owner) is not BoundResolvedRepairTarget
        or owner.closed
        or type(destination) is not CertificateTargetDestination
    ):
        _fail(NativeCertificateRestorationErrorCode.INPUT_INVALID)
    return _destination_evidence(destination, _observe(owner, destination))


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
        _fail(NativeCertificateRestorationErrorCode.TARGET_MISMATCH)
    try:
        package_root.assert_unchanged_while_held()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        _fail(NativeCertificateRestorationErrorCode.TARGET_MISMATCH)


def _close(resource: object | None) -> bool:
    if resource is None:
        return False
    failed = False
    try:
        close = getattr(resource, "close", None)
        if not callable(close):
            return True
        close()
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        failed = True
    try:
        return failed or getattr(resource, "closed") is not True
    except Exception:
        return True


class NativeWindowsCertificateRestoration:
    """Restore only exact candidate destinations on one exact retained target."""

    __slots__ = ("_certificate", "_target_capture", "_temp_capture")

    def __init__(
        self,
        certificate: CertificateIdentity,
        *,
        target_capture: ResolvedTargetCapture = capture_native_windows_resolved_target,
        temp_capture: HeldTempCapture = capture_held_certificate_restore_temps,
    ) -> None:
        if (
            type(certificate) is not CertificateIdentity
            or not callable(target_capture)
            or not callable(temp_capture)
        ):
            raise ValueError("Certificate restoration configuration is invalid.")
        self._certificate = certificate
        self._target_capture = target_capture
        self._temp_capture = temp_capture

    def restore_certificates_while_package_root_held(
        self,
        package_root: PathHierarchyTrust,
        protected_root_path: str,
        stream: JournalStreamIdentity,
        authority: CertificateRestorationAuthority,
    ) -> CertificateRestorationEvidence:
        if (
            type(package_root) is not PathHierarchyTrust
            or type(protected_root_path) is not str
            or not protected_root_path
            or type(stream) is not JournalStreamIdentity
            or type(authority) is not CertificateRestorationAuthority
            or authority.target_token_sha256 != stream.target_token_sha256
            or authority.package_root_identity != stream.package_root_identity
            or authority.package_root_identity != package_root.root_snapshot.identity
        ):
            _fail(NativeCertificateRestorationErrorCode.INPUT_INVALID)
        _assert_package_root(package_root, stream)
        owner: BoundResolvedRepairTarget | None = None
        temps: _HeldTemps | None = None
        result: CertificateRestorationEvidence | None = None
        primary: BaseException | None = None
        try:
            owner = self._target_capture(self._certificate.provider)
            if owner.closed:
                _fail(NativeCertificateRestorationErrorCode.CAPTURE_UNAVAILABLE)
            active_owner = owner
            observed = observe_rollback_runtime_target(
                active_owner.target,
                authority.target_token_sha256,
            )
            if (
                observed.target_token_sha256 != authority.target_token_sha256
                or observed.package_root_identity != authority.package_root_identity
                or observed.runtime_evidence_sha256 != authority.runtime_evidence_sha256
                or observed.container_evidence_sha256
                != authority.container_evidence_sha256
                or observed.volume_evidence_sha256s != authority.volume_evidence_sha256s
            ):
                _fail(NativeCertificateRestorationErrorCode.TARGET_MISMATCH)
            temps = self._temp_capture(protected_root_path, authority)
            if temps.closed:
                _fail(NativeCertificateRestorationErrorCode.CAPTURE_UNAVAILABLE)

            def restore(
                paths: HeldCertificateRestoreTempPaths,
            ) -> CertificateRestorationEvidence:
                local = _restore_destination(
                    active_owner,
                    CertificateTargetDestination.LOCAL_CA,
                    authority.local_ca,
                    paths.local_ca,
                )
                bundle = _restore_destination(
                    active_owner,
                    CertificateTargetDestination.CA_BUNDLE,
                    authority.ca_bundle,
                    paths.ca_bundle,
                )
                active_owner.assert_unchanged()
                return CertificateRestorationEvidence(
                    1,
                    authority.target_token_sha256,
                    authority.package_root_identity,
                    authority.runtime_evidence_sha256,
                    authority.container_evidence_sha256,
                    authority.volume_evidence_sha256s,
                    _destination_evidence(
                        CertificateTargetDestination.LOCAL_CA,
                        local,
                    ),
                    _destination_evidence(
                        CertificateTargetDestination.CA_BUNDLE,
                        bundle,
                    ),
                )

            result = temps.run_while_held(restore)
            _assert_package_root(package_root, stream)
        except BaseException as error:
            primary = error
        cleanup_failed = _close(temps)
        cleanup_failed = _close(owner) or cleanup_failed
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup_failed:
            _fail(NativeCertificateRestorationErrorCode.VERIFY_FAILED)
        if isinstance(primary, NativeCertificateRestorationError):
            raise primary from None
        if primary is not None or result is None:
            _fail(NativeCertificateRestorationErrorCode.CAPTURE_UNAVAILABLE)
        return result

    def __repr__(self) -> str:
        return (
            "NativeWindowsCertificateRestoration("
            f"provider={self._certificate.provider.value!r}, <redacted>)"
        )


__all__ = [
    "HeldTempCapture",
    "NativeCertificateRestorationError",
    "NativeCertificateRestorationErrorCode",
    "NativeWindowsCertificateRestoration",
    "ResolvedTargetCapture",
    "observe_certificate_destination_while_target_held",
]
