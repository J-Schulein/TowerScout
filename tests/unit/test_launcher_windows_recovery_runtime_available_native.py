from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_launcher_runtime_execution import _digest, _target  # noqa: E402
from towerscout_launcher.target_contracts import (  # noqa: E402
    MapProvider,
    RuntimeProduct,
)
from towerscout_launcher.windows_path_trust import (  # noqa: E402
    NativeDirectoryFacts,
    NativeSecurityFacts,
    PathTrustPurpose,
    capture_path_hierarchy,
)
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
)
from towerscout_launcher.windows_recovery_runtime_available_native import (  # noqa: E402, E501
    ExistingRollbackRuntimeObservation,
    NativeRollbackRuntimeAvailabilityError,
    NativeRollbackRuntimeAvailabilityErrorCode,
    NativeWindowsExistingRollbackRuntimeAvailability,
    capture_native_existing_rollback_runtime,
)
from towerscout_launcher.windows_recovery_runtime_authority import (  # noqa: E402
    RollbackRuntimeRecoveryAuthority,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    StableFileIdentity,
)


def _identity(value: int) -> StableFileIdentity:
    return StableFileIdentity(7, value.to_bytes(16, "big"))


class _PackagePathApi:
    supported = True

    def current_user_sid(self) -> str:
        return "S-1-5-21-1000"

    def open_directory(self, path: str, *, follow_reparse: bool) -> object:
        del follow_reparse
        return path

    def query_directory(self, handle: object) -> NativeDirectoryFacts:
        assert isinstance(handle, str)
        file_id = (
            _identity(7).file_id
            if handle.casefold() == r"C:\Users\reviewed-user\TowerScout".casefold()
            else hashlib.sha256(handle.casefold().encode("utf-16-le")).digest()[:16]
        )
        return NativeDirectoryFacts(handle, 7, file_id, 0x10, 3, 1, 0)

    def query_security(self, handle: object) -> NativeSecurityFacts:
        assert isinstance(handle, str)
        return NativeSecurityFacts(self.current_user_sid(), True, ())

    def close_handle(self, handle: object) -> None:
        assert isinstance(handle, str)


def _package_root():
    return capture_path_hierarchy(
        r"C:\Users\reviewed-user\TowerScout",
        purpose=PathTrustPurpose.PACKAGE_ROOT,
        api=_PackagePathApi(),
    )


def _observation(
    *,
    target_token_sha256: str = "b" * 64,
    package_root_identity: StableFileIdentity | None = None,
) -> ExistingRollbackRuntimeObservation:
    return ExistingRollbackRuntimeObservation(
        1,
        target_token_sha256,
        package_root_identity or _identity(7),
        "c" * 64,
        "d" * 64,
        tuple(_digest(str(index)) for index in range(8)),
    )


def _stream() -> JournalStreamIdentity:
    return JournalStreamIdentity(1, "a" * 32, "b" * 64, _identity(7))


def _authority() -> RollbackRuntimeRecoveryAuthority:
    return RollbackRuntimeRecoveryAuthority(
        1,
        "b" * 64,
        _identity(7),
        "c" * 64,
        tuple(_digest(str(index)) for index in range(8)),
        True,
    )


class _Owner:
    def __init__(
        self,
        target,
        *,
        changed: bool = False,
        close_error: bool = False,
    ):
        self.target = target
        self.closed = False
        self.changed = changed
        self.close_error = close_error
        self.assertions = 0

    def assert_unchanged(self) -> object:
        self.assertions += 1
        if self.changed:
            raise OSError("private changed target detail")
        return object()

    def close(self) -> None:
        if self.close_error:
            raise OSError("private close detail")
        self.closed = True


def test_native_capture_binds_exact_target_and_closes_owner():
    target, _python, _key = _target(RuntimeProduct.DOCKER)
    owner = _Owner(target)

    observed = capture_native_existing_rollback_runtime(
        MapProvider.GOOGLE,
        capture=lambda provider: owner,
    )

    assert observed.target_token_sha256 == target.target_token.digest_sha256
    assert observed.package_root_identity == StableFileIdentity(
        target.package_root.volume_serial,
        target.package_root.file_id,
    )
    assert len(observed.volume_evidence_sha256s) == 8
    assert len(set(observed.volume_evidence_sha256s)) == 8
    assert owner.assertions == 2
    assert owner.closed
    assert "container_id" not in repr(observed)


@pytest.mark.parametrize("changed,close_error", [(True, False), (False, True)])
def test_native_capture_fails_sanitized_and_closes_when_possible(
    changed: bool,
    close_error: bool,
):
    target, _python, _key = _target(RuntimeProduct.DOCKER)
    owner = _Owner(target, changed=changed, close_error=close_error)

    with pytest.raises(NativeRollbackRuntimeAvailabilityError) as captured:
        capture_native_existing_rollback_runtime(
            MapProvider.GOOGLE,
            capture=lambda provider: owner,
        )

    assert "private" not in str(captured.value)
    assert captured.value.code in {
        NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE,
        NativeRollbackRuntimeAvailabilityErrorCode.VERIFY_FAILED,
    }
    if not close_error:
        assert owner.closed


def test_adapter_attests_retained_runtime_under_matching_package_root():
    calls: list[MapProvider] = []

    def capture(provider: MapProvider) -> ExistingRollbackRuntimeObservation:
        calls.append(provider)
        return _observation()

    adapter = NativeWindowsExistingRollbackRuntimeAvailability(
        MapProvider.GOOGLE,
        capture=capture,
    )
    package_root = _package_root()
    try:
        evidence = package_root.run_while_held(
            lambda: adapter.establish_rollback_runtime_while_package_root_held(
                package_root,
                _stream(),
                _authority(),
            )
        )
    finally:
        package_root.close()

    assert calls == [MapProvider.GOOGLE]
    assert evidence.existing_container_retained
    assert evidence.target_token_sha256 == "b" * 64
    assert evidence.package_root_identity == _identity(7)


@pytest.mark.parametrize(
    "observed",
    [
        _observation(target_token_sha256="e" * 64),
        _observation(package_root_identity=_identity(8)),
    ],
)
def test_adapter_rejects_wrong_target_without_exposing_details(observed):
    adapter = NativeWindowsExistingRollbackRuntimeAvailability(
        MapProvider.GOOGLE,
        capture=lambda provider: observed,
    )
    package_root = _package_root()
    try:
        with pytest.raises(NativeRollbackRuntimeAvailabilityError) as captured:
            package_root.run_while_held(
                lambda: adapter.establish_rollback_runtime_while_package_root_held(
                    package_root,
                    _stream(),
                    _authority(),
                )
            )
    finally:
        package_root.close()

    assert (
        captured.value.code
        is NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH
    )
    assert "C:\\" not in str(captured.value)


def test_adapter_rejects_wrong_package_root_before_capture():
    calls = 0

    def capture(provider: MapProvider) -> ExistingRollbackRuntimeObservation:
        nonlocal calls
        calls += 1
        return _observation()

    adapter = NativeWindowsExistingRollbackRuntimeAvailability(
        MapProvider.GOOGLE,
        capture=capture,
    )
    wrong_stream = replace(_stream(), package_root_identity=_identity(9))
    package_root = _package_root()
    try:
        with pytest.raises(NativeRollbackRuntimeAvailabilityError) as captured:
            package_root.run_while_held(
                lambda: adapter.establish_rollback_runtime_while_package_root_held(
                    package_root,
                    wrong_stream,
                    _authority(),
                )
            )
    finally:
        package_root.close()

    assert calls == 0
    assert (
        captured.value.code
        is NativeRollbackRuntimeAvailabilityErrorCode.TARGET_MISMATCH
    )


def test_adapter_sanitizes_capture_failure():
    def fail(provider: MapProvider) -> ExistingRollbackRuntimeObservation:
        raise OSError("private endpoint and container detail")

    adapter = NativeWindowsExistingRollbackRuntimeAvailability(
        MapProvider.GOOGLE,
        capture=fail,
    )
    package_root = _package_root()
    try:
        with pytest.raises(NativeRollbackRuntimeAvailabilityError) as captured:
            package_root.run_while_held(
                lambda: adapter.establish_rollback_runtime_while_package_root_held(
                    package_root,
                    _stream(),
                    _authority(),
                )
            )
    finally:
        package_root.close()

    assert (
        captured.value.code
        is NativeRollbackRuntimeAvailabilityErrorCode.CAPTURE_UNAVAILABLE
    )
    assert "private" not in str(captured.value)
