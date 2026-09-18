from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
UNIT_ROOT = Path(__file__).resolve().parent
for item in (LAUNCHER_ROOT, UNIT_ROOT):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from test_launcher_runtime_execution import _target  # noqa: E402
from test_launcher_windows_recovery_runtime_available_native import (  # noqa: E402
    _package_root_for_target,
)
from towerscout_launcher.runtime_target_observation import (  # noqa: E402
    ObservationOperation,
)
from towerscout_launcher.runtime_target_observation_backend import (  # noqa: E402
    TargetObservationProcessResult,
)
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_recovery_journal import (  # noqa: E402
    JournalStreamIdentity,
    RollbackRuntimeRestartedRecord,
    RollbackRuntimeRestartingRecord,
)
from towerscout_launcher.windows_recovery_runtime_available_native import (  # noqa: E402
    observe_rollback_runtime_target,
)
from towerscout_launcher.windows_recovery_runtime_restart_native import (  # noqa: E402
    NativeRollbackRuntimeRestartError,
    NativeRollbackRuntimeRestartErrorCode,
    NativeWindowsRollbackRuntimeRestart,
)


def _stream(target) -> JournalStreamIdentity:
    observed = observe_rollback_runtime_target(target)
    return JournalStreamIdentity(
        1,
        "a" * 32,
        observed.target_token_sha256,
        observed.package_root_identity,
    )


def _intent(target) -> RollbackRuntimeRestartingRecord:
    observed = observe_rollback_runtime_target(target)
    return RollbackRuntimeRestartingRecord(
        1,
        "b" * 64,
        observed.package_root_identity,
        observed.runtime_evidence_sha256,
        observed.container_evidence_sha256,
        observed.volume_evidence_sha256s,
    )


def _recreated_target(target):
    return replace(
        target,
        container=replace(
            target.container,
            container_id="f" * 64,
            private_inspect_sha256="e" * 64,
        ),
    )


def _restarted(original_target, restarted_target) -> RollbackRuntimeRestartedRecord:
    intent = _intent(original_target)
    observed = observe_rollback_runtime_target(
        restarted_target,
        _stream(original_target).target_token_sha256,
    )
    return RollbackRuntimeRestartedRecord(
        1,
        "c" * 64,
        intent.package_root_identity,
        observed.runtime_evidence_sha256,
        observed.container_evidence_sha256,
        observed.volume_evidence_sha256s,
    )


class _Owner:
    def __init__(
        self,
        target,
        *,
        exit_code: int = 0,
        close_error: bool = False,
        transition_error: BaseException | None = None,
    ) -> None:
        self.target = target
        self.exit_code = exit_code
        self.close_error = close_error
        self.transition_error = transition_error
        self.closed = False
        self.assertions = 0
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def assert_unchanged(self) -> object:
        self.assertions += 1
        return object()

    def execute_scoped_transition(
        self,
        operation: str,
        arguments: tuple[object, ...],
    ) -> TargetObservationProcessResult:
        self.calls.append((operation, arguments))
        result = TargetObservationProcessResult(
            ObservationOperation.COMPOSE_RESTART_PRIOR_PROFILE,
            "d" * 64,
            b"PRIVATE OUTPUT",
            hashlib.sha256(b"PRIVATE ERROR").hexdigest(),
            self.exit_code,
            self.target.runtime.product is RuntimeProduct.PODMAN,
            (
                "e" * 64
                if self.target.runtime.product is RuntimeProduct.PODMAN
                else None
            ),
        )
        self.close()
        if self.transition_error is not None:
            raise self.transition_error
        return result

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise OSError("PRIVATE CLOSE DETAIL")


class _Capture:
    def __init__(self, *values) -> None:
        self.values = list(values)

    def __call__(self, provider):
        if not self.values:
            raise OSError("PRIVATE CAPTURE EXHAUSTED")
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class _AbsentOwner:
    def __init__(self, present: _Owner) -> None:
        self.present = present
        self.closed = False
        self.assertions = 0

    def assert_unchanged(self) -> object:
        self.assertions += 1
        return object()

    def recreate_prior_profile(self) -> _Owner:
        self.closed = True
        return self.present

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
def test_native_restart_uses_one_fixed_exact_profile_command(
    product: RuntimeProduct,
) -> None:
    target = _target(product)[0]
    recreated = _recreated_target(target)
    owner = _Owner(target)
    restarted_owner = _Owner(recreated)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=_Capture(owner, restarted_owner),
    )
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.restart_rollback_runtime_while_package_root_held(
            package_root,
            _stream(target),
            _intent(target),
        )
    )

    observed = observe_rollback_runtime_target(
        recreated,
        _stream(target).target_token_sha256,
    )
    assert evidence.runtime_evidence_sha256 == observed.runtime_evidence_sha256
    assert evidence.container_evidence_sha256 == observed.container_evidence_sha256
    assert evidence.volume_evidence_sha256s == observed.volume_evidence_sha256s
    assert owner.calls == [("restart_prior_profile", ())]
    assert owner.assertions == 2
    assert owner.closed is True
    assert restarted_owner.closed is True
    package_root.close()


def test_native_restart_retry_verifies_without_restarting_again() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    recreated = _recreated_target(target)
    owner = _Owner(recreated)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=lambda provider: owner,
    )
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.verify_restarted_rollback_runtime_while_package_root_held(
            package_root,
            _stream(target),
            _restarted(target, recreated),
        )
    )

    assert (
        evidence.container_evidence_sha256
        == _restarted(target, recreated).container_evidence_sha256
    )
    assert owner.calls == []
    assert owner.assertions == 2
    assert owner.closed is True
    package_root.close()


def test_native_restart_blocks_stable_runtime_drift_before_command() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    owner = _Owner(target)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=lambda provider: owner,
    )
    package_root = _package_root_for_target(target)
    intent = replace(_intent(target), runtime_evidence_sha256="f" * 64)

    with pytest.raises(NativeRollbackRuntimeRestartError) as caught:
        package_root.run_while_held(
            lambda: adapter.restart_rollback_runtime_while_package_root_held(
                package_root,
                _stream(target),
                intent,
            )
        )

    assert caught.value.code is NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH
    assert owner.calls == []
    assert owner.closed is True
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    package_root.close()


def test_native_restart_reconciles_nonzero_only_from_exact_new_target() -> None:
    target = _target(RuntimeProduct.PODMAN)[0]
    recreated = _recreated_target(target)
    owner = _Owner(target, exit_code=17)
    restarted_owner = _Owner(recreated)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=_Capture(owner, restarted_owner),
    )
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.restart_rollback_runtime_while_package_root_held(
            package_root,
            _stream(target),
            _intent(target),
        )
    )

    assert (
        evidence.container_evidence_sha256
        == observe_rollback_runtime_target(
            recreated,
            _stream(target).target_token_sha256,
        ).container_evidence_sha256
    )
    assert owner.closed is True
    assert restarted_owner.closed is True
    package_root.close()


@pytest.mark.parametrize(
    "owner",
    [
        pytest.param(_Owner, id="transition-error"),
        pytest.param(None, id="close-error"),
    ],
)
def test_native_restart_reconciles_ambiguous_transition_only_from_exact_new_target(
    owner,
) -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    recreated = _recreated_target(target)
    prior_owner = (
        owner(target, transition_error=OSError("PRIVATE TRANSITION DETAIL"))
        if owner is not None
        else _Owner(target, close_error=True)
    )
    restarted_owner = _Owner(recreated)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=_Capture(prior_owner, restarted_owner),
    )
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.restart_rollback_runtime_while_package_root_held(
            package_root,
            _stream(target),
            _intent(target),
        )
    )

    assert (
        evidence.container_evidence_sha256
        == observe_rollback_runtime_target(
            recreated,
            _stream(target).target_token_sha256,
        ).container_evidence_sha256
    )
    assert prior_owner.closed is True
    assert restarted_owner.closed is True
    package_root.close()


def test_native_restart_rejects_transition_error_when_old_target_remains() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    owner = _Owner(
        target,
        transition_error=OSError("PRIVATE TRANSITION DETAIL"),
    )
    unchanged_owner = _Owner(target)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=_Capture(owner, unchanged_owner),
    )
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackRuntimeRestartError) as caught:
        package_root.run_while_held(
            lambda: adapter.restart_rollback_runtime_while_package_root_held(
                package_root,
                _stream(target),
                _intent(target),
            )
        )

    assert caught.value.code is NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert owner.closed is True
    assert unchanged_owner.closed is True
    package_root.close()


def test_native_restart_rejects_nonzero_without_exact_new_target() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    owner = _Owner(target, exit_code=17)
    unchanged_owner = _Owner(target)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=_Capture(owner, unchanged_owner),
    )
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackRuntimeRestartError) as caught:
        package_root.run_while_held(
            lambda: adapter.restart_rollback_runtime_while_package_root_held(
                package_root,
                _stream(target),
                _intent(target),
            )
        )

    assert caught.value.code is NativeRollbackRuntimeRestartErrorCode.TARGET_MISMATCH
    assert "PRIVATE" not in str(caught.value)
    assert owner.closed is True
    assert unchanged_owner.closed is True
    package_root.close()


def test_native_restart_recovers_exact_absence_without_second_force_recreate() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]
    recreated = _recreated_target(target)
    present = _Owner(recreated)
    absent = _AbsentOwner(present)
    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=_Capture(OSError("PRIVATE MISSING")),
        absent_capture=lambda certificate, authority: absent,
    )
    package_root = _package_root_for_target(target)

    evidence = package_root.run_while_held(
        lambda: adapter.restart_rollback_runtime_while_package_root_held(
            package_root,
            _stream(target),
            _intent(target),
        )
    )

    assert (
        evidence.container_evidence_sha256
        == observe_rollback_runtime_target(
            recreated,
            _stream(target).target_token_sha256,
        ).container_evidence_sha256
    )
    assert absent.assertions == 1
    assert absent.closed is True
    assert present.calls == []
    assert present.closed is True
    package_root.close()


def test_native_restart_capture_failure_is_sanitized() -> None:
    target = _target(RuntimeProduct.DOCKER)[0]

    def fail_capture(provider):
        raise OSError("PRIVATE CAPTURE DETAIL")

    adapter = NativeWindowsRollbackRuntimeRestart(
        target.certificate,
        present_capture=fail_capture,
        absent_capture=lambda certificate, authority: (_ for _ in ()).throw(
            OSError("PRIVATE ABSENT DETAIL")
        ),
    )
    package_root = _package_root_for_target(target)

    with pytest.raises(NativeRollbackRuntimeRestartError) as caught:
        package_root.run_while_held(
            lambda: adapter.restart_rollback_runtime_while_package_root_held(
                package_root,
                _stream(target),
                _intent(target),
            )
        )

    assert caught.value.code is (
        NativeRollbackRuntimeRestartErrorCode.CAPTURE_UNAVAILABLE
    )
    assert "PRIVATE" not in str(caught.value)
    assert "PRIVATE" not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    package_root.close()
