from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

LAUNCHER_ROOT = Path(__file__).resolve().parents[2] / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.exact_target_confirmation as confirmation  # noqa: E402
from towerscout_launcher.exact_target_confirmation import (  # noqa: E402
    CONFIRMATION_TEXT,
    ExactTargetConfirmationCoordinator,
    ExactTargetConfirmationError,
    ExactTargetConfirmationErrorCode,
    ExactTargetConfirmationState,
    TargetRevalidationStage,
)
from towerscout_launcher.target_contracts import (  # noqa: E402
    EffectiveProfile,
    EndpointKind,
    GpuMode,
    MapProvider,
    PublicRepairSummary,
    RuntimeProduct,
)


def _summary() -> PublicRepairSummary:
    return PublicRepairSummary(
        target_token="TSRT1-" + "a" * 32,
        runtime_product=RuntimeProduct.DOCKER,
        runtime_version="29.7.2",
        endpoint_kind=EndpointKind.DOCKER_NAMED_PIPE,
        compose_project="towerscout",
        service="towerscout",
        container_token="b" * 16,
        image_token="c" * 16,
        requested_gpu_mode=GpuMode.OFF,
        effective_profile=EffectiveProfile.CPU,
        provider=MapProvider.AZURE,
        port=5000,
        config_volume_label="towerscout_config",
        config_volume_token="d" * 16,
        compose_model_token="e" * 16,
    )


class _Owner:
    def __init__(self) -> None:
        self.closed = False
        self.assert_calls = 0
        self.close_calls = 0
        self.target = SimpleNamespace(to_public_summary=_summary)
        self.fail_assert = False

    def assert_unchanged(self) -> object:
        self.assert_calls += 1
        if self.fail_assert:
            raise RuntimeError("PRIVATE TARGET DETAIL")
        return object()

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


@pytest.fixture(autouse=True)
def _accept_fake_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(confirmation, "BoundResolvedRepairTarget", _Owner)


def test_confirmation_owns_exact_target_until_explicit_cancel() -> None:
    owner = _Owner()
    coordinator = ExactTargetConfirmationCoordinator(capture=lambda _provider: owner)

    transaction = coordinator.prepare(MapProvider.AZURE)

    assert transaction.summary == _summary()
    assert transaction.state is ExactTargetConfirmationState.AWAITING_CONFIRMATION
    assert transaction.stage is TargetRevalidationStage.BEFORE_CONFIRMATION
    assert owner.assert_calls == 1
    assert not owner.closed

    coordinator.cancel(transaction)

    assert transaction.closed
    assert owner.closed
    assert owner.close_calls == 1


def test_wrong_confirmation_closes_target_and_exposes_no_private_detail() -> None:
    owner = _Owner()
    transaction = ExactTargetConfirmationCoordinator(
        capture=lambda _provider: owner
    ).prepare(MapProvider.AZURE)

    with pytest.raises(ExactTargetConfirmationError) as raised:
        transaction.confirm("repair_tls_and_restart")

    assert raised.value.code is ExactTargetConfirmationErrorCode.CONFIRMATION_REQUIRED
    assert transaction.closed
    assert owner.closed
    assert "PRIVATE" not in str(raised.value)


def test_confirmation_timeout_closes_held_target() -> None:
    owner = _Owner()
    current = [100.0]
    transaction = ExactTargetConfirmationCoordinator(
        capture=lambda _provider: owner,
        timeout_seconds=2.0,
        clock=lambda: current[0],
    ).prepare(MapProvider.AZURE)
    current[0] = 102.0

    with pytest.raises(ExactTargetConfirmationError) as raised:
        transaction.confirm(CONFIRMATION_TEXT)

    assert raised.value.code is ExactTargetConfirmationErrorCode.CONFIRMATION_EXPIRED
    assert transaction.closed
    assert owner.closed


def test_confirm_and_ordered_stage_hooks_revalidate_same_owner() -> None:
    owner = _Owner()
    transaction = ExactTargetConfirmationCoordinator(
        capture=lambda _provider: owner
    ).prepare(MapProvider.AZURE)

    transaction.confirm(CONFIRMATION_TEXT)

    with pytest.raises(ExactTargetConfirmationError) as raised:
        transaction.revalidate(TargetRevalidationStage.TERMINAL)
    assert raised.value.code is ExactTargetConfirmationErrorCode.TARGET_CHANGED
    assert transaction.closed
    assert owner.closed

    with pytest.raises(ExactTargetConfirmationError):
        transaction.revalidate(TargetRevalidationStage.BEFORE_MUTATION)


def test_ordered_stage_hooks_revalidate_same_owner() -> None:
    owner = _Owner()
    transaction = ExactTargetConfirmationCoordinator(
        capture=lambda _provider: owner
    ).prepare(MapProvider.AZURE)
    transaction.confirm(CONFIRMATION_TEXT)

    transaction.revalidate(TargetRevalidationStage.BEFORE_MUTATION)
    transaction.revalidate(TargetRevalidationStage.BEFORE_RESTART)
    transaction.revalidate(TargetRevalidationStage.TERMINAL)

    assert transaction.state is ExactTargetConfirmationState.CONFIRMED
    assert transaction.stage is TargetRevalidationStage.TERMINAL
    assert owner.assert_calls == 5
    assert not owner.closed

    with pytest.raises(ExactTargetConfirmationError) as raised:
        transaction.revalidate(TargetRevalidationStage.BEFORE_MUTATION)
    assert raised.value.code is ExactTargetConfirmationErrorCode.TARGET_CHANGED
    assert transaction.closed
    assert owner.closed


def test_stage_drift_poisons_confirmation_owner() -> None:
    owner = _Owner()
    transaction = ExactTargetConfirmationCoordinator(
        capture=lambda _provider: owner
    ).prepare(MapProvider.AZURE)
    transaction.confirm(CONFIRMATION_TEXT)
    owner.fail_assert = True

    with pytest.raises(ExactTargetConfirmationError) as raised:
        transaction.revalidate(TargetRevalidationStage.BEFORE_MUTATION)

    assert raised.value.code is ExactTargetConfirmationErrorCode.TARGET_CHANGED
    assert transaction.closed
    assert owner.closed
    assert "PRIVATE" not in str(raised.value)


def test_execute_revalidates_pre_mutation_then_remains_disabled() -> None:
    owner = _Owner()
    coordinator = ExactTargetConfirmationCoordinator(capture=lambda _provider: owner)
    transaction = coordinator.prepare(MapProvider.AZURE)
    coordinator.confirm(transaction, CONFIRMATION_TEXT)

    with pytest.raises(ExactTargetConfirmationError) as raised:
        coordinator.execute(transaction)

    assert raised.value.code is ExactTargetConfirmationErrorCode.MUTATION_DISABLED
    assert coordinator.mutation_enabled is False
    assert transaction.closed
    assert owner.closed
    assert owner.assert_calls == 3


def test_capture_failure_is_sanitized() -> None:
    def fail(_provider: MapProvider) -> _Owner:
        raise RuntimeError("PRIVATE CAPTURE DETAIL")

    coordinator = ExactTargetConfirmationCoordinator(capture=fail)

    with pytest.raises(ExactTargetConfirmationError) as raised:
        coordinator.prepare(MapProvider.GOOGLE)

    assert raised.value.code is ExactTargetConfirmationErrorCode.TARGET_UNAVAILABLE
    assert "PRIVATE" not in str(raised.value)


def test_non_enum_provider_is_rejected_before_capture() -> None:
    called = False

    def capture(_provider: MapProvider) -> _Owner:
        nonlocal called
        called = True
        return _Owner()

    with pytest.raises(ExactTargetConfirmationError):
        ExactTargetConfirmationCoordinator(capture=capture).prepare("azure")  # type: ignore[arg-type]

    assert not called
