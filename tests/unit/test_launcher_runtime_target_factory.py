"""Adversarial tests for the native pre-confirmation exact-target facade."""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import launcher.towerscout_launcher.runtime_target_factory as target_factory
from launcher.towerscout_launcher.runtime_target_factory import (
    capture_native_windows_resolved_target,
)
from launcher.towerscout_launcher.runtime_target_inputs import (
    TargetInputError,
    TargetInputErrorCode,
)
from launcher.towerscout_launcher.runtime_target_resolution import (
    TargetResolutionError,
    TargetResolutionErrorCode,
)
from launcher.towerscout_launcher.target_contracts import MapProvider


class _Inputs:
    def __init__(self) -> None:
        self.closed = False
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


class _Resolved:
    def __init__(self, provider: MapProvider) -> None:
        self.closed = False
        self.close_calls = 0
        self.assert_calls = 0
        token = SimpleNamespace(display="TSRT1-" + "a" * 32)
        self.target = SimpleNamespace(provider=provider, target_token=token)
        self.evidence = SimpleNamespace(target_token=token.display)

    def assert_unchanged(self) -> Any:
        self.assert_calls += 1
        return self.evidence

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


def _install_success(
    monkeypatch: pytest.MonkeyPatch,
    provider: MapProvider = MapProvider.GOOGLE,
) -> tuple[_Inputs, _Resolved]:
    inputs = _Inputs()
    resolved = _Resolved(provider)

    def bridge(received: _Inputs) -> _Resolved:
        assert received is inputs
        received.close()
        return resolved

    monkeypatch.setattr(target_factory, "BoundResolvedRepairTarget", _Resolved)
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_target_resolution_plan_inputs",
        lambda selected: inputs,
    )
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_resolved_target_from_inputs",
        bridge,
    )
    return inputs, resolved


def test_connects_fixed_inputs_to_resolved_target_before_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, resolved = _install_success(monkeypatch)

    captured = capture_native_windows_resolved_target(MapProvider.GOOGLE)

    assert captured is resolved
    assert inputs.closed
    assert inputs.close_calls == 1
    assert resolved.assert_calls == 1
    assert not resolved.closed
    assert tuple(
        inspect.signature(capture_native_windows_resolved_target).parameters
    ) == ("provider",)


def test_rejects_non_enum_provider_before_input_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def inputs(_provider: MapProvider) -> _Inputs:
        nonlocal called
        called = True
        return _Inputs()

    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_target_resolution_plan_inputs",
        inputs,
    )

    with pytest.raises(TargetResolutionError) as raised:
        capture_native_windows_resolved_target("google")  # type: ignore[arg-type]

    assert raised.value.code is TargetResolutionErrorCode.AUTHORITY_MISMATCH
    assert not called


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            TargetInputErrorCode.INPUTS_INVALID,
            TargetResolutionErrorCode.AUTHORITY_MISMATCH,
        ),
        (TargetInputErrorCode.INPUTS_CHANGED, TargetResolutionErrorCode.TARGET_CHANGED),
        (
            TargetInputErrorCode.VERIFICATION_UNAVAILABLE,
            TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE,
        ),
    ),
)
def test_preserves_input_failure_category(
    monkeypatch: pytest.MonkeyPatch,
    source: TargetInputErrorCode,
    expected: TargetResolutionErrorCode,
) -> None:
    def fail(_provider: MapProvider) -> _Inputs:
        raise TargetInputError(source)

    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_target_resolution_plan_inputs",
        fail,
    )

    with pytest.raises(TargetResolutionError) as raised:
        capture_native_windows_resolved_target(MapProvider.AZURE)

    assert raised.value.code is expected
    assert raised.value.__cause__ is None


def test_preserves_bridge_failure_and_closes_untransferred_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _Inputs()
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_target_resolution_plan_inputs",
        lambda _provider: inputs,
    )
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_resolved_target_from_inputs",
        lambda _inputs: (_ for _ in ()).throw(
            TargetResolutionError(TargetResolutionErrorCode.TARGET_AMBIGUOUS)
        ),
    )

    with pytest.raises(TargetResolutionError) as raised:
        capture_native_windows_resolved_target(MapProvider.GOOGLE)

    assert raised.value.code is TargetResolutionErrorCode.TARGET_AMBIGUOUS
    assert inputs.closed


def test_rejects_provider_mismatch_and_closes_both_owners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, resolved = _install_success(monkeypatch, MapProvider.AZURE)

    with pytest.raises(TargetResolutionError) as raised:
        capture_native_windows_resolved_target(MapProvider.GOOGLE)

    assert raised.value.code is TargetResolutionErrorCode.AUTHORITY_MISMATCH
    assert inputs.closed
    assert resolved.closed


def test_post_handoff_drift_poisoning_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inputs, resolved = _install_success(monkeypatch)

    def changed() -> Any:
        resolved.closed = True
        raise TargetResolutionError(TargetResolutionErrorCode.TARGET_CHANGED)

    resolved.assert_unchanged = changed  # type: ignore[method-assign]

    with pytest.raises(TargetResolutionError) as raised:
        capture_native_windows_resolved_target(MapProvider.GOOGLE)

    assert raised.value.code is TargetResolutionErrorCode.TARGET_CHANGED
    assert resolved.closed


def test_cleanup_retries_ordinary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _Inputs()

    def flaky_close() -> None:
        inputs.close_calls += 1
        if inputs.close_calls == 1:
            raise RuntimeError("PRIVATE CLOSE DETAIL")
        inputs.closed = True

    inputs.close = flaky_close  # type: ignore[method-assign]
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_target_resolution_plan_inputs",
        lambda _provider: inputs,
    )
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_resolved_target_from_inputs",
        lambda _inputs: (_ for _ in ()).throw(RuntimeError("PRIVATE BRIDGE DETAIL")),
    )

    with pytest.raises(TargetResolutionError) as raised:
        capture_native_windows_resolved_target(MapProvider.GOOGLE)

    assert raised.value.code is TargetResolutionErrorCode.VERIFICATION_UNAVAILABLE
    assert inputs.closed
    assert inputs.close_calls == 2
    assert "PRIVATE" not in str(raised.value)


def test_cleanup_preserves_interruption_after_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _Inputs()

    def interrupted_close() -> None:
        inputs.close_calls += 1
        if inputs.close_calls == 1:
            raise KeyboardInterrupt
        inputs.closed = True

    inputs.close = interrupted_close  # type: ignore[method-assign]
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_target_resolution_plan_inputs",
        lambda _provider: inputs,
    )
    monkeypatch.setattr(
        target_factory,
        "capture_native_windows_resolved_target_from_inputs",
        lambda _inputs: (_ for _ in ()).throw(RuntimeError("PRIVATE BRIDGE DETAIL")),
    )

    with pytest.raises(KeyboardInterrupt):
        capture_native_windows_resolved_target(MapProvider.GOOGLE)

    assert inputs.closed
    assert inputs.close_calls == 2


def test_facade_remains_outside_confirmation_repair_and_discovery() -> None:
    root = Path(target_factory.__file__).resolve().parent
    source = Path(target_factory.__file__).read_text(encoding="utf-8")

    assert "os.environ" not in source
    assert "subprocess" not in source
    assert "from .app" not in source
    assert "from .repair" not in source
    assert "from .discovery" not in source
    for relative in ("app.py", "repair.py", "discovery.py"):
        consumer = (root / relative).read_text(encoding="utf-8")
        assert "runtime_target_factory" not in consumer
