"""Task-075 shared ML device policy tests."""

from unittest.mock import Mock

import pytest

import ts_device
import ts_runtime


def test_runtime_diagnostics_cpu_policy_forces_cpu(monkeypatch):
    monkeypatch.setenv("TOWERSCOUT_DEVICE", "cpu")
    monkeypatch.setattr(ts_device.torch.cuda, "is_available", Mock(return_value=True))
    monkeypatch.setattr(ts_device.torch.cuda, "get_device_name", Mock(return_value="NVIDIA Test GPU"))
    monkeypatch.setattr(ts_device.torch.version, "cuda", "12.1", raising=False)

    diagnostics = ts_device.build_runtime_diagnostics()

    assert diagnostics["requested_policy"] == "cpu"
    assert diagnostics["selected_device"] == "cpu"
    assert diagnostics["torch_cuda_available"] is True
    assert diagnostics["cuda_device_name"] == "NVIDIA Test GPU"
    assert diagnostics["status"] == "ok"


def test_select_model_device_auto_falls_back_after_cuda_transfer_failure(monkeypatch):
    monkeypatch.setenv("TOWERSCOUT_DEVICE", "auto")
    monkeypatch.setattr(ts_device.torch.cuda, "is_available", Mock(return_value=True))
    monkeypatch.setattr(ts_device.torch.cuda, "get_device_name", Mock(return_value="NVIDIA Test GPU"))

    move_to_cuda = Mock(side_effect=RuntimeError("cuda transfer failed"))
    move_to_cpu = Mock()

    selection = ts_device.select_model_device(
        "TestModel",
        move_to_cuda=move_to_cuda,
        move_to_cpu=move_to_cpu,
    )

    assert selection.requested_policy == "auto"
    assert selection.selected_device == "cpu"
    assert selection.fallback_reason == "cuda_setup_failed:RuntimeError"
    move_to_cuda.assert_called_once()
    move_to_cpu.assert_called_once()


def test_select_model_device_cuda_required_raises_when_unavailable(monkeypatch):
    monkeypatch.setenv("TOWERSCOUT_DEVICE", "cuda")
    monkeypatch.setattr(ts_device.torch.cuda, "is_available", Mock(return_value=False))

    with pytest.raises(ts_device.DevicePolicyError) as error:
        ts_device.select_model_device("TestModel")

    assert "requires CUDA" in str(error.value)


def test_readiness_payload_includes_ml_runtime_and_fails_when_cuda_required(monkeypatch):
    monkeypatch.setattr(ts_runtime, "_required_paths", lambda: {})
    monkeypatch.setattr(
        ts_runtime,
        "_config_status",
        lambda: {
            "status": "ok",
            "env_path": "test.env",
            "needs_setup": False,
            "secret_key_persisted": True,
            "providers": {
                "google": {"configured": True},
                "azure": {"configured": False},
                "default": "google",
            },
        },
    )
    monkeypatch.setattr(
        ts_runtime,
        "_asset_status",
        lambda: {
            "status": "ok",
            "manifest_version": "test-manifest",
            "assets": [],
            "missing": [],
            "corrupt": [],
            "optional_missing": [],
        },
    )
    monkeypatch.setattr(
        ts_runtime.ts_device,
        "build_runtime_diagnostics",
        lambda: {
            "status": "fatal",
            "requested_policy": "cuda",
            "configured_policy": "cuda",
            "selected_device": "unavailable",
            "torch_version": "2.2.1+cpu",
            "torch_cuda_build": None,
            "torch_cuda_available": False,
            "cuda_device_name": None,
            "fallback_reason": "cuda_required_but_unavailable",
            "cuda_probe_error": None,
        },
    )

    payload = ts_runtime.build_readiness_payload()

    assert payload["state"] == "fatal"
    assert payload["components"]["ml_runtime"]["requested_policy"] == "cuda"
    assert payload["runtime"]["device_policy"] == "cuda"
    assert payload["runtime"]["selected_device"] == "unavailable"
    assert "TOWERSCOUT_DEVICE=auto or cpu" in " ".join(payload["recovery"])
