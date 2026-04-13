import os
from importlib import metadata
from unittest.mock import Mock, patch

import pytest

from ts_errors import ModelLoadError
from ts_yolov5 import YOLOv5_Detector, _validate_runtime_dependencies
from ts_yolov5_local import (
    YOLOV5_AUTOINSTALL_ENV_VAR,
    YOLO_AUTOINSTALL_ENV_VAR,
    disable_yolo_autoinstall,
)


def test_yolov5_detector_uses_local_loader_not_torch_hub():
    recovered_model = Mock()

    with patch("ts_yolov5.os.path.exists", return_value=True), \
         patch("ts_yolov5._load_local_yolov5_model", return_value=recovered_model) as mock_local_load, \
         patch("ts_yolov5.torch.hub.load") as mock_hub_load, \
         patch("ts_yolov5.torch.cuda.is_available", return_value=False), \
         patch("ts_yolov5.torch.get_num_threads", return_value=4):
        detector = YOLOv5_Detector("newest.pt")

    assert detector.model is recovered_model
    mock_local_load.assert_called_once_with("newest.pt")
    mock_hub_load.assert_not_called()


def test_yolov5_detector_reports_missing_local_snapshot():
    error_message = "TowerScout local YOLOv5 source snapshot is missing."

    with patch("ts_yolov5.os.path.exists", return_value=True), \
         patch("ts_yolov5._load_local_yolov5_model", side_effect=RuntimeError(error_message)), \
         patch("ts_yolov5.torch.cuda.is_available", return_value=False), \
         patch("ts_yolov5.torch.get_num_threads", return_value=4):
        with pytest.raises(ModelLoadError) as exc_info:
            YOLOv5_Detector("newest.pt")

    assert error_message in str(exc_info.value)


def test_yolov5_detector_reports_dependency_mismatch_before_local_load():
    with patch("ts_yolov5.os.path.exists", return_value=True), \
         patch(
             "ts_yolov5._validate_runtime_dependencies",
             side_effect=RuntimeError(
                 "TowerScout runtime dependency check failed before YOLO initialization."
             ),
         ), \
         patch("ts_yolov5._load_local_yolov5_model") as mock_local_load, \
         patch("ts_yolov5.torch.cuda.is_available", return_value=False), \
         patch("ts_yolov5.torch.get_num_threads", return_value=4):
        with pytest.raises(ModelLoadError) as exc_info:
            YOLOv5_Detector("newest.pt")

    assert "runtime dependency check failed before YOLO initialization" in str(exc_info.value)
    mock_local_load.assert_not_called()


def test_validate_runtime_dependencies_reports_missing_required_local_loader_imports():
    def fake_version(dist_name):
        if dist_name == "seaborn":
            raise metadata.PackageNotFoundError

        versions = {
            "numpy": "1.26.4",
            "pillow": "10.3.0",
            "requests": "2.32.2",
            "packaging": "25.0",
            "pandas": "2.3.3",
            "opencv-python": "4.9.0.80",
            "tqdm": "4.67.1",
            "ultralytics": "8.3.249",
        }
        return versions[dist_name]

    with patch("ts_yolov5.metadata.version", side_effect=fake_version):
        with pytest.raises(RuntimeError) as exc_info:
            _validate_runtime_dependencies()

    message = str(exc_info.value)
    assert "seaborn is not installed" in message
    assert "local YOLOv5 runtime" in message
    assert "pip install -r webapp/requirements.txt" in message


def test_disable_yolo_autoinstall_sets_both_env_guards():
    with patch.dict(
        os.environ,
        {
            YOLO_AUTOINSTALL_ENV_VAR: "true",
            YOLOV5_AUTOINSTALL_ENV_VAR: "true",
        },
        clear=False,
    ):
        with disable_yolo_autoinstall():
            assert os.environ[YOLO_AUTOINSTALL_ENV_VAR] == "false"
            assert os.environ[YOLOV5_AUTOINSTALL_ENV_VAR] == "false"

        assert os.environ[YOLO_AUTOINSTALL_ENV_VAR] == "true"
        assert os.environ[YOLOV5_AUTOINSTALL_ENV_VAR] == "true"
