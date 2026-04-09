from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ts_errors import ModelLoadError
from ts_yolov5 import YOLOv5_Detector


def test_yolov5_detector_clears_stale_hub_cache_and_retries():
    stale_repo = Path(r'C:\stale-hub\ultralytics_yolov5_master')
    recovered_model = Mock()

    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5._find_stale_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [stale_repo])), \
         patch('ts_yolov5._clear_stale_yolov5_hub_repos') as mock_clear, \
         patch('ts_yolov5.torch.hub.load', side_effect=[
             ModuleNotFoundError("No module named 'pkg_resources'"),
             recovered_model,
         ]) as mock_load, \
         patch('ts_yolov5.torch.cuda.is_available', return_value=False), \
         patch('ts_yolov5.torch.get_num_threads', return_value=4):
        detector = YOLOv5_Detector('newest.pt')

    assert detector.model is recovered_model
    assert mock_load.call_count == 2
    assert mock_load.call_args_list[1].kwargs['force_reload'] is True
    assert mock_load.call_args_list[1].kwargs['path'] == 'newest.pt'
    mock_clear.assert_called_once_with(Path(r'C:\stale-hub'), [stale_repo])


def test_yolov5_detector_reports_refresh_failure_after_stale_cache_cleanup():
    stale_repo = Path(r'C:\stale-hub\ultralytics_yolov5_master')

    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5._find_stale_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [stale_repo])), \
         patch('ts_yolov5._clear_stale_yolov5_hub_repos') as mock_clear, \
         patch('ts_yolov5.torch.hub.load', side_effect=[
             ModuleNotFoundError("No module named 'pkg_resources'"),
             RuntimeError('network unavailable'),
         ]), \
         patch('ts_yolov5.torch.cuda.is_available', return_value=False), \
         patch('ts_yolov5.torch.get_num_threads', return_value=4):
        with pytest.raises(ModelLoadError) as exc_info:
            YOLOv5_Detector('newest.pt')

    assert "required pkg_resources" in str(exc_info.value)
    assert "network unavailable" in str(exc_info.value)
    mock_clear.assert_called_once_with(Path(r'C:\stale-hub'), [stale_repo])
