from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import URLError

import pytest

from ts_errors import ModelLoadError
from ts_yolov5 import YOLOV5_HUB_REF, YOLOV5_HUB_SPEC, YOLOv5_Detector


def test_yolov5_detector_uses_pinned_hub_spec():
    recovered_model = Mock()

    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5.torch.hub.load', return_value=recovered_model) as mock_load, \
         patch('ts_yolov5.torch.cuda.is_available', return_value=False), \
         patch('ts_yolov5.torch.get_num_threads', return_value=4):
        detector = YOLOv5_Detector('newest.pt')

    assert detector.model is recovered_model
    assert mock_load.call_count == 1
    assert mock_load.call_args.args == (YOLOV5_HUB_SPEC, 'custom')
    assert mock_load.call_args.kwargs['path'] == 'newest.pt'
    assert mock_load.call_args.kwargs['force_reload'] is False
    assert mock_load.call_args.kwargs['trust_repo'] is True


def test_yolov5_detector_refreshes_invalid_pinned_cache_and_retries():
    pinned_repo = Path(fr'C:\stale-hub\ultralytics_yolov5_{YOLOV5_HUB_REF}')
    recovered_model = Mock()

    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5._find_pinned_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [pinned_repo])), \
         patch('ts_yolov5._clear_pinned_yolov5_hub_repos') as mock_clear, \
         patch('ts_yolov5.torch.hub.load', side_effect=[
             ImportError('bad cached repo import'),
             recovered_model,
         ]) as mock_load, \
         patch('ts_yolov5.torch.cuda.is_available', return_value=False), \
         patch('ts_yolov5.torch.get_num_threads', return_value=4):
        detector = YOLOv5_Detector('newest.pt')

    assert detector.model is recovered_model
    assert mock_load.call_count == 2
    assert mock_load.call_args_list[1].kwargs['force_reload'] is True
    mock_clear.assert_called_once_with(Path(r'C:\stale-hub'), [pinned_repo])


def test_yolov5_detector_reports_refresh_failure_after_pinned_cache_cleanup():
    pinned_repo = Path(fr'C:\stale-hub\ultralytics_yolov5_{YOLOV5_HUB_REF}')

    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5._find_pinned_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [pinned_repo])), \
         patch('ts_yolov5._clear_pinned_yolov5_hub_repos') as mock_clear, \
         patch('ts_yolov5.torch.hub.load', side_effect=[
             ImportError('bad cached repo import'),
             RuntimeError('network unavailable'),
         ]), \
         patch('ts_yolov5.torch.cuda.is_available', return_value=False), \
         patch('ts_yolov5.torch.get_num_threads', return_value=4):
        with pytest.raises(ModelLoadError) as exc_info:
            YOLOv5_Detector('newest.pt')

    assert f"pinned YOLOv5 Torch Hub ref {YOLOV5_HUB_REF}" in str(exc_info.value)
    assert "network unavailable" in str(exc_info.value)
    mock_clear.assert_called_once_with(Path(r'C:\stale-hub'), [pinned_repo])


def test_yolov5_detector_clears_stale_legacy_pkg_resources_cache_and_retries():
    stale_repo = Path(r'C:\stale-hub\ultralytics_yolov5_master')
    recovered_model = Mock()

    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5._find_pinned_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [])), \
         patch('ts_yolov5._find_stale_legacy_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [stale_repo])), \
         patch('ts_yolov5._clear_stale_legacy_yolov5_hub_repos') as mock_clear, \
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
    mock_clear.assert_called_once_with(Path(r'C:\stale-hub'), [stale_repo])


def test_yolov5_detector_reports_clear_offline_error_when_no_pinned_cache_exists():
    with patch('ts_yolov5.os.path.exists', return_value=True), \
         patch('ts_yolov5._find_pinned_yolov5_hub_repos', return_value=(Path(r'C:\stale-hub'), [])), \
         patch('ts_yolov5.torch.hub.load', side_effect=URLError('offline')), \
         patch('ts_yolov5.torch.cuda.is_available', return_value=False), \
         patch('ts_yolov5.torch.get_num_threads', return_value=4):
        with pytest.raises(ModelLoadError) as exc_info:
            YOLOv5_Detector('newest.pt')

    assert f"pinned YOLOv5 Torch Hub ref {YOLOV5_HUB_REF}" in str(exc_info.value)
    assert 'GitHub/network access is required' in str(exc_info.value)
