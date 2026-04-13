#
# TowerScout
# A tool for identifying cooling towers from satellite and aerial imagery
#

import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path

YOLOV5_SOURCE_REPO = "ultralytics/yolov5"
YOLOV5_SOURCE_REF = "1d62daa3c6b8ec15fdb319c0a2e341d8b56ec86c"
YOLOV5_LOCAL_SOURCE_DIR = Path(__file__).resolve().parent / "vendor" / "yolov5_local"
YOLO_AUTOINSTALL_ENV_VAR = "YOLO_AUTOINSTALL"
YOLOV5_AUTOINSTALL_ENV_VAR = "YOLOv5_AUTOINSTALL"
YOLO_AUTOINSTALL_ENV_VARS = (
    YOLO_AUTOINSTALL_ENV_VAR,
    YOLOV5_AUTOINSTALL_ENV_VAR,
)


def ensure_local_yolov5_source_available():
    """Fail fast if the vendored YOLO snapshot is missing from the workspace."""
    if YOLOV5_LOCAL_SOURCE_DIR.is_dir():
        return

    raise RuntimeError(
        "TowerScout local YOLOv5 source snapshot is missing. "
        f"Expected vendored runtime under {YOLOV5_LOCAL_SOURCE_DIR} "
        f"from {YOLOV5_SOURCE_REPO}@{YOLOV5_SOURCE_REF}."
    )


@contextmanager
def _prepend_local_yolov5_path():
    """Temporarily prepend the vendored YOLO snapshot so upstream imports resolve locally."""
    ensure_local_yolov5_source_available()

    local_root = str(YOLOV5_LOCAL_SOURCE_DIR)
    sys.path.insert(0, local_root)
    try:
        yield
    finally:
        try:
            sys.path.remove(local_root)
        except ValueError:
            pass


@contextmanager
def disable_yolo_autoinstall():
    """Prevent vendored YOLO code from attempting runtime package mutation."""
    previous_values = {
        env_var: os.environ.get(env_var)
        for env_var in YOLO_AUTOINSTALL_ENV_VARS
    }

    for env_var in YOLO_AUTOINSTALL_ENV_VARS:
        os.environ[env_var] = "false"

    try:
        yield
    finally:
        for env_var, previous_value in previous_values.items():
            if previous_value is None:
                os.environ.pop(env_var, None)
            else:
                os.environ[env_var] = previous_value


def load_local_yolov5_model(filename, autoshape=True, verbose=False, device=None):
    """Load TowerScout's vendored YOLOv5 runtime from local source."""
    with disable_yolo_autoinstall(), _prepend_local_yolov5_path():
        from models.common import AutoShape, DetectMultiBackend
        from models.experimental import attempt_load
        from models.yolo import ClassificationModel, SegmentationModel
        from utils.general import LOGGER
        from utils.torch_utils import select_device

        previous_level = LOGGER.level
        if not verbose:
            LOGGER.setLevel(logging.WARNING)

        path = Path(filename)
        try:
            resolved_device = select_device(device)
            try:
                model = DetectMultiBackend(path, device=resolved_device, fuse=autoshape)
                if autoshape:
                    if model.pt and isinstance(model.model, ClassificationModel):
                        LOGGER.warning(
                            "WARNING: YOLOv5 ClassificationModel is not AutoShape compatible. "
                            "Inference must pass BCHW torch tensors to this model."
                        )
                    elif model.pt and isinstance(model.model, SegmentationModel):
                        LOGGER.warning(
                            "WARNING: YOLOv5 SegmentationModel is not AutoShape compatible."
                        )
                    else:
                        model = AutoShape(model)
            except Exception:
                model = attempt_load(path, device=resolved_device, fuse=False)

            return model.to(resolved_device)
        finally:
            LOGGER.setLevel(previous_level)
