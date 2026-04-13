# TowerScout YOLOv5 Local Runtime

This directory vendors the YOLOv5 runtime snapshot that TowerScout uses for
model initialization and inference.

Source provenance:
- Upstream repo: `ultralytics/yolov5`
- Validated commit: `1d62daa3c6b8ec15fdb319c0a2e341d8b56ec86c`

Vendored contents:
- `models/`
- `utils/`
- `data/`
- `LICENSE`

TowerScout-specific local patches:
- Removed upstream `pip install -U ultralytics` fallback from
  `models/common.py` and `utils/general.py`
- TowerScout loads this snapshot through `webapp/ts_yolov5_local.py` instead of
  `torch.hub`

This runtime is intentionally local to eliminate Torch Hub cache and GitHub
bootstrap dependence during YOLO model initialization.
