# Task-098 Pre-Change Baseline

**Status**: PARTIAL - LOCAL PYTHON 3.12 COMPLETE; PYTHON 3.11 RUNTIME REQUIRED
**Baseline Date**: July 24, 2026
**Planning Checkpoint**: `d336686`
**Source Commit Before Task-098 Code Changes**: `350d56deec7c85545386e3120c1896d48ba20b39`
**Execution Branch**: `fix/task-098-dependency-security`

## Purpose

Record the reproducible functional, dependency, model/output, startup, and
performance state required by Task-098 before dependency pins, application
code, runtime behavior, release assets, alert state, or external repositories
are changed.

## Baseline Contract

- Use only sanitized, repository-owned fixtures and trusted checksummed assets.
- Record exact interpreter, dependency, model, and asset identities.
- Run maintained unit and affected integration checks on Python 3.11 and 3.12
  where those interpreters are locally available.
- Record skipped or unavailable evidence as an explicit external gate; do not
  infer a pass.
- Use three warmed same-host runs for startup, YOLO/EfficientNet inference,
  total local detection, and peak-memory comparisons where the trusted assets
  and runtime profile are available.
- Do not begin Slice A implementation until the available pre-change evidence
  is captured and any unavailable runtime evidence is bounded.

## Environment

- Host: Windows 11 `10.0.26100`, AMD64.
- Available interpreters: Python 3.12.5 and 3.13; Python 3.11 is not installed
  on the host.
- Baseline interpreter: Python 3.12.5, 64-bit.
- Node: 24.14.0; npm: 11.10.1. CI remains on Node 18.
- Clean environment:
  `tmp/task098-baseline/py312-clean` (ignored task scratch).
- ML policy: CPU forced with `TOWERSCOUT_DEVICE=cpu`; debug-image capture off.

## Dependency Resolution

- Reproduced Docker installation order: CPU PyTorch pair first, followed by
  `webapp/requirements.txt` and `requirements-dev.txt`.
- `pip check`: PASS; no broken requirements.
- Security-relevant direct resolution:
  - `aiohttp==3.9.3`
  - `fiona==1.9.6`
  - `Flask==3.0.2`
  - `geopandas==0.14.3`
  - `Pillow==12.2.0`
  - `python-dotenv==1.0.0`
  - `torch==2.2.1+cpu`
  - `torchvision==0.17.1+cpu`
  - `waitress==3.0.0`
- Other runtime pins resolved as declared, including `numpy==1.26.4`,
  `opencv-python==4.9.0.80`, `pandas==2.3.3`, `psutil==7.1.3`,
  `Requests==2.33.1`, and `ultralytics==8.3.249`.
- Python 3.11 clean resolution is pending because no local 3.11 interpreter is
  installed. It must run in the supported Docker CPU baseline or an equivalent
  clean 3.11 environment before Slice A changes.

## Maintained Functional Tests

- Clean Python 3.12 unit suite: PASS, 259 passed and 74 skipped in 117.52
  seconds. The skips are the repository-level Azure, framework, legacy image,
  and legacy validation markers that Task-098 may not count as touched-path
  coverage.
- Clean Python 3.12 broad integration suite: BASELINE DRIFT, 20 passed, 2
  skipped, and 4 failed.
  - Two failures use Flask session state outside a request context.
  - Two failures expect geocache clustering at the exact 100 m boundary.
  - These failures are outside the current Task-098 touched surfaces and are
    preserved as pre-change drift; they are not silently treated as passes.
- ML-focused maintained gate: PASS, 8 passed across the local YOLO loader and
  current end-to-end smoke.
- Setup Wizard validation contract: PASS.
- ProviderStateManager regression contract: PASS; forced Azure failure output
  is the expected negative-path assertion.
- Status-output contract: PASS.
- Blocking flake8 syntax/undefined-name gate: PASS, zero findings.

## Model, Output, And Performance Evidence

- Trusted asset hashes match `webapp/asset_manifest.v1.json`:
  - YOLO `newest.pt`:
    `27315E156D8370D51D9C2A3C047C4BF5CC0C8AE1521036BDF800B7A8A81554E6`
  - EfficientNet `b5_unweighted_best.pt`:
    `645113BADFCD17A1F9B451AABB54BF80E115A4FAACEB65E0CE3FC8DBFB108A5D`
  - All seven local ZCTA files match the manifest checksums.
- Deterministic fixture: generated 640x640 solid RGB `(127, 127, 127)` image.
- Three warmed CPU runs:
  - TowerScout lazy import: 9.661896, 10.214581, 10.417987 seconds; median
    10.214581 seconds.
  - YOLO inference: 2.361409, 2.432936, 2.505506 seconds; median 2.432936
    seconds; detection counts `[0, 0, 0]`.
  - EfficientNet inference: 0.946941, 1.016758, 1.165284 seconds; median
    1.016758 seconds; score `0.82664424` on all three runs.
- Model-load times: YOLO 9.569950 seconds; EfficientNet 0.936259 seconds.
- Process RSS after both model probes: 1,373,687,808 bytes.
- The maintained probe is
  [`baseline_probe.py`](./baseline_probe.py). This synthetic fixture is a
  deterministic compatibility sentinel, not a claim about real-world
  detection accuracy.

## External Runtime Gates

- Docker Desktop CPU is now required to provide the supported clean Python
  3.11 baseline before Slice A changes.
- Docker GPU, Podman CPU/GPU, physical-GPU model parity, and live-provider
  Google/Azure evidence are later slice/final-qualification gates and have not
  been requested yet.
- The active agent must name the exact required profiles and wait for user
  confirmation before each runtime-dependent stage.

## Baseline Disposition

The locally available Python 3.12 functional, dependency, model-output, and
performance baseline is complete. Task-098 remains at the baseline gate because
the required clean Python 3.11 evidence is unavailable on the host. No Slice A
application, dependency, Compose, runtime, release, alert-state, or external
repository change has been made.
