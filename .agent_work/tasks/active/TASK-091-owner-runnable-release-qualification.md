# TASK-091: Owner-Runnable Release Qualification

**Status**: IN_PROGRESS - W01 CPU image built; package and inference pending
**Priority**: CRITICAL
**Type**: C (Release Qualification / Handoff)
**Owner**: Release owner; active agent executes bounded preparation and checks

## Objective

Produce a downloadable, owner-reproducible Windows 11 release qualification
record bound to exact source, CPU/CUDA images, control/asset ZIPs, fixtures,
and tools.

## Requirements

- WHEN a package is qualified, THE PROJECT SHALL prove actual YOLO and
  EfficientNet execution on the required device rather than infer it from
  readiness labels or mocked tests.
- WHEN the full release is claimed, THE PROJECT SHALL reproduce Docker CPU,
  Docker NVIDIA, Podman CPU, and Podman NVIDIA on independent suitable Windows
  computers.
- IF a required artifact, machine, account, policy decision, or test is
  unavailable, THEN THE PROJECT SHALL record the cell as blocked or not run.

## Current Work Packages

- W01: artifact/prerequisite inventory and early real-package installation.
- W05: truthful external combined-model qualification.
- W09: immutable candidate/package inventory and Windows checks.
- W10: four-profile independent reproduction and handoff.

## Acceptance Boundary

- Ordinary-account extraction includes a path with spaces.
- Setup imports the verified asset ZIP and uses pinned image digests.
- Google and Azure detection, review/export, cancellation/error recovery,
  next-request success, stop/relaunch, and reboot persistence are observed.
- CPU fallback does not pass a required-CUDA run.
- Evidence contains sanitized summaries and private raw-evidence references.

## Implementation Log

### 2026-09-22 - Activation

Selected from the existing backlog under ADR-021. The accepted source is
`9276084d91807906c53e00060670692b27e38483`. Baseline artifact, runtime,
asset, fixture, account, signing/policy, and independent-host availability are
being inventoried before any readiness claim.

### 2026-09-22 - W01 First-Host Baseline Attempt

**Host**: `win-7035fbbeab98`; Windows 11 Enterprise build 26200; 31.5 GiB RAM;
266.4 GiB free; Windows PowerShell 5.1; NVIDIA RTX PRO 500 Blackwell Laptop GPU
(driver 596.71, 6113 MiB). Docker Desktop 29.7.2 and Podman 6.0.2 were running.

**Artifacts/prerequisites**:

- Accepted source: `9276084d91807906c53e00060670692b27e38483`.
- No accepted-main CPU/CUDA candidate image or control ZIP existed locally.
- Historical asset ZIP was present for internal reuse review:
  `towerscout-v0.1.2-assets-towerscout-v1-assets-2026-05-05.zip`, 800655295
  bytes, SHA-256
  `00599cc4fe9f2bdb4708c669d7c3d9a8a570a0c3b547bc5c317026196c7bacbb`;
  its sidecar matched.
- No July qualification fixture directories were found at the assessed local
  paths. Fixture provenance/permission and positive EN coverage remain blocked.
- Podman's active Compose path delegated to Docker Desktop Compose v5.3.1;
  no standalone approved `podman-compose` command was found. Podman acceptance
  is blocked until an approved provider/target is installed and selected.
- Effective execution policy was `Restricted`; package PowerShell scripts were
  unsigned and CMD wrappers use process-level bypass. This host can support a
  permissive diagnostic run but cannot establish managed-endpoint policy or
  signing compatibility.
- Independent CPU/GPU hosts and approved Google/Azure accounts were not
  confirmed in this session.

**Attempt**: Started a real CPU image build tagged
`towerscout:main-9276084-cpu` with torch 2.6.0 / torchvision 0.21.0 and exact
source/release labels. Frontend install/build passed (27 packages, zero audit
findings, 30-module bundle). The Debian/GDAL layer then required 236 packages
(181 MB) and sustained very slow downloads; the bounded attempt was stopped
after roughly four minutes before image creation. No container, volume, ZIP,
or package install was created, and no inference was run.

**Forecast**: `at_risk`. Next action is to retry the cached CPU build on an
approved faster network or obtain an existing accepted-main CPU image, then
create a local-validation real ZIP and immediately run ordinary-account setup
from a spaced path with the verified asset ZIP. A digest-pinned published image
and clean-source ZIP are still required for release evidence.

### 2026-09-22 - W01 CPU Build Retry

Retried the same accepted-main CPU build after a short Docker network probe.
The Debian/GDAL layer resolved and installed successfully, but its 236 packages
and 181 MB download took 22 minutes 49 seconds at an average 132 kB/s. Several
individual requests paused for tens of seconds before apt recovered. In
contrast, pip downloaded the 178.7 MB CPU-only PyTorch wheel at about 15 MB/s,
and the complete Python dependency layer finished in 70 seconds. The observed
problem is therefore an oversized uncached Debian dependency layer amplified by
intermittent Docker proxy/mirror request latency, not a demonstrated CPU,
PyTorch-version, memory, disk, or dependency-resolution failure.

The build completed with exit 0 and created
`towerscout:main-9276084-cpu`, image ID/digest
`sha256:522541a6902381e16559e111cc3cab898bf109f99f97ea73a703239941301687`,
size 855191426 bytes. Labels report source
`9276084d91807906c53e00060670692b27e38483`, version
`main-baseline-20260922`, and flavor `cpu`. A no-data import/device smoke passed
for torch, torchvision, Fiona, GeoPandas, and OpenCV; torch reported
`2.6.0+cpu`, no CUDA build, and `cuda_available=False` as expected.

**Forecast remains**: `at_risk`. This proves image construction and basic CPU
runtime imports only. It does not prove control-ZIP installation, asset import,
application readiness, provider operation, model loading, or real YOLO and
EfficientNet inference. Next action is ordinary-account package installation
from a path containing spaces with the verified asset ZIP, followed by real CPU
inference. A bounded image-size/build-time experiment may remove or isolate
`libgdal-dev` only if geospatial runtime tests prove the wheel-based stack is
sufficient.
