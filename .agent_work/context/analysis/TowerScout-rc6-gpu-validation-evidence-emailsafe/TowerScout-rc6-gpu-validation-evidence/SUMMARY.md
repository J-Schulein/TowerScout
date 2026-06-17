# TowerScout GPU Validation Results Summary

**Release:** Unofficial GPU Validation Build - `v0.1.0-rc6` candidate
(`gpu-validation-2026-06-16`)  
**Date:** 2026-06-16/2026-06-17  
**Result:** PASS. Docker GPU and Podman GPU CDI both reached `ready` with
`selected_device=cuda`; Google and Azure provider detection ran end to end on
the CUDA runtime.

> Redaction boundary: the local folder is internal/email-safe evidence, not a
> public-ready packet. Raw detection artifacts and the harness retain the
> fixed test AOI and local validation context, so they are intentionally ignored
> by git in this public repository. Use `PUBLIC-SUMMARY.md` for any public or
> external attachment.

## Release Identity

Standalone artifact provenance is recorded in `ARTIFACT-PROVENANCE.md`.

- Source ref: `12daa5536f580f76d063559e86b9a474451bc54b`.
- GPU-validation prerelease tag: `gpu-validation-2026-06-16`.
- Release candidate name: `v0.1.0-rc6`.
- CUDA control package SHA-256:
  `79800f2ca0af4b274e07878c8ba69cdcc1ba1822618c9a5661bfab004980c603`.
- CPU control package SHA-256:
  `fc32112935d4b7d32e9a9d24272648692e6362cecbd99fd3f3b748ec9757f83d`.
- Shared Model & Data Package ZIP SHA-256:
  `00599cc4fe9f2bdb4708c669d7c3d9a8a570a0c3b547bc5c317026196c7bacbb`.
- CUDA image digest:
  `sha256:392b162b2ebe5f94126e8d7db9b75c4fbcc1652449f8376d0a7a5a5979eec3b0`.
- CPU image digest:
  `sha256:d2b4f668e62ecbcdc0e0b5a5db4d8fbf2865651f5854484ada5db042956a75bd`.

Running GPU containers reported `version.app v0.1.0-rc6` and
`version.image_digest` equal to the pinned CUDA digest.

## Environment

- Windows 11 Pro 22631; NVIDIA T1000 8GB, driver 582.08.
- Docker Desktop 29.4.2 with WSL2 GPU passthrough.
- Podman 5.8.2 with NVIDIA CDI (`nvidia-ctk` 1.19.1,
  `/etc/cdi/nvidia.yaml`, device `nvidia.com/gpu`).
- Package-local Podman Compose provider: `podman-compose` 1.5.0 with
  `PODMAN_COMPOSE_PROVIDER` set.
- Standalone GPU smoke tests passed in Docker (`--gpus all`) and Podman
  (`--device nvidia.com/gpu=all`); both saw the T1000 through `nvidia-smi`.

## Gate Results

| Run | Engine | Provider | state | device_policy | selected_device | pytorch_flavor | image_digest |
|---|---|---|---|---|---|---|---|
| 1a | Docker GPU | Google | ready | cuda | cuda | cuda121 | `392b162b...` |
| 2 | Podman GPU CDI | Google | ready | cuda | cuda | cuda121 | `392b162b...` |
| 1b | Docker GPU | Azure | ready | cuda | cuda | cuda121 | `392b162b...` |
| 2b | Podman GPU CDI | Azure | ready | cuda | cuda | cuda121 | `392b162b...` |
| 3 | Docker CPU package | N/A | refused `-Gpu on`, exit 1 | N/A | N/A | cpu | N/A |

All four GPU runs reported `components.assets.status=ok`,
`torch_cuda_available=true`, `cuda_device_name="NVIDIA T1000 8GB"`, and
`torch_version=2.2.1+cu121`.

## End-To-End Detection

Detection ran on CUDA in every included GPU detection result:
`runtime_metadata.model_device=cuda`, YOLOv5 primary inference on CUDA, and
EfficientNet secondary classification on CUDA. Each run used 10 fetched map
tiles with the newest detection engine.

| Run | Engine | Provider | Included detection evidence | Notes |
|---|---|---|---|---|
| 1a | Docker GPU | Google | 49 selected high mode; repeated Docker log includes 26 selected low mode | Model time about 1.88-2.65 s. |
| 2 | Podman GPU CDI | Google | 49 selected representative high-mode run | Included Podman/Google log contains one row; do not claim low-mode repetition unless the missing run is added. |
| 1b | Docker GPU | Azure | 50 selected high mode; 22 selected low mode | Repeated Docker/Azure log includes both modes. |
| 2b | Podman GPU CDI | Azure | 50 selected high mode; 22 selected low mode | Repeated Podman/Azure log includes both modes. |

For Azure, Docker GPU and Podman GPU CDI produced the same selected-count
distribution. For Google, the included Podman artifact confirms the same
high-mode output as Docker; the Docker log separately captures the low-mode
distribution.

## Detection Reproducibility And Cache

Per-run counts are bimodal because the map provider intermittently returns
slightly different imagery for the same tile request. The included performance
logs show `map_api_calls=10` on every detection row. `CACHE-investigation.md`
records the cache analysis: map tile cache stayed empty on disk, a full cache
wipe reproduced the bimodal output, geocoding cache changed only geocoding
call counts, and model output was deterministic within each imagery mode.

## Notes

- The Podman compose-provider installer initially failed under a PowerShell 7
  harness because `Get-FileHash` was unavailable from that child environment.
  The documented Windows PowerShell path worked after the child process used a
  clean Windows PowerShell module path.
- Each engine/provider run used its own freshly extracted package folder,
  distinct Compose project, and distinct named volumes, preventing provider or
  cache bleed between runs.
- Status captures have `verify_hashes=false` because routine runtime hash
  verification is disabled for performance. Package/import hash verification
  and artifact checksums are recorded in the final package gate and repeated in
  `ARTIFACT-PROVENANCE.md`; the runtime evidence proves assets were present and
  usable during GPU detection.

## Artifacts In This Folder

- `ARTIFACT-PROVENANCE.md`: standalone source, checksum, digest, and evidence
  index for the packet.
- `PUBLIC-SUMMARY.md`: public-safe summary with AOI/local context omitted.
- `.gitignore`: keeps raw local evidence artifacts out of the public
  repository while allowing the public-safe summaries above to be committed.
- `*-GATE-status.txt`, `*-READY-status.txt`: readiness JSON per run.
- `*-DETECTION.json`: representative detection result and full performance
  metrics.
- `perf-logs/<run>/performance.jsonl`: raw per-detection metrics captured by
  the runtime.
- `3-cpu-guardrail.txt`: CPU-package `-Gpu on` refusal.
- `BONUS-docker-gpu-BOTH-providers-ready.txt`: both providers ready in a
  pre-strict Docker GPU run.
- `CACHE-investigation.md`: cache versus detection-output analysis.
- `tools/detect_harness_source.txt`: reusable detection harness source.
