# Task-105 Candidate Notes — Qualification In Progress

The corrected Windows 11 CPU and CUDA 12.8 validation candidate is the
immutable, non-Latest `v0.1.3-rc5` prerelease from accepted `main`
`835cbb910573a931350c5b704d14496952d7ef87`. Its exact browser-downloaded
control and asset ZIPs passed first-host integrity checks. Docker CPU/CUDA and
Podman CPU/CUDA passed real model and provider workflows, lifecycle checks,
and reboot persistence on that host. The separate NVIDIA host must repeat all
four profiles before final-candidate qualification. RC9 remains historical
validation evidence; no stable release is implied.

| Published input | SHA-256 |
| --- | --- |
| CPU control ZIP | `dfcc653eef4d0c9666604d6455797c123b757d92d4507ad1d451032f5cdd7a8f` |
| CUDA 12.8 control ZIP | `c418e1948ed2719cd8c3678b612addccf468a139aafc97f99d3f4bd7676974d0` |
| Shared asset ZIP | `00599cc4fe9f2bdb4708c669d7c3d9a8a570a0c3b547bc5c317026196c7bacbb` |

The CPU image digest is
`sha256:833dbe0d0097ffcc9e52dcf39d64f25cf503c3c9ffc806f55c42b60e452845d5`;
the CUDA image digest is
`sha256:df0f30ac1bed4514d50c5b11eeac4ea64e38e6575bb209448fea4c53e5347890`.
The three `.sha256` sidecars and internal package checksums also passed.

## Tested GPU evidence

- NVIDIA RTX PRO 500 Blackwell Generation Laptop GPU (`sm_120`): the RC5
  first host passed Docker and rootless Podman CUDA 12.8 workflows with both
  YOLO and EfficientNet on CUDA and no CPU fallback.
- NVIDIA T1000 (`sm_75`): one independent Windows host passed the RC9 Docker
  and rootless Podman CUDA 12.8 profiles with both models on CUDA, subject to
  the Task-105 fresh-install and UI findings.

These are GPU models observed in the RC5 first-host and retained RC9 evidence,
not a blanket claim for every driver, Windows build, WSL version, or engine
version. The independent NVIDIA host must still repeat Docker CPU/CUDA and
Podman CPU/CUDA using the exact RC5 public bytes. CPU-only hardware and Podman
without Docker Desktop installed are outside the tested
claim. The CUDA package expects Volta or newer; an architecture present in a
wheel alone does not qualify an untested GPU. Maxwell and Pascal use the CPU
package.

## Tested support boundary

The tested Podman path uses a rootless WSL 2 machine, 64-bit Python 3.12,
TowerScout's package-local Compose provider, and NVIDIA CDI for GPU work.
A reviewer observed Python 3.13.6 and rootful Podman during onboarding, but
those alternatives are not claimed as tested support. The standard Windows
control package is unsigned and uses its supplied process-scoped wrappers;
signature-enforcing endpoints are outside the claim.

The control ZIP uses Windows path separators in ZIP entry names. It is a
Windows package and is not claimed as a portable Unix archive. This remains
an explicit packaging limitation for this candidate.

The accepted ADR-024 security residuals expire October 31, 2026. A corrected
build or publication after that date needs a new written disposition. No
`latest` promotion or stable/general release follows from these notes.
