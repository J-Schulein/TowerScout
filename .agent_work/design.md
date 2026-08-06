# TowerScout Current Technical Design

**Last Updated**: August 5, 2026
**Scope**: Fix-first candidate development, four-profile runtime qualification,
and cdcai handoff through October 2026
**Archived Pre-Rebaseline Design**:
[`2026-07-23-pre-rebaseline-design.md`](./context/archive/2026-07/2026-07-23-pre-rebaseline-design.md)

## Current Architecture

TowerScout is a Flask web application packaged as an OCI-compatible local
application for Windows 11 AMD64. The normal user path is a GitHub Release
control package plus a digest-pinned GHCR image and a shared checksummed Model &
Data Package.

The application includes:

- Flask routes, filesystem-backed sessions, setup/settings, provider
  validation, detection, progress/cancel, export, restore, and readiness.
- Google Maps and Azure Maps frontend/backend provider paths.
- YOLOv5 primary detection plus EfficientNet secondary classification.
- Named volumes for configuration, model/data assets, logs, sessions, uploads,
  cache, and working data.
- Windows launch/setup/status/log/stop/import/TLS support scripts.
- Docker- and Podman-compatible Compose execution.

## Release And Repository Topology

### During Candidate Development

- `J-Schulein/TowerScout` hosts the immutable `v0.1.2` pilot.
- The same fork is the development and validation surface for
  `v0.1.3-rc.N` candidates.
- `cdcai/TowerScout` remains unchanged.

### At Final Adoption

- The cdcai owner and project lead select the official tag and display title.
- The official image, package, manifests, checksums, and documentation are
  built consistently for that identity.
- The official release is published from cdcai only after qualification and
  explicit adoption approval.
- The fork remains available as pilot and provenance history.

## Runtime Profiles

The final supported matrix contains four profiles:

| Engine | Compute | Required qualification |
| --- | --- | --- |
| Docker | CPU | Normal CPU package setup, readiness, provider, detection, persistence, and stop |
| Docker | GPU | CUDA package plus selected-engine NVIDIA validation and CUDA readiness |
| Podman | CPU | Running Podman machine plus approved non-Docker-Desktop Compose provider |
| Podman | GPU | Podman WSL2 machine, NVIDIA host support, CDI, approved Compose provider, and CUDA readiness |

The profiles are equally supported once their documented prerequisites are met.
This final-candidate target does not retroactively change the narrower support
wording of the frozen `v0.1.2` pilot.

## Provider TLS Design Boundary

ADR-018 provisionally replaces the earlier browser-to-loopback-helper
implementation direction with a time-boxed, reversible Windows launcher proof.
The older helper design and evidence remain preserved in the Task-087 record,
but they do not authorize helper activation during this checkpoint.

The candidate flow is:

1. Setup/Settings classifies a repairable Google or Azure certificate trust
   failure.
2. The browser directs the user to a visible TowerScout launcher; it does not
   issue a host operation.
3. The package-local launcher identifies the exact package, engine, runtime
   profile, and target, then presents a fixed operation and confirmation.
4. The first proof is non-mutating status and TLS repair preview. It uses no
   listener, dormant helper import, hidden worker, execution-policy bypass,
   arbitrary command input, administrator-only setup, or Windows trust-store
   mutation.
5. If the non-mutating proof passes, Task-096 Stop is the preferred first
   controlled mutation. TLS repair follows only with candidate staging,
   verification, backup, recovery, and named-volume preservation.
6. Signing-path work proceeds in parallel. The production-shaped signed
   artifact must pass representative managed-endpoint validation before
   candidate inclusion.
7. The command-based Task-086 repair remains available throughout the proof
   and becomes the supported disposition if the launcher fails.

All existing browser/helper activation gates remain off, and PR #64 is on hold
until the August 14 proceed/conditional/stop decision.

Podman-machine image-pull/build TLS is outside this application-provider flow
and belongs to Task-097.

## Exit/Stop Design Boundary

If the Task-087 launcher proof passes, Task-096 will use the launcher as its
first controlled mutation without exposing Docker or Podman sockets to the
application container. If the proof fails, Task-096 must be re-planned around
the current user-run stop path or another separately approved mechanism.

Expected sequence:

1. User selects Exit/Stop TowerScout in the visible launcher.
2. The launcher explains that TowerScout will stop while saved data remains.
3. User confirms.
4. The launcher validates the exact package and captured runtime profile.
5. The package-local stop path runs for Docker or Podman.
6. The container is removed without deleting named volumes.
7. The launcher shows a final status or manual fallback when it cannot
   complete.

Exact endpoint and lifecycle details remain Task-096 design work.

## Podman Qualification Boundary

Task-097 owns:

- CPU and GPU/CDI qualification.
- Docker-Desktop-free Compose-provider selection and installer fallback.
- Setup, launch, stop, status, logs, asset import, persistence, provider TLS,
  and Exit/Stop checks.
- Managed-network image-pull and source-build TLS investigation.
- A pass/fix/documented-limitation decision before final freeze.

Task-097 must not silently expand the product UI to install Compose providers
or modify Podman-machine trust.

## Dependency Security Boundary

Task-090 and Task-098 completed the 62-alert Trivy baseline classification,
approved remediation, and affected-runtime qualification. PR #51 merged as
`e499b50`.

The current security boundary is:

1. Loopback publication and content-sniffed custom-image validation protect
   the normal local runtime.
2. Release-model hashes are enforced by default; model upload remains disabled
   by default and requires both an administrator key and approved SHA-256 hash
   when enabled.
3. The selected `torch==2.6.0` / `torchvision==0.21.0` pair is qualified for
   the Task-098 CPU/CUDA boundary.
4. Eight medium/low torch advisories remain visible and non-reachable on
   supported paths. A future upgrade must move torch and torchvision together
   and repeat CPU/CUDA, model-load, output-parity, and performance validation.
5. All-severity SARIF reporting remains advisory, while new or reintroduced
   critical/high dependency findings are blocking unless covered by a narrow,
   unexpired exception.

## Task Dependency Flow

```text
TASK-095 Phase A rebaseline
        |
        v
TASK-090 bounded security investigation [COMPLETE]
        |
        v
TASK-098 dependency-security remediation/disposition gate [COMPLETE]
        |
        v
TASK-087 launcher feasibility / universal provider TLS repair [IN PROGRESS]
        |
        v
TASK-096 user Exit/Stop
        |
        v
TASK-097 Podman CPU/GPU qualification
        |
        +--> TASK-058 only if schedule and risk gates pass
        |          |
        |          +--> TASK-059 only if remaining margin is safe
        |
        v
TASK-091/092/093 qualification, docs, and recovery
        |
        +--> TASK-094 only if pilot/support evidence justifies it
        |
        v
Final candidate freeze -> owner qualification -> TASK-089 adoption/handoff
```

Task-095 Phase B spans the remaining work to keep governance, backlog, and
handoff material current. Task-098 is separately scoped from Task-090 so the
investigation cannot hide dependency upgrades, CPU/CUDA compatibility work, or
four-profile regression effort.

## Validation Strategy

Automated validation covers unit, route, frontend contract, packaging, and
security checks where practical. Manual evidence remains required for:

- Windows package behavior
- Docker and Podman runtime behavior
- CPU/GPU execution
- managed-network provider TLS
- live-provider browser behavior
- asset-backed package smoke
- owner-operated release and recovery rehearsal

No runtime-dependent validation should begin until the user has been told which
runtime is needed and has confirmed Docker Desktop and/or Podman is running.

## Safety Boundaries

- Do not mount Docker or Podman control sockets into the application container.
- Do not accept browser-supplied command text or executable paths.
- Do not record provider keys, helper tokens, local certificate details, raw
  browser traces, private AOIs, or unsanitized logs in repository evidence.
- Do not delete named volumes during normal stop, upgrade, or container
  replacement.
- Do not mutate `v0.1.2` or publish `v0.1.3` final prematurely.
- Do not change cdcai before explicit owner authorization.
