# TASK-083: RC5 Podman Independence, GPU CDI, And Release Validation

**Status**: IN_PROGRESS - implementation branch created from the `v0.1.0-rc4` `main` baseline; planning checkpoint in progress before code changes
**Priority**: CRITICAL
**Type**: C (Runtime Support / Podman GPU / Release Validation)
**Estimated Effort**: 3-6 days (24-48 hours), split across CPU-dev-able implementation, GPU-host validation, and package release validation
**Target Sprint**: Sprint 06 V1 RC1 / post-rc4 to rc5 readiness

## Objective

Implement the RC4 follow-up fixes and Podman independence work needed before the
next release-candidate package, then build and validate an `rc5` release artifact
from the resulting branch.

This task deliberately joins the related runtime/release work into one gate:
setup rerun resilience, Docker-Desktop-free Podman CPU, Podman GPU via NVIDIA CDI,
release manifest polish, fixed-fixture parity evidence, and next-package
validation. The goal is not just to make Podman GPU work once; the goal is to
ship a supportable release candidate whose Podman path does not rely on Docker
Desktop and whose GPU support claim is bounded by evidence.

## Background

RC4 passed its release validation matrix and did not expose a model or TF32
correctness issue. The remaining release-relevant findings are runtime and
supportability issues:

- `setup-towerscout.cmd` can fail on rerun when staged assets already exist and
  the asset ZIP is auto-discovered.
- RC4 Podman CPU validation proved independence from the Docker engine, but not
  independence from the Docker Desktop installation, because `podman compose`
  selected Docker Desktop's bundled `docker-compose.exe`.
- The Podman GPU reference packet proves a CDI-based implementation can reach
  `selected_device=cuda` on real NVIDIA T1000 hardware, but that implementation
  is not present in this checkout.
- Release parity evidence needs fixed replay fixtures and summaries so future
  RC comparisons can distinguish imagery/provider drift from runtime/model drift.
- Release manifest generation should carry package and asset checksum metadata
  cleanly.

Supporting analysis:

- `.agent_work/context/analysis/RC4-APPLICATION-FOLLOWUPS-2026-06-15.md`
- `.agent_work/context/analysis/PODMAN-GPU-IMPLEMENTATION-REVIEW-2026-06-15.md`
- `.agent_work/context/analysis/Podman-GPU-Implementation-Reference/`

## Requirements (EARS Notation)

**R-083-001**: WHEN setup is rerun with valid staged assets already present,
THE SYSTEM SHALL reuse the staged assets and continue importing them into the
selected engine instead of failing because an asset ZIP was auto-discovered.

**R-083-002**: IF staged assets are incomplete, corrupt, or incompatible with
the control manifest, THEN THE SYSTEM SHALL fail before launch/import with clear
guidance and SHALL NOT delete or overwrite user assets silently.

**R-083-003**: WHEN Podman CPU is selected for the supported package path,
THE SYSTEM SHALL use an approved Compose provider that does not require Docker
Desktop to be installed.

**R-083-004**: WHEN `PODMAN_COMPOSE_PROVIDER` is configured, THE SYSTEM SHALL
validate the provider path/version early and report the selected provider in
support-safe setup, launch, and status output.

**R-083-005**: WHERE Podman GPU support is included, THE SYSTEM SHALL require a
WSL2 Podman machine, a compatible Podman version, host NVIDIA visibility,
machine NVIDIA visibility, NVIDIA Toolkit/CDI registration, a container GPU
smoke, and TowerScout readiness `selected_device=cuda`.

**R-083-006**: WHEN Podman GPU prerequisites are missing and `-Gpu on` is
requested, THE SYSTEM SHALL fail closed with a rung-specific message and SHALL
not start a misleading CPU container.

**R-083-007**: WHEN Podman GPU prerequisites are missing and `-Gpu auto` is
requested, THE SYSTEM SHALL remain CPU-safe unless the explicit Podman GPU gate
is satisfied.

**R-083-008**: WHEN `enable-podman-gpu.ps1 -DryRun` is executed, THE SYSTEM
SHALL print the intended provisioning plan and SHALL make no machine changes.

**R-083-009**: WHEN `enable-podman-gpu.ps1 -VerifyOnly` is executed, THE SYSTEM
SHALL run only read-only checks and SHALL fail cleanly when CDI is missing.

**R-083-010**: WHEN Podman GPU provisioning runs, THE SYSTEM SHALL install or
verify NVIDIA Container Toolkit, generate or refresh a CDI spec, verify
`nvidia.com/gpu`, run a GPU container smoke, and record host/runtime versions.

**R-083-011**: WHEN launch/import would reuse an existing container with a
different engine, image, port, GPU mode, or selected ML device policy,
THE SYSTEM SHALL recreate or stop with guidance rather than silently reusing the
wrong runtime state.

**R-083-012**: WHEN release manifests are generated, THE SYSTEM SHALL include
release version/posture, source ref, image digest, application package checksum,
and model/data asset checksum in fields accepted by the manifest checker.

**R-083-013**: WHEN release parity evidence is captured, THE PROJECT SHALL
preserve a fixed fixture or support-safe equivalent plus a parity summary
covering counts, flips, deltas, image digest, model manifest hash, provider,
engine, and selected device.

**R-083-014**: WHEN the next release image/package is built, THE PACKAGE SHALL
pin the GHCR image by digest and SHALL include current docs, Compose overlays,
launch scripts, manifests, checksums, and support notices consistent with the
validated runtime support boundary.

**R-083-015**: WHEN `rc5` validation completes, THE PROJECT SHALL have evidence
for Docker CPU, Docker GPU, Podman CPU without Docker Desktop provider
selection, Podman GPU with CDI, setup rerun staged-asset reuse, asset import,
readiness, health, and fixed-fixture parity.

## Acceptance Criteria

- [ ] Valid staged asset reuse is implemented and covered by focused tests.
- [ ] Invalid staged assets still fail safely before import/launch.
- [ ] Podman CPU setup/import/start/status succeeds with an approved provider
      that is not Docker Desktop's bundled `docker-compose.exe`.
- [ ] Provider selection and version are visible in support-safe output.
- [ ] `compose.gpu.podman.yaml` is added and validated through `compose config`.
- [ ] `scripts/enable-podman-gpu.ps1` and a testable helper module are added.
- [ ] Podman GPU hard blocks in `TowerScoutCompose.ps1` are replaced with a
      gated CDI decision tree.
- [ ] `-Gpu on` remains fail-closed unless readiness reports
      `selected_device=cuda`.
- [ ] `-Gpu auto` remains CPU-safe unless the explicit Podman GPU gate is ready.
- [ ] Windows PowerShell 5.1 unit tests cover preflight rungs, provider
      resolution, image-reference splitting, provisioner scenarios, and stale
      CDI self-heal.
- [ ] Release manifest/package checksum metadata validates without known
      recommended-field warnings, or the checker is updated to accept the
      canonical schema fields.
- [ ] Fixed-fixture parity evidence is preserved for the next RC.
- [ ] The next image/package is generated only after implementation validation
      passes.
- [ ] The next release matrix passes or records bounded, owner-accepted caveats.
- [ ] Documentation support language does not claim Docker-Desktop-free Podman or
      Podman GPU beyond evidence.
- [ ] `.agent_work` validation passes after task and evidence updates.

## Dependencies

- `TASK-066`: release-candidate package validation gate.
- `TASK-074`: bootstrap/preflight and asset ZIP staging/import flow.
- `TASK-075`: GPU-capable package and readiness diagnostics.
- `TASK-080`: simplified setup path and UAT guide assumptions.
- `TASK-081`: runtime hardening, Podman CPU groundwork, stale-container guard,
  and fail-closed GPU behavior.
- `TASK-082`: stable package docs and app docs routing.
- RC4 analysis and Podman GPU reference packet listed in Background.
- A Windows 11 WSL2 Podman host with NVIDIA GPU for final Podman GPU validation.

## Implementation Plan

1. **Phase 0 - Scope Lock And Branch Prep**
   - Confirm whether this task starts from latest `main` after `TASK-082` lands
     or from a stacked branch.
   - Confirm the approved Compose provider strategy for Docker-Desktop-free
     Podman.
   - Decide whether provider binary vendoring is in scope or whether the first
     implementation uses documented support-installed provider placement.

2. **Phase 1 - RC4 Application Follow-ups**
   - Implement staged-asset reuse on setup rerun.
   - Fix release manifest checksum/recommended metadata generation.
   - Add or document fixed-fixture parity artifact handling.
   - Keep reviewer-audit hardening outside this phase unless release-critical.

3. **Phase 2 - Docker-Desktop-Free Podman CPU**
   - Implement or finish provider resolution and integrity/version reporting.
   - Validate setup/import/start/status without Docker Desktop provider
     selection.
   - Keep direct `podman cp` fallback behavior intact.

4. **Phase 3 - Podman GPU CDI Enablement**
   - Add Podman GPU overlay.
   - Add `enable-podman-gpu.ps1` and helper module.
   - Replace the current Podman GPU hard block with the gated preflight ladder.
   - Preserve fail-closed readiness assertion for `-Gpu on`.
   - Add focused Windows PowerShell tests.

5. **Phase 4 - Docs, Tests, And CI Hooks**
   - Update runtime/support docs to describe the gated Podman GPU path.
   - Add compose-overlay validation and provider-resolution tests.
   - Keep support language bounded until Phase 6 evidence is complete.

6. **Phase 5 - Build Next Release Candidate**
   - Publish or select the next GHCR image digest.
   - Generate the next application package and checksum sidecars.
   - Confirm manifest, `IMAGE.txt`, `SOURCE.txt`, docs, overlays, and scripts
     match the intended release state.

7. **Phase 6 - Release Matrix Validation**
   - Validate Docker CPU and Docker GPU.
   - Validate Podman CPU with approved non-Docker-Desktop provider.
   - Validate Podman GPU after CDI provisioning.
   - Validate setup rerun with staged assets.
   - Validate asset import and readiness/health on both engines.
   - Run fixed-fixture parity and record support-safe evidence.

8. **Phase 7 - Handoff**
   - Summarize final support claims and caveats.
   - Record release-blocking findings, non-blocking follow-ups, and exact
     artifact identities.
   - Prepare PR/release notes with evidence links.

## Validation Strategy

Initial planning validation:

- `python .agent_work/scripts/validate_agent_work.py`
- `python .agents/skills/towerscout-agent-work-hygiene/scripts/check_agent_work_quick.py .`
- `git diff --check`

Implementation validation should include:

- Focused unit tests for bootstrap/staged asset reuse.
- Focused PowerShell tests for `TowerScoutCompose.ps1`, provider resolution, and
  Podman GPU preflight/provisioner behavior under Windows PowerShell 5.1.
- Compose config validation for base, Docker GPU, Podman GPU, and build-overlay
  combinations.
- Release manifest/schema tests.
- Package-release tests.
- Docker CPU and Docker GPU package smokes on a GPU-capable Windows host.
- Podman CPU package smoke with Docker Desktop absent or not selected.
- Podman GPU provisioning and launch evidence on a WSL2 NVIDIA Podman host.
- Fixed-fixture parity comparison across validated engine/device cells.

## Non-Goals

- Do not make model, threshold, TF32, or detector pipeline changes unless new
  evidence proves a model/runtime correctness issue.
- Do not claim Podman GPU support before the gated CDI path passes on hardware.
- Do not claim Docker-Desktop-free Podman support until the Compose provider path
  is proven without Docker Desktop selection.
- Do not broaden release scope to Mac, ARM64, VDI, shared deployment, native
  installer behavior, or air-gapped GPU toolkit installation.
- Do not delete or reorganize broad repo-root research/legacy folders as part of
  this runtime/release task.

## Risks And Open Questions

- Vendoring or blessing a standalone Compose provider creates license,
  checksum, update, and CVE-response obligations.
- The Podman GPU evidence used Docker Desktop's Compose binary; true
  Docker-Desktop-free GPU validation still needs an approved provider.
- WSL2 Podman memory/resource guidance must be validated before publishing exact
  `podman machine set` commands.
- NVIDIA Toolkit installation requires network egress inside the Podman machine
  unless an offline RPM side-load path is designed later.
- Hosted CI cannot prove GPU/CDI; CI can only cover syntax and decision logic.
- The release matrix may require coordination across one GPU-capable host and
  one Docker-Desktop-free Podman host if a single machine cannot represent both.

## Evidence Handling

Keep raw logs, screenshots, provider responses, `.env` files, private AOIs,
tile/map URLs, provider keys, and user-identifying paths out of project-wide
status files. Store sanitized task-local evidence under a `TASK-083/` support
folder if needed, and summarize only non-secret commands, versions, hashes,
counts, readiness fields, and pass/fail outcomes in the task file.

---

## Implementation Log

### 2026-06-15 - Task Documentation Created
**Objective**: Create a dedicated active task for implementing RC4 follow-ups,
Docker-Desktop-free Podman, Podman GPU CDI support, and next release-candidate
validation.
**Context**: RC4 passed validation, but follow-up analysis identified setup
rerun asset reuse, true Podman provider independence, gated Podman GPU CDI,
release manifest metadata, fixed-fixture evidence, and next package validation
as the correct next work before building another release image.
**Decision**: Track this as `TASK-083` instead of expanding `TASK-081` or
`TASK-082`. `TASK-081` delivered the first runtime hardening slice; `TASK-082`
covers documentation/package organization. This task owns the next runtime and
release validation gate.
**Execution**: Added this task file and linked it from `current-tasks.md`.
**Output**: `TASK-083` is ready for owner review and implementation approval.
**Validation**: `.agent_work` structural validation, agent-work quick check, and
whitespace validation passed.
**Next**: Confirm approved Compose provider strategy and branch base before
implementation begins.

### 2026-06-15 - Branch Prep And RC4 Baseline Lock
**Objective**: Start Task-083 from the landed rc4 baseline and remove stale Task-082 status language before implementation.
**Context**: `TASK-082` landed on `main` as `v0.1.0-rc4` in commit `32074a7`, so Task-083 no longer needs to stack on a docs branch.
**Decision**: Use short-lived branch `feature/task-083-rc5-podman-independence-gpu-release` from current `main` and checkpoint planning/task hygiene before touching runtime code.
**Execution**: Created the Task-083 feature branch, marked Task-082 as landed in the task tracker, and updated Task-083 status from pending approval to branch-prep in progress.
**Output**: Task-083 now starts from the exact rc4 baseline and the active task tracker no longer implies PR #32 is still open.
**Validation**: `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py`, `.venv\Scripts\python.exe .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`, and `git diff --check` passed.
**Next**: Commit the planning checkpoint, then begin Phase 1 implementation.

---

## Validation Results

### Planning Validation
**Test Date**: 2026-06-15
**Test Environment**: Local TowerScout workspace on Windows
**Test Status**: PASS for planning/task-tracker validation

### Acceptance Criteria Validation

- [x] Task tracker entry created in `current-tasks.md`.
- [x] Active task file created under `.agent_work/tasks/active/`.
- [ ] Implementation criteria pending code changes.
- [ ] Runtime/package validation pending implementation.

### Test Results

- [x] `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` - PASS.
- [x] `.venv\Scripts\python.exe .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .` - PASS.
- [x] `git diff --check` - PASS.
- [x] Branch-prep rerun after Task-082 status cleanup and Task-083 status update:
      `.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py`,
      `.venv\Scripts\python.exe .agents\skills\towerscout-agent-work-hygiene\scripts\check_agent_work_quick.py .`,
      and `git diff --check` - PASS.

### Issues Identified

None yet. This checkpoint is planning and branch preparation only.

### Remediation Actions

None yet.

### Sign-off

Not signed off. Planning and branch preparation are complete; implementation
validation is still pending code changes and release-matrix evidence.
