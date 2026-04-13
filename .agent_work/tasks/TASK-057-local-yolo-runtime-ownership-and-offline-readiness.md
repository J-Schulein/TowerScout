# TASK-057: Local YOLO Runtime Ownership and Torch Hub Independence

**Status**: NOT_STARTED  
**Priority**: CRITICAL  
**Type**: C (Runtime Architecture / Deployment Readiness)  
**Estimated Effort**: 12-20 hours  
**Created**: April 10, 2026  
**Last Updated**: April 13, 2026  
**Target Sprint**: Sprint 05

---

## Objective

Remove TowerScout's remaining runtime dependence on `torch.hub` and GitHub for YOLO initialization by switching to a TowerScout-owned local YOLO load path before the Sprint 05 smoke baseline and Docker work proceed.

This task is about YOLO runtime ownership and deterministic model initialization. It does not redefine TowerScout as a fully offline application; provider-backed mapping and geocoding still require network access in normal workflows.

This task is the structural follow-on to `TASK-056`. It is intentionally larger than the earlier pinned-ref hardening because it changes who owns the inference code path, but it is still bounded: no ONNX/TensorRT migration, no background-job architecture, and no Docker implementation in this task.

---

## Related Issues

- `UT-014`: YOLO loading still depends on Torch Hub and GitHub at runtime
- `UT-006`: Pinned YOLO Hub autoupdate mutates Pillow/Requests and breaks first detection
- `UT-001`: Pre-Task-055 YOLO master autoupdate detection failure
- `UT-004`: Default install path yields CPU-only Torch; CUDA requires explicit install choice

---

## Context

`TASK-055` made the YOLO runtime safer by pinning a tested upstream commit, but it did not change the deeper deployment problem: TowerScout still loads YOLO through `torch.hub`, which means first-run behavior still depends on Hub cache state, upstream repository availability, and runtime loader behavior not fully owned by TowerScout.

If Sprint 05 is intended to produce a reliable, reproducible, and container-ready application, the stronger end-state is to own the validated YOLO inference source locally and remove runtime GitHub dependence before the smoke baseline and Docker work are frozen.

That requirement is narrower than full offline operation. TowerScout's main imagery and geocoding workflows still depend on external providers, so this task should remove YOLO bootstrap dependence on Torch Hub and GitHub without implying that the entire app must function offline in all contexts.

---

## Scope

### Included

- Vendor or otherwise ship the validated YOLOv5 source snapshot locally inside the TowerScout repo/runtime tree
- Replace the `torch.hub.load(...)` runtime path with a local TowerScout-owned loader
- Validate the local loader against `webapp/model_params/yolov5/newest.pt`
- Preserve the current detection interface expected by TowerScout
- Preserve current automatic CUDA selection behavior when `torch.cuda.is_available()` is true
- Reconfirm the CPU baseline and document/validate optional CUDA compatibility on the local loader path
- Remove Torch Hub / GitHub dependence from first-run YOLO initialization
- Update active runtime/setup docs to reflect the new local-loader contract
- Re-run the bounded clean-runtime proofs needed before `TASK-052`

### Explicitly Excluded

- Exporting the model to ONNX, TensorRT, OpenVINO, or another inference runtime
- Background-job architecture changes
- Docker implementation
- Full performance tuning or large refactors unrelated to the local YOLO ownership goal
- Changing current `dev` lazy-loading behavior
- Declaring TowerScout fully offline-capable across provider-backed workflows

---

## Requirements (EARS Notation)

**R-057-001**: WHEN TowerScout initializes YOLO after this task, THE SYSTEM SHALL use a TowerScout-owned local inference source rather than `torch.hub.load(...)` from GitHub.

**R-057-002**: WHEN the local YOLO loader is used on a clean machine with the validated runtime dependencies already installed, THE SYSTEM SHALL NOT require Torch Hub cache state or first-run GitHub access to initialize the detector.

**R-057-003**: WHEN the local loader is validated, THE SYSTEM SHALL load `webapp/model_params/yolov5/newest.pt` successfully through the local code path.

**R-057-004**: WHEN the local YOLO loader replaces the Hub path, THE SYSTEM SHALL preserve TowerScout's expected detector interface closely enough that existing detection orchestration code does not need unrelated workflow redesign.

**R-057-005**: WHEN TowerScout runs on the validated CPU baseline, THE SYSTEM SHALL support the local loader without requiring CUDA.

**R-057-006**: WHEN TowerScout runs with a compatible CUDA-enabled PyTorch install, THE SYSTEM SHALL continue to document and support CUDA use on the local loader path unless validation proves a specific incompatibility.

**R-057-007**: WHEN first-run validation is executed after this task, THE SYSTEM SHALL prove that the detector can initialize without Torch Hub cache state and without contacting GitHub or Torch Hub during model load.

**R-057-008**: WHEN the runtime contract changes from Hub-based to local-loader-based, THE SYSTEM SHALL update active setup/runtime docs before `TASK-052` defines the smoke baseline.

---

## Acceptance Criteria

- [ ] Type C task artifact exists for `TASK-057`
- [ ] TowerScout no longer uses `torch.hub.load(...)` in the active YOLO load path
- [ ] A validated local YOLO source snapshot is present and referenced by TowerScout
- [ ] `webapp/model_params/yolov5/newest.pt` loads successfully through the local loader
- [ ] First-run detector initialization works without Torch Hub cache state or GitHub/Torch Hub runtime fetches when the runtime dependencies are already installed
- [ ] The current CPU baseline is revalidated on the local loader path
- [ ] Optional CUDA documentation and validation notes are updated for the local loader path
- [ ] Active setup/runtime docs no longer describe first-run GitHub dependence as part of normal YOLO initialization
- [ ] Targeted loader tests and smoke-level proofs exist for the local loader path
- [ ] `pytest --collect-only tests -q` remains clean after the task

---

## Dependencies

- `TASK-056` runtime hardening and deterministic first-run contract
- local access to the validated YOLO weights file at `webapp/model_params/yolov5/newest.pt`
- current issue analysis under `.agent_work/user-testing/issues/`

---

## Implementation Plan

### Phase 1: Local Loader Design
- Select the exact validated YOLO snapshot to vendor locally
- Define the minimal TowerScout-owned loader interface
- Identify any direct dependency adjustments required once the Hub path is removed

### Phase 2: Loader Replacement
- Add the local YOLO snapshot to the repo/runtime tree
- Replace the active `torch.hub` load path with a local load path
- Preserve the surrounding detector contract used by TowerScout

### Phase 3: Runtime and Docs Reconciliation
- Update runtime docs to remove first-run GitHub dependence
- Reconfirm CPU baseline behavior
- Reconfirm optional CUDA path expectations

### Phase 4: Validation and Handoff
- Run clean-runtime proof against the local loader path and verify YOLO initialization no longer uses Torch Hub / GitHub bootstrap behavior
- Run startup/import and pytest-collection validation
- Hand off to `TASK-052` so the smoke baseline is defined on the intended long-lived loader contract

---

## Validation Plan

- Targeted loader tests for the local YOLO path
- Clean-runtime first-run proof without Torch Hub cache dependence
- Proof showing that YOLO initialization no longer contacts GitHub or Torch Hub during model load
- CPU baseline validation
- CUDA compatibility note or proof where hardware is available
- `pytest --collect-only tests -q`

---

## Non-Goals and Safety Boundaries

- Do not let this task expand into alternate inference runtimes
- Do not fold Docker or smoke-baseline implementation into this task
- Do not silently change the current `dev` lazy-loading behavior
- Do not widen into general backend decomposition or queue architecture
- Do not recast this task as a promise that TowerScout's full provider-backed workflow is offline-capable

---

## Initial Planning Log

### TYPE C - TASK-057 SCOPE CORRECTION - 2026-04-13
**Objective**: Narrow `TASK-057` to the actual runtime-contract problem that still blocks `TASK-052` and `TASK-025`.
**Context**: The earlier task title and validation language had started to imply a broad offline-readiness requirement, but TowerScout still depends on online mapping and geocoding providers for normal workflows.
**Decision**: Keep the local YOLO ownership transition and remove the broader offline framing. The acceptance target is now GitHub/Torch Hub-independent model initialization, not a claim that the whole app works fully offline.
**Execution**: Updated the task title, scope, requirements, acceptance criteria, validation plan, and non-goals to focus on local YOLO runtime ownership and first-run independence from Torch Hub / GitHub bootstrap behavior.
**Output**: `TASK-057` now defines the narrower runtime contract that Sprint 05 actually needs before the smoke baseline and Docker work proceed.
**Validation**: `current-tasks.md` and `SPRINT-05-PLAN.md` must reflect the same narrowed contract.
**Next**: Record the scope change in a decision memo and align the remaining planning surfaces.

### TYPE C - TASK-057 PROPOSAL AND SCOPE LOCK - 2026-04-10
**Objective**: Create the Type C task definition for local YOLO runtime ownership before the Sprint 05 smoke baseline is frozen.
**Context**: Issue `UT-014` and the senior engineer critique both concluded that the current pinned Torch Hub path is safer than the old `master` path but still not the right end-state for reproducible deployment and containerization.
**Decision**: Define `TASK-057` as the bounded local-loader transition, separate from `TASK-056` so immediate runtime blockers and the structural loader change remain independently reviewable.
**Execution**: Drafted this task file with issue mapping, scope, EARS requirements, acceptance criteria, and validation boundaries.
**Output**: `TASK-057` now exists as an explicit Sprint 05 task proposal.
**Validation**: Planning artifact created and ready to be referenced by Sprint 05 planning docs.
**Next**: Sync `current-tasks.md`, `SPRINT-05-PLAN.md`, and the backlog to the revised sequence.
