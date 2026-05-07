# TASK-054: Local Launch UX

**Status**: NOT_STARTED - READY FOR PHASE 1 PLANNING
**Priority**: MEDIUM  
**Type**: B (Deployment UX / Local Supportability)  
**Estimated Effort**: 1-2 days (8-12 hours)  
**Target Sprint**: Sprint 05 extension / Sprint 06 carry-forward after `TASK-025`

## Objective

Deliver a launcher-first local startup and support flow over the selected OCI/container runtime baseline so a supported Windows/AMD64 local user can start, stop, inspect status/logs, and open TowerScout without relying on raw container CLI workflows.

`TASK-054` is the local UX layer over the `TASK-025` runtime contract. It must not become container implementation, native installer work, cross-platform packaging, or background-job architecture.

After the `TASK-025` merge, this task should assume the normal user path is a GitHub Release ZIP package that wraps the merged OCI/runtime contract. Podman is the preferred open-source Windows runtime target after release-support gates; `TASK-025` validated the Windows WSL engine path, including while Docker Desktop's engine was unavailable, while Docker-Desktop-free Compose-provider validation remains under `TASK-065`. Docker-compatible paths remain useful for developer/support fallback where licensing and endpoint policy allow.

## Requirements (EARS Notation)

**R-054-001**: WHEN a supported Windows local user launches TowerScout from a GitHub Release ZIP package, THE SYSTEM SHALL provide a host-side launcher path beginning with `start.bat` or equivalent release-package script.

**R-054-002**: WHEN the launcher starts TowerScout, THE SYSTEM SHALL wait for application shell readiness before opening the browser.

**R-054-003**: WHEN the selected container engine is running but the application is not ready, THE SYSTEM SHALL distinguish container startup from application readiness.

**R-054-004**: WHEN first-run asset bootstrap is still in progress or has failed, THE SYSTEM SHALL surface actionable status instead of hiding the delay behind a generic startup wait.

**R-054-005**: WHEN users need routine support actions, THE SYSTEM SHALL provide documented or scripted start, stop, logs, and status paths.

**R-054-006**: WHEN startup fails, THE SYSTEM SHALL provide troubleshooting guidance for selected engine not running, Podman machine/WSL2/Hyper-V failures where applicable, Docker Desktop licensing/endpoint issues where applicable, port conflicts, startup timeout, failed first-run asset bootstrap, restricted network behavior, and provider-key failures.

**R-054-007**: WHEN support information is requested, THE PROJECT SHALL document log locations and version/asset manifest collection steps.

**R-054-008**: WHEN unsupported environments are discussed, THE PROJECT SHALL state that Mac, ARM64, offline, air-gapped, shared deployment, and native installer behavior are not v1 support promises.

**R-054-009**: WHEN the launcher polls readiness, THE SYSTEM SHALL consume the `TASK-025` `/api/health` and structured `/api/readiness` contract, including `starting`, `setup_required`, `degraded`, `ready`, and `fatal` states.

## Acceptance Criteria

- [ ] `start.bat` or equivalent Windows-first GitHub Release launcher exists.
- [ ] Launcher waits for app readiness before opening the browser.
- [ ] Stop/logs/status support exists as scripts or clear user-facing guidance.
- [ ] First-run asset/bootstrap delay and failure handling is visible to users.
- [ ] Troubleshooting docs cover selected engine, Podman machine/WSL2/Hyper-V where applicable, Docker Desktop licensing/endpoint where applicable, port, timeout, network, asset, and provider-key failures.
- [ ] Log locations and version/asset manifest collection guidance are documented.
- [ ] Unsupported v1 environments are documented without implying support.
- [ ] Launcher consumes or documents `/api/health` and structured `/api/readiness` state handling.
- [ ] Launcher behavior is validated against the selected runtime-host path from `TASK-025`.

## Dependencies

- `TASK-025`: Docker-compatible / OCI containerization baseline
- `TASK-063`: Pre-Docker release hardening and CI reproducibility gate
- `TASK-065`: Release packaging and runtime support follow-through for Docker-Desktop-free Podman Compose-provider validation and final support language

## Implementation Plan

1. Confirm the merged `TASK-025` scripts, Compose files, `/api/health`, and `/api/readiness` states that the launcher will wrap.
2. Implement Windows-first GitHub Release launcher script and companion stop/logs/status path.
3. Add browser-open behavior only after readiness succeeds.
4. Add first-run asset/bootstrap status and failure guidance.
5. Document routine startup, shutdown, support-log, and troubleshooting flows.
6. Validate clean first launch, repeat launch, startup timeout, and selected-engine-not-running behavior.
7. Coordinate with `TASK-065` before broad Podman support language depends on Docker-Desktop-free Compose-provider behavior.

---

## Implementation Log

### 2026-04-28 - Task File Creation
**Objective**: Create task-specific documentation for the local launcher/support UX layer.  
**Context**: `TASK-054` existed in `current-tasks.md` as a post-Docker stretch task but did not have an individual active task file. The latest review emphasized support diagnostics and operational clarity as v1 success criteria.  
**Decision**: Keep `TASK-054` as the post-Docker local UX/support layer, with explicit boundaries against installer and architecture work.  
**Execution**: Created this task file with EARS requirements, acceptance criteria, dependencies, and implementation plan.  
**Output**: `TASK-054` now has task-specific active documentation.  
**Validation**: Pending `.agent_work` structure validation.  
**Next**: Start only after the selected container runtime baseline is stable enough to target.

### 2026-05-04 - Open-Source Release Package Direction Update
**Objective**: Align launcher scope with the newer GitHub-first, Podman-as-open-source-candidate deployment direction.
**Context**: Client feedback asked for an open-source-friendly path for sites to deploy from GitHub to laptops with clear folder and asset instructions. `TASK-025` now treats GitHub Releases as the normal user-facing release control plane and Podman as the preferred open-source runtime target pending validation.
**Decision**: Keep `TASK-054` as the UX/support layer over the selected runtime contract rather than a Docker-only launcher. The launcher should wrap the GitHub Release ZIP package path and report engine-specific failures without absorbing container implementation.
**Execution**: Updated objective, requirements, acceptance criteria, dependencies, and implementation plan to refer to the selected container engine, GitHub Release package scripts, Podman machine/WSL2/Hyper-V failure handling, and Docker Desktop licensing/endpoint caveats where applicable.
**Output**: `TASK-054` now matches the updated deployment strategy while preserving its boundary from `TASK-025`.
**Validation**: Documentation update only; implementation validation remains pending.
**Next**: Start only after `TASK-025` chooses and validates the runtime-host path that the launcher will wrap.

### 2026-05-05 - Finalized TASK-025 Decision Lock Intake
**Objective**: Align launcher assumptions with the finalized pre-`TASK-025` containerization decisions.
**Context**: The selected package direction is now a GitHub Release ZIP with a pinned GHCR image digest, optional OCI archive fallback, Podman-first target after validation, Docker-compatible fallback, manifest-managed assets, and structured readiness.
**Decision**: Keep `TASK-054` as the runtime UX wrapper. It should consume the structured `/api/health` and `/api/readiness` states from `TASK-025` rather than inventing separate readiness semantics.
**Execution**: Updated objective text, requirements, and acceptance criteria to reference the finalized package/runtime direction and readiness state contract.
**Output**: `TASK-054` now matches the locked `TASK-025` starting contract.
**Validation**: Documentation update only; implementation validation remains pending.
**Next**: Start only after `TASK-025` produces the selected runtime start command and readiness contract.

### 2026-05-07 - Post-TASK-025 Merge Reconciliation
**Objective**: Reconcile `TASK-054` with the merged `TASK-025` baseline without starting launcher implementation.
**Context**: PR #7 merged `TASK-025` into `main`, making the Docker-compatible / OCI runtime baseline available for the launcher task. Podman engine behavior passed on this host, including with Docker Desktop's engine unavailable, but Docker-Desktop-free Compose-provider validation is intentionally deferred to `TASK-065`.
**Decision**: Mark this task ready for Phase 1 planning while keeping implementation unstarted. Keep the launcher scope pointed at the merged `TASK-025` scripts, Compose files, and readiness contract, and keep final Podman support language gated by `TASK-065`.
**Execution**: Updated task status, target sprint, objective context, dependencies, and implementation-plan wording.
**Output**: `TASK-054` is aligned to the post-merge runtime baseline and ready for a separate Phase 1 planning/implementation start.
**Validation**:
- `git diff --check -- .agent_work\design.md .agent_work\requirements.md .agent_work\current-tasks.md .agent_work\task-backlog.md .agent_work\tasks\active\TASK-054-local-launch-ux.md .github\copilot-instructions.md .github\instructions\github-repo-management.instructions.md` -> passed.
- `.\.venv\Scripts\python.exe .agent_work\scripts\validate_agent_work.py` -> passed.
**Next**: Begin Phase 1 only after explicit go-ahead.

---

## Validation Results

Pending implementation.
