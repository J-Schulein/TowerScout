# Current Tasks - Active Sprint

**Sprint Period**: Sprint 06 preparation begins May 8, 2026  
**Last Updated**: May 8, 2026  
**Focus**: Finish release-support review and prepare Sprint 06 without prematurely pulling unstarted backlog work into the active sprint  
**Status**: Sprint 05 closeout complete for finished task artifacts. `TASK-065` remains the only active carry-forward task.

---

## Sprint 05 Closeout Summary

Sprint 05 delivered the runtime and release-readiness foundation that Sprint 04 intentionally left open. The completed Sprint 05 task artifacts have been moved from `.agent_work/tasks/active/` to `.agent_work/tasks/completed/`:

- `TASK-051`: runtime dependency verification and split
- `TASK-055`: YOLO Torch Hub pinned-ref hardening
- `TASK-056`: first-run reliability and runtime determinism hardening
- `TASK-057`: local YOLO runtime ownership and Torch Hub independence
- `TASK-052`: current integration smoke-test baseline
- `TASK-062`: pre-Docker runtime cleanup and YOLO loader hardening
- `TASK-063`: pre-Docker release hardening and CI reproducibility gate
- `TASK-064`: targeted runtime responsiveness and inference baseline
- `TASK-025`: Docker-compatible / OCI containerization
- `TASK-054`: local launch UX Phase 1 MVP

`TASK-029` was never started during Sprint 05. Its task artifact has been archived as a not-started planning artifact, and the task remains in the backlog table rather than staying in the active sprint.

---

## Active Carry-Forward

### **TASK-065: Release Packaging And Runtime Support Follow-Through**
**Status**: IN_PROGRESS - implementation-complete pending release-owner support-language review and commit/PR checkpoint  
**Type**: B/C (Release Engineering / Runtime Supportability)  
**Priority**: HIGH  
**Estimated Effort**: 1-2 days (8-16 hours)  
**Target Sprint**: Sprint 06 intake / post-`TASK-054` release-support gate  
**Task File**: `.agent_work/tasks/active/TASK-065-release-packaging-runtime-support.md`

**Objective**: Close the release-support items intentionally deferred from `TASK-025` and informed by `TASK-054`, without reopening the completed OCI/container runtime baseline or launcher MVP.

**Current State**:
- Docker-Desktop-free Podman Compose-provider validation passed with `podman-compose 1.5.0`.
- Hosted asset download/bootstrap is out of scope for the v1 control package.
- Bundled OCI image archive fallback is unsupported for the v1 control package; restricted-network support should use support-managed image preload plus local asset import.
- Broad browser/provider regression passed for Google and Azure after launcher browser targeting was changed to `http://localhost:<port>`.
- Missing TLS CA bundle handling now returns actionable setup/support guidance instead of a generic provider-validation 500.
- Release package assembly validation passed into ignored `dist/towerscout-task065-validation`.
- Reviewer hardening addressed evidence redaction, immutable digest enforcement, provider-aware TLS CA verification, Compose-provider reporting, and focused tests.

**Remaining Before Close**:
- Release owner reviews the final support language and residual caveats.
- Commit/PR checkpoint records the release-support updates.
- Follow-up tasks remain in the backlog for clean-machine release-candidate validation, CI gate tightening, Windows/Podman automation, license policy review, and restricted-network package enhancements.

**Validation Notes**:
- `tests/unit/test_config.py tests/unit/test_release_package_script.py` passed after reviewer hardening.
- PowerShell parser checks passed for release helper scripts.
- Podman launcher provider-reporting check passed and reached readiness `ready`.
- `npm.cmd run test:stage-0` remains not runnable in this shell because the Windows `bash.exe` path resolves to WSL without `/bin/bash`.

**User Value**: Turns the completed container and launcher baseline into release-support language and validation evidence that can be trusted by non-technical local users and first-line support.

---

## Sprint 06 Planning Guardrails

- Do not move unstarted backlog tasks into `current-tasks.md` until Sprint 06 planning explicitly selects them.
- Use `.agent_work/task-backlog.md` as the ordered remaining-work table.
- Treat the first Sprint 06 planning decision as a release-readiness decision: close or explicitly carry `TASK-065`, then choose whether `TASK-066`, `TASK-069`, and `TASK-067` are sprint commitments.
- Keep architecture follow-on work (`TASK-058`, `TASK-059`) behind release-candidate readiness unless the team intentionally pauses release work.

---

## Related Documentation

- [Sprint 05 Retrospective Analysis](./context/analysis/SPRINT-05-RETROSPECTIVE-ANALYSIS-2026-05-08.md)
- [Task Backlog](./task-backlog.md)
- [Completed Tasks](./completed-tasks.md)
- [Archived Sprint 05 Plan](./context/archive/2026-05/status/SPRINT-05-PLAN.md)
